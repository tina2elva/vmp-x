// vmpkeywrap —— 把 1b 的**产物主密钥**包成受保护文件。
//
// 两种形态：
//
//	<产物>.vmpkey.dpapi    DPAPI 用户作用域（STATUS #590）：密文只对**本机 + 本用户**有效。
//	                       挡的是"把文件拷到别的机器/别的用户"，同一用户在本机仍能解开。
//	<产物>.vmpkey.ncrypt   CNG/TPM 包裹（本次新增）：用本机 CNG 持久化密钥（优先
//	                       Microsoft Platform Crypto Provider = TPM，退软件 KSP）的**公钥**
//	                       包裹 32 字节主密钥；私钥永不以可用形式存在，运行期由 blob 调
//	                       NCryptOpenKey + NCryptDecrypt 现场解开。这是"私钥不出安全边界"那一档。
//
// 用法（必须在**目标机器、目标用户**下执行 —— DPAPI 的密钥来自该用户的登录凭据，
// CNG 的持久化密钥也属于那台机器）：
//
//	vmpkeywrap -in build/target_ext.vmpkey -out build/target_ext.exe.vmpkey.ncrypt
//	vmpkeywrap -key 000102...1f          -out <产物>.vmpkey.dpapi
//
// -form 不给（auto）时按 -out 后缀判：.ncrypt -> ncrypt，其它 -> dpapi。
// 产物侧（运行期）优先级：<产物>.vmpkey.ncrypt > <产物>.vmpkey.dpapi > 明文 <产物>.vmpkey。
// 所以"分发时只放受保护文件"是默认姿势，而已有部署（只有明文）逐字节不受影响。
//
// 两条形态都会在**写文件之前**自检：刚做出来的密文必须能在这台机器上解回，且与输入逐字节一致；
// 自检不过就拒绝写出（宁可这里失败，也不要让产物在部署后才炸）。
//
// 边界（如实说）：
//   - DPAPI 用户作用域不挡同一用户在本机的 CryptUnprotectData 调用（本机攻击/内存抓取挡不住）；
//   - ncrypt 形态用软件 KSP 时，只能说"私钥不出 CNG 边界"（我们的 API 导不出来），
//     真正的硬件保证要 TPM —— 工具会把实际用的提供程序打印出来，不冒充硬件。
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vmpx/vmp-x/internal/cred"
)

func main() {
	key := flag.String("key", "", "64 个十六进制字符的主密钥（与 -in 二选一）")
	in := flag.String("in", "", "含 64 个十六进制字符的密钥文件（vmpbuild -key-out 的产物；与 -key 二选一）")
	out := flag.String("out", "", "输出路径：<产物全名>.vmpkey.dpapi 或 <产物全名>.vmpkey.ncrypt")
	form := flag.String("form", "auto", "输出形态：auto（按 -out 后缀判）/ dpapi / ncrypt")
	keyName := flag.String("keyname", cred.PayloadWrapKeyName, "ncrypt 形态用的 CNG 持久化密钥名")
	provider := flag.String("provider", "auto", "ncrypt 形态用哪个 CNG 供应程序：auto（TPM 优先）/ tpm / software")
	// 运维子开关（A4）：删掉本工具/探针在这台机器上留下的**持久化**密钥。
	// 必须显式给 -cleanup 才动手：删除是不可逆的，绝不能让它成为默认行为。
	cleanup := flag.Bool("cleanup", false, "运维：删掉 -keyname 指定的持久化 CNG 密钥（本工具自己创建的；不写任何文件）")
	listKeys := flag.Bool("list", false, "运维：列出本机当前可用的持久化 CNG 密钥名（配合 -cleanup 只看不删）")
	flag.Parse()

	if *cleanup {
		cleanupKeys(*provider, *keyName, *listKeys)
		return
	}

	if (*key == "") == (*in == "") {
		fmt.Fprintln(os.Stderr, "[!] 必须且只能给一个：-key <hex> 或 -in <file>")
		os.Exit(2)
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "[!] 缺少 -out（应写成 <产物全名>.vmpkey.dpapi 或 .vmpkey.ncrypt）")
		os.Exit(2)
	}
	f := strings.ToLower(strings.TrimSpace(*form))
	if f == "" || f == "auto" {
		if strings.HasSuffix(strings.ToLower(*out), cred.PayloadNCryptSuffix) {
			f = "ncrypt"
		} else {
			f = "dpapi"
		}
	}
	if f != "ncrypt" && f != "dpapi" {
		fmt.Fprintf(os.Stderr, "[!] -form 只能是 auto/dpapi/ncrypt（实得 %q）\n", *form)
		os.Exit(2)
	}

	hexStr := strings.TrimSpace(*key)
	if *in != "" {
		b, err := os.ReadFile(*in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] 读密钥文件失败: %v\n", err)
			os.Exit(1)
		}
		hexStr = strings.TrimSpace(string(b))
	}
	// 校验必须是**恰好 64 个 hex 字符**：宁可在这里拒绝，也不要写出一个运行期必然解不开的文件。
	if len(hexStr) != 64 {
		fmt.Fprintf(os.Stderr, "[!] 主密钥必须是 64 个十六进制字符，实得 %d 个\n", len(hexStr))
		os.Exit(2)
	}
	raw, err := hex.DecodeString(hexStr)
	if err != nil || len(raw) != 32 {
		fmt.Fprintln(os.Stderr, "[!] 主密钥不是合法的十六进制")
		os.Exit(2)
	}

	if f == "ncrypt" {
		wrapNCrypt(*provider, *keyName, raw, *out)
		return
	}
	wrapDPAPI(raw, *out)
}

// cleanupKeys：运维子命令（A4）。删掉 -keyname 指定的持久化 CNG 密钥。
//
// 为什么要有它：工具与探针会在这台机器上建**持久化**密钥，它们不随进程退出消失，
// 而 certutil 那条路要管理员（本机实测不行）⇒ 残留只能靠 NCryptDeleteKey 清。
// 输出三件事，缺一不可：真的删了哪些（逐 store）、每个 store 在文件系统的哪里、
// 删不掉的**实际错误码**。删不掉就**明确说没删掉**，绝不写成"已清理"。
//
// -list：先列出当前存在的持久化密钥名（只看不删），用于"这台机器上还有什么是我们建的"。
func cleanupKeys(sel, keyName string, list bool) {
	if err := cred.ValidWrapKeyName(keyName); err != nil {
		fmt.Fprintf(os.Stderr, "[!] -keyname 不合法: %v\n", err)
		os.Exit(2)
	}
	if list {
		names, notes, lerr := cred.CNGEnumPersisted(sel)
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "[!] 列密钥失败: %v\n", lerr)
			os.Exit(1)
		}
		fmt.Printf("[*] persisted CNG keys visible to the current user (%d)\n", len(names))
		// 注意是 range 的**键**（密钥名），值是供应程序名 —— 写成 range names 的
		// 第二个返回值就会把 32 把密钥打印成 32 行"Microsoft Software Key Storage Provider"
		// （冒烟测试时真踩到过）。所以这里用 for n := range names。
		for n := range names {
			mark := ""
			if n == keyName {
				mark = "   <-- this is -keyname"
			}
			fmt.Printf("    %s%s\n", n, mark)
		}
		for _, note := range notes {
			fmt.Printf("    [note] %s\n", note)
		}
		if len(names) == 0 {
			fmt.Println("[!] 没看到任何持久化密钥 —— 空结果要先怀疑枚举/权限，别当成机器很干净")
		}
		// -list 只看不删：显式结束，避免"带了 -list 却把密钥删了"。
		fmt.Println("[*] -list only: nothing was deleted")
		return
	}
	deleted, tried, err := cred.CNGDeletePersisted(sel, keyName)
	fmt.Printf("[*] -cleanup -keyname %q (-provider %s)\n", keyName, showSel(sel))
	if len(deleted) > 0 {
		fmt.Printf("[+] deleted from %d store(s):\n", len(deleted))
		for _, p := range deleted {
			fmt.Printf("    %s  (store: %s)\n", p, storeDir(p))
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] NOT deleted: %v\n", err)
		for _, t := range tried {
			fmt.Fprintf(os.Stderr, "    tried: %s\n", t)
		}
		fmt.Fprintln(os.Stderr, "    (0x80090016 = NTE_BAD_KEYSET: 这个 store 下没有这把密钥)")
		if len(deleted) == 0 {
			os.Exit(1)
		}
	}
	if len(deleted) == 0 {
		fmt.Println("[+] nothing left to delete")
	}
}

// storeDir：这个 store 的用户可见落点在文件系统里的位置（当前用户的 profile 下）。
// 如实说：软件 KSP 的密钥文件确实在这里；Platform Crypto Provider 那把的**私钥材料在 TPM 芯片里**，
// 这里只报告它归属的那个 store 目录（删除是否成功与这个目录无关，只认 NCryptDeleteKey 的返回码）。
func storeDir(provider string) string {
	base := os.Getenv("USERPROFILE")
	if base == "" {
		base = "%USERPROFILE%"
	}
	if strings.Contains(provider, "Platform Crypto") {
		return base + "\\AppData\\Microsoft\\Crypto\\Keys (TPM-backed: the key material itself lives in the chip)"
	}
	return base + "\\AppData\\Microsoft\\Crypto\\Keys"
}

func showSel(sel string) string {
	s := strings.ToLower(strings.TrimSpace(sel))
	if s == "" {
		return "auto"
	}
	return s
}

// wrapDPAPI：<产物>.vmpkey.dpapi（用户作用域；与 STATUS #590 的行为完全一致）。
func wrapDPAPI(raw []byte, out string) {
	blob, err := cred.ProtectPayload(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] 保护失败: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(out, blob, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "[!] 写 %s 失败: %v\n", out, err)
		os.Exit(1)
	}
	// 自检：解回来的必须逐字节等于原密钥 —— 否则说明这台机器上的 DPAPI 行为与预期不符，
	// 与其让产物在部署后才失败，不如现在就说清楚。
	back, err := cred.UnprotectPayload(blob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] 自检失败（刚写出的密文解不开）: %v\n", err)
		os.Exit(1)
	}
	if len(back) != 32 || string(back) != string(raw) {
		fmt.Fprintln(os.Stderr, "[!] 自检失败：解回来的密钥与输入不一致")
		os.Exit(1)
	}
	fmt.Printf("[+] wrote %s (%d bytes, DPAPI user scope)\n", out, len(blob))
	fmt.Println("    machine+user bound: copying it elsewhere or changing one byte will not decrypt")
}

// wrapNCrypt：<产物>.vmpkey.ncrypt（CNG/TPM 持久化密钥的公钥包裹；自检不过就不写文件）。
func wrapNCrypt(sel, keyName string, raw []byte, out string) {
	if err := cred.ValidWrapKeyName(keyName); err != nil {
		fmt.Fprintf(os.Stderr, "[!] -keyname 不合法: %v\n", err)
		os.Exit(2)
	}
	if _, err := cred.CNGProviderSelection(sel); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(2)
	}
	_, created, err := cred.CNGEnsurePayloadKey(sel, keyName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] CNG 包裹密钥不可用: %v\n", err)
		fmt.Fprintln(os.Stderr, "    （本机没有 TPM 也可以：会自动退到 Microsoft Software Key Storage Provider）")
		os.Exit(1)
	}
	blob, used, err := cred.CNGWrapPayload(sel, keyName, raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] 包裹失败: %v\n", err)
		os.Exit(1)
	}
	// 自检（**写文件之前**）：解回来的必须与输入逐字节一致。
	// 这一步走的是与运行期 blob 逐条对应的解析+解密路径，所以它过了，产物侧才会过。
	// 判据只有一份、在 internal/cred（VerifyWrappedPayload）：写在这里会分叉，
	// 而且包外那条路没法用故障注入证明"A3 自检失败即拒绝写出"。
	if err := cred.VerifyWrappedPayload(blob, raw); err != nil {
		fmt.Fprintf(os.Stderr, "[!] 自检失败（拒绝写出）: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(out, blob, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "[!] 写 %s 失败: %v\n", out, err)
		os.Exit(1)
	}
	hw := "software KSP (not hardware-backed)"
	if cred.CNGIsHardwareProvider(used) {
		hw = "TPM (hardware-backed)"
	}
	made := "reused existing key"
	if created {
		made = "created now (non-exportable)"
	}
	selShown := strings.ToLower(strings.TrimSpace(sel))
	if selShown == "" {
		selShown = "auto"
	}
	fmt.Printf("[+] wrote %s (%d bytes, CNG-wrapped RSA-2048/PKCS#1)\n", out, len(blob))
	fmt.Printf("    provider: %s -- %s\n", used, hw)
	fmt.Printf("    key name: %s (%s, -provider %s)\n", keyName, made, selShown)
	fmt.Println("    self-check: decrypted on this machine and matched the input byte for byte")
	if !cred.CNGIsHardwareProvider(used) {
		fmt.Println("    note: the private key stays inside the CNG boundary, but this provider is")
		fmt.Println("          software. Hardware (TPM) assurance was NOT verified on this machine.")
	}
}

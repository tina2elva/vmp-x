// vmpkeywrap —— 把 1b 的**产物主密钥**包成 DPAPI 受保护文件（<产物>.vmpkey.dpapi）。
//
// 为什么要它：部署默认形态是"产物旁边放一个 64 位 hex 的 <产物>.vmpkey"，谁拷走这个文件，
// 就能在别的机器上把产物跑起来。用 DPAPI（用户作用域）包一层之后，密文只对**本机 + 本用户**有效：
// 拷到别的机器/别的用户解不开，被改动一个字节也解不开。
//
// 用法（必须在**目标机器、目标用户**下执行 —— DPAPI 的密钥来自该用户的登录凭据）：
//
//	vmpkeywrap -in build/target_ext.vmpkey -out build/target_ext.exe.vmpkey.dpapi
//	vmpkeywrap -key 000102...1f          -out <产物>.vmpkey.dpapi
//
// 产物侧（运行期）会**优先**读 <产物>.vmpkey.dpapi，解不开或不存在时才回退明文 <产物>.vmpkey。
// 所以"分发时只放受保护文件"是默认姿势，而已有部署（只有明文）逐字节不受影响。
//
// 边界（如实说）：DPAPI 用户作用域挡的是"拷走文件到别的机器/用户"，**不挡**同一用户在本机
// 直接调用 CryptUnprotectData（本机攻击与内存抓取也挡不住）；要更强得上 TPM/软狗。
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
	out := flag.String("out", "", "输出路径，固定用 <产物全名>.vmpkey.dpapi")
	flag.Parse()

	if (*key == "") == (*in == "") {
		fmt.Fprintln(os.Stderr, "[!] 必须且只能给一个：-key <hex> 或 -in <file>")
		os.Exit(2)
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "[!] 缺少 -out（应写成 <产物全名>.vmpkey.dpapi）")
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

	blob, err := cred.ProtectPayload(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] 保护失败: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, blob, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "[!] 写 %s 失败: %v\n", *out, err)
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
	fmt.Printf("[+] wrote %s (%d bytes, DPAPI user scope)\n", *out, len(blob))
	fmt.Println("    machine+user bound: copying it elsewhere or changing one byte will not decrypt")
}

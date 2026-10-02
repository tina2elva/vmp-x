//go:build windows

package cred

// Windows 下的 CNG/TPM 密钥：私钥**永不离开安全边界**（TPM 或 CNG 的不可导出密钥）。
//
// 与 DPAPI 的区别（重要）：
//   DPAPI 保护的是"磁盘上的密钥文件"——同一用户在本机仍可解密（内存抓取/本机攻击挡不住）；
//   这里私钥根本不以可用形式存在：我们只能**让它签一段挑战**，用公钥验签来证明"它在这台机器上"。
//   于是就算把全部文件拷走、把内存 dump 出来，也拿不到可用的私钥。
//
// 提供程序选择：优先 **Microsoft Platform Crypto Provider**（TPM），不可用则退到
// **Microsoft Software Key Storage Provider**（软件不可导出密钥）。
// 如实说明：软件 KSP 的"不可导出"是 CNG 层面的（我们的 API 导不出来），
// 同机管理员仍可能有办法；要真正的硬件保证必须走 TPM 那一档（本文件的尝试顺序已经优先它）。

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	ncryptDLL    = syscall.NewLazyDLL("ncrypt.dll")
	procOpenProv = ncryptDLL.NewProc("NCryptOpenStorageProvider")
	procCreate   = ncryptDLL.NewProc("NCryptCreatePersistedKey")
	procFinalize = ncryptDLL.NewProc("NCryptFinalizeKey")
	procOpenKey  = ncryptDLL.NewProc("NCryptOpenKey")
	procExport   = ncryptDLL.NewProc("NCryptExportKey")
	procSign     = ncryptDLL.NewProc("NCryptSignHash")
	procFree     = ncryptDLL.NewProc("NCryptFreeObject")
	// 产物主密钥包裹（<产物>.vmpkey.ncrypt）用的三个：
	procSetProp = ncryptDLL.NewProc("NCryptSetProperty")
	procEncrypt = ncryptDLL.NewProc("NCryptEncrypt")
	procDecrypt = ncryptDLL.NewProc("NCryptDecrypt")
)

const (
	provTPM         = CNGTPMProviderName
	provSoftware    = "Microsoft Software Key Storage Provider"
	algECDSA256     = "ECDSA_P256"
	blobECCPub      = "ECCPUBLICBLOB"
	blobECCPriv     = "ECCPRIVATEBLOB"
	ncryptOverwrite = 0x00000080
	ncryptSilent    = 0x00000040
)

const eccP256PublicMagic = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC

func mustUTF16(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		return nil
	}
	return p
}

// CNGProviders 返回尝试顺序：TPM 优先。
func CNGProviders() []string { return []string{provTPM, provSoftware} }

func openProvider(name string) (uintptr, error) {
	var h uintptr
	r, _, _ := procOpenProv.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(mustUTF16(name))), 0)
	if r != 0 {
		return 0, fmt.Errorf("NCryptOpenStorageProvider(%s) 失败: 0x%X", name, r)
	}
	return h, nil
}

// cngOpenKey 在某个提供程序下打开已存在的持久化密钥。
func cngOpenKey(provider, keyName string) (uintptr, uintptr, error) {
	hp, err := openProvider(provider)
	if err != nil {
		return 0, 0, err
	}
	var hk uintptr
	r, _, _ := procOpenKey.Call(hp, uintptr(unsafe.Pointer(&hk)), uintptr(unsafe.Pointer(mustUTF16(keyName))), 0, ncryptSilent)
	if r != 0 {
		procFree.Call(hp)
		return 0, 0, fmt.Errorf("NCryptOpenKey(%s @ %s) 失败: 0x%X", keyName, provider, r)
	}
	return hp, hk, nil
}

// CNGCreate 创建（或覆盖）一把持久化的 P-256 密钥，返回公钥 X||Y（64 字节）与实际使用的提供程序。
func CNGCreate(name string) (pub []byte, providerUsed string, err error) {
	var lastErr error
	var hk uintptr
	for _, prov := range CNGProviders() {
		hp, perr := openProvider(prov)
		if perr != nil {
			lastErr = perr
			continue
		}
		var h uintptr
		r, _, _ := procCreate.Call(hp, uintptr(unsafe.Pointer(&h)),
			uintptr(unsafe.Pointer(mustUTF16(algECDSA256))), uintptr(unsafe.Pointer(mustUTF16(name))), 0, ncryptOverwrite)
		if r != 0 {
			procFree.Call(hp)
			lastErr = fmt.Errorf("NCryptCreatePersistedKey(%s) 失败: 0x%X", prov, r)
			continue
		}
		r, _, _ = procFinalize.Call(h, ncryptSilent)
		if r != 0 {
			procFree.Call(h)
			procFree.Call(hp)
			lastErr = fmt.Errorf("NCryptFinalizeKey(%s) 失败: 0x%X", prov, r)
			continue
		}
		hk = h
		providerUsed = prov
		break
	}
	if hk == 0 {
		return nil, "", fmt.Errorf("没有可用的 CNG 提供程序（TPM 与软件 KSP 都失败）: %v", lastErr)
	}
	defer procFree.Call(hk)
	pub, err = exportPub(hk)
	if err != nil {
		return nil, "", err
	}
	return pub, providerUsed, nil
}

func exportPub(hk uintptr) ([]byte, error) {
	buf := make([]byte, 256)
	var need uint32
	r, _, _ := procExport.Call(hk, 0, uintptr(unsafe.Pointer(mustUTF16(blobECCPub))), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&need)), ncryptSilent)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey(公钥) 失败: 0x%X", r)
	}
	if need < 8 || int(need) > len(buf) {
		return nil, fmt.Errorf("公钥 blob 长度异常: %d", need)
	}
	b := buf[:need]
	magic := binary.LittleEndian.Uint32(b[0:4])
	cbKey := binary.LittleEndian.Uint32(b[4:8])
	if magic != eccP256PublicMagic || cbKey != 32 || len(b) < 8+64 {
		return nil, fmt.Errorf("公钥 blob 不是 P-256（magic=0x%X cbKey=%d）", magic, cbKey)
	}
	out := make([]byte, 64)
	copy(out, b[8:8+64])
	return out, nil
}

// CNGSignChallenge 用持久化密钥对一段消息做 ECDSA P-256 签名，返回 r||s（64 字节，与 CNG 的格式一致）。
func CNGSignChallenge(name string, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	var lastErr error
	for _, prov := range CNGProviders() {
		hp, hk, err := cngOpenKey(prov, name)
		if err != nil {
			lastErr = err
			continue
		}
		sig := make([]byte, 128)
		var need uint32
		r, _, _ := procSign.Call(hk, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
			uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)), uintptr(unsafe.Pointer(&need)), ncryptSilent)
		procFree.Call(hk)
		procFree.Call(hp)
		if r != 0 {
			lastErr = fmt.Errorf("NCryptSignHash(%s) 失败: 0x%X", prov, r)
			continue
		}
		if need != 64 {
			return nil, fmt.Errorf("签名长度异常: %d（期望 64）", need)
		}
		return sig[:64], nil
	}
	return nil, fmt.Errorf("找不到可用的密钥 %q: %v", name, lastErr)
}

// CNGTryExportPrivate 尝试导出**私钥**：成功说明这把密钥是可导出的（不可导出密钥会失败）。
// 这是给 cng-probe 用的证据探针，不参与授权校验。
func CNGTryExportPrivate(name string) error {
	var lastErr error
	for _, prov := range CNGProviders() {
		hp, hk, err := cngOpenKey(prov, name)
		if err != nil {
			lastErr = err
			continue
		}
		defer procFree.Call(hp)
		defer procFree.Call(hk)
		buf := make([]byte, 512)
		var need uint32
		r, _, _ := procExport.Call(hk, 0, uintptr(unsafe.Pointer(mustUTF16(blobECCPriv))), 0,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&need)), ncryptSilent)
		if r == 0 {
			return fmt.Errorf("这把密钥**可以被导出**（%d 字节私钥 blob）—— 说明它不是不可导出的", need)
		}
		return fmt.Errorf("导出私钥被拒绝（0x%X）—— 符合预期：密钥不可导出", r)
	}
	return fmt.Errorf("打不开密钥 %q: %v", name, lastErr)
}

// CNGVerifyChallenge 用公钥验签（供测试与自检使用）。
func CNGVerifyChallenge(pub []byte, msg, sig []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("签名长度不是 64")
	}
	p, err := PubFromHex(hexOf(pub))
	if err != nil {
		return err
	}
	return VerifySigDigest(p, sha256Sum(msg), sig)
}

// hexOf 只是把字节转成 hex（内部小工具）。
func hexOf(b []byte) string {
	const tab = "0123456789abcdef"
	sb := strings.Builder{}
	for _, c := range b {
		sb.WriteByte(tab[c>>4])
		sb.WriteByte(tab[c&0xF])
	}
	return sb.String()
}

// ---------------- 产物主密钥的 CNG/TPM 包裉（<产物>.vmpkey.ncrypt）----------------
//
// 这就是「私钥永不出安全边界」的那一档：
//   - 包裹用的是持久化 RSA-2048 密钥的**公钥**，私钥在 CNG 安全边界里
//     （优先 Microsoft Platform Crypto Provider = TPM，不可用则退软件 KSP）；
//   - 文件里只有 RSA 密文 + 密钥名，拷到别的机器/别的用户都解不开；
//   - 运行期由 blob 自己调 NCryptOpenKey + NCryptDecrypt（见 stub/win/x64/vm_interp.c）。
//
// 算法与填充：RSA-2048 + PKCS#1 v1.5（NCRYPT_PAD_PKCS1）。
// 选 PKCS#1 而不是 OAEP 是为了兼容性：TPM 那一档（Platform Crypto Provider）
// 对 PKCS#1 解密的支持在各个 Windows 版本上最稳。
//
// 诚实说明：软件 KSP 只能说“私钥不出 CNG 边界”（我们的 API 导不出来），
// 不能说“私钥不出芯片”——后者要硬件 TPM。
const (
	// rsaAlgorithm：包裹密钥的算法名（NCryptCreatePersistedKey 用的是算法标识字符串）。
	rsaAlgorithm = "RSA"
	// wrapKeyBits：包裹密钥长度。
	wrapKeyBits = 2048
	// ncryptPadPKCS1 = NCRYPT_PAD_PKCS1；NCRYPT_SILENT_FLAG 用已有的 ncryptSilent。
	ncryptPadPKCS1 = 0x00000002
	// ncryptLengthProp = NCRYPT_LENGTH_PROPERTY 的属性名（必须在 Finalize 之前设）。
	ncryptLengthProp = "Length"
	// wrapPlainLen：包裹的明文总是 32 字节（解密缓冲区也就是这么大，与运行期一致）。
	wrapPlainLen = 32
)

func ncryptStatus(op string, r uintptr) error {
	return fmt.Errorf("%s failed: 0x%X", op, uint32(r))
}

// ncryptEncrypt 用已打开的密钥（只需公钥部分）做 RSA/PKCS#1 加密。
func ncryptEncrypt(hk uintptr, plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("ncryptEncrypt: 明文为空")
	}
	buf := make([]byte, 512)
	var need uint32
	r, _, _ := procEncrypt.Call(hk, uintptr(unsafe.Pointer(&plain[0])), uintptr(len(plain)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&need)),
		ncryptSilent|ncryptPadPKCS1)
	if r != 0 {
		return nil, ncryptStatus("NCryptEncrypt(PKCS1)", r)
	}
	if need < 32 || int(need) > len(buf) {
		return nil, fmt.Errorf("NCryptEncrypt 返回的密文长度异常: %d", need)
	}
	out := make([]byte, need)
	copy(out, buf[:need])
	return out, nil
}

// ncryptDecrypt 用已打开的密钥做 RSA/PKCS#1 解密，输出必须正好 32 字节。
// 填充被动过、密钥不对、不是同一台机器 —— 都会在这里失败。
func ncryptDecrypt(hk uintptr, ct []byte) ([]byte, error) {
	if len(ct) == 0 {
		return nil, fmt.Errorf("ncryptDecrypt: 密文为空")
	}
	buf := make([]byte, wrapPlainLen)
	var need uint32
	r, _, _ := procDecrypt.Call(hk, uintptr(unsafe.Pointer(&ct[0])), uintptr(len(ct)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&need)),
		ncryptSilent|ncryptPadPKCS1)
	if r != 0 {
		return nil, ncryptStatus("NCryptDecrypt(PKCS1)", r)
	}
	if need != wrapPlainLen {
		return nil, fmt.Errorf("解出来的明文长度不是 %d（实得 %d）", wrapPlainLen, need)
	}
	out := make([]byte, wrapPlainLen)
	copy(out, buf[:need])
	return out, nil
}

// ncryptRoundTrip：用同一把密钥做一次 加密→解密，答案必须逐字节相等。
// 这是在「这台机器上这把密钥到底能不能做 RSA 解密」上的唯一可信证据：
// TPM 那一档既可能“能建但不能解”（用途策略不对），也可能“能解但解错”。
func ncryptRoundTrip(hk uintptr) error {
	probe := make([]byte, wrapPlainLen)
	copy(probe, "vmpx-wrap-selftest-v1")
	ct, err := ncryptEncrypt(hk, probe)
	if err != nil {
		return err
	}
	back, err := ncryptDecrypt(hk, ct)
	if err != nil {
		return err
	}
	if string(back) != string(probe) {
		return fmt.Errorf("加密→解密的往返结果与输入不一致")
	}
	return nil
}

// CNGProviderSelection：把 -provider 选项译成供应程序队列。
//
//	auto（空串）= TPM 优先，不可用则退软件 KSP（运行期的顺序也是这个）；
//	tpm / software = 只用指定的那一个（验收用来把两条路径分开测）。
func CNGProviderSelection(sel string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(sel)) {
	case "", "auto":
		return CNGProviders(), nil
	case "tpm":
		return []string{provTPM}, nil
	case "software", "ksp":
		return []string{provSoftware}, nil
	}
	return nil, fmt.Errorf("-provider 只能是 auto/tpm/software（实得 %q）", sel)
}

// CNGFindPayloadKey 在给定供应程序队列里找到能用的包裉密钥，并**实测**一次往返。
func CNGFindPayloadKey(sel, name string) (provider string, err error) {
	if err := ValidWrapKeyName(name); err != nil {
		return "", err
	}
	provs, serr := CNGProviderSelection(sel)
	if serr != nil {
		return "", serr
	}
	var lastErr error
	for _, prov := range provs {
		hp, hk, oerr := cngOpenKey(prov, name)
		if oerr != nil {
			lastErr = oerr
			continue
		}
		perr := ncryptRoundTrip(hk)
		procFree.Call(hk)
		procFree.Call(hp)
		if perr != nil {
			lastErr = fmt.Errorf("%s 下的密钥 %q 不能做 RSA 解密: %v", prov, name, perr)
			continue
		}
		return prov, nil
	}
	return "", fmt.Errorf("找不到可用的包裹密钥 %q（TPM 与软件 KSP 都没成功）: %v", name, lastErr)
}

// CNGEnsurePayloadKey：找得到就直接用；找不到就在给定的供应程序队列（默认 TPM → 软件 KSP）里
// 建一把不可导出的 RSA-2048（建完立刻做一次加解密往返，不行就换下一个提供程序）。
func CNGEnsurePayloadKey(sel, name string) (provider string, created bool, err error) {
	if prov, ferr := CNGFindPayloadKey(sel, name); ferr == nil {
		return prov, false, nil
	}
	if err := ValidWrapKeyName(name); err != nil {
		return "", false, err
	}
	provs, serr := CNGProviderSelection(sel)
	if serr != nil {
		return "", false, serr
	}
	var lastErr error
	for _, prov := range provs {
		hp, oerr := openProvider(prov)
		if oerr != nil {
			lastErr = oerr
			continue
		}
		var h uintptr
		r, _, _ := procCreate.Call(hp, uintptr(unsafe.Pointer(&h)),
			uintptr(unsafe.Pointer(mustUTF16(rsaAlgorithm))), uintptr(unsafe.Pointer(mustUTF16(name))), 0, 0)
		if r != 0 {
			procFree.Call(hp)
			lastErr = fmt.Errorf("NCryptCreatePersistedKey(RSA @ %s) 失败: 0x%X", prov, uint32(r))
			continue
		}
		bits := make([]byte, 4)
		binary.LittleEndian.PutUint32(bits, uint32(wrapKeyBits))
		if sr, _, _ := procSetProp.Call(h, uintptr(unsafe.Pointer(mustUTF16(ncryptLengthProp))),
			uintptr(unsafe.Pointer(&bits[0])), uintptr(len(bits)), ncryptSilent); sr != 0 {
			// 设不上不算失败（默认就是 2048）：真正的判定是下面的往返测试。
			lastErr = fmt.Errorf("NCryptSetProperty(Length @ %s) 失败: 0x%X", prov, uint32(sr))
		}
		if fr, _, _ := procFinalize.Call(h, ncryptSilent); fr != 0 {
			procFree.Call(h)
			procFree.Call(hp)
			lastErr = fmt.Errorf("NCryptFinalizeKey(RSA @ %s) 失败: 0x%X", prov, uint32(fr))
			continue
		}
		perr := ncryptRoundTrip(h)
		procFree.Call(h)
		procFree.Call(hp)
		if perr != nil {
			lastErr = fmt.Errorf("在 %s 下建的包裹密钥不能做 RSA 解密: %v", prov, perr)
			continue
		}
		return prov, true, nil
	}
	return "", false, fmt.Errorf("没有可用的 CNG 提供程序来建包裹密钥（TPM 与软件 KSP 都失败）: %v", lastErr)
}

// CNGWrapPayload 用持久化密钥的公钥把 32 字节主密钥包成 .ncrypt 文件内容。
func CNGWrapPayload(sel, name string, master []byte) (blob []byte, provider string, err error) {
	if len(master) != wrapPlainLen {
		return nil, "", fmt.Errorf("主密钥必须是 %d 字节（实得 %d）", wrapPlainLen, len(master))
	}
	provs, serr := CNGProviderSelection(sel)
	if serr != nil {
		return nil, "", serr
	}
	var lastErr error
	for _, prov := range provs {
		hp, hk, oerr := cngOpenKey(prov, name)
		if oerr != nil {
			lastErr = oerr
			continue
		}
		ct, eerr := ncryptEncrypt(hk, master)
		procFree.Call(hk)
		procFree.Call(hp)
		if eerr != nil {
			lastErr = eerr
			continue
		}
		b, merr := MarshalPayloadNCrypt(name, ct)
		if merr != nil {
			return nil, "", merr
		}
		return b, prov, nil
	}
	return nil, "", fmt.Errorf("用 %q 包裹失败（TPM 与软件 KSP 都没成功）: %v", name, lastErr)
}

// CNGUnwrapPayloadBlob 解开 .ncrypt 内容，返回 32 字节主密钥。
// 工具侧自检用的就是这个：它与运行期 blob 的解析/解密逐条对应
// （同一份格式、同一个提供程序顺序、同一个填充标志），自检不过就不写文件。
func CNGUnwrapPayloadBlob(blob []byte) ([]byte, error) {
	name, ct, err := ParsePayloadNCrypt(blob)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, prov := range CNGProviders() {
		hp, hk, oerr := cngOpenKey(prov, name)
		if oerr != nil {
			lastErr = oerr
			continue
		}
		pt, derr := ncryptDecrypt(hk, ct)
		procFree.Call(hk)
		procFree.Call(hp)
		if derr != nil {
			lastErr = fmt.Errorf("%s: %v", prov, derr)
			continue
		}
		return pt, nil
	}
	return nil, fmt.Errorf("解不开密钥名 %q 的密文（本机没有这把持久化密钥，或密文被改过/来自别的机器）: %v", name, lastErr)
}

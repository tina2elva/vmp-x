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
)

const (
	provTPM         = "Microsoft Platform Crypto Provider"
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

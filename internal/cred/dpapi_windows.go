//go:build windows

package cred

// Windows 下的密钥保护：DPAPI（CryptProtectData / CryptUnprotectData，用户作用域）。
//
// 为什么需要它：工具授权的配套私钥原来是明文 vmpx.key —— 谁拷走这个文件就能用工具。
// 用 DPAPI 包一层之后，密文只有**同一台机器上的同一个用户**能解开：
// 拷到别的机器/别的用户 ⇒ 解不开 ⇒ 工具拒绝启动（正是我们要的"明确拒绝"）。
//
// 边界（如实说明）：DPAPI 的用户作用域**不防同一用户下的本机攻击**，也不防内存抓取；
// 要"私钥永不出芯片"得上 TPM/CNG（NCryptCreatePersistedKey + 不可导出），那是下一步。

import (
	"fmt"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32DLL    = syscall.NewLazyDLL("crypt32.dll")
	procProtect   = crypt32DLL.NewProc("CryptProtectData")
	procUnprot    = crypt32DLL.NewProc("CryptUnprotectData")
	kernel32DLL   = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree = kernel32DLL.NewProc("LocalFree")
)

// Entropy 是额外混入的固定串：让这份密文只对"本工具的密钥保护"有意义，
// 别的程序即使用同一个用户也解不出一份"通用"明文。
var Entropy = []byte("vmpx-toolkey-v1")

const cryptprotectUIFORBIDDEN = 0x1

func blobOf(b []byte) (*dataBlob, error) {
	if len(b) == 0 {
		return &dataBlob{}, nil
	}
	return &dataBlob{cbData: uint32(len(b)), pbData: &b[0]}, nil
}

func takeBlob(out dataBlob) []byte {
	if out.cbData == 0 || out.pbData == nil {
		return nil
	}
	cp := make([]byte, out.cbData)
	copy(cp, unsafe.Slice(out.pbData, out.cbData))
	_, _, _ = procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return cp
}

// Protect 用 DPAPI 加密（用户作用域）。
func Protect(plain []byte) ([]byte, error) {
	in, err := blobOf(plain)
	if err != nil {
		return nil, err
	}
	ent, _ := blobOf(Entropy)
	var out dataBlob
	r, _, lastErr := procProtect.Call(uintptr(unsafe.Pointer(in)), 0,
		uintptr(unsafe.Pointer(ent)), 0, 0, cryptprotectUIFORBIDDEN, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData 失败: %v", lastErr)
	}
	return takeBlob(out), nil
}

// Unprotect 解密；换机器/换用户/被篡改都会失败。
func Unprotect(blob []byte) ([]byte, error) {
	in, err := blobOf(blob)
	if err != nil {
		return nil, err
	}
	ent, _ := blobOf(Entropy)
	var out dataBlob
	r, _, lastErr := procUnprot.Call(uintptr(unsafe.Pointer(in)), 0,
		uintptr(unsafe.Pointer(ent)), 0, 0, cryptprotectUIFORBIDDEN, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData 失败（换机器/换用户/被篡改都会这样）: %v", lastErr)
	}
	return takeBlob(out), nil
}

// Available 表示本平台支持这种保护。
func Available() bool { return true }

//go:build !windows

package cred

// 非 Windows：没有 DPAPI。这里明确报错而不是静默退回明文 ——
// "以为受保护、其实没有"比"不受保护"更危险。

import "fmt"

func Protect(plain []byte) ([]byte, error) {
	return nil, fmt.Errorf("DPAPI 只在 Windows 可用（本平台请改用 TPM/软狗，或接受明文密钥的风险）")
}

func Unprotect(blob []byte) ([]byte, error) {
	return nil, fmt.Errorf("DPAPI 只在 Windows 可用")
}

func Available() bool { return false }

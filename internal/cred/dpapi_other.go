//go:build !windows

package cred

// 非 Windows：没有 DPAPI。这里明确报错而不是静默退回明文 ——
// "以为受保护、其实没有"比"不受保护"更危险。

import "fmt"

// EntropyPayload 与 Windows 侧同名（非 Windows 下没有任何密文会被它保护，仅为接口对称）。
var EntropyPayload = []byte("vmpx-payload-key-v1")

func Protect(plain []byte) ([]byte, error) {
	return nil, fmt.Errorf("DPAPI 只在 Windows 可用（本平台请改用 TPM/软狗，或接受明文密钥的风险）")
}

// ProtectPayload：产物主密钥的受保护形态同样只在 Windows 可用。
func ProtectPayload(plain []byte) ([]byte, error) {
	return nil, fmt.Errorf("DPAPI 只在 Windows 可用（产物主密钥的受保护形态需要 Windows）")
}

// UnprotectPayload：同上。
func UnprotectPayload(blob []byte) ([]byte, error) {
	return nil, fmt.Errorf("DPAPI 只在 Windows 可用")
}

func Unprotect(blob []byte) ([]byte, error) {
	return nil, fmt.Errorf("DPAPI 只在 Windows 可用")
}

func Available() bool { return false }

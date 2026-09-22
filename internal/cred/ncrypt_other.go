//go:build !windows

package cred

import "fmt"

// 非 Windows：没有 CNG/TPM。明确报错，不静默降级。
func CNGProviders() []string { return nil }

func CNGCreate(name string) ([]byte, string, error) {
	return nil, "", fmt.Errorf("CNG/TPM 密钥只在 Windows 可用")
}

func CNGSignChallenge(name string, msg []byte) ([]byte, error) {
	return nil, fmt.Errorf("CNG/TPM 密钥只在 Windows 可用")
}

func CNGTryExportPrivate(name string) error {
	return fmt.Errorf("CNG/TPM 密钥只在 Windows 可用")
}

func CNGVerifyChallenge(pub []byte, msg, sig []byte) error {
	return fmt.Errorf("CNG/TPM 密钥只在 Windows 可用")
}

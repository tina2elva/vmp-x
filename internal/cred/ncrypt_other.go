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

// 产物主密钥的 CNG 包裹：非 Windows 上没有 CNG，明确报错（不静默降级到明文）。
func CNGProviderSelection(sel string) ([]string, error) {
	return nil, fmt.Errorf("CNG/TPM 密钥只在 Windows 可用")
}

func CNGFindPayloadKey(sel, name string) (string, error) {
	return "", fmt.Errorf("CNG/TPM 密钥只在 Windows 可用")
}

func CNGEnsurePayloadKey(sel, name string) (string, bool, error) {
	return "", false, fmt.Errorf("CNG/TPM 密钥只在 Windows 可用")
}

func CNGWrapPayload(sel, name string, master []byte) ([]byte, string, error) {
	return nil, "", fmt.Errorf("CNG/TPM 密钥只在 Windows 可用")
}

func CNGUnwrapPayloadBlob(blob []byte) ([]byte, error) {
	return nil, fmt.Errorf("CNG/TPM 密钥只在 Windows 可用")
}

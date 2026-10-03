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

// A4 的运维入口只在 Windows 上有意义（别的平台连 CNG 都没有）。
// **必须有这两个桩**：cmd/vmpkeywrap 是无 build tag 的 main 包，Linux 上的
// "go build ./..." 会把它一起编 —— 少了它们整条 Linux 半场会红（已踩过）。
func CNGDeletePersisted(sel, name string) ([]string, []string, error) {
	return nil, nil, fmt.Errorf("CNG/TPM 密钥只在 Windows 可用（-cleanup 也一样）")
}

func CNGEnumPersisted(sel string) (map[string]string, []string, error) {
	return nil, nil, fmt.Errorf("CNG/TPM 密钥只在 Windows 可用（-list 也一样）")
}

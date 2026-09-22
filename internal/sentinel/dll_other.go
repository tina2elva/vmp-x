//go:build !windows

package sentinel

import "fmt"

// 非 Windows：Sentinel LDK 的运行时按平台分发，这里明确报错而不是假装成功。
func openReal(o Options) (Backend, error) {
	if o.DLLPath != "" {
		return nil, fmt.Errorf("本平台不支持 Sentinel DLL 后端（仅 Windows）；没有狗时请用假后端：VMPX_SENTINEL_FAKE=<文件>")
	}
	return nil, fmt.Errorf("本平台没有 Sentinel 后端（仅 Windows）；没有狗时请用假后端：VMPX_SENTINEL_FAKE=<文件>")
}

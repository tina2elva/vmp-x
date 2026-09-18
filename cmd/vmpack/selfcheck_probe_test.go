package main

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/load/pe"
)

// TestProbeCookieCheck：真实样本上的回归测试（__security_check_cookie 两种形态都要识别出来）。
func TestProbeCookieCheck(t *testing.T) {
	const p = "D:/taiji/pytest/example.cp313-win_amd64.pyd"
	f, err := pe.Open(p)
	if err != nil {
		t.Skipf("样本不可用: %v", err)
	}
	b, ok := peRvaBytes(f.Data, 0x6E40, 32)
	if !ok {
		t.Fatal("取不到 RVA 0x6E40 的字节")
	}
	t.Logf("bytes=% x", b)
	if !isSecurityCookieCheck(b) {
		t.Fatal("未识别出 __security_check_cookie")
	}
	// 普通函数不能被误判
	for _, rva := range []uint32{0x3C90, 0x6630} {
		b2, _ := peRvaBytes(f.Data, rva, 32)
		if isSecurityCookieCheck(b2) {
			t.Fatalf("误判 RVA 0x%X 为 cookie 检查", rva)
		}
	}
}

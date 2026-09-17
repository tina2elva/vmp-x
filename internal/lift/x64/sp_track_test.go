package x64

import (
	"strings"
	"testing"
)

// 回归：只读指令（CMP/TEST）**不能**被当成"改写了 RSP"。
//
// 这条 bug 曾在 Go 二进制上造成 14651/19506 条被拒指令——Go 的栈增长检查是
// "CMP RSP, [R14+0x10]"（R14 = g），旧规则按"第一个操作数是 RSP 就当被改写"处理，
// 于是函数里后续所有栈访问全部报废。修好后该二进制函数级覆盖率 19.6% → 50.3%。
func TestCmpRspKeepsStackTracking(t *testing.T) {
	code := []byte{
		0x49, 0x3B, 0x66, 0x10, // cmp rsp, [r14+0x10]   (Go 的 stackguard 检查)
		0x48, 0x8B, 0x44, 0x24, 0x08, // mov rax, [rsp+0x8]
		0xC3, // ret
	}
	l := &Lifter{}
	fn, err := l.LiftFunc("t", code, 0)
	if err != nil {
		t.Fatalf("CMP RSP 之后不该失去栈跟踪：%v", err)
	}
	for _, u := range fn.Unsupported {
		if strings.Contains(u, "不可跟踪") {
			t.Fatalf("仍把 CMP 当成改写了 RSP：%s", u)
		}
	}
	if len(fn.Insns) < 2 {
		t.Fatalf("翻译出的 IR 指令太少：%d", len(fn.Insns))
	}
}

// TEST 同理（它也是只写标志位）
func TestTestRspKeepsStackTracking(t *testing.T) {
	code := []byte{
		0x48, 0x85, 0xE4, // test rsp, rsp
		0x48, 0x8B, 0x44, 0x24, 0x08, // mov rax, [rsp+0x8]
		0xC3,
	}
	l := &Lifter{}
	fn, err := l.LiftFunc("t", code, 0)
	if err != nil {
		t.Fatalf("TEST RSP 之后不该失去栈跟踪：%v", err)
	}
	for _, u := range fn.Unsupported {
		if strings.Contains(u, "不可跟踪") {
			t.Fatalf("仍把 TEST 当成改写了 RSP：%s", u)
		}
	}
}

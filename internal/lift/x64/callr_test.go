package x64

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
)

// 间接 CALL（虚调用/函数指针）应当翻成 CallR；相对 CALL 仍是 CallN。
// 语义层面由 Windows E2E 的 callptr 用例端到端验证（native == protected）。
func TestLiftIndirectCall(t *testing.T) {
	// call *%rcx  = FF D1
	l := &Lifter{}
	fn, err := l.LiftFunc("t", []byte{0xFF, 0xD1, 0xC3}, 0)
	if err != nil {
		t.Fatalf("lift 间接 CALL 失败: %v", err)
	}
	got := false
	for _, in := range fn.Insns {
		if in.Op == ir.CallR {
			got = true
			if in.A != ir.RCX {
				t.Fatalf("CallR 的目标寄存器应是 RCX，实际 %v", in.A)
			}
		}
	}
	if !got {
		t.Fatal("间接 CALL 没有被翻成 CallR")
	}

	// call *0x8(%rax) = FF 50 08 → 先 Load 到 VMSCR，再 CallR VMSCR
	l2 := &Lifter{}
	fn2, err := l2.LiftFunc("t", []byte{0xFF, 0x50, 0x08, 0xC3}, 0)
	if err != nil {
		t.Fatalf("lift 内存间接 CALL 失败: %v", err)
	}
	sawLoad, sawCall := false, false
	for _, in := range fn2.Insns {
		if in.Op == ir.Load && in.Dst == ir.VMSCR {
			sawLoad = true
		}
		if in.Op == ir.CallR && in.A == ir.VMSCR {
			sawCall = true
		}
	}
	if !sawLoad || !sawCall {
		t.Fatalf("内存间接 CALL 应翻成 Load VMSCR + CallR VMSCR（load=%v call=%v）", sawLoad, sawCall)
	}
}

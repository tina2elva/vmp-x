package x64

// 32 位客户机的**典型函数序言**在两种模式下的 IR 断言。
//
// 为什么用它当 ③-d 的判据：这段序言浓缩了 32 位 ABI 的两个要点 ——
//   1) 栈槽是 4 字节（push ebp / pop ebp）；
//   2) 第一个参数在 [ebp+8]（不是 x64 的 RCX）。
// 只要它能完整翻译、且 IR 形状正确，说明"地址/指针宽度按模式走"这条接线是通的；
// 反过来说，之前硬要求 W64 时这里是 **3/5 条无法翻译**（fail-loud，不是静默）。

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
)

// 55        push ebp
// 8B EC     mov ebp, esp
// 8B 45 08  mov eax, [ebp+8]
// 5D        pop ebp
// C3        ret
var prologue32Code = []byte{0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x5D, 0xC3}

func liftPrologue(t *testing.T, mode int) *ir.Func {
	t.Helper()
	l := NewLifterMode(0x400000, mode)
	f, err := l.LiftFunc("prologue", prologue32Code, 0x1000)
	if err != nil {
		t.Fatalf("mode=%d 序言翻译失败: %v", mode, err)
	}
	return f
}

func TestLift32Prologue(t *testing.T) {
	f := liftPrologue(t, 32)
	if len(f.Insns) != 5 {
		t.Fatalf("指令数=%d，期望 5（push/mov/mov-load/pop/ret）", len(f.Insns))
	}
	if f.Insns[0].Op != ir.PushR || f.Insns[0].Dst != ir.RBP {
		t.Fatalf("第 1 条应当是 PUSH RBP，实际 %v %v", f.Insns[0].Op, f.Insns[0].Dst)
	}
	if f.Insns[1].Op != ir.MovRR || f.Insns[1].Dst != ir.RBP || f.Insns[1].A != ir.RSP {
		t.Fatalf("第 2 条应当是 MOV RBP,RSP，实际 %v %v<-%v", f.Insns[1].Op, f.Insns[1].Dst, f.Insns[1].A)
	}
	ld := f.Insns[2]
	if ld.Op != ir.Load || ld.Base != ir.RBP || ld.Disp != 8 {
		t.Fatalf("第 3 条应当是 LOAD [RBP+8]（32 位 ABI 第一个参数），实际 %v base=%v disp=0x%X", ld.Op, ld.Base, uint32(ld.Disp))
	}
	if ld.Width != ir.W32 {
		t.Fatalf("参数宽度应当是 32 位，实际 %v", ld.Width)
	}
	if f.Insns[3].Op != ir.PopR || f.Insns[3].Dst != ir.RBP {
		t.Fatalf("第 4 条应当是 POP RBP，实际 %v %v", f.Insns[3].Op, f.Insns[3].Dst)
	}
	if f.Insns[4].Op != ir.Ret {
		t.Fatalf("第 5 条应当是 RET，实际 %v", f.Insns[4].Op)
	}
}

// 同一段字节在 64 位下也必须能翻（无 REX 的 55/5D 在 64 位里是 RBP 的 push/pop）——
// 这条同时保证 32 位支持**没有**把 64 位行为改坏。
func TestLift64PrologueStillWorks(t *testing.T) {
	f := liftPrologue(t, 64)
	if len(f.Insns) != 5 {
		t.Fatalf("64 位下指令数=%d，期望 5", len(f.Insns))
	}
	if f.Insns[0].Op != ir.PushR || f.Insns[3].Op != ir.PopR || f.Insns[4].Op != ir.Ret {
		t.Fatalf("64 位下 push/pop/ret 的形状变了: %v/%v/%v", f.Insns[0].Op, f.Insns[3].Op, f.Insns[4].Op)
	}
}

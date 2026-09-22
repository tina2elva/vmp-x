package x64

// 32 位 ABI 的**栈传参记账**：模拟栈必须镜像客户机真实栈的槽宽。
//
// 判据用一段最小序列：
//   6A 2A        push 42          ; 32 位压 4 字节 / 64 位压 8 字节
//   8B 44 24 04  mov eax,[esp+4]  ; 这次访问的"有效偏移"在两种模式下会跨过 0 边界
//   C3           ret
// 把 FrameSkew 设成非零：lifter 只对"有效偏移 ≥ 0"的访问补 FrameSkew，
// 于是 32 位（eff=0）会补、64 位（eff=-4）不会补 ⇒ 两种模式的 Disp 必须不同。

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
)

var stackArgCode = []byte{0x6A, 0x2A, 0x8B, 0x44, 0x24, 0x04, 0xC3}

func liftStackArg(t *testing.T, mode int, skew int64) ir.Insn {
	t.Helper()
	l := NewLifterMode(0x400000, mode)
	l.FrameSkew = skew
	f, err := l.LiftFunc("stackarg", stackArgCode, 0x1000)
	if err != nil {
		t.Fatalf("mode=%d 翻译失败: %v", mode, err)
	}
	for i := range f.Insns {
		if f.Insns[i].Op == ir.Load {
			return f.Insns[i]
		}
	}
	t.Fatalf("mode=%d 没有产生 Load", mode)
	return ir.Insn{}
}

func TestLift32StackArgAccounting(t *testing.T) {
	const skew = int64(64)
	ld32 := liftStackArg(t, 32, skew)
	ld64 := liftStackArg(t, 64, skew)
	t.Logf("Load Disp：32 位=0x%X(%d) 64 位=0x%X(%d)（FrameSkew=%d）", uint32(ld32.Disp), ld32.Disp, uint32(ld64.Disp), ld64.Disp, skew)
	if ld32.Disp == ld64.Disp {
		t.Fatalf("两种模式的栈传参位移相同（0x%X）—— 说明 push 的槽宽记账没有按模式走", uint32(ld32.Disp))
	}
	// 32 位：push 4 字节 ⇒ eff = 4-4 = 0 ⇒ 属于"相对进入时 ≥ 0"的访问 ⇒ 补 FrameSkew
	if want := int32(4 + skew); ld32.Disp != want {
		t.Fatalf("32 位 Disp=0x%X，期望 0x%X（4 + FrameSkew）", uint32(ld32.Disp), uint32(want))
	}
	// 64 位：push 8 字节 ⇒ eff = 4-8 = -4 < 0 ⇒ 函数私有区，不补 FrameSkew
	if ld64.Disp != 4 {
		t.Fatalf("64 位 Disp=0x%X，期望 0x4（不补 FrameSkew）", uint32(ld64.Disp))
	}
}

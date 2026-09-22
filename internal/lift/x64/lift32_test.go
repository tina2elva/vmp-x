package x64

// 32 位解码模式在 lifter 里的接线测试：**同一段字节**在两种模式下必须得到不同的 IR。
//
// 这是 PE32 支持里最容易静默出错的一处：
//   mov eax,[disp32]  在 64 位是 RIP-relative，在 32 位是**绝对地址**。
// 如果 lifter 不知道模式，32 位代码里的全局变量访问会被折算到完全错误的地址上 ——
// 不报错、不崩溃，只是**算错**（正是本项目最想消灭的那类问题）。

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
)

const (
	testImageBase = uint64(0x400000)
	testFuncRVA   = uint32(0x1000)
)

// 8B 05 00 10 40 00 = mov eax,[disp32]；C3 = ret
var memMovCode = []byte{0x8B, 0x05, 0x00, 0x10, 0x40, 0x00, 0xC3}

func firstLoad(t *testing.T, code []byte, mode int) ir.Insn {
	t.Helper()
	l := NewLifterMode(testImageBase, mode)
	f, err := l.LiftFunc("f", code, testFuncRVA)
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

// 32 位：[0x401000] 是绝对地址 ⇒ VMBASE + (0x401000 - 0x400000) = VMBASE + 0x1000
func TestLift32AbsoluteOperand(t *testing.T) {
	ld := firstLoad(t, memMovCode, 32)
	if ld.Base != ir.VMBASE {
		t.Fatalf("32 位绝对地址应当折算到 VMBASE，实际 Base=%v", ld.Base)
	}
	if ld.Disp != 0x1000 {
		t.Fatalf("32 位绝对地址 0x401000 折算后 Disp 应当是 0x1000，实际 0x%X", ld.Disp)
	}
	if ld.Width != ir.W32 {
		t.Fatalf("操作数宽度应当是 32 位，实际 %v", ld.Width)
	}
}

// 64 位：同样的字节是 RIP-relative ⇒ 目标 = PC + 6 + 0x401000 = 0x802006 ⇒ Disp = 0x402006
func TestLift64RIPRelativeOperand(t *testing.T) {
	ld := firstLoad(t, memMovCode, 64)
	if ld.Base != ir.VMBASE {
		t.Fatalf("RIP-relative 也折算到 VMBASE，实际 Base=%v", ld.Base)
	}
	if ld.Disp == 0x1000 {
		t.Fatal("64 位下不该得到 32 位绝对地址的折算结果（说明模式没生效）")
	}
	const want = int32(0x1000 + 6 + 0x401000) // PC(0x401000) + 6 + disp(0x401000) - ImageBase(0x400000)
	if ld.Disp != want {
		t.Fatalf("RIP-relative 折算后 Disp 应当是 0x%X，实际 0x%X", want, ld.Disp)
	}
}

// 两种模式对同一段字节必须给出**不同**的结果 —— 这条断言本身就是"模式接线生效"的判据。
func TestLiftModeChangesResult(t *testing.T) {
	a := firstLoad(t, memMovCode, 32)
	b := firstLoad(t, memMovCode, 64)
	if a.Disp == b.Disp {
		t.Fatalf("32/64 两种模式对 mov eax,[disp32] 给出了相同的 Disp=0x%X，说明模式没有生效", a.Disp)
	}
}

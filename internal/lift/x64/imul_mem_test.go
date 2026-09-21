package x64

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
)

// 回归：三操作数 IMUL（内存源 + 立即数）必须保住立即数、且被乘数是刚载入的内存操作数。
//
// /Od 下 MSVC 大量生成  imul ecx, dword ptr [rsp+18h], 3  这种形式。
// 曾经的实现（内存操作数那一支）**丢掉了立即数**、并把被乘数写成 dst，
// 于是 dst = dst × mem，静默算错：a + b*2 + c*3 + d*4 得到 27 而不是 30（客户 demo 的 /Od 症状）。
func TestLiftImulMemImmKeepsImmediate(t *testing.T) {
	l := NewLifter(0)
	// imul ecx, dword ptr [rsp+18h], 3 ; ret
	fn, err := l.LiftFunc("f", []byte{0x6B, 0x4C, 0x24, 0x18, 0x03, 0xC3}, 0)
	if err != nil {
		t.Fatal(err)
	}
	loads, muls := 0, 0
	for _, in := range fn.Insns {
		switch in.Op {
		case ir.Load:
			loads++
		case ir.AluRI:
			if in.Kind == uint8(ir.Mul) {
				muls++
				if in.Imm != 3 {
					t.Fatalf("立即数丢了：Imm=%d，期望 3", in.Imm)
				}
				if in.A != ir.VMSCR {
					t.Fatalf("被乘数应当是刚载入的内存操作数 VMSCR，得到 A=%v", in.A)
				}
			}
		case ir.AluRR:
			if in.Kind&^ir.KeepFlags == uint8(ir.Mul) {
				t.Fatalf("三操作数形式不该退化成两操作数乘法（A=%v B=%v）", in.A, in.B)
			}
		}
	}
	if loads == 0 || muls == 0 {
		t.Fatalf("期望 1 条 Load + 1 条 Mul(imm)：loads=%d muls=%d", loads, muls)
	}
}

// 回归：两操作数 IMUL（寄存器 + 内存）仍然是 dst = dst × mem（别被上面的修法改坏）。
func TestLiftImulMemTwoOperand(t *testing.T) {
	l := NewLifter(0)
	// imul ecx, dword ptr [rsp+18h] ; ret
	fn, err := l.LiftFunc("f", []byte{0x0F, 0xAF, 0x4C, 0x24, 0x18, 0xC3}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range fn.Insns {
		if in.Op == ir.AluRR && in.Kind&^ir.KeepFlags == uint8(ir.Mul) {
			if in.A != ir.RCX || in.B != ir.VMSCR {
				t.Fatalf("两操作数形式应是 dst=RCX × mem：A=%v B=%v", in.A, in.B)
			}
			return
		}
	}
	t.Fatal("没有找到两操作数乘法对应的 IR")
}

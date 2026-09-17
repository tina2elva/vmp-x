package x64

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// condRef 是 x86 条件码的**独立**参考实现（直接照 SDM 写，不复用 VM 的判断）。
// 位序：Z=1, N(S)=2, C=4, V(O)=8, P=16（与 vm.Flag* 一致）。
func condRef(cc uint32, f uint32) bool {
	z := f&vm.FlagZ != 0
	s := f&vm.FlagN != 0
	c := f&vm.FlagC != 0
	o := f&vm.FlagV != 0
	p := f&vm.FlagP != 0
	switch cc {
	case 0:
		return o
	case 1:
		return !o
	case 2:
		return c
	case 3:
		return !c
	case 4:
		return z
	case 5:
		return !z
	case 6:
		return c || z
	case 7:
		return !c && !z
	case 8:
		return s
	case 9:
		return !s
	case 10:
		return p
	case 11:
		return !p
	case 12:
		return s != o
	case 13:
		return s == o
	case 14:
		return z || (s != o)
	default:
		return !z && (s == o)
	}
}

// liftOne 把一段字节码当成单指令函数翻译并生成 VM 字节码（末尾补 RET）
func liftOneInsn(t *testing.T, code []byte) []byte {
	t.Helper()
	l := &Lifter{}
	fn, err := l.LiftFunc("t", code, 0)
	if err != nil {
		t.Fatalf("lift % X 失败: %v", code, err)
	}
	fn.Insns = append(fn.Insns, ir.Insn{Op: ir.Ret})
	res, err := vm.Generate(fn)
	if err != nil {
		t.Fatalf("codegen 失败: %v", err)
	}
	return res.Code
}

// SETcc：16 个条件 × 全部 32 种 Z/S/C/O/P 组合，与独立参考实现比对
func TestLiftSetccDifferential(t *testing.T) {
	for cc := uint32(0); cc < 16; cc++ {
		code := []byte{0x0F, byte(0x90 + cc), 0xC0} // setcc %al
		bc := liftOneInsn(t, code)
		for f := uint32(0); f < 32; f++ {
			// 把 5 位组合映射到 Z/S/C/O/P 位
			flags := uint32(0)
			if f&1 != 0 {
				flags |= vm.FlagZ
			}
			if f&2 != 0 {
				flags |= vm.FlagN
			}
			if f&4 != 0 {
				flags |= vm.FlagC
			}
			if f&8 != 0 {
				flags |= vm.FlagV
			}
			if f&16 != 0 {
				flags |= vm.FlagP
			}
			st := &vm.RefState{Guest: vm.GuestX86, Mem: map[uint64]byte{}}
			st.Regs[ir.RAX] = 0xAAAAAAAAAAAAAAAA // 高位必须保留
			st.Flags = flags
			if rc, err := st.Run(bc, 64); err != nil || rc != 0 {
				t.Fatalf("cc=%d flags=0x%X: 执行失败 rc=%d err=%v", cc, flags, rc, err)
			}
			want := uint64(0)
			if condRef(cc, flags) {
				want = 1
			}
			got := st.Regs[ir.RAX] & 0xFF
			if got != want {
				t.Errorf("cc=%d flags=0x%X: AL=%d，参考=%d", cc, flags, got, want)
			}
			if hi := st.Regs[ir.RAX] &^ 0xFF; hi != 0xAAAAAAAAAAAAAA00 {
				t.Errorf("cc=%d: 8 位写把高 56 位写坏了：0x%X", cc, st.Regs[ir.RAX])
			}
		}
	}
}

// CMOVcc：16 个条件 × 32 种标志组合；不成立时目标寄存器必须保持原值
func TestLiftCmovccDifferential(t *testing.T) {
	for cc := uint32(0); cc < 16; cc++ {
		code := []byte{0x48, 0x0F, byte(0x40 + cc), 0xC1} // cmovcc %rcx, %rax
		bc := liftOneInsn(t, code)
		for f := uint32(0); f < 32; f++ {
			flags := uint32(0)
			if f&1 != 0 {
				flags |= vm.FlagZ
			}
			if f&2 != 0 {
				flags |= vm.FlagN
			}
			if f&4 != 0 {
				flags |= vm.FlagC
			}
			if f&8 != 0 {
				flags |= vm.FlagV
			}
			if f&16 != 0 {
				flags |= vm.FlagP
			}
			st := &vm.RefState{Guest: vm.GuestX86, Mem: map[uint64]byte{}}
			st.Regs[ir.RAX] = 0x1111111111111111
			st.Regs[ir.RCX] = 0x2222222222222222
			st.Flags = flags
			if rc, err := st.Run(bc, 64); err != nil || rc != 0 {
				t.Fatalf("cc=%d: 执行失败 rc=%d err=%v", cc, rc, err)
			}
			want := uint64(0x1111111111111111)
			if condRef(cc, flags) {
				want = 0x2222222222222222
			}
			if st.Regs[ir.RAX] != want {
				t.Errorf("cc=%d flags=0x%X: RAX=0x%X，参考=0x%X", cc, flags, st.Regs[ir.RAX], want)
			}
			// CMOVcc 不许改标志位
			if st.Flags != flags {
				t.Errorf("cc=%d: CMOVcc 改了标志位（0x%X → 0x%X）", cc, flags, st.Flags)
			}
		}
	}
}

// 32 位形式的 CMOVcc 必须零扩展到 64 位（x86-64 语义）
func TestLiftCmovcc32ZeroExtends(t *testing.T) {
	code := []byte{0x0F, 0x44, 0xC1} // cmove %ecx, %eax
	bc := liftOneInsn(t, code)
	st := &vm.RefState{Guest: vm.GuestX86, Mem: map[uint64]byte{}}
	st.Regs[ir.RAX] = 0xAAAAAAAAAAAAAAAA
	st.Regs[ir.RCX] = 0xFFFFFFFFBBBBBBBB
	st.Flags = vm.FlagZ
	if rc, err := st.Run(bc, 64); err != nil || rc != 0 {
		t.Fatalf("执行失败 rc=%d err=%v", rc, err)
	}
	if st.Regs[ir.RAX] != 0xBBBBBBBB {
		t.Fatalf("32 位 CMOVcc 应零扩展到 64 位，实际 0x%X", st.Regs[ir.RAX])
	}
}

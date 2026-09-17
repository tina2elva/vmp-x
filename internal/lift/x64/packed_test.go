package x64

import (
	"math/rand"
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// 打包（按 lane）加减：逐 lane 与 Go 的独立参考比对，并确认标志位不被改动
func TestLiftPackedArithmetic(t *testing.T) {
	const (
		xmmRVA     = 0x1000
		scratchRVA = 0x2000
		vbase      = 0x100000
	)
	cases := []struct {
		name      string
		code      []byte
		laneBytes int
		sub       bool
	}{
		{"paddb", []byte{0x66, 0x0F, 0xFC, 0xC1, 0xC3}, 1, false},
		{"paddw", []byte{0x66, 0x0F, 0xFD, 0xC1, 0xC3}, 2, false},
		{"paddd", []byte{0x66, 0x0F, 0xFE, 0xC1, 0xC3}, 4, false},
		{"paddq", []byte{0x66, 0x0F, 0xD4, 0xC1, 0xC3}, 8, false},
		{"psubb", []byte{0x66, 0x0F, 0xF8, 0xC1, 0xC3}, 1, true},
		{"psubd", []byte{0x66, 0x0F, 0xFA, 0xC1, 0xC3}, 4, true},
	}
	rng := rand.New(rand.NewSource(20260215))
	for _, c := range cases {
		a := make([]byte, 16)
		b := make([]byte, 16)
		rng.Read(a)
		rng.Read(b)
		l := NewLifter(0)
		l.SetXMMArea(xmmRVA)
		l.SetScratchArea(scratchRVA)
		fn, err := l.LiftFunc("p", c.code, 0)
		if err != nil {
			t.Fatalf("%s 未翻译: %v", c.name, err)
		}
		fn.Insns = append(fn.Insns, ir.Insn{Op: ir.Ret})
		res, err := vm.Generate(fn)
		if err != nil {
			t.Fatal(err)
		}
		st := &vm.RefState{Guest: vm.GuestX86, Mem: map[uint64]byte{}, BufBase: vbase, BufSize: 0x4000}
		st.Regs[ir.VMBASE] = vbase
		st.Regs[ir.RSP] = vbase + 0x3000
		st.Regs[ir.R11] = 0xDEADBEEFCAFEBABE
		st.Flags = vm.FlagZ | vm.FlagC
		for i := 0; i < 16; i++ {
			st.Mem[vbase+xmmRVA+uint64(i)] = a[i]
			st.Mem[vbase+xmmRVA+16+uint64(i)] = b[i]
		}
		if rc, err := st.Run(res.Code, 400); err != nil || rc != 0 {
			t.Fatalf("%s 执行失败 rc=%d err=%v", c.name, rc, err)
		}
		for lane := 0; lane < 16/c.laneBytes; lane++ {
			var wa, wb, wr uint64
			for i := 0; i < c.laneBytes; i++ {
				wa |= uint64(a[lane*c.laneBytes+i]) << (8 * i)
				wb |= uint64(b[lane*c.laneBytes+i]) << (8 * i)
			}
			if c.sub {
				wr = wa - wb
			} else {
				wr = wa + wb
			}
			mask := (uint64(1) << (8 * c.laneBytes)) - 1
			wr &= mask
			var got uint64
			for i := 0; i < c.laneBytes; i++ {
				got |= uint64(st.Mem[vbase+xmmRVA+uint64(lane*c.laneBytes+i)]) << (8 * i)
			}
			if got != wr {
				t.Fatalf("%s lane %d: got=0x%X want=0x%X", c.name, lane, got, wr)
			}
		}
		if st.Regs[ir.R11] != 0xDEADBEEFCAFEBABE {
			t.Fatalf("%s: 借用的 R11 没还原", c.name)
		}
		if st.Flags != vm.FlagZ|vm.FlagC {
			t.Fatalf("%s: 打包指令改动了标志位", c.name)
		}
	}
}

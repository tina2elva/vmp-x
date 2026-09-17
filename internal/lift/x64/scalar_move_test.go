package x64

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// MOVSD/MOVSS 三种形式的语义。关键差别：
//
//	寄存器-寄存器：只覆盖低 8/4 字节，**高位保持**
//	内存 → 寄存器：低 8/4 字节来自内存，**其余位清零**
//	寄存器 → 内存：只写低 8/4 字节
func TestLiftScalarMoves(t *testing.T) {
	const (
		xmmRVA  = 0x1000
		vbase   = 0x100000
		memAddr = vbase + 0x2100
	)
	hiX0 := []byte{0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF}
	loX1 := []byte{0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7}
	loX1d := []byte{0xC0, 0xC1, 0xC2, 0xC3}
	hiX0w := []byte{0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF}
	mem8 := []byte{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57}
	mem4 := []byte{0x50, 0x51, 0x52, 0x53}
	zeros8 := make([]byte, 8)
	zeros12 := make([]byte, 12)

	mk := func(parts ...[]byte) [16]byte {
		var out [16]byte
		n := 0
		for _, p := range parts {
			copy(out[n:], p)
			n += len(p)
		}
		return out
	}
	cases := []struct {
		name string
		code []byte
		want [16]byte
	}{
		{"movsd %xmm1,%xmm0", []byte{0xF2, 0x0F, 0x10, 0xC1, 0xC3}, mk(loX1, hiX0)},
		{"movsd (%rcx),%xmm0", []byte{0xF2, 0x0F, 0x10, 0x01, 0xC3}, mk(mem8, zeros8)},
		{"movss %xmm1,%xmm0", []byte{0xF3, 0x0F, 0x10, 0xC1, 0xC3}, mk(loX1d, hiX0w)},
		{"movss (%rcx),%xmm0", []byte{0xF3, 0x0F, 0x10, 0x01, 0xC3}, mk(mem4, zeros12)},
	}
	for _, c := range cases {
		l := NewLifter(0)
		l.SetXMMArea(xmmRVA)
		l.SetScratchArea(0x2000)
		fn, err := l.LiftFunc("mv", c.code, 0)
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
		st.Regs[ir.RCX] = memAddr
		st.Flags = vm.FlagZ | vm.FlagC
		for i := 0; i < 16; i++ {
			st.Mem[vbase+xmmRVA+uint64(i)] = byte(0xA0 + i)
			st.Mem[vbase+xmmRVA+16+uint64(i)] = byte(0xC0 + i)
			st.Mem[memAddr+uint64(i)] = byte(0x50 + i)
		}
		if rc, err := st.Run(res.Code, 200); err != nil || rc != 0 {
			t.Fatalf("%s 执行失败 rc=%d err=%v", c.name, rc, err)
		}
		for i := 0; i < 16; i++ {
			if got := st.Mem[vbase+xmmRVA+uint64(i)]; got != c.want[i] {
				t.Fatalf("%s 第 %d 字节: got=0x%02X want=0x%02X", c.name, i, got, c.want[i])
			}
		}
		if st.Flags != vm.FlagZ|vm.FlagC {
			t.Fatalf("%s: 标志位被改动了", c.name)
		}
	}
}

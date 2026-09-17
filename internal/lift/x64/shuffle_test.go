package x64

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// PUNPCKLQDQ / PUNPCKHQDQ / MOVDDUP 的 64 位半搬移语义（在参考 VM 里逐字节验证）
func TestLiftShuffleMoves(t *testing.T) {
	const (
		xmmRVA = 0x1000
		vbase  = 0x100000
	)
	cases := []struct {
		name string
		code []byte // 66 0F ... /r
		want [4]uint64
	}{
		// punpcklqdq %xmm1,%xmm0 : xmm0 = { xmm0.lo, xmm1.lo }
		{"punpcklqdq", []byte{0x66, 0x0F, 0x6C, 0xC1, 0xC3}, [4]uint64{0xA, 0xC, 0xA, 0xB}},
		// punpckhqdq %xmm1,%xmm0 : xmm0 = { xmm1.hi, xmm0.hi }
		{"punpckhqdq", []byte{0x66, 0x0F, 0x6D, 0xC1, 0xC3}, [4]uint64{0xD, 0xB, 0xA, 0xB}},
		// movddup %xmm1,%xmm0（F2 0F 12 /r） : xmm0 = { xmm1.lo, xmm1.lo }
		{"movddup", []byte{0xF2, 0x0F, 0x12, 0xC1, 0xC3}, [4]uint64{0xC, 0xC, 0xA, 0xB}},
	}
	for _, c := range cases {
		l := NewLifter(0)
		l.SetXMMArea(xmmRVA)
		fn, err := l.LiftFunc("sh", c.code, 0)
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
		st.Flags = vm.FlagZ | vm.FlagC
		// xmm0 = {lo=0xA, hi=0xB}, xmm1 = {lo=0xC, hi=0xD}
		st.Mem[vbase+xmmRVA+0] = 0xA
		st.Mem[vbase+xmmRVA+8] = 0xB
		st.Mem[vbase+xmmRVA+16] = 0xC
		st.Mem[vbase+xmmRVA+24] = 0xD
		if rc, err := st.Run(res.Code, 100); err != nil || rc != 0 {
			t.Fatalf("%s 执行失败 rc=%d err=%v", c.name, rc, err)
		}
		for half := 0; half < 2; half++ {
			if got := st.Mem[vbase+xmmRVA+uint64(half*8)]; got != byte(c.want[half]) {
				t.Fatalf("%s 低/高半 %d: got=0x%X want=0x%X", c.name, half, got, c.want[half])
			}
		}
		if st.Flags != vm.FlagZ|vm.FlagC {
			t.Fatalf("%s: 标志位被改动了", c.name)
		}
	}
}

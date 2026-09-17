package x64

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// SIMD 位搬运的语义测试：在 Go 参考 VM 里跑"movdqu (%rdx),%xmm0 ; movups %xmm0,(%rcx); ret"，
// 断言 16 字节真的被搬过去了（并检查 XMM 寄存器堆里的内容）。
func TestLiftSimdMoveSemantics(t *testing.T) {
	const (
		xmmRVA = 0x1000
		vbase  = 0x100000
		src    = 0x200000
		dst    = 0x300000
	)
	code := []byte{
		0xF3, 0x0F, 0x6F, 0x02, // movdqu (%rdx),%xmm0
		0x0F, 0x11, 0x01, // movups %xmm0,(%rcx)
		0xC3, // ret
	}
	l := NewLifter(0)
	l.SetXMMArea(xmmRVA)
	fn, err := l.LiftFunc("c", code, 0)
	if err != nil {
		t.Fatalf("SIMD 搬运未翻译: %v", err)
	}
	fn.Insns = append(fn.Insns, ir.Insn{Op: ir.Ret})
	bc, err := vm.Generate(fn)
	if err != nil {
		t.Fatal(err)
	}
	st := &vm.RefState{Guest: vm.GuestX86, Mem: map[uint64]byte{}, BufBase: 0x100000, BufSize: 0x300000}
	st.Regs[ir.VMBASE] = vbase
	st.Regs[ir.RDX] = src
	st.Regs[ir.RCX] = dst
	for i := 0; i < 16; i++ {
		st.Mem[src+uint64(i)] = byte(0xA0 + i)
	}
	if rc, err := st.Run(bc.Code, 200); err != nil || rc != 0 {
		t.Fatalf("执行失败 rc=%d err=%v", rc, err)
	}
	for i := 0; i < 16; i++ {
		if got := st.Mem[dst+uint64(i)]; got != byte(0xA0+i) {
			t.Fatalf("第 %d 字节没搬对：got=0x%02X want=0x%02X", i, got, byte(0xA0+i))
		}
		if got := st.Mem[vbase+xmmRVA+uint64(i)]; got != byte(0xA0+i) {
			t.Fatalf("XMM 寄存器堆第 %d 字节不对：got=0x%02X", i, got)
		}
	}
}

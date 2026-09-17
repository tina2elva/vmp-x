package x64

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// 非清零形式的按位 SIMD：pxor %xmm1,%xmm0 / pxor (%rcx),%xmm0
//   - 16 字节逐位异或
//   - 借用的 R11 必须通过 blob 里的暂存槽保存/还原（**不能用 push/pop**：会动模拟 RSP）
//   - 标志位完全不变
func TestLiftSimdBitwiseXor(t *testing.T) {
	const (
		xmmRVA     = 0x1000
		scratchRVA = 0x2000
		vbase      = 0x100000
	)
	for _, tc := range []struct {
		name string
		code []byte
		mem  bool
	}{
		{"pxor %xmm1,%xmm0", []byte{0x66, 0x0F, 0xEF, 0xC1, 0xC3}, false},
		{"pxor (%rcx),%xmm0", []byte{0x66, 0x0F, 0xEF, 0x01, 0xC3}, true},
	} {
		l := NewLifter(0)
		l.SetXMMArea(xmmRVA)
		l.SetScratchArea(scratchRVA)
		fn, err := l.LiftFunc("px", tc.code, 0)
		if err != nil {
			t.Fatalf("%s 未翻译: %v", tc.name, err)
		}
		fn.Insns = append(fn.Insns, ir.Insn{Op: ir.Ret})
		res, err := vm.Generate(fn)
		if err != nil {
			t.Fatal(err)
		}
		st := &vm.RefState{Guest: vm.GuestX86, Mem: map[uint64]byte{}, BufBase: vbase, BufSize: 0x4000}
		st.Regs[ir.VMBASE] = vbase
		st.Regs[ir.R11] = 0xDEADBEEFCAFEBABE
		st.Regs[ir.RSP] = vbase + 0x3000
		st.Regs[ir.RCX] = vbase + 0x2100 // 注意避开暂存槽（vbase+0x2000）
		st.Flags = vm.FlagZ | vm.FlagC | vm.FlagP
		for i := 0; i < 16; i++ {
			st.Mem[vbase+xmmRVA+uint64(i)] = byte(0xA0 + i)
			st.Mem[vbase+xmmRVA+16+uint64(i)] = byte(0x0F + i)
			st.Mem[vbase+0x2100+uint64(i)] = byte(0x0F + i)
		}
		if rc, err := st.Run(res.Code, 200); err != nil || rc != 0 {
			t.Fatalf("%s 执行失败 rc=%d err=%v", tc.name, rc, err)
		}
		for i := 0; i < 16; i++ {
			want := byte(0xA0+i) ^ byte(0x0F+i)
			if got := st.Mem[vbase+xmmRVA+uint64(i)]; got != want {
				t.Fatalf("%s 第 %d 字节: got=0x%02X want=0x%02X", tc.name, i, got, want)
			}
		}
		if st.Regs[ir.R11] != 0xDEADBEEFCAFEBABE {
			t.Fatalf("%s: 借用的 R11 没有还原: 0x%X", tc.name, st.Regs[ir.R11])
		}
		if st.Regs[ir.RSP] != vbase+0x3000 {
			t.Fatalf("%s: RSP 被动了（不该用 push/pop）: 0x%X", tc.name, st.Regs[ir.RSP])
		}
		if st.Flags != vm.FlagZ|vm.FlagC|vm.FlagP {
			t.Fatalf("%s: 标志位被改动了: 0x%X", tc.name, st.Flags)
		}
	}
}

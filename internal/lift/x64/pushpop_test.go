package x64

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// 隔离测试：参考 VM 的 PUSH_R / POP_R 是否真的还原寄存器
func TestRefPushPopRoundTrip(t *testing.T) {
	f := &ir.Func{Name: "pp", Insns: []ir.Insn{
		{Op: ir.PushR, Dst: ir.R11},
		{Op: ir.PopR, Dst: ir.R11},
		{Op: ir.Ret},
	}}
	res, err := vm.Generate(f)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("字节码: % X", res.Code)
	st := &vm.RefState{Guest: vm.GuestX86, Mem: map[uint64]byte{}, BufBase: 0x100000, BufSize: 0x4000}
	st.Regs[ir.RSP] = 0x103000
	st.Regs[ir.R11] = 0xDEADBEEFCAFEBABE
	if rc, err := st.Run(res.Code, 20); err != nil || rc != 0 {
		t.Fatalf("执行失败 rc=%d err=%v", rc, err)
	}
	t.Logf("R11=0x%X RSP=0x%X", st.Regs[ir.R11], st.Regs[ir.RSP])
	if st.Regs[ir.R11] != 0xDEADBEEFCAFEBABE {
		t.Fatalf("PUSH/POP 没还原 R11: 0x%X", st.Regs[ir.R11])
	}
}

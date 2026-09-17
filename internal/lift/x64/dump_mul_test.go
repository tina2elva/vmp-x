package x64

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

func TestDumpMulBytecode(t *testing.T) {
	l := NewLifter(0)
	fn, err := l.LiftFunc("m", []byte{0x48, 0xF7, 0xE1, 0xC3}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i, in := range fn.Insns {
		t.Logf("IR[%d] %v kind=0x%02X width=%d dst=%v A=%v B=%v", i, in.Op, in.Kind, in.Width, in.Dst, in.A, in.B)
	}
	fn.Insns = append(fn.Insns, ir.Insn{Op: ir.Ret})
	res, err := vm.Generate(fn)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range vm.DisasmAll(res.Code) {
		t.Logf("   %s", line)
	}
}

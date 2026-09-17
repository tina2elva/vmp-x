package x64

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// 打印 SIMD 内存形态生成的字节码，用于和正常的 Load/Store 对照
func TestDumpSimdBytecode(t *testing.T) {
	cases := []struct {
		name string
		code []byte
	}{
		{"movdqu (%rcx),%xmm0", []byte{0xF3, 0x0F, 0x6F, 0x01, 0xC3}},
		{"movups %xmm0,(%rcx)", []byte{0x0F, 0x11, 0x01, 0xC3}},
	}
	for _, c := range cases {
		l := NewLifter(0)
		l.SetXMMArea(0x28000)
		fn, err := l.LiftFunc("t", c.code, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		fn.Insns = append(fn.Insns, ir.Insn{Op: ir.Ret})
		res, err := vm.Generate(fn)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("== %s (%d IR, %d 字节) ==", c.name, len(fn.Insns), len(res.Code))
		for _, line := range vm.DisasmAll(res.Code) {
			t.Logf("   %s", line)
		}
	}
}

package arm64

import (
	"encoding/binary"
	"strings"
	"testing"

	dec "github.com/vmpx/vmp-x/internal/decode/arm64"
	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// 回归：sum_to 那种循环里的 cmp（= subs xzr, x, y）必须被翻译出来，不能静默丢掉。
// 之前寄存器形式的 ADD/SUB 对 Rd/Rn=31 直接报错，而 arm64 适配器又吞掉了 Unsupported，
// 于是循环失去退出条件、永不返回（CI 上 sum_to 就是这个现象）。
func TestArm64CmpAloneIsLifted(t *testing.T) {
	words := []uint32{
		0xD2800021, // mov  x1, #1
		0xD2800000, // mov  x0, #0
		0x8B010000, // add  x0, x0, x1
		0x91000421, // add  x1, x1, #1
		0xEB02003F, // cmp  x1, x2      （就是 subs xzr, x1, x2）
		0x54FFFF69, // b.ls -5         （回到 add x0, x0, x1）
		0xD65F03C0, // ret
	}
	var code []byte
	for _, w := range words {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, w)
		code = append(code, b...)
	}
	insns, err := dec.DecodeRange(code, 0x1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	fn := &ir.Func{}
	(&Lifter{ImageBase: 0}).Lift(fn, insns)
	if len(fn.Unsupported) > 0 {
		t.Fatalf("仍有指令无法翻译: %v", fn.Unsupported)
	}
	hasCmp, hasJcc, hasZR := false, false, false
	for i := range fn.Insns {
		in := &fn.Insns[i]
		t.Logf("IR %v kind=0x%X w=%d dst=%d a=%d b=%d imm=0x%X", in.Op, in.Kind, in.Width, in.Dst, in.A, in.B, in.Imm)
		if in.Op == ir.AluRR && in.Kind == uint8(ir.Sub) && in.Dst == ZR {
			hasCmp = true
		}
		if in.Op == ir.Jcc {
			hasJcc = true
		}
		if in.Dst == ZR || in.A == ZR {
			hasZR = true
		}
	}
	if !hasCmp || !hasJcc || !hasZR {
		t.Fatalf("缺少 cmp/Jcc/ZR[%v %v %v]", hasCmp, hasJcc, hasZR)
	}
	fn.Insns = append(fn.Insns, ir.Insn{Op: ir.Ret})
	res, err := vm.Generate(fn)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(vm.DisasmAll(res.Code), " | ")
	t.Logf("字节码: %s", all)
	if !strings.Contains(all, "CMP") && !strings.Contains(all, "SUB") {
		t.Fatalf("字节码里看不到比较（cmp 又丢了）: %s", all)
	}
}

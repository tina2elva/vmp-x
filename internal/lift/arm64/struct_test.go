package arm64

import (
	"encoding/binary"
	"strings"
	"testing"

	dec "github.com/vmpx/vmp-x/internal/decode/arm64"
	"github.com/vmpx/vmp-x/internal/ir"
)

// 控制流的**结构化**验证（语义差分的程序级验证见 control_test.go）：
// 断言 IR 形状、分支目标合法、条件码是 ARM64 编码。
func TestArm64BranchStructure(t *testing.T) {
	cases := []struct {
		name  string
		words []uint32
		want  []string
		unsup bool
	}{
		{name: "CBZ + RET", words: []uint32{0xB4000020, 0xD65F03C0}, want: []string{"JBZ", "RET"}},
		{name: "CBNZ + RET", words: []uint32{0xB5000020, 0xD65F03C0}, want: []string{"JBNZ", "RET"}},
		{name: "TBZ + RET", words: []uint32{0x36000020, 0xD65F03C0}, want: []string{"MOV_RI", "ALU_RR", "JBZ", "RET"}},
		{name: "TBNZ + RET", words: []uint32{0x37000020, 0xD65F03C0}, want: []string{"MOV_RI", "ALU_RR", "JBNZ", "RET"}},
		{name: "B.cond + RET", words: []uint32{0x54000020, 0xD65F03C0}, want: []string{"JCC", "RET"}},
		{name: "B + RET", words: []uint32{0x14000001, 0xD65F03C0}, want: []string{"JMP", "RET"}},
		{name: "RET", words: []uint32{0xD65F03C0}, want: []string{"RET"}},
		{name: "ADR + RET", words: []uint32{0x10000040, 0xD65F03C0}, want: []string{"LEA", "RET"}},
		{name: "BR 不支持", words: []uint32{0xD61F0000, 0xD65F03C0}, unsup: true},
	}
	for _, c := range cases {
		var code []byte
		for _, w := range c.words {
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, w)
			code = append(code, b...)
		}
		insns, err := dec.DecodeRange(code, 0x1000, 0)
		if err != nil {
			t.Fatalf("%s: 解码失败 %v", c.name, err)
		}
		fn := &ir.Func{}
		l := &Lifter{ImageBase: 0x1000, ImageSize: 0x10000}
		l.Lift(fn, insns)
		if c.unsup {
			if len(fn.Unsupported) == 0 {
				t.Errorf("%s: 期望被拒绝，实际生成了 %d 条 IR", c.name, len(fn.Insns))
			}
			continue
		}
		if len(fn.Unsupported) > 0 {
			t.Errorf("%s: 不该被拒绝: %v", c.name, fn.Unsupported)
			continue
		}
		var got []string
		for i := range fn.Insns {
			got = append(got, fn.Insns[i].Op.String())
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s (%v): IR = %v，期望 %v", c.name, c.words, got, c.want)
		}
		for i := range fn.Insns {
			in := &fn.Insns[i]
			if in.Op == ir.Jcc || in.Op == ir.Jmp || in.Op == ir.JRegZ || in.Op == ir.JRegNZ {
				if in.Target < 0 || in.Target >= len(fn.Insns) {
					t.Errorf("%s: 分支目标 %d 越界（共 %d 条 IR）", c.name, in.Target, len(fn.Insns))
				}
			}
		}
	}
}

// MOVZ/MOVN/MOVK 与 LSL/LSR/ASR 的结构
func TestArm64MoveWideAndShiftStructure(t *testing.T) {
	cases := []struct {
		name string
		word uint32
		want []string
	}{
		{name: "MOVZ X0, #0x1234", word: 0xD2824680, want: []string{"MOV_RI"}},
		{name: "MOVK X0, #0x1234, LSL #16", word: 0xF2A24680, want: []string{"MOV_RI", "ALU_RR", "MOV_RI", "ALU_RR"}},
		{name: "LSL X1, X1, #4", word: 0xD37CEC21, want: []string{"ALU_RI"}},
		{name: "LSR W1, W1, #4", word: 0x53107C21, want: []string{"ALU_RI"}},
	}
	for _, c := range cases {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, c.word)
		ins, err := dec.Decode(b, 0x1000)
		if err != nil {
			t.Fatalf("%s: 解码失败 %v", c.name, err)
		}
		fn := &ir.Func{}
		(&Lifter{ImageBase: 0x1000}).Lift(fn, []dec.Insn{ins})
		if len(fn.Unsupported) > 0 {
			t.Errorf("%s (%s): 被拒绝: %v", c.name, ins.Text(), fn.Unsupported)
			continue
		}
		var got []string
		for i := range fn.Insns {
			got = append(got, fn.Insns[i].Op.String())
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s (%s): IR = %v，期望 %v", c.name, ins.Text(), got, c.want)
		}
	}
}

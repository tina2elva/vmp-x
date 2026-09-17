package x64

import (
	"encoding/hex"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestDecodeKnownEncodings(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want int
		op   x86asm.Op
	}{
		{"push rbx", "53", 1, x86asm.PUSH},
		{"sub rsp,0x28", "4883ec28", 4, x86asm.SUB},
		{"mov rax,[rip+disp]", "488b0512340000", 7, x86asm.MOV},
		{"lea rcx,[rip+disp]", "488d0d10000000", 7, x86asm.LEA},
		{"cmp eax,imm8", "83f863", 3, x86asm.CMP},
		{"jne rel8", "75e0", 2, x86asm.JNE},
		{"movzx eax,byte [rdi+8]", "0fb64708", 4, x86asm.MOVZX},
		{"imul eax,esi,imm8", "6bc607", 3, x86asm.IMUL},
		{"ret", "c3", 1, x86asm.RET},
		{"lock cmpxchg", "f0480fb137", 5, x86asm.CMPXCHG},
		{"rep movsb", "f3a4", 2, x86asm.MOVSB},
	}
	for _, c := range cases {
		code := mustHex(t, c.hex)
		ins, err := Decode(code, 0x1000)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.name, err)
		}
		if ins.Len() != c.want {
			t.Errorf("%s: len=%d want %d", c.name, ins.Len(), c.want)
		}
		if ins.Op() != c.op {
			t.Errorf("%s: op=%v want %v", c.name, ins.Op(), c.op)
		}
	}
}

// ENDBR64 是 x86asm 的解码陷阱：必须被识别为 4 字节，而不是 1 字节的 REP
func TestDecodeCETLandingPad(t *testing.T) {
	for _, c := range []struct {
		hex     string
		len     int
		endbr64 bool
	}{{"f30f1efa", 4, true}, {"f30f1efb", 4, false}} {
		ins, err := Decode(mustHex(t, c.hex), 0)
		if err != nil {
			t.Fatalf("%s: %v", c.hex, err)
		}
		if ins.Len() != c.len {
			t.Errorf("%s: len=%d want %d", c.hex, ins.Len(), c.len)
		}
		if ins.Endbr64 != c.endbr64 {
			t.Errorf("%s: endbr64=%v want %v", c.hex, ins.Endbr64, c.endbr64)
		}
		if ins.Text() == "" {
			t.Errorf("%s: empty text", c.hex)
		}
	}
}

func TestPCRelTarget(t *testing.T) {
	// 48 8b 05 10 00 00 00 : mov rax,[rip+0x10] @0x1000 -> 0x1000+7+0x10
	ins, err := Decode(mustHex(t, "488b0510000000"), 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	target, ok := ins.PCRelTarget()
	if !ok {
		t.Fatal("expected a PC-relative operand")
	}
	if target != 0x1017 {
		t.Fatalf("target=0x%X want 0x1017", target)
	}
	// 非 PC-relative 指令
	ins2, _ := Decode(mustHex(t, "4883ec28"), 0)
	if _, ok := ins2.PCRelTarget(); ok {
		t.Fatal("sub rsp should not be PC-relative")
	}
}

func TestDecodeRangeCoversWholeFunction(t *testing.T) {
	// endbr64 | push rbp | mov rbp,rsp | sub rsp,0x20 | mov rax,[rip+0x12] | leave | ret
	code := mustHex(t, "f30f1efa"+"55"+"4889e5"+"4883ec20"+"488b0512000000"+"c9"+"c3")
	insns, err := DecodeRange(code, 0x140001000, 0)
	if err != nil {
		t.Fatalf("DecodeRange: %v", err)
	}
	if len(insns) != 7 {
		t.Fatalf("got %d insns, want 7", len(insns))
	}
	if insns[0].PC != 0x140001000 || !insns[0].Endbr64 {
		t.Errorf("first insn should be ENDBR64 at 0x140001000, got %q @0x%X", insns[0].Text(), insns[0].PC)
	}
}

func TestFailFastOnDesync(t *testing.T) {
	// 只有前缀，没有操作码：必须是错误而不是“1 字节指令”
	for _, h := range []string{"f3", "66", "f0", "2e"} {
		if _, err := Decode(mustHex(t, h), 0); err == nil {
			t.Errorf("%s: expected error for prefix-only decode", h)
		}
	}
	// 截断指令
	for _, h := range []string{"488b", "0f", "4883"} {
		if _, err := Decode(mustHex(t, h), 0); err == nil {
			t.Errorf("%s: expected error for truncated instruction", h)
		}
	}
	if _, err := Decode(nil, 0); err == nil {
		t.Error("expected error for empty input")
	}
}

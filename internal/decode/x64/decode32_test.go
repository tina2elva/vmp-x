package x64

// 32 位解码模式的回归测试：用三个"两种模式必然不同"的例子把模式接线钉住。
//
// 为什么值得单独测：PE32 支持的第一块地基就是"解码必须知道自己在 32 位模式"，
// 一旦这里退化成 64 位，32 位代码里的 0x40-0x4F（INC EAX..）会被当 REX 前缀吞掉、
// 绝对 disp32 会被当成 RIP-relative —— 症状是**静默错位/静默算错**，不是报错。

import (
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// 0x40：64 位里是 REX 前缀（单独出现无法构成指令 ⇒ 我们的封装必须报错）；
// 32 位里是 INC EAX（1 字节）。
func TestModeDiffers_REXvsINC(t *testing.T) {
	if _, err := DecodeMode([]byte{0x40}, 0x1000, Mode32); err != nil {
		t.Fatalf("32 位模式下 0x40 应当是 INC EAX，却报错: %v", err)
	}
	ins32, err := DecodeMode([]byte{0x40}, 0x1000, Mode32)
	if err != nil {
		t.Fatal(err)
	}
	if ins32.Op() != x86asm.INC || ins32.Len() != 1 {
		t.Fatalf("32 位 0x40: op=%v len=%d，期望 INC/1", ins32.Op(), ins32.Len())
	}
	// 64 位：0x40 是 REX，后面没有操作码 ⇒ 封装应当 fail-fast（而不是当成 1 字节指令混过去）
	if _, err := DecodeMode([]byte{0x40}, 0x1000, Mode64); err == nil {
		t.Fatal("64 位模式下孤立的 REX 前缀应当报错（fail-fast）")
	}
}

// push 的操作数宽度：32 位是 EAX（4 字节栈槽），64 位是 RAX。
func TestModeDiffers_PushWidth(t *testing.T) {
	ins32, err := DecodeMode([]byte{0x50}, 0x2000, Mode32)
	if err != nil {
		t.Fatal(err)
	}
	ins64, err := DecodeMode([]byte{0x50}, 0x2000, Mode64)
	if err != nil {
		t.Fatal(err)
	}
	if ins32.Op() != x86asm.PUSH || ins64.Op() != x86asm.PUSH {
		t.Fatalf("都应当是 PUSH：32=%v 64=%v", ins32.Op(), ins64.Op())
	}
	if got := ins32.Inst.Args[0]; got != x86asm.EAX {
		t.Fatalf("32 位 push 的操作数=%v，期望 EAX", got)
	}
	if got := ins64.Inst.Args[0]; got != x86asm.RAX {
		t.Fatalf("64 位 push 的操作数=%v，期望 RAX", got)
	}
}

// mov eax,[disp32]：32 位是**绝对地址**（PCRel 必须为 0）；64 位是 RIP-relative（PCRel=4）。
func TestModeDiffers_AbsoluteVsRIPRelative(t *testing.T) {
	code := []byte{0x8B, 0x05, 0x78, 0x56, 0x34, 0x12} // mov eax, [disp32]
	ins32, err := DecodeMode(code, 0x3000, Mode32)
	if err != nil {
		t.Fatal(err)
	}
	ins64, err := DecodeMode(code, 0x3000, Mode64)
	if err != nil {
		t.Fatal(err)
	}
	if ins32.Inst.PCRel != 0 {
		t.Fatalf("32 位的 [disp32] 是绝对地址，PCRel 应当为 0，实际 %d", ins32.Inst.PCRel)
	}
	if ins64.Inst.PCRel != 4 {
		t.Fatalf("64 位的 [disp32] 是 RIP-relative，PCRel 应当为 4，实际 %d", ins64.Inst.PCRel)
	}
	if _, ok := ins32.PCRelTarget(); ok {
		t.Fatal("32 位下不应有 PC-relative 目标")
	}
	if target, ok := ins64.PCRelTarget(); !ok || target != 0x3000+6+0x12345678 {
		t.Fatalf("64 位 RIP-relative 目标=0x%X ok=%v", target, ok)
	}
}

// DecodeRangeMode 也要真的用上模式：同样的字节流在 32 位下应当能整段消费。
func TestDecodeRangeMode32(t *testing.T) {
	code := []byte{0x40, 0x40, 0x58, 0x50} // inc eax; inc eax; pop eax; push eax
	insns, err := DecodeRangeMode(code, 0x4000, 0, Mode32)
	if err != nil {
		t.Fatalf("32 位线性扫描应当成功: %v", err)
	}
	if len(insns) != 4 {
		t.Fatalf("指令数=%d，期望 4", len(insns))
	}
	// 同一段在 64 位下会被 REX 前缀吞掉/错位 ⇒ 必须失败（这正说明模式接线是必要的）
	if _, err := DecodeRange(code, 0x4000, 0); err == nil {
		t.Fatal("同一段在 64 位下应当解码失败（REX 前缀）")
	}
}

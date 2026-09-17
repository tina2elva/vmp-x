package main

import (
	"fmt"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

// decode 把一条 32 位 AArch64 指令交给 x/arch 的独立解码器（它要的是字节切片）
func decodeA64(insn uint32) (arm64asm.Inst, error) {
	b := []byte{byte(insn), byte(insn >> 8), byte(insn >> 16), byte(insn >> 24)}
	return arm64asm.Decode(b)
}

// AArch64 的 ADRP/ADD 重定位补丁：用 x/arch 的**独立解码器**验证写进去的立即数对不对。
// 为什么需要它：这条路径只有 aarch64 工具链才会触发（本机没有），所以必须有本地自测，
// 否则只能靠 CI 猜。这里用 arm64asm.Decode 把打完补丁的指令反解出来比对。
func TestAArch64RelocPatches(t *testing.T) {
	// ADRP X0, #0 的编码：1 immlo(2) 10000 immhi(19) Rd(5) 全零
	const adrpX0 = uint32(0x90000000)
	// ADD X0, X0, #0（64 位立即数形式）
	const addX0 = uint32(0x91000000)

	cases := []struct {
		name   string
		insn   uint32
		target int
		field  int
		want   string
		isADRP bool
	}{
		{"adrp 同页", adrpX0, 0x12345000, 0x1000, "adrp x0, #133300224", true},
		{"adrp 跨页", adrpX0, 0x12345000, 0x1000 + 0x2000, "adrp x0, #133296128", true},
		{"adrp 页内偏移不影响页号", adrpX0, 0x12345ABC, 0x1000, "adrp x0, #133300224", true},
	}
	for _, c := range cases {
		got, err := patchAArch64ADRP(c.insn, c.target, c.field)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		inst, derr := decodeA64(got)
		if derr != nil {
			t.Fatalf("%s: 解码失败 %v", c.name, derr)
		}
		text := inst.String()
		fmt.Println("  " + c.name + " -> " + text)
		if inst.Op != arm64asm.ADRP {
			t.Fatalf("%s: 期望 ADRP，实际 %v", c.name, inst.Op)
		}
		// x/arch 对 ADRP 可能给出 Imm（绝对地址）或 PCRel（相对指令地址的偏移），两种都接受。
		var gotAddr int64 = -1
		switch a := inst.Args[1].(type) {
		case arm64asm.Imm:
			gotAddr = int64(a.Imm)
		case arm64asm.PCRel:
			gotAddr = int64(a)
		}
		wantPage := int64(c.target &^ 0xFFF)
		if gotAddr != wantPage && gotAddr+int64(c.field) != wantPage {
			t.Fatalf("%s: ADRP 目标页 = 0x%X（或含指令地址 0x%X），期望 0x%X；指令文本 %s",
				c.name, gotAddr, gotAddr+int64(c.field), wantPage, text)
		}
	}

	// ADD (immediate)：低 12 位
	addCases := []struct {
		target int
		want   string
	}{
		{0x12345ABC, "add x0, x0, #0xabc"},
		{0x1000, "add x0, x0, #0x0"},
		{0x1FFF, "add x0, x0, #0xfff"},
	}
	for _, c := range addCases {
		got := patchAArch64AddLo12(addX0, c.target)
		inst, derr := decodeA64(got)
		if derr != nil {
			t.Fatalf("ADD 0x%X: 解码失败 %v", c.target, derr)
		}
		fmt.Println("  ADD lo12 -> " + inst.String())
		// 直接比对解码器的文本输出（比掏操作数结构更稳，且同样是独立解码器给出的结论）
		if got := inst.String(); got != c.want {
			t.Fatalf("ADD 0x%X: 解码为 %q，期望 %q", c.target, got, c.want)
		}
	}
}

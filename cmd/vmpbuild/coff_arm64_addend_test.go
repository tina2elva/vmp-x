package main

import "testing"

// AArch64 COFF 的字段是**指令**，隐式加数必须按各自编码解出来。
// 这组用例是 Windows/arm64 blob 那两个真实事故的锚点：
//
//	· BRANCH26 曾被整条指令字当加数 → 「分支超出 ±128MB」（0x94000000 = bl）
//	· 之后是 PAGEBASE_REL21（adrp）与 PAGEOFFSET_12A（add #:lo12:）
func TestDecodeAArch64COFFImplicitAddends(t *testing.T) {
	// bl（imm26 = 0）与 bl +1 / bl -1
	if v := decodeBranch26Addend(0x94000000); v != 0 {
		t.Errorf("bl imm26=0 应为 0，得到 %d", v)
	}
	if v := decodeBranch26Addend(0x94000001); v != 4 { // imm26 以 4 字节为单位：1 → 4 字节
		t.Errorf("bl imm26=1 应为 4 字节，得到 %d", v)
	}
	if v := decodeBranch26Addend(0x97FFFFFF); v != -4 {
		t.Errorf("bl imm26=-1 应为 -4，得到 %d", v)
	}
	// adrp：immlo/immlo 组合成 21 位有符号页数，左移 12
	if v := decodeADRPStoredAddend(0x90000000); v != 0 {
		t.Errorf("adrp 0 应为 0，得到 %d", v)
	}
	if v := decodeADRPStoredAddend(0xB0000000); v != 0x1000 { // immlo=1（bit29）→ +1 页
		t.Errorf("adrp +1 页应为 0x1000，得到 0x%X", v)
	}
	if v := decodeADRPStoredAddend(0xF0FFFFE0); v != -0x1000 { // 全 1 → -1 页
		t.Errorf("adrp -1 页应为 -0x1000，得到 0x%X", v)
	}
	// ldr/str x, [x, #:lo12:]：imm12 按访问宽度缩放（size 位 31:30）
	if v := decodeLDSTLo12StoredAddend(0xF9400020); v != 0 { // ldr x0,[x1] imm12=0
		t.Errorf("ldst lo12 imm12=0 应为 0，得到 %d", v)
	}
	if v := decodeLDSTLo12StoredAddend(0xF9400420); v != 8 { // imm12=1、size=3(8B) → 8 字节
		t.Errorf("ldst lo12 imm12=1/8B 应为 8，得到 %d", v)
	}
	patched, err := patchAArch64LDSTLo12(0xF9400020, 0x1238)
	if err != nil {
		t.Fatal(err)
	}
	if got := (patched >> 10) & 0xFFF; got != 0x47 { // (0x238 >> 3) = 0x47
		t.Errorf("patch ldst lo12 应为 0x47，得到 0x%X", got)
	}
	if _, err := patchAArch64LDSTLo12(0xF9400020, 0x1234); err == nil {
		t.Error("未按访问宽度对齐的目标应当报错（不能静默写错）")
	}
	// add x, x, #:lo12:（未缩放 imm12）
	if v := decodeAddLo12StoredAddend(0x91000000 | (0x123 << 10)); v != 0x123 {
		t.Errorf("add lo12 应为 0x123，得到 0x%X", v)
	}
}

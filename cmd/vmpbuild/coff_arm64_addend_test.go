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
	// add x, x, #:lo12:（未缩放 imm12）
	if v := decodeAddLo12StoredAddend(0x91000000 | (0x123 << 10)); v != 0x123 {
		t.Errorf("add lo12 应为 0x123，得到 0x%X", v)
	}
}

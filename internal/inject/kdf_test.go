package inject

import (
	"encoding/hex"
	"testing"
)

// 与 C 侧 KAT（stub/win/x64/kdf_kat.c）用同一组输入；期望值来自 C 侧实测输出，
// 任何一侧改动都会让这条断言失败 —— 这就是"两侧必须逐字节一致"的钉子。
func TestKDFEntryMatchesC(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(0x10 + i)
	}
	cases := []struct {
		rva, salt uint32
		want      string
	}{
		{0x1670, 0x11223344, "03504d6e5b8919be8be4810bcfa62727fde35898e3050c9438777953a8a04fc1"},
		{0x16A0, 0x11223344, "4bbdfb88dc35a67a794a1b620eeeb4c4da95a0cf77461ae1983bffd93d8538ce"},
		{0x93000, 0xAABBCCDD, "1966610b4c9164cb8a8ddff7b28736395af1fd503ccb5947aa1c0e137d41e149"},
	}
	for _, c := range cases {
		got := KDFEntry(master, c.rva, c.salt)
		hexs := hex.EncodeToString(got[:])
		if hexs != c.want {
			t.Fatalf("rva=0x%X: got %s want %s", c.rva, hexs, c.want)
		}
	}
}

// 逐条目的 salt 必须互不相同（这是"一把密钥解全部"被打断的前提之一）。
func TestKDFSaltDistinctAndStable(t *testing.T) {
	seen := map[uint32]uint32{}
	rv := []uint32{0x1670, 0x16A0, 0x1700, 0x1730, 0x93000}
	for _, r := range rv {
		s := KDFSaltForPlacement(r, 0x90, 40)
		if prev, dup := seen[s]; dup {
			t.Fatalf("salt 撞车: rva=0x%X 与 0x%X 都是 0x%X", r, prev, s)
		}
		seen[s] = r
		t.Logf("rva=0x%-6X salt=0x%08X key=%s", r, s,
			hex.EncodeToString(func() []byte { k := KDFEntry(master32(), r, s); return k[:] }()))
	}
}

// 接线约定 KAT：描述符 → 条目密钥。C 侧是 vm_interp.c 的 vm_desc_key（输入与 kdf_kat.c 的 desc 行相同），
// Go 侧是 payload.go 里 KDFEntry(master, fn.RVA, KDFSaltForPlacement(descSelfRVA, fn.RVA, len(code)))。
// 期望值来自 kdf_kat.exe 实测输出 —— 改任何一侧的"用哪三个字段算 salt / 哪个字段当 rva"都会让它失败。
func TestKDFDescriptorKeyMatchesC(t *testing.T) {
	const (
		selfRVA = 0x3140
		funcRVA = 0x1670
		codeLen = 40
	)
	salt := KDFSaltForPlacement(selfRVA, funcRVA, codeLen)
	if salt != 0x95EA2DB0 {
		t.Fatalf("salt = 0x%08X，期望 0x95EA2DB0", salt)
	}
	got := KDFEntry(master32(), funcRVA, salt)
	if hexs := hex.EncodeToString(got[:]); hexs != "f5ca3224112b1132be4f2d763ac738230936e67c8f34d4b168b4fadb6b5886c3" {
		t.Fatalf("描述符条目密钥 = %s", hexs)
	}
}

// 接线约定 KAT：镜像节 → 节密钥（KDFEntry(master, rva = 节 RVA, salt = 表头 salt)；nonce/aad 不变）。
func TestKDFSectionKeyMatchesC(t *testing.T) {
	got := KDFEntry(master32(), 0x1000, 0xDEADBEEF)
	if hexs := hex.EncodeToString(got[:]); hexs != "1e6e3b42e39a2a70e7763b95f5c88c3fbb90d9cba23eefedf08710b23e9b7aeb" {
		t.Fatalf("节密钥 = %s", hexs)
	}
}

// "不同条目 ⇒ 不同密钥"：这是 1a 接线要买到的东西（第三方报告 P3.13）。
func TestKDFEntryDistinctPerFunc(t *testing.T) {
	seen := map[string]uint32{}
	for _, r := range []uint32{0x1670, 0x16A0, 0x1700, 0x1730, 0x93000} {
		k := KDFEntry(master32(), r, KDFSaltForPlacement(r, 0x90, 40))
		h := hex.EncodeToString(k[:])
		if prev, dup := seen[h]; dup {
			t.Fatalf("密钥撞车: funcRVA=0x%X 与 0x%X 派生出了同一把密钥", r, prev)
		}
		seen[h] = r
	}
}

// master32 是 KAT 统一用的测试主密钥（0x10..0x2F）。
func master32() []byte {
	m := make([]byte, 32)
	for i := range m {
		m[i] = byte(0x10 + i)
	}
	return m
}

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

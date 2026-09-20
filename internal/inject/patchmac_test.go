package inject

import (
	"encoding/hex"
	"testing"
)

// 接线约定 KAT：入口补丁的带密钥 MAC。期望值来自 C 侧实测（stub/win/x64/kdf_kat.c 的 pmac 行，
// 实现是 vm_kdf.c 的 vm_patch_mac —— C 与 Go 必须逐字节一致，否则运行期校验必然 trap）。
func TestPatchMACMatchesC(t *testing.T) {
	master := master32()
	patch, _ := hex.DecodeString("e97b211200")
	got := PatchMAC(master, 0x95EA2DB0, 0x3140, 0x1670, 40, patch)
	if got != 0x4DC8B8A6 {
		t.Fatalf("PatchMAC = 0x%08X，期望 0x4DC8B8A6", got)
	}
}

// MAC 必须对"补丁字节 / selfRVA / funcRVA / codeLen"任一变化都变（否则绑定是假的）。
func TestPatchMACBindsContext(t *testing.T) {
	master := master32()
	patch, _ := hex.DecodeString("e97b211200")
	base := PatchMAC(master, 0x95EA2DB0, 0x3140, 0x1670, 40, patch)
	alt := []struct {
		name string
		v    uint32
	}{
		{"patch", PatchMAC(master, 0x95EA2DB0, 0x3140, 0x1670, 40, []byte{0xE8, 0x7B, 0x21, 0x12, 0x00})},
		{"selfRVA", PatchMAC(master, 0x95EA2DB0, 0x3141, 0x1670, 40, patch)},
		{"funcRVA", PatchMAC(master, 0x95EA2DB0, 0x3140, 0x1671, 40, patch)},
		{"codeLen", PatchMAC(master, 0x95EA2DB0, 0x3140, 0x1670, 41, patch)},
		{"salt", PatchMAC(master, 0x95EA2DB1, 0x3140, 0x1670, 40, patch)},
	}
	for _, a := range alt {
		if a.v == base {
			t.Fatalf("%s 变了但 MAC 没变（0x%08X）—— 绑定不成立", a.name, base)
		}
	}
}

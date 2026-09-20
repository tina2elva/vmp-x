package inject

import (
	"encoding/hex"
	"testing"
)

// 打包端接线断言：BuildPayload 交给 EncryptFunc 的必须是**每条目的派生密钥**
// （K_e = KDFEntry(master, fn.RVA, KDFSaltForPlacement(descSelfRVA, fn.RVA, len(code)))），
// 而不是主密钥本身 —— 运行期按同一算式现推，两边不一致就是全量 trap。
//
// descSelfRVA 由 payload 布局决定：Stub 0x200 字节 + desc(64)+thunk(5) 逐条排布，
// 所以两条目的 selfRVA 分别是 base+0x200 与 base+0x245。
func TestPayloadPassesPerEntryDerivedKey(t *testing.T) {
	const baseRVA = uint32(0x3000)
	master := master32()
	var keys []string
	enc := func(plain []byte, aad []byte, key [32]byte) ([]byte, [12]byte, [16]byte, error) {
		keys = append(keys, hex.EncodeToString(key[:]))
		var n [12]byte
		var tag [16]byte
		return plain, n, tag, nil
	}
	opt := Options{
		SectionName: ".t", Stub: make([]byte, 0x200), StubEntry: 0x40,
		Funcs: []FuncSpec{
			{Name: "a", RVA: 0x1670, Code: make([]byte, 40), NativeSize: 16},
			{Name: "b", RVA: 0x16A0, Code: make([]byte, 40), NativeSize: 16},
		},
		Encrypt: enc, PatchKey: [8]byte{1, 2, 3}, Master: master,
	}
	if _, err := BuildPayload(opt, baseRVA); err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("EncryptFunc 被调用 %d 次，期望 2 次", len(keys))
	}
	want := []struct {
		selfRVA, funcRVA uint32
	}{
		{baseRVA + 0x200, 0x1670},
		{baseRVA + 0x245, 0x16A0},
	}
	for i, w := range want {
		k := KDFEntry(master, w.funcRVA, KDFSaltForPlacement(w.selfRVA, w.funcRVA, 40))
		if got := hex.EncodeToString(k[:]); got != keys[i] {
			t.Fatalf("条目 %d 密钥 = %s，期望 %s（selfRVA=0x%X funcRVA=0x%X）", i, keys[i], got, w.selfRVA, w.funcRVA)
		}
	}
	if keys[0] == keys[1] {
		t.Fatal("两条目拿到了同一把密钥 —— KDF 没接上（又回到 P3.13 的「一把密钥解全部」）")
	}
}

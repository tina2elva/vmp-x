package inject

import (
	"encoding/binary"
	"testing"
)

// 打包端接线断言：描述符里那 6 个标量字段（偏移 8..32）写出来必须是**加过掩码**的，
// 而且用同一个掩码异或回去要能还原成真值（异或的对合性）。
// 这条盯的是"接线本身"：谁把掩码忘了加/加错了位置，运行期就是全量 trap。
func TestPayloadMasksDescriptorFields(t *testing.T) {
	const baseRVA = uint32(0x3000)
	master := master32()
	const salt = uint32(0x12345678)
	opt := Options{
		SectionName: ".t", Stub: make([]byte, 0x200), StubEntry: 0x40,
		Funcs: []FuncSpec{{Name: "f", RVA: 0x1670, Code: make([]byte, 40), NativeSize: 16}},
		Encrypt: func(plain []byte, aad []byte, key [32]byte) ([]byte, [12]byte, [16]byte, error) {
			var n [12]byte
			var tag [16]byte
			return plain, n, tag, nil
		},
		PatchKey: [8]byte{1, 2, 3}, Master: master, FieldMaskSalt: salt,
	}
	pl, err := BuildPayload(opt, baseRVA)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	selfRVA := baseRVA + 0x200 // 第一个描述符的 selfRVA（Stub 0x200 字节后对齐）
	d := int(selfRVA - baseRVA)
	raw := pl.Data[d+8 : d+32]

	md := FieldMask(master, FieldMaskDomainDesc, salt)
	got := make([]byte, 24)
	for i := range got {
		got[i] = raw[i] ^ md[i]
	}
	// 解出来的应当是：codeRVA(相对描述符) / codeLen / encLen / flags / reserved1(funcRVA) / reserved2
	if v := binary.LittleEndian.Uint32(got[4:]); v != 40 {
		t.Fatalf("codeLen = %d，期望 40", v)
	}
	if v := binary.LittleEndian.Uint32(got[8:]); v != 40 {
		t.Fatalf("encLen = %d，期望 40", v)
	}
	if v := binary.LittleEndian.Uint32(got[12:]); v&1 == 0 {
		t.Fatalf("flags = 0x%X，期望 VM_DESC_FLAG_ENC 位已置", v)
	}
	if v := binary.LittleEndian.Uint32(got[16:]); v != 0x1670 {
		t.Fatalf("reserved1(funcRVA) = 0x%X，期望 0x1670", v)
	}
	// 原始字节里不该直接看到这些**确切值**（否则掩码没生效）。
	// 注意：不要断言"flags 的 bit0 必须为 0"—— 异或掩码下每个比特都是以 1/2 概率被翻转的，
	// 单个比特看起来"对"并不意味着能读出明文（攻击者分不清 plain=1/mask=1 与 plain=0/mask=0）。
	// 真正要看的是"确切字段值不再出现"。
	if binary.LittleEndian.Uint32(raw[4:]) == 40 {
		t.Fatal("描述符里的 codeLen 仍是明文 —— 掩码没加上")
	}
	if binary.LittleEndian.Uint32(raw[16:]) == 0x1670 {
		t.Fatal("描述符里的 reserved1(funcRVA) 仍是明文 —— 掩码没加上")
	}
}

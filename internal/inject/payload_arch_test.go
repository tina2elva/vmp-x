package inject

import (
	"encoding/binary"
	"testing"
)

// AArch64 的 thunk（BL）与入口补丁（B）：imm26 = (target - pc) / 4，PC 是**指令本身**。
func TestBuildPayloadAArch64BranchEncoding(t *testing.T) {
	stub := make([]byte, 0x1000)
	opt := Options{
		Stub:      stub,
		StubEntry: 0x200,
		Arch:      ArchARM64,
		Funcs: []FuncSpec{
			{Name: "f", RVA: 0x1000, Code: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		},
	}
	pl, err := BuildPayload(opt, 0x30000)
	if err != nil {
		t.Fatal(err)
	}
	thunkOff := pl.Placements[0].ThunkRVA - 0x30000

	// thunk 是 BL vm_entry：imm26 = (0x200 - thunkOff)/4
	insn := binary.LittleEndian.Uint32(pl.Data[thunkOff:])
	if insn>>26 != 0x25 { // 0b100101 = BL
		t.Fatalf("thunk 不是 BL：0x%08X", insn)
	}
	wantImm := int32((int64(0x200) - int64(thunkOff)) / 4)
	if got := decodeImm26(insn); got != wantImm {
		t.Fatalf("thunk imm26 = %d，期望 %d", got, wantImm)
	}

	// 入口补丁是 4 字节 B，跳到自己那个 thunk
	patch := pl.Placements[0].EntryPatch
	if len(patch) != 8 {
		t.Fatalf("ARM64 入口补丁应为 8 字节（mov x16,x30 ; b thunk），实际 %d", len(patch))
	}
	// 第一条必须是 mov x16, x30（把调用方返回地址挪进 IP0，供 thunk 里的 BL 覆盖 LR 后仍能返回）
	if got := binary.LittleEndian.Uint32(patch[0:]); got != 0xAA1E03F0 {
		t.Fatalf("入口补丁第一条不是 mov x16,x30：0x%08X", got)
	}
	b := binary.LittleEndian.Uint32(patch[4:])
	if b>>26 != 0x05 { // 0b000101 = B
		t.Fatalf("入口补丁不是 B：0x%08X", b)
	}
	wantB := int32((int64(pl.Placements[0].ThunkRVA) - int64(pl.Placements[0].FuncRVA) - 4) / 4)
	if got := decodeImm26(b); got != wantB {
		t.Fatalf("入口补丁 imm26 = %d，期望 %d", got, wantB)
	}
	// 反解：B 位于 funcRVA+4，因此 funcRVA+4 + imm*4 应当正好落在 thunk 上
	if int64(pl.Placements[0].FuncRVA)+4+int64(decodeImm26(b))*4 != int64(pl.Placements[0].ThunkRVA) {
		t.Fatalf("入口补丁目标不对")
	}
}

// x86-64 仍然是 5 字节 E8/E9（回归保护）
func TestBuildPayloadX64PatchUnchanged(t *testing.T) {
	opt := Options{
		Stub:      make([]byte, 0x1000),
		StubEntry: 0x200,
		Arch:      ArchX64,
		Funcs:     []FuncSpec{{Name: "f", RVA: 0x1000, Code: []byte{1, 2, 3, 4, 5, 6, 7, 8}}},
	}
	pl, err := BuildPayload(opt, 0x30000)
	if err != nil {
		t.Fatal(err)
	}
	thunkOff := pl.Placements[0].ThunkRVA - 0x30000
	if pl.Data[thunkOff] != 0xE8 {
		t.Fatalf("x86-64 thunk 应以 E8 开头，实际 0x%02X", pl.Data[thunkOff])
	}
	patch := pl.Placements[0].EntryPatch
	if len(patch) != 5 || patch[0] != 0xE9 {
		t.Fatalf("x86-64 入口补丁应为 5 字节 E9，实际 % X", patch)
	}
}

// AArch64 的入口补丁是 8 字节（mov x16,x30 + b），所以函数的原生长度必须 ≥ 8，
// 否则会把相邻函数的指令覆盖掉——必须在打包前明确失败。
func TestBuildPayloadAArch64RejectsShortEntry(t *testing.T) {
	opt := Options{
		Stub:      make([]byte, 0x1000),
		StubEntry: 0x200,
		Arch:      ArchARM64,
		Funcs:     []FuncSpec{{Name: "f", RVA: 0x1000, Code: make([]byte, 7)}},
	}
	if _, err := BuildPayload(opt, 0x30000); err == nil {
		t.Fatal("7 字节的函数体应当因为放不下 8 字节 ARM64 入口补丁而失败")
	}
	// 8 字节正好够
	opt.Funcs[0].Code = make([]byte, 8)
	if _, err := BuildPayload(opt, 0x30000); err != nil {
		t.Fatalf("8 字节函数体应当可以打包：%v", err)
	}
	// x86-64 的门槛仍是 5 字节
	x := Options{
		Stub:      make([]byte, 0x1000),
		StubEntry: 0x200,
		Arch:      ArchX64,
		Funcs:     []FuncSpec{{Name: "f", RVA: 0x1000, Code: make([]byte, 4)}},
	}
	if _, err := BuildPayload(x, 0x30000); err == nil {
		t.Fatal("4 字节的函数体应当因为放不下 5 字节 x86-64 入口补丁而失败")
	}
}

// decodeImm26 把 B/BL 的 imm26 解成以指令为单位的偏移（先符号扩展）
func decodeImm26(insn uint32) int32 {
	v := int32(insn & 0x03FFFFFF)
	if v&(1<<25) != 0 {
		v -= 1 << 26
	}
	return v
}

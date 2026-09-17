package main

import (
	"encoding/binary"
	"testing"
)

// AArch64 的 BL/B 重定位（R_AARCH64_CALL26）：imm26 = (target - field) / 4，
// 写进低 26 位、保留操作码位。本机没有 aarch64 工具链，因此用手工构造的重定位记录验证位运算。
func TestApplyRelocsAArch64Branch26(t *testing.T) {
	const bl = uint32(0x94000000) // bl <placeholder>
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:], bl)

	obj := &objFile{
		Sections: []objSection{{Name: ".text", Data: data}},
		Symbols:  []objSymbol{{Name: "vm_run", Sec: 0, Value: 0x40}},
		Relocs: []objReloc{{
			SecIdx: 0, Off: 0, TargetSec: 0, SymName: "vm_run", Kind: relAArch64Branch26,
		}},
	}
	blob := append([]byte(nil), data...)
	secOff := map[int]int{0: 0}
	n, err := applyRelocsObj(obj, blob, secOff, false)
	if err != nil {
		t.Fatalf("重定位失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("应用了 %d 条重定位，期望 1", n)
	}
	got := binary.LittleEndian.Uint32(blob[0:])
	want := bl | (0x40 / 4) // imm26 = 0x10
	if got != want {
		t.Fatalf("BL 重定位结果 0x%08X，期望 0x%08X", got, want)
	}
	// 反向检查：imm26 解码回来应当指向 0x40
	imm := decodeBranch26(got)
	if imm != 0x40 {
		t.Fatalf("imm26 解码 = 0x%X，期望 0x40", imm)
	}
}

// decodeBranch26 把指令里的 imm26 解成字节偏移（**先符号扩展再左移 2 位**）
func decodeBranch26(insn uint32) int32 {
	v := int32(insn & 0x03FFFFFF)
	if v&(1<<25) != 0 {
		v -= 1 << 26
	}
	return v << 2
}

// 回退分支（负数位移）也要正确：目标在字段之前
func TestApplyRelocsAArch64Branch26Backward(t *testing.T) {
	const b = uint32(0x14000000) // b <placeholder>
	data := make([]byte, 0x20)
	binary.LittleEndian.PutUint32(data[0x10:], b)
	obj := &objFile{
		Sections: []objSection{{Name: ".text", Data: data}},
		Symbols:  []objSymbol{{Name: "target", Sec: 0, Value: 0x04}},
		Relocs: []objReloc{{
			SecIdx: 0, Off: 0x10, TargetSec: 0, SymName: "target", Kind: relAArch64Branch26,
		}},
	}
	blob := append([]byte(nil), data...)
	if _, err := applyRelocsObj(obj, blob, map[int]int{0: 0}, false); err != nil {
		t.Fatalf("重定位失败: %v", err)
	}
	got := binary.LittleEndian.Uint32(blob[0x10:])
	imm := decodeBranch26(got)
	if imm != -0x0C { // 0x04 - 0x10
		t.Fatalf("imm26 解码 = 0x%X，期望 -0x0C", imm)
	}
}

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
			// SymValue 是解析期按**符号索引**取到的值；应用重定位时只认它（见 objReloc 的注释）
			SecIdx: 0, Off: 0, TargetSec: 0, SymName: "vm_run", SymValue: 0x40, Kind: relAArch64Branch26,
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

// 同名节符号的回归用例（2026-09-20 实测的 vmpbuild 缺陷）：
// ld -r 合并多个目标文件后，同一节会有**多个同名节符号**（例如 .rdata 值 0 与 .rdata 值 0x80）。
// 旧实现按**名字**回查符号值，取到第一个（0）—— 于是"不是第一份只读数据"的字符串
// 被解析到节的起点（现场的 vm_kdf_salt 就是把 "VMPXKDF" 指到了 .rdata+0）。
// 现在只认解析期按索引取到的 r.SymValue：把解析改回按名字查，这条会红。
func TestApplyRelocsUsesSymbolValueNotName(t *testing.T) {
	data := make([]byte, 0x20) // 字段已经是全 0（COFF 的 REL32 把加数放在字段里）
	obj := &objFile{
		Sections: []objSection{{Name: ".text", Data: data}},
		// 两个同名节符号：这正是 ld -r 合并后的样子
		Symbols: []objSymbol{
			{Name: ".rdata", Sec: 1, Value: 0x00},
			{Name: ".rdata", Sec: 1, Value: 0x80},
		},
		Relocs: []objReloc{{
			SecIdx: 0, Off: 0, TargetSec: 1, SymName: ".rdata", SymValue: 0x80, Kind: relPCRel32,
		}},
	}
	obj.Sections = append(obj.Sections, objSection{Name: ".rdata", Data: make([]byte, 0xA0)})
	blob := append([]byte(nil), data...)
	blob = append(blob, make([]byte, 0xA0)...)
	if _, err := applyRelocsObj(obj, blob, map[int]int{0: 0, 1: 0x20}, false); err != nil {
		t.Fatalf("重定位失败: %v", err)
	}
	disp := int32(binary.LittleEndian.Uint32(blob[0:]))
	// target = 0x20(.rdata base) + 0x80(SymValue)；frame = field(0) + 4（COFF 约定）
	if want := int32(0x20 + 0x80 - 4); disp != want {
		t.Fatalf("PC 相对位移 = 0x%X，期望 0x%X（按名字查会得到 0x20+0-4）", uint32(disp), uint32(want))
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
			SecIdx: 0, Off: 0x10, TargetSec: 0, SymName: "target", SymValue: 0x04, Kind: relAArch64Branch26,
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

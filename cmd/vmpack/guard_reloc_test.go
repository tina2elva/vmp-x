package main

import (
	"testing"

	"github.com/vmpx/vmp-x/internal/inject"
	"github.com/vmpx/vmp-x/internal/load/elf"
)

// guardELFRelocsInRange 是 #597 守卫 2 的判定核心，抽出来单测（主流程在 main() 里，
// 没法被 go test 直接驱动）。四个用例分别钉住：
//
//	① 范围内 + 相对 + 已入表  ⇒ 通过（这是 -enc-image-elf-pie-relocs 的正常形态）
//	② 范围内 + 相对 + 未入表  ⇒ **拒绝**。#597 复评 F3 的正题：记表循环对 ET_EXEC 不跑，
//	   旧实现里这一类被无声放过（守卫空转）。
//	③ 范围内 + 非相对        ⇒ 拒绝（#597 原守卫的回归钉子，实测 aarch64 GLOB_DAT 那条）
//	④ 范围外                ⇒ 不管
//
// 反面校准（能把本条用例弄红）：把 guardELFRelocsInRange 里那段
// "if !recorded[rva] { ... }" 注释掉，再跑 go test ./cmd/vmpack/ -run TestGuardELFRelocsInRange
// ⇒ 用例 ② 会报 "ET_EXEC 形状（不建表）必须被拒绝，得到 []"。
func TestGuardELFRelocsInRange(t *testing.T) {
	const base = uint64(0x400000)
	secs := []inject.ImgSection{{RVA: 0x1000, Size: 0x100}} // VA [0x401000, 0x401100)
	inRel := base + 0x1000 + 8
	outVA := base + 0x3000

	if bad := guardELFRelocsInRange(secs, []inject.ImgReloc{{RVA: 0x1008}}, []elf.Reloc{{Offset: inRel, Type: elf.R_X86_64_RELATIVE}}, base, elf.R_X86_64_RELATIVE); len(bad) != 0 {
		t.Fatalf("① 已入表的相对重定位必须通过，得到 %v", bad)
	}
	bad2 := guardELFRelocsInRange(secs, nil, []elf.Reloc{{Offset: inRel, Type: elf.R_X86_64_RELATIVE}}, base, elf.R_X86_64_RELATIVE)
	if len(bad2) != 1 {
		t.Fatalf("② ET_EXEC 形状（不建表）必须被拒绝，得到 %v", bad2)
	}
	bad3 := guardELFRelocsInRange(secs, nil, []elf.Reloc{{Offset: inRel, Type: 6 /* R_X86_64_GLOB_DAT */}}, base, elf.R_X86_64_RELATIVE)
	if len(bad3) != 1 {
		t.Fatalf("③ 非相对动重定位必须被拒绝，得到 %v", bad3)
	}
	if bad := guardELFRelocsInRange(secs, nil, []elf.Reloc{{Offset: outVA, Type: 6}}, base, elf.R_X86_64_RELATIVE); len(bad) != 0 {
		t.Fatalf("④ 范围外的重定位不该被管，得到 %v", bad)
	}
	// DT_JMPREL 的 IRELATIVE（r_offset 落在可执行段 = 加密范围）走的是 ③ 那条判据：
	// 它不是 R_*_RELATIVE，运行期应用器还原不了 ⇒ 必须拒绝。
	if bad := guardELFRelocsInRange(secs, nil, []elf.Reloc{{Offset: inRel, Type: 37 /* R_X86_64_IRELATIVE */}}, base, elf.R_X86_64_RELATIVE); len(bad) != 1 {
		t.Fatalf("⑤ 加密范围内的 IRELATIVE 必须被拒绝，得到 %v", bad)
	}
}

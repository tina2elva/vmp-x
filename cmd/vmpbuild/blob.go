package main

// blob 组装：在归一化目标文件模型（objfile.go）之上工作，
// 因此 COFF 与 ELF 可重定位目标走同一条路径。
import (
	"encoding/binary"
	"fmt"
	"strings"
)

// buildBlobObj 组装单目标 blob。
// 顺序很重要：**.bss 必须最后**——注入时它会被单独映射成"可写区"，
// 因此它必须是 blob 结尾的一段连续区间（其余部分按 RX 映射）。
// wantSection 判断某个节名是否要进 blob。
// 除了精确名字，还必须接受 gcc 生成的子节：ELF 会把 8 字节常量放进 .rodata.cst8、
// 把冷代码放进 .text.unlikely —— 不合并它们，重定位检查就会报"引用了 blob 之外的节"
// （CI 的 linux-amd64 作业实测就是死在 .rodata.cst8 上）。
func wantSection(name string) bool {
	switch name {
	case ".text", ".rdata", ".rodata", ".data", ".bss":
		return true
	}
	for _, p := range []string{".text.", ".rodata.", ".rdata.", ".data.", ".bss."} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// isMappingSymbol 过滤 AArch64 的映射符号（$x/$d/$t）：它们不是真符号，
// 多个目标文件里同名，内置合并器会误判成"重复定义"（CI 的 linux-arm64 作业实测）。
func isMappingSymbol(name string) bool { return strings.HasPrefix(name, "$") }

func buildBlobObj(obj *objFile) ([]sectInfo, []byte, map[int]int, error) {
	// .rdata 是 mingw/COFF 的只读数据节名，.rodata 是 ELF 的
	want := []string{".text", ".rdata", ".rodata", ".data", ".bss"}
	var (
		infos []sectInfo
		blob  []byte
		offs  = map[int]int{} // 节索引(0-based) -> blob 偏移
	)
	for _, name := range want {
		for _, s := range obj.Sections {
			if len(s.Data) == 0 || !wantSection(s.Name) || (s.Name != name && !strings.HasPrefix(s.Name, name+".")) {
				continue
			}
			// .bss 会被注入器单独映射成一个 RW 段，而 PE/ELF 的段起点必须落在**节对齐**
			// （这里是 0x1000）上，所以它的起点和终点都要对齐到 0x1000。
			step := 16
			if name == ".bss" {
				step = 0x1000
			}
			for len(blob)%step != 0 {
				blob = append(blob, 0)
			}
			offs[s.Index] = len(blob)
			blob = append(blob, s.Data...)
			infos = append(infos, sectInfo{Name: name, BlobOff: offs[s.Index], Size: len(s.Data)})
			if name == ".bss" {
				for len(blob)%0x1000 != 0 { // 尾部也要对齐，后续内容才能落在新的页上
					blob = append(blob, 0)
				}
			}
		}
	}
	if len(offs) == 0 {
		return nil, nil, nil, fmt.Errorf("目标文件中没有可用的代码节")
	}
	return infos, blob, offs, nil
}

// applyRelocsObj：PC-relative 自行重算；绝对引用 / 未定义符号一律失败。
func applyRelocsObj(obj *objFile, blob []byte, secBlobOff map[int]int, verbose bool) (int, error) {
	total := 0
	for _, r := range obj.Relocs {
		base, ok := secBlobOff[r.SecIdx]
		if !ok {
			continue // 该节没进 blob（例如调试节）
		}
		total++
		if r.SecIdx < 0 || r.SecIdx >= len(obj.Sections) {
			return 0, fmt.Errorf("重定位的节索引 %d 越界", r.SecIdx)
		}
		secName := obj.Sections[r.SecIdx].Name
		if r.TargetSec < 0 {
			return 0, fmt.Errorf("%s+0x%X: 引用了未定义符号 %q — 该 stub 不是自包含的",
				secName, r.Off, r.SymName)
		}
		tgtBase, inBlob := secBlobOff[r.TargetSec]
		if !inBlob {
			return 0, fmt.Errorf("%s+0x%X: 引用了 blob 之外的节 %q — 该 stub 不是位置无关的",
				secName, r.Off, obj.Sections[r.TargetSec].Name)
		}
		field := base + int(r.Off)
		if field+4 > len(blob) {
			return 0, fmt.Errorf("%s+0x%X: 重定位位置越界", secName, r.Off)
		}
		var symValue uint64
		for _, s := range obj.Symbols {
			if s.Name == r.SymName && s.Sec == r.TargetSec {
				symValue = s.Value
				break
			}
		}
		target := tgtBase + int(symValue) + int(r.Addend)

		switch r.Kind {
		case relPCRel32:
			// ELF 的加数是显式的（RELA 的 r_addend；x86-64 上 call/jmp 通常是 -4），
			// 所以写入值就是 target - field；COFF 的加数藏在字段里，才需要 +4 / PlusN 补偿。
			// 之前不分格式一律 +4，等于把 ELF 的每条 PC 相对 call/jmp 都写偏 4 字节
			// —— 这正是"Windows 正常、Linux SIGILL"的根因（探针把它定位到 blob+0xCBF）。
			frame := field + r.PlusN
			if obj.Format != "elf" {
				frame = field + 4 + r.PlusN
			}
			binary.LittleEndian.PutUint32(blob[field:], uint32(int32(target-frame)))
		case relAArch64Branch26:
			// BL/B：imm26 = (target - field) / 4，写进低 26 位（操作码位保留）
			delta := int64(target) - int64(field)
			if delta%4 != 0 {
				return 0, fmt.Errorf("%s+0x%X: AArch64 分支目标未 4 字节对齐", secName, r.Off)
			}
			imm := delta / 4
			if imm < -(1<<25) || imm >= (1<<25) {
				return 0, fmt.Errorf("%s+0x%X: AArch64 分支超出 ±128MB 范围", secName, r.Off)
			}
			insn := binary.LittleEndian.Uint32(blob[field:])
			insn = (insn &^ 0x03FFFFFF) | (uint32(imm) & 0x03FFFFFF)
			binary.LittleEndian.PutUint32(blob[field:], insn)
		case relAArch64ADRPrelPGHi21:
			insn, err := patchAArch64ADRP(binary.LittleEndian.Uint32(blob[field:]), target, field)
			if err != nil {
				return 0, fmt.Errorf("%s+0x%X: %w", secName, r.Off, err)
			}
			binary.LittleEndian.PutUint32(blob[field:], insn)
		case relAArch64AddAbsLo12:
			binary.LittleEndian.PutUint32(blob[field:], patchAArch64AddLo12(binary.LittleEndian.Uint32(blob[field:]), target))
		case relAbsolute32, relAbsolute64:
			return 0, fmt.Errorf("%s+0x%X: 出现绝对重定位 (type 0x%X) — 拒绝注入（stub 必须位置无关）",
				secName, r.Off, r.RawType)
		default:
			return 0, fmt.Errorf("%s+0x%X: 不支持的重定位类型 0x%X", secName, r.Off, r.RawType)
		}
		if verbose {
			fmt.Printf("    [reloc] %s+0x%X type=0x%X sym=%s(+0x%X) addend=%d -> target=0x%X",
				secName, r.Off, r.RawType, r.SymName, symValue, r.Addend, target)
			fmt.Println()
		}
	}
	return total, nil
}

// ---------------- 多目标直拼（不依赖 GNU ld -r） ----------------
//
// 为什么需要：COFF 上没有 ld -r 的等价物（lld-link 不支持可重定位链接），
// 而 Windows/arm64 的 blob 由 clang 分文件编译成 COFF 对象。于是自己做一个最小链接器：
//   - 按固定的节顺序把各对象的节拼进 blob（16 字节对齐）；
//   - 建立"全局符号名 → blob 偏移"表（跨对象引用靠它解析）；
//   - 重定位：PC 相对自行重算，绝对引用一律失败（与单目标路径同样的纪律）。

type mergedBlob struct {
	Sections []sectInfo
	Data     []byte
	secOff   map[[2]int]int // (对象下标, 节下标) -> blob 偏移
	symOff   map[string]int // 符号名 -> blob 偏移（只含已定义符号）
}

func buildBlobMulti(objs []*objFile) (*mergedBlob, error) {
	// 与 buildBlobObj 一致：.bss 放最后（会被单独映射成可写区）
	want := []string{".text", ".rdata", ".rodata", ".data", ".bss"}
	m := &mergedBlob{secOff: map[[2]int]int{}, symOff: map[string]int{}}
	for oi, o := range objs {
		for _, name := range want {
			for _, s := range o.Sections {
				if len(s.Data) == 0 || !wantSection(s.Name) || (s.Name != name && !strings.HasPrefix(s.Name, name+".")) {
					continue
				}
				step := 16
				if name == ".bss" {
					step = 0x1000 // 与单目标路径一致：.bss 起止都对齐到节对齐
				}
				for len(m.Data)%step != 0 {
					m.Data = append(m.Data, 0)
				}
				m.secOff[[2]int{oi, s.Index}] = len(m.Data)
				m.Data = append(m.Data, s.Data...)
				m.Sections = append(m.Sections, sectInfo{Name: name, BlobOff: len(m.Data) - len(s.Data), Size: len(s.Data)})
				if name == ".bss" {
					for len(m.Data)%0x1000 != 0 {
						m.Data = append(m.Data, 0)
					}
				}
			}
		}
	}
	if len(m.secOff) == 0 {
		return nil, fmt.Errorf("目标文件里没有可用的代码节")
	}
	for oi, o := range objs {
		for _, s := range o.Symbols {
			if s.Sec < 0 {
				continue // 未定义符号：等别的目标文件定义
			}
			base, ok := m.secOff[[2]int{oi, s.Sec}]
			if !ok {
				continue // 该节没进 blob（例如调试节）
			}
			// 跳过节符号（COFF 里每个对象都有一个与节同名的符号）与无名符号（ELF 的 STT_SECTION）
			if s.Name == "" || isMappingSymbol(s.Name) || (s.Sec < len(o.Sections) && s.Name == o.Sections[s.Sec].Name) {
				continue
			}
			off := base + int(s.Value)
			if prev, dup := m.symOff[s.Name]; dup && prev != off {
				// 同名不同址：只有**全局符号**才是真冲突（例如两个目标文件各定义一个函数）。
				// 局部符号（static）不能跨目标文件引用，多个文件重名是合法的 —— 之前这里一律报错，
				// CI 的 linux-arm64 作业就死在 guest_semantics_arm64.c 里的局部名 "nz" 上。
				if s.Binding != 0 {
					return nil, fmt.Errorf("全局符号 %q 被重复定义（0x%X / 0x%X）", s.Name, prev, off)
				}
				continue
			}
			m.symOff[s.Name] = off
		}
	}
	return m, nil
}

// applyAllRelocs 在多目标视图上应用重定位
func (m *mergedBlob) applyAllRelocs(objs []*objFile, verbose bool) (int, error) {
	total := 0
	for oi, o := range objs {
		for _, r := range o.Relocs {
			base, ok := m.secOff[[2]int{oi, r.SecIdx}]
			if !ok {
				continue
			}
			total++
			field := base + int(r.Off)
			if field+4 > len(m.Data) {
				return 0, fmt.Errorf("%s+0x%X: 重定位位置越界", o.Sections[r.SecIdx].Name, r.Off)
			}
			// 目标：同一对象内的节内符号，或跨对象的全局符号
			var target int
			if r.TargetSec >= 0 {
				tb, ok := m.secOff[[2]int{oi, r.TargetSec}]
				if !ok {
					return 0, fmt.Errorf("%s+0x%X: 引用了 blob 之外的节 %q", o.Sections[r.SecIdx].Name, r.Off, o.Sections[r.TargetSec].Name)
				}
				var symValue int
				for _, s := range o.Symbols {
					if s.Name == r.SymName && s.Sec == r.TargetSec {
						symValue = int(s.Value)
						break
					}
				}
				target = tb + symValue + int(r.Addend)
			} else {
				off, ok := m.symOff[r.SymName]
				if !ok {
					return 0, fmt.Errorf("%s+0x%X: 引用了未定义符号 %q — 该 stub 不是自包含的", o.Sections[r.SecIdx].Name, r.Off, r.SymName)
				}
				target = off + int(r.Addend)
			}
			switch r.Kind {
			case relPCRel32:
				frame := field + r.PlusN
				if o.Format != "elf" { // 同 applyRelocsObj：ELF 的加数在 RELA 里，不再 +4
					frame = field + 4 + r.PlusN
				}
				binary.LittleEndian.PutUint32(m.Data[field:], uint32(int32(target-frame)))
			case relAArch64Branch26:
				delta := int64(target) - int64(field)
				if delta%4 != 0 {
					return 0, fmt.Errorf("%s+0x%X: AArch64 分支目标未 4 字节对齐", o.Sections[r.SecIdx].Name, r.Off)
				}
				imm := delta / 4
				if imm < -(1<<25) || imm >= (1<<25) {
					return 0, fmt.Errorf("%s+0x%X: AArch64 分支超出 ±128MB", o.Sections[r.SecIdx].Name, r.Off)
				}
				insn := binary.LittleEndian.Uint32(m.Data[field:])
				insn = (insn &^ 0x03FFFFFF) | (uint32(imm) & 0x03FFFFFF)
				binary.LittleEndian.PutUint32(m.Data[field:], insn)
			case relAArch64ADRPrelPGHi21:
				insn, err := patchAArch64ADRP(binary.LittleEndian.Uint32(m.Data[field:]), target, field)
				if err != nil {
					return 0, fmt.Errorf("%s+0x%X: %w", o.Sections[r.SecIdx].Name, r.Off, err)
				}
				binary.LittleEndian.PutUint32(m.Data[field:], insn)
			case relAArch64AddAbsLo12:
				binary.LittleEndian.PutUint32(m.Data[field:], patchAArch64AddLo12(binary.LittleEndian.Uint32(m.Data[field:]), target))
			default:
				return 0, fmt.Errorf("%s+0x%X: 不支持的重定位类型 0x%X（绝对引用必须失败）", o.Sections[r.SecIdx].Name, r.Off, r.RawType)
			}
			if verbose {
				fmt.Printf("    [reloc] %s+0x%X type=0x%X sym=%s -> target=0x%X\n", o.Sections[r.SecIdx].Name, r.Off, r.RawType, r.SymName, target)
			}
		}
	}
	return total, nil
}

// patchAArch64ADRP 把 ADRP 的页相对立即数写进指令：
//
//	imm = page(S+A) - page(P)，编码为 immlo(30:29) = imm[13:12]、immhi(23:5) = imm[32:14]
func patchAArch64ADRP(insn uint32, target, field int) (uint32, error) {
	imm := int64(target&^0xFFF) - int64(field&^0xFFF)
	if imm < -(1<<32) || imm > (1<<32) {
		return 0, fmt.Errorf("ADRP 目标超出 ±4GB（目标 0x%X）", int64(target))
	}
	immPage := uint32(imm>>12) & 0x1FFFFF
	insn &^= (uint32(3) << 29) | (uint32(0x7FFFF) << 5)
	insn |= (immPage & 3) << 29
	insn |= ((immPage >> 2) & 0x7FFFF) << 5
	return insn, nil
}

// patchAArch64AddLo12 把绝对地址的低 12 位写进 ADD (immediate)：位域 21:10
func patchAArch64AddLo12(insn uint32, target int) uint32 {
	insn &^= uint32(0xFFF) << 10
	insn |= (uint32(target) & 0xFFF) << 10
	return insn
}

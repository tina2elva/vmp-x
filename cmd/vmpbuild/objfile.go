package main

// 目标文件读取：把 COFF（Windows 工具链）与 ELF 可重定位目标（Linux 工具链）
// 归一化成同一套结构，供 blob 组装与重定位解析使用。
//
// 归一化后的重定位只区分三类：
//   relPCRel32     —— 4 字节 PC 相对（COFF REL32 家族 / ELF PC32、PLT32）
//   relAbsolute32  —— 4 字节绝对（不可注入，必须失败）
//   relAbsolute64  —— 8 字节绝对（不可注入，必须失败）
// 其余类型一律 relUnsupported，同样失败。
import (
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

type relKind int

const (
	relPCRel32 relKind = iota
	relAbsolute32
	relAbsolute64
	relAArch64Branch26 // 26 位 PC 相对分支（BL/B），字段低 26 位存 imm26（以 4 字节为单位）
	relUnsupported
)

type objSection struct {
	Name  string
	Data  []byte
	Index int
}

type objSymbol struct {
	Name  string
	Sec   int // -1 = 未定义
	Value uint64
}

type objReloc struct {
	SecIdx    int
	Off       uint64
	TargetSec int
	SymName   string
	Kind      relKind
	RawType   uint32
	Addend    int64
	PlusN     int // PC 相对基准的额外偏移（COFF REL32_1..5）
}

type objFile struct {
	Machine  elf.Machine
	IsARM64  bool // 目标架构是 AArch64（ELF 的 EM_AARCH64 / COFF 的 0xAA64）
	Format   string
	Sections []objSection
	Symbols  []objSymbol
	Relocs   []objReloc
}

func readObject(path string) (*objFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// 注意：COFF **目标文件**开头是机器码（不是 PE 映像的 "MZ"），
	// 所以只用 ELF magic 区分，其余交给 pe.Open 去校验。
	if len(b) >= 4 && b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F' {
		return readELFObject(path)
	}
	return readCOFFObject(path)
}

// ---------------- COFF ----------------

func readCOFFObject(path string) (*objFile, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := &objFile{Format: "coff"}
	// COFF 的 Machine：0x8664 = AMD64，0xAA64 = ARM64
	out.IsARM64 = uint16(f.FileHeader.Machine) == coffMachineARM64
	for i, s := range f.Sections {
		data, derr := s.Data()
		if derr != nil {
			// 未初始化数据（.bss 之类）：Go 的 debug/pe 会报错。blob 是**按字节拷贝**的映像，
			// 这类节的正确内容就是全零，所以补零即可（不这样做，statics 就直接进不了 blob）。
			data = make([]byte, s.Size)
		}
		out.Sections = append(out.Sections, objSection{Name: s.Name, Data: data, Index: i})
	}
	for i := range f.COFFSymbols {
		c := f.COFFSymbols[i]
		name, _ := c.FullName(f.StringTable)
		sec := int(c.SectionNumber) - 1
		if c.SectionNumber <= 0 {
			sec = -1
		}
		out.Symbols = append(out.Symbols, objSymbol{Name: name, Sec: sec, Value: uint64(c.Value)})
	}
	for i, s := range f.Sections {
		for _, r := range s.Relocs {
			sym := -1
			name := ""
			if int(r.SymbolTableIndex) < len(out.Symbols) {
				sym = out.Symbols[r.SymbolTableIndex].Sec
				name = out.Symbols[r.SymbolTableIndex].Name
			}
			// COFF 的加数存在字段里
			var addend int64
			if int(r.VirtualAddress)+4 <= len(s.SectionHeader.Name) { // 占位，实际在下面读
			}
			// 读取字段：需要原始节数据
			data, _ := s.Data()
			if int(r.VirtualAddress)+4 <= len(data) {
				addend = int64(int32(binary.LittleEndian.Uint32(data[r.VirtualAddress:])))
			}
			rel := objReloc{SecIdx: i, Off: uint64(r.VirtualAddress), TargetSec: sym, SymName: name, RawType: uint32(r.Type), Addend: addend}
			if out.IsARM64 {
				// ARM64 COFF：只接受 26 位分支（BL/B），其余一律失败
				if r.Type == coffRelARM64Branch26 {
					rel.Kind = relAArch64Branch26
				} else {
					rel.Kind = relUnsupported
				}
				out.Relocs = append(out.Relocs, rel)
				continue
			}
			switch {
			case r.Type == relAMD64Rel32:
				rel.Kind = relPCRel32
			case r.Type >= relAMD64Rel32+1 && r.Type <= relAMD64Rel32N:
				rel.Kind = relPCRel32
				rel.PlusN = int(r.Type-relAMD64Rel32) + 1
			case r.Type == relAMD64Addr32 || r.Type == relAMD64Addr32NB:
				rel.Kind = relAbsolute32
			case r.Type == relAMD64Addr64:
				rel.Kind = relAbsolute64
			default:
				rel.Kind = relUnsupported
			}
			out.Relocs = append(out.Relocs, rel)
		}
	}
	return out, nil
}

// ---------------- ELF 可重定位目标 ----------------

const (
	R_X86_64_64    = 1
	R_X86_64_PC32  = 2
	R_X86_64_PLT32 = 4

	/* COFF（Windows 对象文件）*/
	coffMachineARM64     = 0xAA64
	coffRelARM64Branch26 = 3 /* IMAGE_REL_ARM64_BRANCH26 */

	/* AArch64（ELF for the ARM 64-bit Architecture）*/
	R_AARCH64_CALL26           = 283
	R_AARCH64_JUMP26           = 282
	R_AARCH64_ADR_PREL_PG_HI21 = 275
	R_AARCH64_ADD_ABS_LO12_NC  = 277
	R_AARCH64_ADR_GOT_PAGE     = 311
	R_AARCH64_LD64_GOT_LO12_NC = 312
	R_X86_64_32                = 10
	R_X86_64_32S               = 11
)

func readELFObject(path string) (*objFile, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Type != elf.ET_REL {
		return nil, fmt.Errorf("%s: 期望可重定位目标 (ET_REL)，实际 %v", path, f.Type)
	}
	if f.Machine != elf.EM_X86_64 && f.Machine != elf.EM_AARCH64 {
		return nil, fmt.Errorf("%s: 期望 EM_X86_64 或 EM_AARCH64，实际 %v", path, f.Machine)
	}

	out := &objFile{Format: "elf", Machine: f.Machine, IsARM64: f.Machine == elf.EM_AARCH64}
	for i, s := range f.Sections {
		data, derr := s.Data()
		if derr != nil {
			// 未初始化数据（.bss，SHT_NOBITS）：Go 的 debug/elf 在这里会直接报
			// "unexpected read from SHT_NOBITS section"。blob 是**按字节拷贝**的映像，
			// 这类节的正确内容就是全零，补零即可（COFF 侧一直这么做；ELF 侧漏了，
			// 于是 Linux 上用宿主 gcc 走 ELF 目标这条路一直失败，CI 首次真跑才暴露）。
			if s.Type == elf.SHT_NOBITS {
				data = make([]byte, s.Size)
			} else {
				return nil, derr
			}
		}
		out.Sections = append(out.Sections, objSection{Name: s.Name, Data: data, Index: i})
	}

	// 符号表：ET_REL 里 .symtab 的符号值是该节内的偏移
	syms, err := f.Symbols()
	if err != nil {
		return nil, fmt.Errorf("%s: 读取符号表失败: %w", path, err)
	}
	for i := range syms {
		s := &syms[i]
		sec := -1
		// 保留索引（SHN_ABS/SHN_COMMON/... ≥ SHN_LORESERVE）不是真实节：
		// 这类符号引用意味着绝对地址，必须让后面的解析器拒绝，而不是当节索引用。
		if s.Section != elf.SHN_UNDEF && s.Section < elf.SHN_LORESERVE {
			sec = int(s.Section)
		}
		out.Symbols = append(out.Symbols, objSymbol{Name: s.Name, Sec: sec, Value: s.Value})
	}

	// 重定位节：SHT_RELA（带显式加数）与 SHT_REL（加数在字段里）
	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA && s.Type != elf.SHT_REL {
			continue
		}
		target := int(s.Info) // sh_info = 被重定位的节
		data, derr := s.Data()
		if derr != nil {
			return nil, derr
		}
		if s.Type == elf.SHT_RELA {
			for off := 0; off+24 <= len(data); off += 24 {
				rOff := binary.LittleEndian.Uint64(data[off:])
				info := binary.LittleEndian.Uint64(data[off+8:])
				addend := int64(binary.LittleEndian.Uint64(data[off+16:]))
				out.Relocs = append(out.Relocs, makeELFReloc(out, target, rOff, info, addend, false))
			}
		} else {
			for off := 0; off+16 <= len(data); off += 16 {
				rOff := binary.LittleEndian.Uint64(data[off:])
				info := binary.LittleEndian.Uint64(data[off+8:])
				out.Relocs = append(out.Relocs, makeELFReloc(out, target, rOff, info, 0, true))
			}
		}
	}
	return out, nil
}

func makeELFReloc(out *objFile, target int, rOff, info uint64, addend int64, implicit bool) objReloc {
	// AArch64 与 x86-64 的重定位编号空间不同，按 e_machine 分派
	symIdx := int(info >> 32)
	typ := uint32(info & 0xFFFFFFFF)
	rel := objReloc{SecIdx: target, Off: rOff, TargetSec: -1, RawType: typ, Addend: addend}
	if symIdx < len(out.Symbols) {
		rel.TargetSec = out.Symbols[symIdx].Sec
		rel.SymName = out.Symbols[symIdx].Name
	}
	if implicit {
		// SHT_REL：加数在字段里
		if target < len(out.Sections) {
			d := out.Sections[target].Data
			if int(rOff)+4 <= len(d) {
				rel.Addend = int64(int32(binary.LittleEndian.Uint32(d[rOff:])))
			}
		}
	}
	if out.IsARM64 {
		switch typ {
		case R_AARCH64_CALL26, R_AARCH64_JUMP26:
			rel.Kind = relAArch64Branch26
		case R_AARCH64_ADR_PREL_PG_HI21, R_AARCH64_ADD_ABS_LO12_NC, R_AARCH64_ADR_GOT_PAGE, R_AARCH64_LD64_GOT_LO12_NC:
			// adrp/add 与 GOT 访问：本 stub 不使用（入口只靠 LR 反推描述符），出现即失败
			rel.Kind = relUnsupported
		default:
			rel.Kind = relUnsupported
		}
		return rel
	}
	switch typ {
	case R_X86_64_PC32, R_X86_64_PLT32:
		rel.Kind = relPCRel32
	case R_X86_64_32, R_X86_64_32S:
		rel.Kind = relAbsolute32
	case R_X86_64_64:
		rel.Kind = relAbsolute64
	default:
		rel.Kind = relUnsupported
	}
	return rel
}

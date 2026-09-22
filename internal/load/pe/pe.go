// Package pe 提供最小可用的 PE32+ 读写能力：
// 解析 DOS/COFF/Optional/Section 头，并支持“新增一个节”的注入操作。
//
// 设计约束（PoC）：
//   - 只支持 PE32+ (Magic 0x20B)，AMD64 / ARM64。
//   - 新增节一律追加到文件尾并按 FileAlignment/节对齐规则修正头部字段。
//   - 不做任何重定位改写：注入的内容必须是位置无关代码（RIP-relative）。
package pe

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// 关键偏移与常量
const (
	offLfanew = 0x3C
	// DOS 签名 "MZ"
	MzMagic = 0x5A4D
	// PE 签名 "PE\0\0"
	PeMagic = 0x00004550

	MachineI386  = 0x14C
	MachineAMD64 = 0x8664
	MachineARM64 = 0xAA64

	OptMagicPE32     = 0x10B
	OptMagicPE32Plus = 0x20B

	SectionHeaderSize = 40

	// 节属性
	ScnCntCode        = 0x00000020
	ScnCntInitData    = 0x00000040
	ScnMemExecute     = 0x20000000
	ScnMemRead        = 0x40000000
	ScnMemWrite       = 0x80000000
	ScnMemDiscardable = 0x02000000
)

// Section 是 PE 节表中的一个条目
type Section struct {
	Name             string
	VirtualSize      uint32
	VirtualAddress   uint32
	SizeOfRawData    uint32
	PointerToRawData uint32
	Characteristics  uint32
	HeaderOffset     int // 该节头在文件中的偏移
}

// File 是内存中的 PE 镜像
type File struct {
	Data []byte

	Lfanew               int
	Machine              uint16
	NumberOfSections     int
	SizeOfOptionalHeader int
	Characteristics      uint16

	OptHeaderOffset  int
	OptMagic         uint16
	SectionTableOff  int
	SectionAlignment uint32
	FileAlignment    uint32
	SizeOfImage      uint32
	SizeOfHeaders    uint32
	AddressOfEntry   uint32
	ImageBase        uint64
	Subsystem        uint16

	Sections []Section
}

// Is32Bit 报告这是不是 32 位（PE32）镜像。
// 注意：vmp-x 的 VM blob 目前只有 64 位平台（stub/win/x64、stub/win/arm64），
// 所以 PE32 到这里能正确解析，但还**不能**被注入 —— 打包端会明确拒绝（见 cmd/vmpack）。
func (f *File) Is32Bit() bool { return f.OptMagic == OptMagicPE32 }

func u16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func u32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

// AlignUp 向上对齐；align 必须为 2 的幂
func AlignUp(v, align uint32) uint32 {
	if align == 0 {
		return v
	}
	return (v + align - 1) &^ (align - 1)
}

// Parse 解析 PE 头部
func Parse(data []byte) (*File, error) {
	if len(data) < offLfanew+4 {
		return nil, fmt.Errorf("file too small for DOS header (%d bytes)", len(data))
	}
	if u16(data, 0) != MzMagic {
		return nil, fmt.Errorf("not a PE: bad MZ signature 0x%04X", u16(data, 0))
	}
	lfanew := int(u32(data, offLfanew))
	if lfanew <= 0 || lfanew+24 > len(data) {
		return nil, fmt.Errorf("bad e_lfanew 0x%X", lfanew)
	}
	if u32(data, lfanew) != PeMagic {
		return nil, fmt.Errorf("not a PE: bad signature at 0x%X", lfanew)
	}

	f := &File{Data: data, Lfanew: lfanew}
	f.Machine = u16(data, lfanew+4)
	f.NumberOfSections = int(u16(data, lfanew+6))
	f.SizeOfOptionalHeader = int(u16(data, lfanew+20))
	f.Characteristics = u16(data, lfanew+22)

	f.OptHeaderOffset = lfanew + 24
	if f.OptHeaderOffset+2 > len(data) {
		return nil, fmt.Errorf("optional header out of range")
	}
	// PE32（0x10B，32 位）与 PE32+（0x20B，64 位）在下面这些字段上**偏移相同**，
	// 只有 ImageBase 的宽度/偏移不同（PE32: u32 @+28；PE32+: u64 @+24）。
	f.OptMagic = u16(data, f.OptHeaderOffset)
	switch f.OptMagic {
	case OptMagicPE32:
		if f.OptHeaderOffset+96 > len(data) {
			return nil, fmt.Errorf("optional header truncated")
		}
		f.AddressOfEntry = u32(data, f.OptHeaderOffset+16)
		f.ImageBase = uint64(u32(data, f.OptHeaderOffset+28))
	case OptMagicPE32Plus:
		if f.OptHeaderOffset+112 > len(data) {
			return nil, fmt.Errorf("optional header truncated")
		}
		f.AddressOfEntry = u32(data, f.OptHeaderOffset+16)
		f.ImageBase = binary.LittleEndian.Uint64(data[f.OptHeaderOffset+24:])
	default:
		return nil, fmt.Errorf("unknown optional magic 0x%X", f.OptMagic)
	}
	f.SectionAlignment = u32(data, f.OptHeaderOffset+32)
	f.FileAlignment = u32(data, f.OptHeaderOffset+36)
	f.SizeOfImage = u32(data, f.OptHeaderOffset+56)
	f.SizeOfHeaders = u32(data, f.OptHeaderOffset+60)
	f.Subsystem = u16(data, f.OptHeaderOffset+68)

	if f.SectionAlignment == 0 || f.FileAlignment == 0 {
		return nil, fmt.Errorf("invalid alignment (section=0x%X file=0x%X)", f.SectionAlignment, f.FileAlignment)
	}

	f.SectionTableOff = f.OptHeaderOffset + f.SizeOfOptionalHeader
	if f.NumberOfSections < 0 || f.NumberOfSections > 96 {
		return nil, fmt.Errorf("implausible section count %d", f.NumberOfSections)
	}
	for i := 0; i < f.NumberOfSections; i++ {
		off := f.SectionTableOff + i*SectionHeaderSize
		if off+SectionHeaderSize > len(data) {
			return nil, fmt.Errorf("section header %d out of range", i)
		}
		name := strings.TrimRight(string(data[off:off+8]), "\x00")
		f.Sections = append(f.Sections, Section{
			Name:             name,
			VirtualSize:      u32(data, off+8),
			VirtualAddress:   u32(data, off+12),
			SizeOfRawData:    u32(data, off+16),
			PointerToRawData: u32(data, off+20),
			Characteristics:  u32(data, off+36),
			HeaderOffset:     off,
		})
	}
	return f, nil
}

// Open 从磁盘读取并解析
func Open(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// NextRVA 返回下一个可用的节虚拟地址（按 SectionAlignment 对齐）
func (f *File) NextRVA() uint32 {
	end := f.SizeOfImage
	for _, s := range f.Sections {
		cand := s.VirtualAddress + AlignUp(s.VirtualSize, f.SectionAlignment)
		if cand > end {
			end = cand
		}
	}
	return AlignUp(end, f.SectionAlignment)
}

// headerRoom 返回节表之后、第一个节的原始数据之前还剩多少字节
func (f *File) headerRoom() int {
	limit := f.SizeOfHeaders
	for _, s := range f.Sections {
		if s.PointerToRawData != 0 && s.PointerToRawData < limit {
			limit = s.PointerToRawData
		}
	}
	if int(limit) > len(f.Data) {
		limit = uint32(len(f.Data))
	}
	return int(limit) - (f.SectionTableOff + f.NumberOfSections*SectionHeaderSize)
}

// AddSection 追加一个节：原始数据写到文件尾（按 FileAlignment 对齐并补零），
// 节头写入节表后的空闲空间，并修正 NumberOfSections / SizeOfImage。
func (f *File) AddSection(name string, payload []byte, char uint32) (*Section, error) {
	if len(name) == 0 || len(name) > 8 {
		return nil, fmt.Errorf("section name must be 1..8 bytes, got %q", name)
	}
	if f.NumberOfSections >= 96 {
		return nil, fmt.Errorf("section table full (96 entries)")
	}
	if f.headerRoom() < SectionHeaderSize {
		return nil, fmt.Errorf("no room for a new section header (need %d bytes, have %d)", SectionHeaderSize, f.headerRoom())
	}

	rawOff := AlignUp(uint32(len(f.Data)), f.FileAlignment)
	// 补齐到对齐位置
	for uint32(len(f.Data)) < rawOff {
		f.Data = append(f.Data, 0)
	}
	rawSize := AlignUp(uint32(len(payload)), f.FileAlignment)
	if rawSize == 0 {
		rawSize = f.FileAlignment
	}
	f.Data = append(f.Data, payload...)
	for uint32(len(f.Data)) < rawOff+rawSize {
		f.Data = append(f.Data, 0)
	}

	rva := f.NextRVA()
	vsize := uint32(len(payload))

	off := f.SectionTableOff + f.NumberOfSections*SectionHeaderSize
	hdr := make([]byte, SectionHeaderSize)
	copy(hdr[0:8], name)
	binary.LittleEndian.PutUint32(hdr[8:], vsize)
	binary.LittleEndian.PutUint32(hdr[12:], rva)
	binary.LittleEndian.PutUint32(hdr[16:], rawSize)
	binary.LittleEndian.PutUint32(hdr[20:], rawOff)
	binary.LittleEndian.PutUint32(hdr[36:], char)
	copy(f.Data[off:off+SectionHeaderSize], hdr)

	sec := Section{
		Name:             name,
		VirtualSize:      vsize,
		VirtualAddress:   rva,
		SizeOfRawData:    rawSize,
		PointerToRawData: rawOff,
		Characteristics:  char,
		HeaderOffset:     off,
	}
	f.Sections = append(f.Sections, sec)
	f.NumberOfSections++

	binary.LittleEndian.PutUint16(f.Data[f.Lfanew+6:], uint16(f.NumberOfSections))
	f.SizeOfImage = rva + AlignUp(vsize, f.SectionAlignment)
	binary.LittleEndian.PutUint32(f.Data[f.OptHeaderOffset+56:], f.SizeOfImage)

	return &sec, nil
}

// RVAtoOffset 把 RVA 折算为文件偏移
func (f *File) RVAtoOffset(rva uint32) (int, error) {
	for _, s := range f.Sections {
		start := s.VirtualAddress
		end := s.VirtualAddress + s.SizeOfRawData
		if rva >= start && rva < end {
			off := int(s.PointerToRawData + (rva - start))
			if off >= len(f.Data) {
				return 0, fmt.Errorf("rva 0x%X maps beyond EOF", rva)
			}
			return off, nil
		}
	}
	return 0, fmt.Errorf("rva 0x%X not in any section", rva)
}

// Save 写回磁盘（保持可执行位）
func (f *File) Save(path string) error {
	return os.WriteFile(path, f.Data, 0o755)
}

// Summary 生成人类可读摘要
func (f *File) Summary() string {
	mach := "unknown"
	switch f.Machine {
	case MachineAMD64:
		mach = "x86-64"
	case MachineARM64:
		mach = "arm64"
	}
	out := fmt.Sprintf("PE32+ %s, sections=%d, SizeOfImage=0x%X, SectionAlign=0x%X, FileAlign=0x%X, entry=0x%X\n",
		mach, f.NumberOfSections, f.SizeOfImage, f.SectionAlignment, f.FileAlignment, f.AddressOfEntry)
	for _, s := range f.Sections {
		out += fmt.Sprintf("  %-8s VA=0x%-8X vsize=0x%-8X raw=0x%-8X off=0x%-8X flags=0x%08X\n",
			s.Name, s.VirtualAddress, s.VirtualSize, s.SizeOfRawData, s.PointerToRawData, s.Characteristics)
	}
	return out
}

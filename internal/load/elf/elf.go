// Package elf 提供最小可用的 ELF64 读写能力（Linux/amd64 目标）：
// 解析 ELF/程序头，并支持“把某个 PT_NOTE 改写成新的 PT_LOAD(RX)”的注入方式。
//
// 设计约束：
//   - 只支持 ELFCLASS64 + ELFDATA2LSB + EM_X86_64；
//   - 不改动任何已有段/节的数据与偏移（payload 追加到文件尾）；
//   - 新增段与已有段在虚拟地址上不重叠，且满足 p_offset ≡ p_vaddr (mod p_align)。
package elf

import (
	"encoding/binary"
	"fmt"
	"os"
)

const (
	EhdrSize = 64
	PhdrSize = 56
	ShdrSize = 64

	PT_NULL      = 0
	PT_LOAD      = 1
	PT_NOTE      = 4
	PT_PHDR      = 6
	PT_INTERP    = 3
	PT_GNU_RELRO = 0x6474e552
	ET_EXEC      = 2
	ET_DYN       = 3
	PF_X         = 1
	PF_W         = 2
	PF_R         = 4
	PageAlign    = 0x1000

	EM_X86_64  = 62
	EM_AARCH64 = 183
)

// Program 一个程序头
type Program struct {
	Type   uint32
	Flags  uint32
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
	index  int
}

// File 内存中的 ELF 镜像
type File struct {
	Data    []byte
	Entry   uint64
	Machine uint16 // e_machine（EM_X86_64=62 / EM_AARCH64=183）
	// EType 是 e_type（2=ET_EXEC，3=ET_DYN/PIE）
	EType uint16

	Phoff     uint64
	Phentsize uint16
	Phnum     uint16
	Shoff     uint64
	Shentsize uint16
	Shnum     uint16

	Progs []Program
}

func u16(b []byte, off int) uint16  { return binary.LittleEndian.Uint16(b[off:]) }
func u32(b []byte, off int) uint32  { return binary.LittleEndian.Uint32(b[off:]) }
func u64v(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }

// AlignUp 向上对齐（align 为 2 的幂）
func AlignUp(v, align uint64) uint64 {
	if align == 0 {
		return v
	}
	return (v + align - 1) &^ (align - 1)
}

// Parse 解析 ELF 头与程序头
func Parse(data []byte) (*File, error) {
	if len(data) < EhdrSize {
		return nil, fmt.Errorf("文件太小，不足以包含 ELF 头")
	}
	if data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return nil, fmt.Errorf("不是 ELF 文件")
	}
	if data[4] != 2 {
		return nil, fmt.Errorf("只支持 ELFCLASS64（class=%d）", data[4])
	}
	if data[5] != 1 {
		return nil, fmt.Errorf("只支持小端 ELF（data=%d）", data[5])
	}
	f := &File{Data: data, Machine: u16(data, 18)}
	// x86-64 与 AArch64 都接受：AArch64 的载荷侧（BL thunk + 8 字节入口补丁）早有实现与单测，
	// 之前只是打包器一直只挑 x86-64 lifter，所以在 CI 上表现为"只支持 EM_X86_64"。
	mach := u16(data, 18)
	if mach != EM_X86_64 && mach != EM_AARCH64 {
		return nil, fmt.Errorf("目前只支持 EM_X86_64 / EM_AARCH64，该文件 machine=%d", mach)
	}
	// ET_EXEC(2) 与 ET_DYN(3, PIE/共享库) 都接受：
	// payload 段、thunk(E8 rel32)、描述符 selfRVA 全都是**相对**的，
	// 入口 stub 又用 "描述符地址 - selfRVA" 反推运行期基址，
	// 因此内核/加载器把镜像搬到哪都不会影响正确性。
	switch t := u16(data, 16); t {
	case ET_EXEC, ET_DYN:
	default:
		return nil, fmt.Errorf("只支持 ET_EXEC / ET_DYN(PIE)，该文件 e_type=%d", t)
	}
	f.EType = u16(data, 16)
	f.Entry = u64v(data, 24)
	f.Phoff = u64v(data, 32)
	f.Shoff = u64v(data, 40)
	f.Phentsize = u16(data, 54)
	f.Phnum = u16(data, 56)
	f.Shentsize = u16(data, 58)
	f.Shnum = u16(data, 60)
	if f.Phentsize != PhdrSize {
		return nil, fmt.Errorf("非预期的 e_phentsize=%d", f.Phentsize)
	}
	for i := 0; i < int(f.Phnum); i++ {
		off := int(f.Phoff) + i*PhdrSize
		if off+PhdrSize > len(data) {
			return nil, fmt.Errorf("程序头 %d 越界", i)
		}
		f.Progs = append(f.Progs, Program{
			Type:   u32(data, off),
			Flags:  u32(data, off+4),
			Off:    u64v(data, off+8),
			Vaddr:  u64v(data, off+16),
			Paddr:  u64v(data, off+24),
			Filesz: u64v(data, off+32),
			Memsz:  u64v(data, off+40),
			Align:  u64v(data, off+48),
			index:  i,
		})
	}
	return f, nil
}

// Open 从磁盘读取
func Open(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// ImageBase 最小 PT_LOAD 的 vaddr 向下按页对齐
func (f *File) ImageBase() uint64 {
	base := ^uint64(0)
	for _, p := range f.Progs {
		if p.Type == PT_LOAD && p.Vaddr < base {
			base = p.Vaddr
		}
	}
	if base == ^uint64(0) {
		return 0
	}
	return base &^ (PageAlign - 1)
}

// NextVA 所有段结束之后的第一个页对齐地址
func (f *File) NextVA() uint64 {
	end := uint64(0)
	for _, p := range f.Progs {
		if p.Type == PT_LOAD && p.Vaddr+p.Memsz > end {
			end = p.Vaddr + p.Memsz
		}
	}
	return AlignUp(end, PageAlign)
}

// VAtoOffset 把虚拟地址折算为文件偏移（按 PT_LOAD 映射）
func (f *File) VAtoOffset(va uint64) (int, error) {
	for _, p := range f.Progs {
		if p.Type != PT_LOAD {
			continue
		}
		if va >= p.Vaddr && va < p.Vaddr+p.Filesz {
			off := p.Off + (va - p.Vaddr)
			if int(off) >= len(f.Data) {
				return 0, fmt.Errorf("VA 0x%X 映射到文件之外", va)
			}
			return int(off), nil
		}
	}
	return 0, fmt.Errorf("VA 0x%X 不在任何 PT_LOAD 中", va)
}

// ReadVA 按虚拟地址读取
func (f *File) ReadVA(va uint64, n int) ([]byte, error) {
	off, err := f.VAtoOffset(va)
	if err != nil {
		return nil, err
	}
	if off+n > len(f.Data) {
		return nil, fmt.Errorf("VA 0x%X 读取 %d 字节越界", va, n)
	}
	out := make([]byte, n)
	copy(out, f.Data[off:off+n])
	return out, nil
}

// WriteVA 按虚拟地址写入（原地补丁）
func (f *File) WriteVA(va uint64, b []byte) error {
	off, err := f.VAtoOffset(va)
	if err != nil {
		return err
	}
	if off+len(b) > len(f.Data) {
		return fmt.Errorf("VA 0x%X 写入越界", va)
	}
	copy(f.Data[off:], b)
	return nil
}

// sparePhdrSlot 找一个可以改写成 PT_LOAD 的空槽位。
//
// 优先级：PT_NOTE（对内核无意义）→ PT_PHDR（仅当是**静态 ET_EXEC**时）。
// PT_PHDR 被复用会丢掉"程序头表位置"这条信息：内核自己从 e_phoff 取（不受影响），
// 而 ld.so 只在动态/静态-PIE 时依赖它——所以只有"没有 PT_INTERP 且 e_type==ET_EXEC"
// 时才允许复用，其它情况宁可不做分段（调用方退回整体 RWX）。
func (f *File) sparePhdrSlot() int {
	for i, p := range f.Progs {
		if p.Type == PT_NOTE {
			return i
		}
	}
	// 再退一步：PT_GNU_RELRO —— 只有 ld.so 用它把 .data.rel.ro 设成只读，
	// 复用它会**削弱 RELRO 加固**但不会影响正确性，所以带告警地允许。
	for i, p := range f.Progs {
		if p.Type == PT_GNU_RELRO {
			return i
		}
	}
	if !f.canDropPHDR() {
		return -1
	}
	for i, p := range f.Progs {
		if p.Type == PT_PHDR {
			return i
		}
	}
	for i, p := range f.Progs {
		if p.Type == PT_NULL {
			return i
		}
	}
	return -1
}

// canDropPHDR：没有 PT_INTERP（静态链接，含静态 PIE）。
// 有 PT_INTERP 时 ld.so 会用 AT_PHDR/PT_PHDR，所以动态链接的镜像不丢它。
func (f *File) canDropPHDR() bool {
	for _, p := range f.Progs {
		if p.Type == PT_INTERP {
			return false
		}
	}
	return true
}

// AddLoadSegmentFromNote 把第一个 PT_NOTE 改写为指向 payload 的 PT_LOAD(R+X)，
// payload 追加到文件尾（页对齐）。返回新段的虚拟地址与**文件偏移**。
//
// 这里只给 R+X：blob 里 .bss（解释器的明文解密缓存）需要的**写**权限由调用方
// 用 AddOverlayLoadSegment 覆盖成单独的 RW 段——这样代码页不会变成可写（去掉 RWX）。
func (f *File) AddLoadSegmentFromNote(payload []byte) (uint64, int64, error) {
	noteIdx := f.sparePhdrSlot()
	if noteIdx < 0 {
		return 0, 0, fmt.Errorf("没有可复用的 PT_NOTE 段")
	}

	// 追加 payload（页对齐）
	fileOff := AlignUp(uint64(len(f.Data)), PageAlign)
	for uint64(len(f.Data)) < fileOff {
		f.Data = append(f.Data, 0)
	}
	f.Data = append(f.Data, payload...)

	va := f.NextVA()
	p := Program{
		Type:   PT_LOAD,
		Flags:  PF_R | PF_X,
		Off:    fileOff,
		Vaddr:  va,
		Paddr:  va,
		Filesz: uint64(len(payload)),
		Memsz:  uint64(len(payload)),
		Align:  PageAlign,
	}
	f.Progs[noteIdx] = p
	off := int(f.Phoff) + noteIdx*PhdrSize
	writePhdr(f.Data, off, p)
	return va, int64(fileOff), nil
}

// SetLoadSegmentFlags 改一个已存在 PT_LOAD 的权限（用于"分段不可行时退回整体 RWX"）
func (f *File) SetLoadSegmentFlags(va uint64, flags uint32) bool {
	for i, p := range f.Progs {
		if p.Type == PT_LOAD && p.Vaddr == va {
			p.Flags = flags
			f.Progs[i] = p
			writePhdr(f.Data, int(f.Phoff)+i*PhdrSize, p)
			return true
		}
	}
	return false
}

// AddOverlayLoadSegment 追加一个**指向已存在文件字节**的 PT_LOAD（不新增文件内容），
// 用来把 payload 中某一段"覆盖"成不同权限（例如把 .bss 那一截单独标成 RW）。
//
// 前提：off 与 va 满足 ELF 要求的同余关系（off ≡ va (mod align)），且调用方保证
// 区间按页对齐——blob 构建时已经把 .bss 的起止都对齐到 0x1000，所以这里成立。
func (f *File) AddOverlayLoadSegment(va uint64, fileOff int64, size uint64, flags uint32) error {
	if size == 0 {
		return nil
	}
	if (va % PageAlign) != (uint64(fileOff) % PageAlign) {
		return fmt.Errorf("覆盖段的 vaddr(0x%X) 与文件偏移(0x%X) 不同余", va, fileOff)
	}
	slot := f.sparePhdrSlot()
	if slot < 0 {
		return fmt.Errorf("没有可复用的 PT_NOTE 段（覆盖段需要第二个槽位）")
	}
	p := Program{
		Type:   PT_LOAD,
		Flags:  flags,
		Off:    uint64(fileOff),
		Vaddr:  va,
		Paddr:  va,
		Filesz: size,
		Memsz:  size,
		Align:  PageAlign,
	}
	f.Progs[slot] = p
	writePhdr(f.Data, int(f.Phoff)+slot*PhdrSize, p)
	return nil
}

// SwapPhdrs 交换程序头表里的两项。
// 为什么需要它：内核按**表顺序**依次 mmap 各个 PT_LOAD，重叠区间上**后面的映射覆盖前面的**。
// 覆盖段（RW，给 .bss）必须排在 payload 段（RX）**之后**，否则 RX 会把 RW 覆盖掉，
// 于是解释器写解密缓存就 SIGSEGV（SEGV_ACCERR，Linux 上实测如此；PE 侧按节合并且写标志生效，
// 所以这个顺序问题只在 ELF 上现形）。
func (f *File) SwapPhdrs(i, j int) {
	if i == j || i < 0 || j < 0 || i >= len(f.Progs) || j >= len(f.Progs) {
		return
	}
	f.Progs[i], f.Progs[j] = f.Progs[j], f.Progs[i]
	writePhdr(f.Data, int(f.Phoff)+i*PhdrSize, f.Progs[i])
	writePhdr(f.Data, int(f.Phoff)+j*PhdrSize, f.Progs[j])
}

func writePhdr(data []byte, off int, p Program) {
	binary.LittleEndian.PutUint32(data[off:], p.Type)
	binary.LittleEndian.PutUint32(data[off+4:], p.Flags)
	binary.LittleEndian.PutUint64(data[off+8:], p.Off)
	binary.LittleEndian.PutUint64(data[off+16:], p.Vaddr)
	binary.LittleEndian.PutUint64(data[off+24:], p.Paddr)
	binary.LittleEndian.PutUint64(data[off+32:], p.Filesz)
	binary.LittleEndian.PutUint64(data[off+40:], p.Memsz)
	binary.LittleEndian.PutUint64(data[off+48:], p.Align)
}

// Save 写回磁盘
// SetEntry 改写 ELF64 头里的 e_entry（偏移 24）：入口挂钩用它把控制权先交给"校验蹦床"。
func (f *File) SetEntry(v uint64) error {
	if len(f.Data) < 32 {
		return fmt.Errorf("ELF 头过短")
	}
	binary.LittleEndian.PutUint64(f.Data[24:], v)
	f.Entry = v
	return nil
}

func (f *File) Save(path string) error {
	return os.WriteFile(path, f.Data, 0o755)
}

// Summary 可读摘要
func (f *File) Summary() string {
	arch := "x86-64"
	if f.Machine == EM_AARCH64 {
		arch = "arm64"
	}
	s := fmt.Sprintf("ELF64 %s exec, entry=0x%X, imageBase=0x%X, phnum=%d",
		arch, f.Entry, f.ImageBase(), len(f.Progs))
	for i, p := range f.Progs {
		name := "?"
		switch p.Type {
		case PT_LOAD:
			name = "LOAD"
		case PT_NOTE:
			name = "NOTE"
		case PT_PHDR:
			name = "PHDR"
		case 0x6474e551:
			name = "GNU_STACK"
		}
		s += fmt.Sprintf(" | PH[%d] %s off=0x%X va=0x%X filesz=0x%X memsz=0x%X",
			i, name, p.Off, p.Vaddr, p.Filesz, p.Memsz)
	}
	return s
}

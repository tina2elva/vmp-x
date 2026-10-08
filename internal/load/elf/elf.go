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
	PT_DYNAMIC   = 2
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

	// 动态表（PT_DYNAMIC）里本包用到的 d_tag。
	DT_NULL    = 0
	DT_RELA    = 7
	DT_RELASZ  = 8
	DT_RELAENT = 9
	DT_REL     = 17
	DT_RELSZ   = 18
	DT_RELENT  = 19
	// PLT/IFUNC 重定位表（.rela.plt）：长度与语义分别由 DT_PLTRELSZ / DT_PLTREL 给出。
	DT_PLTRELSZ = 2
	DT_PLTREL   = 20
	DT_JMPREL   = 23
	// 压缩相对重定位表（.relr.dyn）：条目本身不写类型，隐含为 R_*_RELATIVE。
	DT_RELRSZ  = 35
	DT_RELR    = 36
	DT_RELRENT = 37

	// 相对重定位的类型号（本仓库支持的两种架构）。两者语义相同：
	// 运行期槽位值 = 装载基址 + r_addend，所以运行期一套「先减 delta → 验签 → 解密 → 再加回 delta」
	// 对两种架构都够用（见 internal/inject 的重定位应用表）。
	R_X86_64_RELATIVE  = 8
	R_AARCH64_RELATIVE = 1027

	// Elf64_Rela = 24 字节（offset/info/addend）；Elf64_Rel = 16 字节（offset/info）。
	RelaEntrySize = 24
	RelEntrySize  = 16
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
// 优先级：PT_NOTE（对内核无意义）→ PT_GNU_RELRO（只削弱 RELRO 加固）→ PT_PHDR / PT_NULL
// （仅当没有 PT_INTERP 时；有 PT_INTERP 的动态镜像里 ld.so 会用到它）。
//
// 复用的**代价**只是"这一段语义丢了"（NOTE 对内核无意义、RELRO 只是加固、PHDR 的位置内核从
// e_phoff 取），所以调用方可以放心用它来放相邻的载荷段。槽位不够时**不是**退回老的重叠形状，
// 而是按 inject 侧的三档梯子降级（② 窗口+尾部合一成一段 W+X / ③ 整段 W+X），见 SparePhdrSlots。
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

// AddLoadSegmentFromNote 把第一个可复用槽位改写为指向 payload 的 PT_LOAD(R+X)，
// payload 追加到文件尾（页对齐）。返回新段的虚拟地址与**文件偏移**。
//
// 这里只给 R+X：blob 里 .bss（解释器的明文解密缓存）需要的**写**权限由调用方再加一个
// **相邻**（不是重叠）的段来给，见 AddOverlayLoadSegment —— 这样代码页不会变成可写（去掉 RWX）。
// 也就是 M5 的首选几何：RX 前缀 [0,bssOff) + RW 窗口 [bssOff,+bssSize) +（有尾部时）R+X 尾部。
func (f *File) AddLoadSegmentFromNote(payload []byte) (uint64, int64, error) {
	return f.AddLoadSegmentFromNoteSized(payload, len(payload))
}

// AddLoadSegmentFromNoteSized 与 AddLoadSegmentFromNote 同义，但段只**映射** payload 的
// 前 mapLen 字节（filesz = memsz = mapLen），文件的其余字节留给调用方用
// AddOverlayLoadSegment 按别的权限映射。
//
// 为什么需要它（M5，STATUS #597）：载荷几何必须让"可写窗口"**不在载荷 RX 段的
// vaddr 范围之内**。glibc 只在 DT_TEXTREL 路径按 PT_LOAD 重设保护，载荷 RX 段一旦
// 页对齐后盖住窗口所在的页，解释器第一次写自己的解密缓存就 SIGSEGV（实测）。
// 于是调用方把 [0, bssOff) 映射成 RX、[bssOff, …) 另起一段 —— 前者就靠这里的 mapLen。
//
// **整个 payload 都会被追加到文件尾**（不是只有前 mapLen 字节）：后面那几段的
// p_offset 指向的正是这份字节。只追加前缀会造成 p_offset 越过 EOF，内核 mmap 之后
// 一碰那一页就 SIGBUS（实测：textrel 夹具 rc=135，gdb 报 SIGBUS 在尾部页上）——
// 也就是说"未映射的字节"必须在**文件里真的存在**，只是没有被这个段映射。
func (f *File) AddLoadSegmentFromNoteSized(payload []byte, mapLen int) (uint64, int64, error) {
	slot := f.sparePhdrSlot()
	if slot < 0 {
		return 0, 0, fmt.Errorf("没有可复用的 PT_NOTE 段")
	}
	if mapLen < 0 || mapLen > len(payload) {
		return 0, 0, fmt.Errorf("mapLen=%d 超出 payload 长度 %d", mapLen, len(payload))
	}

	// 追加整个 payload（页对齐）；段只映射前 mapLen 字节。
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
		Filesz: uint64(mapLen),
		Memsz:  uint64(mapLen),
		Align:  PageAlign,
	}
	f.Progs[slot] = p
	off := int(f.Phoff) + slot*PhdrSize
	writePhdr(f.Data, off, p)
	return va, int64(fileOff), nil
}

// SparePhdrSlots 返回**还能**改写成新段的槽位数（判据与 sparePhdrSlot 完全一致）。
//
// 调用方必须先问这个数再决定"能不能分段"：三段相邻需要 3 个槽（RX 前缀 + RW 窗口 + R+X 尾部；
// 载荷在窗口之后没有字节时只要 2 个）。**槽位不够时按 ②窗口+尾部合一 / ③整段 的梯子降级**，
// 绝不回到重叠形状：② = 前缀仍只读、窗口与尾部合成一段 W+X；③ = 整段 W+X。②③ 都是"那一整段
// 可写"，所以对 glibc 的 TEXTREL 保护重设同样免疫（M5 的成因是"非可写段盖住窗口"，不是可写本身）。
//
// 关键：必须**按 sparePhdrSlot 的优先级顺序**模拟消耗，不能简单地对 PR_NOTE / PT_NULL /
// PT_PHDR 各数一遍。实测过的反例：aarch64 夹具（1 个 PT_NOTE + 若干被改成 PT_NULL 的 NOTE）
// 里 PT_NULL 排在 PT_NOTE **后面** —— 前置 PT_NULL 被用掉后，sparePhdrSlot 的 PT_NOTE 分支
// 不再匹配，PT_NULL 分支只找到**已消耗**的那些索引 ⇒ 第二个段"没有可复用槽位"。
// 于是分包前数出 2 个、真去分段时第二个却失败（打出来的告警还会说"需要 2 个"）。
func (f *File) SparePhdrSlots() int {
	used := make([]bool, len(f.Progs))
	n := 0
	// 每一趟都精准复刻 sparePhdrSlot 的对应分支：**类型优先 + 取最低空闲索引**。
	// 只要少模拟一处"连续调用"的语义，计数就会比真实可用槽位多（实测过两次：
	// ① aarch64 夹具里 PT_NULL 排在 PT_NOTE 后面；② PT_NULL 排在 PT_NOTE **前面**），
	// 后果都是"先数出够用、真去分段时第二个段报没有可复用槽位"。
	// takeLowest：把该类型中**索引最小**的空闲槽位记下来（sparePhdrSlot 就是从前往后找的）。
	// 不能拿 p_vaddr 当"先后"（PT_NULL/PT_PHDR 的 p_vaddr 通常是 0，会 tie，选错槽位 —— 实测踩过）。
	takeLowest := func(want func(Program) bool) bool {
		idx := -1
		for i, p := range f.Progs {
			if used[i] || !want(p) {
				continue
			}
			idx = i
			break
		}
		if idx < 0 {
			return false
		}
		used[idx] = true
		n++
		return true
	}
	drain := func(want func(Program) bool) {
		for takeLowest(want) {
		}
	}
	drain(func(p Program) bool { return p.Type == PT_NOTE })
	drain(func(p Program) bool { return p.Type == PT_GNU_RELRO })
	if f.canDropPHDR() {
		// 这一对必须**同趟**取最低空闲索引：若先扫 PT_PHDR，最低空闲的 PT_NULL 会被当成 PHDR
		// 用掉，下一趟再找不到它，于是把一个排在前面的 PT_NULL 后面的 PT_NOTE 误判成"不可达"。
		drain(func(p Program) bool { return p.Type == PT_PHDR || p.Type == PT_NULL })
	}
	return n
}

// MakeBssFileBacked 把每个 "memsz > filesz" 的 PT_LOAD 改成**整段文件承载**
// （filesz = memsz，原来的 .bss 那一截以 0 写进文件），并把该段的文件数据整体搬到文件尾。
//
// 为什么必须做（在本仓库实测出来的真 bug）：
// Linux 内核对 bss 的映射是**一次性的全局区间**
//
//	set_brk(PAGEALIGN(max(p_vaddr+p_filesz)), PAGEALIGN(max(p_vaddr+p_memsz)))
//
// （fs/binfmt_elf.c 的老逻辑；WSL 的内核 6.6 实测如此），**不是**"每个 PT_LOAD 各映射自己的 bss"。
// 一旦我们在某个 LOAD 的**上方**再加段（注入载荷必然如此），那个 LOAD 的
// [p_vaddr+p_filesz, p_vaddr+p_memsz) 就再也不会被映射 —— 程序第一次写全局变量就 SIGSEGV：
// 内核记录 "segfault at <bss 地址> ip ... error 6"（error 6 = 页不存在 + 写 + 用户态），
// 实测崩在 Go 的 runtime.rt0_go 写 runtime.g0（0x5851e0，而 rw-p 映射只到 0x585000）。
// 把 bss 变成文件承载后由 elf_map 直接映射，与"bss/brk 的全局区间"那套逻辑彻底解耦。
//
// 代价与副作用（如实登记）：
//   - 文件变大：多出 (memsz-filesz) 个 0 字节，以及该段原有数据的**一份副本**（旧副本留在原地当死数据，
//     因为"把 0 插到文件中间"会让后面所有节的 sh_offset 失准）；
//   - 只有 PT_LOAD 被改写，节头表原样不动（旧副本仍可被 readelf 按节读到，不会指向垃圾）；
//   - 该段通常只含 .data/.got/.bss，**不含函数体**，所以不会让 -wipe 的"原生机器码残留"回归。
//
// 返回被处理的段数。
func (f *File) MakeBssFileBacked() int {
	n := 0
	for i := range f.Progs {
		p := f.Progs[i]
		if p.Type != PT_LOAD || p.Memsz <= p.Filesz {
			continue
		}
		if p.Off+p.Filesz > uint64(len(f.Data)) {
			continue // 文件里没有这段数据（不该发生）：跳过而不是越界
		}
		body := make([]byte, p.Filesz)
		copy(body, f.Data[p.Off:p.Off+p.Filesz])

		al := uint64(PageAlign)
		if p.Align > al {
			al = p.Align
		}
		newOff := AlignUp(uint64(len(f.Data)), al)
		// ELF 要求 p_offset ≡ p_vaddr (mod p_align)；不满足就往后挪到同余的位置。
		if newOff%al != p.Vaddr%al {
			newOff += (p.Vaddr%al - newOff%al + al) % al
		}
		for uint64(len(f.Data)) < newOff {
			f.Data = append(f.Data, 0)
		}
		f.Data = append(f.Data, body...)
		f.Data = append(f.Data, make([]byte, p.Memsz-p.Filesz)...)

		p.Off = newOff
		p.Filesz = p.Memsz
		f.Progs[i] = p
		writePhdr(f.Data, int(f.Phoff)+i*PhdrSize, p)
		n++
	}
	return n
}

// unmappedBss 返回"内核不会映射其 bss"的 PT_LOAD。
//
// 内核把 bss 当成**一个全局区间**：
//
//	set_brk(PAGEALIGN(max(vaddr+filesz)), PAGEALIGN(max(vaddr+memsz)))
//
// 所以一个 memsz>filesz 的段，只有当它的 PAGEALIGN(vaddr+filesz) **就是所有段的那个最大值**时，
// 它的 bss 才会落在这个区间里；否则 bss 整段没有映射 —— 程序第一次写全局变量就 SIGSEGV
// （内核 "segfault at <bss> ... error 6"＝页不存在 + 写）。
//
// 这是 MakeBssFileBacked 的判据，也是回归测试的校准点：探针必须能在"未修"时报出来。
func (f *File) unmappedBss() []Program {
	var top uint64
	for _, p := range f.Progs {
		if p.Type != PT_LOAD {
			continue
		}
		if e := AlignUp(p.Vaddr+p.Filesz, PageAlign); e > top {
			top = e
		}
	}
	var bad []Program
	for _, p := range f.Progs {
		if p.Type != PT_LOAD || p.Memsz <= p.Filesz {
			continue
		}
		if AlignUp(p.Vaddr+p.Filesz, PageAlign) < top {
			bad = append(bad, p)
		}
	}
	return bad
}

// SetLoadSegmentFlags 改一个已存在 PT_LOAD 的权限（梯子 ③ 用：整段 W+X；整段可写 ⇒ 对
// glibc 的 TEXTREL 保护重设同样免疫，且不产生任何重叠段）。
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

// ---- 动态重定位（ET_DYN/PIE 的镜像整体加密要用） ----
//
// 为什么走 PT_DYNAMIC 而不是节头表：打包端会搬动文件里的段
// （MakeBssFileBacked 把带 .bss 的段整段挪到文件尾、只改程序头不改 sh_offset），
// 一旦 .rela.* 落在那样的段里，节头表读出来的就是**死副本**。而加载器（ld.so）与运行期
// 应用器都只按 PT_DYNAMIC 看，所以这里必须用同一份信息。

// DynEntry 一条动态表项（d_tag / d_val）
type DynEntry struct {
	Tag uint64
	Val uint64
}

// Reloc 一条动态重定位。
//
// Offset 是 **r_offset（链接期 VA，不是 RVA）**：PIE 里它等于"首选基址 + 偏移"，
// 而 r_addend/槽位值也都是链接期 VA（实测 Go 的 -buildmode=pie 产物 7175/7175 条如此）。
// 运行期槽位值 = 装载基址 + Addend ⇒ delta = 装载基址 = 运行期基址 − 首选基址。
type Reloc struct {
	Offset uint64 // r_offset：链接期 VA
	Type   uint32 // r_info 的低 32 位（ELF64：sym<<32 | type）
	Sym    uint32 // r_info 的高 32 位
	Addend int64  // r_addend（只有 RELA 语义的表有这项；隐式 addend 的表按 0 处理，见 ImplicitAddend）
	// ImplicitAddend 表示"这张表不写 r_addend，加数就在槽位里"（DT_REL 语义、以及 DT_RELR）。
	//
	// 为什么要区分（#597 复评 R3）：打包端的 NormalizeRelocSlots 是拿 r.Addend **重写槽位**的，
	// 对隐式 addend 的条目来说 Addend 恒为 0 ⇒ 会把真实槽位**清零**（评审在真实 RELR 二进制上
	// 实测 changed=63 ⇒ 直接把镜像改坏）。所以这类条目一律不进重定位应用表、也绝不走
	// NormalizeRelocSlots；一旦落在加密范围里就拒绝打包（见 cmd/vmpack 的守卫 2 与 HasRELR）。
	ImplicitAddend bool
}

// DynamicEntries 读 PT_DYNAMIC（没有这个段就返回 nil，不报错）。
func (f *File) DynamicEntries() ([]DynEntry, error) {
	var out []DynEntry
	for _, p := range f.Progs {
		if p.Type != PT_DYNAMIC {
			continue
		}
		if p.Filesz == 0 || p.Off+p.Filesz > uint64(len(f.Data)) {
			return nil, fmt.Errorf("PT_DYNAMIC 越界（off=0x%X filesz=0x%X）", p.Off, p.Filesz)
		}
		for o := p.Off; o+16 <= p.Off+p.Filesz; o += 16 {
			tag := binary.LittleEndian.Uint64(f.Data[o:])
			val := binary.LittleEndian.Uint64(f.Data[o+8:])
			if tag == DT_NULL {
				return out, nil
			}
			out = append(out, DynEntry{Tag: tag, Val: val})
		}
		return out, nil
	}
	return nil, nil
}

// DynRelocs 读**三张**动态重定位表，合并成一个按"表顺序"排列的切片：
//
//	① DT_RELA/DT_RELASZ/DT_RELAENT（x86-64/aarch64 的主表，.rela.dyn），或 REL 语义的 DT_REL/…
//	② DT_JMPREL/DT_PLTRELSZ/DT_PLTREL（.rela.plt：JUMP_SLOT 与 **IRELATIVE**）
//	③ DT_RELR/DT_RELRSZ/DT_RELRENT（压缩相对重定位，.relr.dyn：条目不写类型，按架构隐含 RELATIVE）
//
// 为什么要读全三张（#597 复评 F4）：打包端守卫 2 的判据是"加密范围内的动重定位必须可还原"，
// 而 ld.so 在**入口点之前**会把这三张表都应用一遍。少读一张，那条守卫对**那一类**槽位就是空的 ——
// 尤其 DT_JMPREL 里的 R_*_IRELATIVE，它的 r_offset 指向的正是可执行段里的 PLT 桩（加密范围）。
//
// 表本身用 **VA** 寻址，走 VAtoOffset（也就是按程序头映射），因此对打包端搬动过的产物仍有效。
// 读不出来（越界/条目尺寸/语义不对）时返回错误，调用方必须 fail-closed —— 静默当成"没有重定位"
// 会让加密范围里那些真存在的重定位在运行期被解出垃圾。
func (f *File) DynRelocs() ([]Reloc, error) {
	ents, err := f.DynamicEntries()
	if err != nil {
		return nil, err
	}
	if len(ents) == 0 {
		return nil, nil
	}
	// 三张表都要读，缺一张就会让调用方（打包端守卫 2）对**那一类**槽位空转：
	//   ① DT_RELA/DT_REL      —— 主表（.rela.dyn）
	//   ② DT_JMPREL           —— PLT/IFUNC 表（.rela.plt）：JUMP_SLOT 落在可写段不算危险，
	//      但 **IRELATIVE** 的 r_offset 指向的正是可执行段里的 PLT 桩，也就是加密范围
	//   ③ DT_RELR             —— 压缩相对重定位（.relr.dyn）：槽位类型不写在条目里，按架构隐含
	// 这三张表都会在**入口点之前**被 ld.so 改写，所以它们的目标落在加密范围里就必须能被
	// 运行期应用器还原（否则密文的 AEAD tag 已经变了）。详见 cmd/vmpack 的守卫 2。
	type table struct{ addr, size, ent uint64 }
	var tbl, tblRel, tblJmp table
	var pltRel uint64
	for _, e := range ents {
		switch e.Tag {
		case DT_RELA:
			tbl.addr = e.Val
		case DT_RELASZ:
			tbl.size = e.Val
		case DT_RELAENT:
			tbl.ent = e.Val
		case DT_REL:
			tblRel.addr = e.Val
		case DT_RELSZ:
			tblRel.size = e.Val
		case DT_RELENT:
			tblRel.ent = e.Val
		case DT_JMPREL:
			tblJmp.addr = e.Val
		case DT_PLTRELSZ:
			tblJmp.size = e.Val
		case DT_PLTREL:
			pltRel = e.Val
		}
		// DT_RELR（压缩相对重定位）**故意不在这里解析**：它是隐式 addend 表，本包的运行期应用器
		// （stub 的 vm_reloc_fix）只读 DT_RELA/DT_REL，根本没有 RELR 还原路径 ⇒ 解出来的条目
		// 也"不可还原"。打包端因此改为"目标带 DT_RELR 且要加密任何范围就拒绝打包"
		// （见 HasRELR 与 cmd/vmpack 的守卫 2），不依赖任何解码器。
	}
	var out []Reloc
	// DT_RELA 优先（x86-64/aarch64 都是 RELA）；没有再退回 DT_REL。
	if tbl.size != 0 || tblRel.size != 0 {
		withAddend := tbl.size != 0
		t := tbl
		if !withAddend {
			t = tblRel
		}
		if t.addr == 0 {
			return nil, fmt.Errorf("动态表声明了重定位（size=0x%X）但没有地址", t.size)
		}
		entSize := t.ent
		if entSize == 0 {
			if withAddend {
				entSize = RelaEntrySize
			} else {
				entSize = RelEntrySize
			}
		}
		if withAddend && entSize != RelaEntrySize {
			return nil, fmt.Errorf("DT_RELAENT=%d，本包只支持 %d", entSize, RelaEntrySize)
		}
		if !withAddend && entSize != RelEntrySize {
			return nil, fmt.Errorf("DT_RELENT=%d，本包只支持 %d", entSize, RelEntrySize)
		}
		rs, rerr := f.readRelTable(t.addr, t.size, entSize, withAddend)
		if rerr != nil {
			return nil, rerr
		}
		out = append(out, rs...)
	}
	if tblJmp.size != 0 {
		if tblJmp.addr == 0 {
			return nil, fmt.Errorf("DT_JMPREL 声明了 size=0x%X 但没有地址", tblJmp.size)
		}
		withAddend := false
		switch pltRel {
		case DT_RELA:
			withAddend = true
		case DT_REL:
			withAddend = false
		case 0:
			// 没有 DT_PLTREL：x86-64 与 aarch64 都是 RELA 语义（并按下面的条目尺寸校验兜底）
			withAddend = true
		default:
			return nil, fmt.Errorf("DT_PLTREL=%d 既不是 DT_REL(%d) 也不是 DT_RELA(%d)", pltRel, DT_REL, DT_RELA)
		}
		entSize := uint64(RelEntrySize)
		if withAddend {
			entSize = RelaEntrySize
		}
		rs, rerr := f.readRelTable(tblJmp.addr, tblJmp.size, entSize, withAddend)
		if rerr != nil {
			return nil, fmt.Errorf("DT_JMPREL 表：%w", rerr)
		}
		out = append(out, rs...)
	}
	return out, nil
}

// HasRELR 报告目标是否带 DT_RELR（压缩相对重定位 / RELR）。
//
// 为什么打包端需要它（#597 复评 R1/R2）：DT_RELR 的条目没有 r_addend —— 加数在槽位里，
// 而**运行期应用器只读 DT_RELA/DT_REL**（stub/win/x64/vm_interp.c 里的 vm_reloc_fix 只按
// DT_RELA/DT_RELASZ 找表），根本没有 RELR 还原路径。于是"记进应用表 ⇒ 运行期可还原"这条
// 推理对 RELR **不成立**，放行它等于产出一个运行期必然硬门的坏产物。
//
// 所以本包**不做 RELR 解码**（解码器曾经写错过三处：bitmap 之后缺 base += 63*8、首个 bitmap 的
// base 应是 addr+8、裸地址条目本身也是一条重定位；评审用真实产物对照 readelf：readelf 解出 203 条，
// 当时的解码器只给 202 条、去重 68 条、139 条重复、>= 0x5970 的条目全丢）。打包端改为
// "带 DT_RELR 且要加密任何范围 ⇒ 直接拒绝打包"，不依赖解码正确性。RELR 支持登记为后续项。
func (f *File) HasRELR() (bool, error) {
	ents, err := f.DynamicEntries()
	if err != nil {
		return false, err
	}
	for _, e := range ents {
		switch e.Tag {
		case DT_RELR:
			if e.Val != 0 {
				return true, nil
			}
		case DT_RELRSZ:
			if e.Val != 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// readRelTable 读一张由 (VA, size, 条目尺寸) 描述的动态重定位表。
// withAddend 表示 RELA 语义（条目 24 字节，带 r_addend）；否则 REL 语义（16 字节）。
func (f *File) readRelTable(addr, size, entSize uint64, withAddend bool) ([]Reloc, error) {
	if entSize == 0 {
		return nil, fmt.Errorf("重定位表 0x%X 的条目尺寸为 0", addr)
	}
	off, err := f.VAtoOffset(addr)
	if err != nil {
		return nil, fmt.Errorf("重定位表 VA 0x%X：%w", addr, err)
	}
	if uint64(off)+size > uint64(len(f.Data)) {
		return nil, fmt.Errorf("重定位表 0x%X+0x%X 超出文件", off, size)
	}
	n := int(size / entSize)
	out := make([]Reloc, 0, n)
	for i := 0; i < n; i++ {
		o := off + i*int(entSize)
		info := binary.LittleEndian.Uint64(f.Data[o+8:])
		r := Reloc{
			Offset:         binary.LittleEndian.Uint64(f.Data[o:]),
			Type:           uint32(info),
			Sym:            uint32(info >> 32),
			ImplicitAddend: !withAddend,
		}
		if withAddend {
			r.Addend = int64(binary.LittleEndian.Uint64(f.Data[o+16:]))
		}
		out = append(out, r)
	}
	return out, nil
}

// relativeRelocType 返回本架构的相对重定位类型号（不认识的架构报错，绝不猜）。
func relativeRelocType(machine uint16) (uint32, error) {
	switch machine {
	case EM_X86_64:
		return R_X86_64_RELATIVE, nil
	case EM_AARCH64:
		return R_AARCH64_RELATIVE, nil
	default:
		return 0, fmt.Errorf("架构 %d 没有登记相对重定位类型号", machine)
	}
}

// RelativeRelocs 只返回本架构的 R_*_RELATIVE 项（其它类型丢弃）。
// ET_EXEC/静态链接的目标返回空切片 —— 它们没有动态重定位。类型号不认识的架构返回错误。
//
// **隐式 addend 的条目（DT_REL 语义）一律不返回**（#597 复评 R3）：调用方拿这些条目去跑
// NormalizeRelocSlots 会把槽位清零（Addend 恒为 0）。落在加密范围里的这类条目由打包端
// 守卫 2 直接拒绝打包，不会走到这里。
func (f *File) RelativeRelocs() ([]Reloc, error) {
	want, werr := relativeRelocType(f.Machine)
	if werr != nil {
		return nil, werr
	}
	all, err := f.DynRelocs()
	if err != nil {
		return nil, err
	}
	var out []Reloc
	for _, r := range all {
		if r.Type == want && !r.ImplicitAddend {
			out = append(out, r)
		}
	}
	return out, nil
}

// RelocsInVA 返回 r_offset 落在 [lo, hi) 的项（顺序保持）。
func RelocsInVA(rel []Reloc, lo, hi uint64) []Reloc {
	var out []Reloc
	for _, r := range rel {
		if r.Offset >= lo && r.Offset < hi {
			out = append(out, r)
		}
	}
	return out
}

// SlotValue 读一个重定位槽位（8 字节，小端）。
func (f *File) SlotValue(va uint64) (uint64, error) {
	b, err := f.ReadVA(va, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// NormalizeRelocSlots 把给定重定位的槽位值**归一成链接期（首选基址）形式**：slot := r_addend。
//
// 为什么必须在加密之前做（这就是"先减"那一步）：
// 运行期应用器按「先减 delta → 验签 → 解密 → 再加回 delta」工作（delta = 运行期基址 − 首选基址，
// 见 internal/inject 的重定位应用表）。它要求**密文解密出来的字节就是链接期形式的槽位值**：
// 如果打包端加密的是"已经加过基址的值"，运行期先减 delta 再解密就还原不回去（多减/少减一次），
// 而且 AEAD 的 tag 覆盖整个范围 —— 差一字节就是验签失败。
//
// 实测 RELA 目标（Go -buildmode=pie：7175/7175 条 R_X86_64_RELATIVE）的槽位本来就等于 r_addend，
// 所以这一步通常是 no-op；但它是**校准点**：文件被预重定位过、或目标用 REL（addend 在槽位里）语义时，
// 必须在这里先减回链接期形式。返回被改写的槽位数。
func (f *File) NormalizeRelocSlots(rel []Reloc) (int, error) {
	changed := 0
	for _, r := range rel {
		off, err := f.VAtoOffset(r.Offset)
		if err != nil {
			return changed, fmt.Errorf("重定位槽位 VA 0x%X：%w", r.Offset, err)
		}
		if off+8 > len(f.Data) {
			return changed, fmt.Errorf("重定位槽位 VA 0x%X 越界", r.Offset)
		}
		want := uint64(r.Addend)
		if binary.LittleEndian.Uint64(f.Data[off:]) == want {
			continue
		}
		binary.LittleEndian.PutUint64(f.Data[off:], want)
		changed++
	}
	return changed, nil
}

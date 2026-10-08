package inject

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/vmpx/vmp-x/internal/load/elf"
	"github.com/vmpx/vmp-x/internal/vm"
)

// TestApplyELFNoOverlappingPayloadSegments 钉住 M5 的形状不变量（STATUS #597）：
// **注入器的任何一条路径都不得产生"非可写段盖住可写窗口"的形状**。
//
// 成因与后果：glibc 只在 DT_TEXTREL 路径按 PT_LOAD 重设回原保护。老形状是
// "整段 RX + 重叠的 RW 覆盖段"，靠"后映射者胜"才拿到可写；一旦 glibc 按 RX 段把页重设成
// 只读，解释器第一次写自己的解密缓存就 SIGSEGV（实测 rc=139）。修法是让窗口**不在**任何
// 非可写段的 vaddr 范围内。
//
// 形状梯子（与 internal/load/elf.SparePhdrSlots 的计数一致）：
//
//	① 槽位够     → RX 前缀 [0,bssOff) + RW 窗口 + R+X 尾部（三段**相邻不重叠**）；
//	② 只有 2 槽  → 前缀仍是 RX，窗口与尾部合成**一段 RWX**（该段可写 ⇒ 同样免疫）；
//	③ 只有 1 槽  → 整个载荷段 RWX。
//
// 真实夹具上 ② / ③ 都会出现（Go 的 ET_EXEC 只有 2 个可复用槽；只有 1 个的程序头表虽罕见，
// 但注入器必须能正确走完），所以这里直接把程序头表改成对应槽位数来覆盖三条路径。
func TestApplyELFNoOverlappingPayloadSegments(t *testing.T) {
	const eh, ph = 64, 56

	// build 造一个最小 ELF：imageBase=0x400000，一个 RX 代码页 + 四个可复用槽位
	// （PT_NOTE / PT_GNU_RELRO / PT_PHDR / PT_NULL —— 四种被 sparePhdrSlot 认的类型各一个）。
	// 文件里再补 0x4000 字节，好让注入器把载荷追加到 len(f.Data) 之后（页对齐后 0x8000）。
	buildELF := func(t *testing.T) *elf.File {
		t.Helper()
		f := &elf.File{Entry: 0x400000, Machine: elf.EM_X86_64, EType: elf.ET_EXEC}
		f.Data = make([]byte, 0x4000)
		copy(f.Data[:0x1000], bytes.Repeat([]byte{0x90}, 0x1000)) // 函数 RVA 0x300 要落在里面
		f.Phoff = eh
		f.Phentsize = ph
		f.Phnum = 5
		f.Progs = []elf.Program{
			{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: 0, Vaddr: 0x400000, Paddr: 0x400000,
				Filesz: 0x1000, Memsz: 0x1000, Align: elf.PageAlign},
			{Type: elf.PT_NOTE, Flags: elf.PF_R, Off: 0x400, Vaddr: 0x401000, Paddr: 0x401000, Align: 4},
			{Type: elf.PT_GNU_RELRO, Flags: elf.PF_R, Off: 0x500, Vaddr: 0x401100, Paddr: 0x401100,
				Filesz: 0x10, Memsz: 0x10, Align: 1},
			{Type: elf.PT_PHDR, Flags: elf.PF_R, Off: eh, Vaddr: 0x400040, Paddr: 0x400040,
				Filesz: uint64(5 * ph), Memsz: uint64(5 * ph), Align: 8},
			{Type: elf.PT_NULL},
		}
		binary.LittleEndian.PutUint32(f.Data[0:], 0x464C457F) // ELF
		f.Data[4], f.Data[5] = 2, 1
		binary.LittleEndian.PutUint16(f.Data[16:], elf.ET_EXEC)
		binary.LittleEndian.PutUint16(f.Data[18:], elf.EM_X86_64)
		binary.LittleEndian.PutUint64(f.Data[24:], f.Entry)
		binary.LittleEndian.PutUint64(f.Data[32:], f.Phoff)
		binary.LittleEndian.PutUint16(f.Data[54:], uint16(f.Phentsize))
		binary.LittleEndian.PutUint16(f.Data[56:], uint16(f.Phnum))
		for i, p := range f.Progs {
			o := int(f.Phoff) + i*ph
			binary.LittleEndian.PutUint32(f.Data[o:], p.Type)
			binary.LittleEndian.PutUint32(f.Data[o+4:], p.Flags)
			binary.LittleEndian.PutUint64(f.Data[o+8:], p.Off)
			binary.LittleEndian.PutUint64(f.Data[o+16:], p.Vaddr)
			binary.LittleEndian.PutUint64(f.Data[o+24:], p.Paddr)
			binary.LittleEndian.PutUint64(f.Data[o+32:], p.Filesz)
			binary.LittleEndian.PutUint64(f.Data[o+40:], p.Memsz)
			binary.LittleEndian.PutUint64(f.Data[o+48:], p.Align)
		}
		return f
	}

	// blankSlot 把某个槽位改成**谁都不认**的类型（既不是可复用槽位，也不会让 canDropPHDR 变假）。
	// 别用 PT_INTERP 来废槽位：那会顺手让 PT_PHDR 也不再可复用（本轮校准踩过这一脚）。
	const deadType = 0x60000000
	blankSlot := func(f *elf.File, slot int) {
		o := int(f.Phoff) + slot*int(f.Phentsize)
		binary.LittleEndian.PutUint32(f.Data[o:], deadType)
		f.Progs[slot].Type = deadType
	}

	const stubLen = 0x1000 // 4 KiB：bssOff / bssSize 都对齐到页，窗口才能切成独立段
	// 每个被保护函数在载荷里占 descSize(64) + thunk(5→16) + 字节码，所以条目越多载荷越长；
	// "带尾部"的情形需要一个比窗口更长的载荷（真实产物就是：窗口后面还有 0x203 字节的表）。
	const nFuncs = 100
	funcs := make([]FuncSpec, 0, nFuncs)
	for i := 0; i < nFuncs; i++ {
		// RVA 落在 build() 的代码页里（0x300 起，8 字节一个），够写 5 字节入口补丁。
		funcs = append(funcs, FuncSpec{Name: fmt.Sprintf("f%d", i), RVA: uint32(0x300 + i*8),
			Code: []byte{vm.OpMovRI32, 0, 0x2a, 0, 0, 0, vm.OpRet}})
	}
	build := func(stub []byte, bssOff, bssSize int) []byte {
		pl, err := BuildPayload(Options{SectionName: ".vmp", Stub: stub, StubEntry: 0,
			BSSOff: bssOff, BSSSize: bssSize, Arch: ArchX64, Funcs: funcs}, 0x1000)
		if err != nil {
			t.Fatalf("BuildPayload: %v", err)
		}
		return pl.Data
	}
	// 先量一次"stub + 条目"的头部长度，然后把 stub 补齐到页对齐 —— 这样"窗口正好到载荷末尾"
	// 的用例里 bssSize 也是页对齐的（否则注入器（正确地）拒绝分段）。
	probe := build(bytes.Repeat([]byte{0xCC}, stubLen), stubLen, 0x1000)
	const wantPayloadLen = 0x4000
	stub := bytes.Repeat([]byte{0xCC}, stubLen+(wantPayloadLen-len(probe)))
	if pad := len(stub) - stubLen; pad < 0 {
		t.Fatalf("test fixture is broken: header is already %d bytes past the stub", -pad)
	}
	payload := build(stub, stubLen, wantPayloadLen-stubLen)
	if len(payload) != wantPayloadLen {
		t.Fatalf("test fixture is broken: padded payload=%d, want %d", len(payload), wantPayloadLen)
	}
	payloadLen := len(payload)
	if payloadLen <= stubLen+0x1000 {
		t.Fatalf("test fixture is broken: payload=%d must exceed stub+window (%d) to have a tail",
			payloadLen, stubLen+0x1000)
	}

	cases := []struct {
		name      string
		deadSlots []int // 先废掉这些槽位，剩下的就是注入器实际能用的数量
		bssOff    int
		bssSize   int
		wantSplit bool // 期望"前缀止于 bssOff、代码页保持只读"
	}{
		// 基础夹具 5 个程序头 → spare = NOTE+RELRO+PHDR+NULL = 4；注入器自己用掉 1 个。
		{"three-segment split (RX prefix + RW window + R+X tail)", []int{3}, stubLen, 0x1000, true},
		{"two-segment split (RX prefix + RW window, no tail)", []int{3}, stubLen, payloadLen - stubLen, true},
		{"2-slot fallback (RX prefix + RWX window+tail)", []int{2, 3}, stubLen, 0x1000, true},
		{"1-slot fallback (whole payload RWX)", []int{1, 2, 3}, stubLen, 0x1000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := buildELF(t)
			for _, s := range tc.deadSlots {
				blankSlot(f, s)
			}
			spare := f.SparePhdrSlots()
			opt := Options{
				SectionName: ".vmp", Stub: stub, StubEntry: 0, Arch: ArchX64,
				BSSOff: tc.bssOff, BSSSize: tc.bssSize,
				Funcs: funcs,
			}
			res, err := ApplyELF(f, opt)
			if err != nil {
				t.Fatalf("ApplyELF(spare=%d): %v", spare, err)
			}
			baseVA := f.ImageBase() + uint64(res.SectionRVA)
			if res.SectionSize < payloadLen {
				t.Fatalf("SectionSize=%d < payload len %d", res.SectionSize, payloadLen)
			}
			tail := payloadLen - tc.bssOff - tc.bssSize
			if tail < 0 {
				t.Fatalf("test case is broken: window runs past the payload")
			}

			// ---- 断言 ①：载荷段两两不重叠（除非后来的段是前面可写段的权限子集，那是无害嵌套）
			var payload []elf.Program
			for _, p := range f.Progs {
				if p.Type == elf.PT_LOAD && p.Memsz > 0 &&
					p.Vaddr < baseVA+uint64(payloadLen) && baseVA < p.Vaddr+p.Memsz {
					payload = append(payload, p)
				}
			}
			if len(payload) == 0 {
				t.Fatal("no payload LOAD in the product")
			}
			for i := range payload {
				for j := range payload {
					if i == j {
						continue
					}
					a, b := payload[i], payload[j]
					if b.Vaddr >= a.Vaddr+a.Memsz || a.Vaddr >= b.Vaddr+b.Memsz {
						continue
					}
					if a.Flags&elf.PF_W != 0 && b.Flags&a.Flags == a.Flags {
						continue // 可写段内部的嵌套：后映射者权限不更宽，无害
					}
					t.Fatalf("payload LOADs overlap: %+v vs %+v", a, b)
				}
			}

			// ---- 断言 ②：窗口必须被"某个可写段"完整覆盖（否则解释器第一次写就 SIGSEGV）
			winVA := baseVA + uint64(tc.bssOff)
			winEnd := winVA + uint64(tc.bssSize)
			var cover *elf.Program
			for i := range payload {
				p := &payload[i]
				if p.Vaddr <= winVA && winEnd <= p.Vaddr+p.Memsz && p.Flags&elf.PF_W != 0 {
					cover = p
				}
			}
			if cover == nil {
				t.Fatalf("no writable payload LOAD covers the window [0x%X,0x%X): %s",
					winVA, winEnd, fmt.Sprint(payload))
			}

			// ---- 断言 ③：**没有任何非可写载荷段**的页范围与窗口页范围相交（M5 的不变量）
			winLo, winHi := winVA/elf.PageAlign, (winEnd-1)/elf.PageAlign
			for _, p := range payload {
				if p.Flags&elf.PF_W != 0 || p.Memsz == 0 {
					continue
				}
				lo := p.Vaddr / elf.PageAlign
				hi := (p.Vaddr + p.Memsz - 1) / elf.PageAlign
				if lo <= winHi && winLo <= hi {
					t.Fatalf("non-writable LOAD %+v covers the writable window [0x%X,0x%X)", p, winVA, winEnd)
				}
			}

			// ---- 断言 ④：拆分段的前缀必须**止于** bssOff，且代码页不得可写
			if tc.wantSplit {
				prefix := payload[0]
				if prefix.Vaddr != baseVA || prefix.Filesz != uint64(tc.bssOff) || prefix.Memsz != uint64(tc.bssOff) {
					t.Fatalf("RX prefix must stop at bssOff=0x%X; payload=%s", tc.bssOff, fmt.Sprint(payload))
				}
				if prefix.Flags&elf.PF_W != 0 {
					t.Fatalf("RX prefix must not be writable; payload=%s", fmt.Sprint(payload))
				}
			} else if cover.Flags&elf.PF_X == 0 {
				t.Fatalf("whole-payload fallback must be RWX; got flags=0x%X", cover.Flags)
			}
			t.Logf("spare=%d tail=0x%X cover=flags 0x%X size 0x%X segments=%s",
				spare, tail, cover.Flags, cover.Filesz, fmt.Sprint(payload))
		})
	}
}

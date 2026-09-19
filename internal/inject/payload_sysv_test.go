package inject

import (
	"encoding/binary"
	"testing"
)

// 这组断言盯的是 **ELF/SysV 版**的解密蹦床编码（PE 侧走 Win64 那条，已经在 E2E 里跑过；
// SysV 那条本机跑不了真实 ELF，所以至少把字节级约定钉死在单测里）。
//
// 期望形状（26 字节序言 + 5 字节 jmp）：
//
//	52                    push rdx
//	49 89 E4              mov r12, rsp
//	48 83 E4 F0           and rsp, -16
//	48 8D 3D <disp32>     lea rdi, [rip + disp32]   → 指向解密表
//	E8 <rel32>            call vm_unpack_image
//	85 C0 74 02 0F 0B     test eax,eax; jz +2; ud2  （失败即 trap）
//	4C 89 E4 5A           mov rsp, r12; pop rdx
//	E9 <rel32>            jmp 下一跳（有校验蹦床就跳它，否则跳原始入口）
func TestSysVUnpackTrampoline(t *testing.T) {
	const baseRVA = uint32(0x3000)
	enc := func(plain []byte, aad []byte) ([]byte, [12]byte, [16]byte, error) {
		var n [12]byte
		var tag [16]byte
		return plain, n, tag, nil
	}
	opt := Options{
		SectionName: ".t",
		Stub:        make([]byte, 0x200),
		StubEntry:   0x40,
		Funcs:       []FuncSpec{{Name: "f", RVA: 0x2000, Code: []byte{1, 2, 3, 4, 5, 6, 7, 8}, NativeSize: 16}},
		Encrypt:     enc,
		PatchKey:    [8]byte{1, 2, 3},
		EntryHook:   true,
		VerifyFn:    0x80,
		EntryRVA:    0x1234,
		// ELF 侧的约定：EntryHookSysV、ImageBase=0（运行期不强制校验基址）、表在 payload 里
		EntryHookSysV: true,
		ImgSections:   []ImgSection{{RVA: 0x1000, Size: 0x200, Flags: 1}},
		ImageBase:     0,
		UnpackFn:      0x60,
	}
	pl, err := BuildPayload(opt, baseRVA)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if pl.ImgHookRVA == 0 || pl.ImgTableRVA == 0 || pl.EntryHookRVA == 0 {
		t.Fatalf("蹦床/表没生成：imgHook=0x%X table=0x%X verifyHook=0x%X", pl.ImgHookRVA, pl.ImgTableRVA, pl.EntryHookRVA)
	}
	off := int(pl.ImgHookRVA - baseRVA)
	const hookLen = 35 // 26 字节序言/中段 + 5 字节 jmp 的 rel32 + 前 4 字节 opcode
	if off <= 0 || off+hookLen > len(pl.Data) {
		t.Fatalf("蹦床偏移越界: off=%d len=%d", off, len(pl.Data))
	}
	b := pl.Data[off:]

	want := []byte{0x52, 0x49, 0x89, 0xE4, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x8D, 0x3D}
	for i := range want {
		if b[i] != want[i] {
			t.Fatalf("序言第 %d 字节 = 0x%02X，期望 0x%02X（实际序言 % X）", i, b[i], want[i], b[:11])
		}
	}
	if got := b[15]; got != 0xE8 {
		t.Fatalf("第 15 字节应为 call(E8)，实际 0x%02X", got)
	}
	mid := []byte{0x85, 0xC0, 0x74, 0x02, 0x0F, 0x0B, 0x4C, 0x89, 0xE4, 0x5A, 0xE9}
	for i := range mid {
		if b[20+i] != mid[i] {
			t.Fatalf("第 %d 字节 = 0x%02X，期望 0x%02X（实际中段 % X）", 20+i, b[20+i], mid[i], b[20:31])
		}
	}
	// 三个 rel32 必须分别指向：解密表、vm_unpack_image、下一跳（这里是校验蹦床）
	leaDisp := int32(binary.LittleEndian.Uint32(b[11:]))
	if got, want := uint32(int64(pl.ImgHookRVA)+15+int64(leaDisp)), pl.ImgTableRVA; got != want {
		t.Fatalf("lea 指向 0x%X，期望解密表 0x%X", got, want)
	}
	callDisp := int32(binary.LittleEndian.Uint32(b[16:]))
	if got, want := uint32(int64(pl.ImgHookRVA)+20+int64(callDisp)), baseRVA+uint32(opt.UnpackFn); got != want {
		t.Fatalf("call 指向 0x%X，期望 vm_unpack_image 0x%X", got, want)
	}
	jmpDisp := int32(binary.LittleEndian.Uint32(b[31:]))
	if got, want := uint32(int64(pl.ImgHookRVA)+35+int64(jmpDisp)), pl.EntryHookRVA; got != want {
		t.Fatalf("jmp 指向 0x%X，期望校验蹦床 0x%X", got, want)
	}

	// 表头：imageBase / salt / count / selfRVA / 保留；selfRVA 必须等于表自身的 RVA
	to := int(pl.ImgTableRVA - baseRVA)
	if to <= 0 || to+24+32 > len(pl.Data) {
		t.Fatalf("表偏移越界: %d", to)
	}
	tb := pl.Data[to:]
	if ib := binary.LittleEndian.Uint64(tb[0:]); ib != 0 {
		t.Fatalf("表头 imageBase = 0x%X，ELF 侧期望 0（运行期不强制校验）", ib)
	}
	if n := binary.LittleEndian.Uint32(tb[12:]); n != 1 {
		t.Fatalf("表头 count = %d，期望 1", n)
	}
	if self := binary.LittleEndian.Uint32(tb[16:]); self != pl.ImgTableRVA {
		t.Fatalf("表头 selfRVA = 0x%X，期望 0x%X（运行期靠它反推基址）", self, pl.ImgTableRVA)
	}
	e := tb[24:]
	if rva, size, flags := binary.LittleEndian.Uint32(e[0:]), binary.LittleEndian.Uint32(e[4:]), binary.LittleEndian.Uint32(e[8:]); rva != 0x1000 || size != 0x200 || flags != 1 {
		t.Fatalf("条目 = {0x%X,0x%X,0x%X}，期望 {0x1000,0x200,1}", rva, size, flags)
	}
}

// Win64 那条也不能被改坏：寄存器搬运必须是 rcx（PE 的入口参数寄存器）。
func TestWin64UnpackTrampolineKeepsRcx(t *testing.T) {
	enc := func(plain []byte, aad []byte) ([]byte, [12]byte, [16]byte, error) {
		var n [12]byte
		var v [16]byte
		return plain, n, v, nil
	}
	opt := Options{
		SectionName: ".t", Stub: make([]byte, 0x200), StubEntry: 0x40,
		Funcs:   []FuncSpec{{Name: "f", RVA: 0x2000, Code: []byte{1, 2, 3, 4, 5, 6, 7, 8}, NativeSize: 16}},
		Encrypt: enc, PatchKey: [8]byte{1}, EntryHook: true, VerifyFn: 0x80, EntryRVA: 0x1234,
		ImgSections: []ImgSection{{RVA: 0x1000, Size: 0x200, Flags: 1}}, ImageBase: 0x140000000, UnpackFn: 0x60,
	}
	pl, err := BuildPayload(opt, 0x3000)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	b := pl.Data[int(pl.ImgHookRVA-0x3000):]
	want := []byte{0x51, 0x52, 0x41, 0x50, 0x48, 0x8D, 0x0D}
	for i := range want {
		if b[i] != want[i] {
			t.Fatalf("Win64 序言第 %d 字节 = 0x%02X，期望 0x%02X（实际 % X）", i, b[i], want[i], b[:7])
		}
	}
}

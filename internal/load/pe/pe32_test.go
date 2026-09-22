package pe

// PE32（32 位 x86）解析的回归测试：合成一份最小 PE32 镜像，验证机器类型/ImageBase 宽度/入口/对齐，
// 并（如果本机有的话）拿真实的 C:\Windows\SysWOW64\notepad.exe 试一次 —— 不存在就跳过。
//
// 为什么先做"解析"：它是 PE32 支持的地基，且完全不碰 blob（32 位 blob 需要 i686 工具链，本机没有）。

import (
	"encoding/binary"
	"os"
	"testing"
)

// makePE32 合成一份最小可解析的 PE32：1 个节、可选头 224 字节（PE32 的标准大小）。
func makePE32() []byte {
	d := make([]byte, 0x400)
	binary.LittleEndian.PutUint16(d[0:], MzMagic)
	const lfanew = 0x80
	binary.LittleEndian.PutUint32(d[0x3C:], lfanew)
	binary.LittleEndian.PutUint32(d[lfanew:], PeMagic)
	binary.LittleEndian.PutUint16(d[lfanew+4:], MachineI386)
	binary.LittleEndian.PutUint16(d[lfanew+6:], 1) // numberOfSections
	binary.LittleEndian.PutUint16(d[lfanew+20:], 224)
	opt := lfanew + 24
	binary.LittleEndian.PutUint16(d[opt:], OptMagicPE32)
	binary.LittleEndian.PutUint32(d[opt+16:], 0x1000)     // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(d[opt+28:], 0x00400000) // ImageBase（PE32 是 u32）
	binary.LittleEndian.PutUint32(d[opt+32:], 0x1000)     // SectionAlignment
	binary.LittleEndian.PutUint32(d[opt+36:], 0x200)      // FileAlignment
	binary.LittleEndian.PutUint32(d[opt+56:], 0x2000)     // SizeOfImage
	binary.LittleEndian.PutUint32(d[opt+60:], 0x200)      // SizeOfHeaders
	binary.LittleEndian.PutUint16(d[opt+68:], 3)          // Subsystem = console
	sec := opt + 224
	copy(d[sec:], []byte(".text"))
	binary.LittleEndian.PutUint32(d[sec+8:], 0x100)   // VirtualSize
	binary.LittleEndian.PutUint32(d[sec+12:], 0x1000) // VirtualAddress
	binary.LittleEndian.PutUint32(d[sec+16:], 0x200)  // SizeOfRawData
	binary.LittleEndian.PutUint32(d[sec+20:], 0x200)  // PointerToRawData
	binary.LittleEndian.PutUint32(d[sec+36:], ScnCntCode|ScnMemExecute|ScnMemRead)
	return d
}

func TestParsePE32(t *testing.T) {
	f, err := Parse(makePE32())
	if err != nil {
		t.Fatalf("PE32 应当能解析: %v", err)
	}
	if f.Machine != MachineI386 {
		t.Fatalf("machine=0x%X，期望 0x14C", f.Machine)
	}
	if !f.Is32Bit() {
		t.Fatalf("Is32Bit 应当为 true（OptMagic=0x%X）", f.OptMagic)
	}
	if f.ImageBase != 0x00400000 {
		t.Fatalf("ImageBase=0x%X，期望 0x400000（PE32 的 u32 偏移 +28）", f.ImageBase)
	}
	if f.AddressOfEntry != 0x1000 {
		t.Fatalf("entry=0x%X", f.AddressOfEntry)
	}
	if f.SectionAlignment != 0x1000 || f.FileAlignment != 0x200 {
		t.Fatalf("alignment 解析错：section=0x%X file=0x%X", f.SectionAlignment, f.FileAlignment)
	}
	if len(f.Sections) != 1 || f.Sections[0].Name != ".text" {
		t.Fatalf("节解析错: %+v", f.Sections)
	}
}

// 真实的 32 位 exe（没有就跳过 —— 别的机器上未必有）。
func TestParseRealPE32(t *testing.T) {
	const p = `C:\Windows\SysWOW64\notepad.exe`
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("没有 %s（跳过真实 PE32 用例）", p)
	}
	f, err := Parse(b)
	if err != nil {
		t.Fatalf("真实 PE32 应当能解析: %v", err)
	}
	if f.Machine != MachineI386 || !f.Is32Bit() {
		t.Fatalf("machine=0x%X optMagic=0x%X，期望 i386/PE32", f.Machine, f.OptMagic)
	}
	if f.ImageBase == 0 || len(f.Sections) == 0 {
		t.Fatalf("解析结果不合理: base=0x%X sections=%d", f.ImageBase, len(f.Sections))
	}
	t.Logf("SysWOW64 notepad: base=0x%X entry=0x%X sections=%d", f.ImageBase, f.AddressOfEntry, len(f.Sections))
}

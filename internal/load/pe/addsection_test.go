package pe

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// synthPE 构造一个结构合法的最小 PE32+（不保证可执行，仅用于结构测试）
func synthPE(numSections int, sizeOfHeaders, fileSize int) []byte {
	const lfanew = 0x40
	const optSize = 0xF0
	secTableOff := lfanew + 24 + optSize

	if fileSize < sizeOfHeaders+numSections*0x200 {
		fileSize = sizeOfHeaders + numSections*0x200
	}
	data := make([]byte, fileSize)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3C:], lfanew)
	copy(data[lfanew:], []byte{'P', 'E', 0, 0})
	binary.LittleEndian.PutUint16(data[lfanew+4:], MachineAMD64)
	binary.LittleEndian.PutUint16(data[lfanew+6:], uint16(numSections))
	binary.LittleEndian.PutUint16(data[lfanew+20:], optSize)
	binary.LittleEndian.PutUint16(data[lfanew+22:], 0x22)

	opt := lfanew + 24
	binary.LittleEndian.PutUint16(data[opt:], OptMagicPE32Plus)
	binary.LittleEndian.PutUint32(data[opt+16:], 0x1000) // entry
	binary.LittleEndian.PutUint32(data[opt+32:], 0x1000) // section align
	binary.LittleEndian.PutUint32(data[opt+36:], 0x200)  // file align
	binary.LittleEndian.PutUint32(data[opt+56:], 0x2000) // size of image
	binary.LittleEndian.PutUint32(data[opt+60:], uint32(sizeOfHeaders))
	binary.LittleEndian.PutUint16(data[opt+68:], 3) // console

	for i := 0; i < numSections; i++ {
		off := secTableOff + i*SectionHeaderSize
		name := []byte{'.', 's', 'e', 'c', byte('0' + i)}
		copy(data[off:], name)
		binary.LittleEndian.PutUint32(data[off+8:], 0x100)
		binary.LittleEndian.PutUint32(data[off+12:], uint32(0x1000*(i+1)))
		binary.LittleEndian.PutUint32(data[off+16:], 0x200)
		binary.LittleEndian.PutUint32(data[off+20:], uint32(sizeOfHeaders+i*0x200))
		binary.LittleEndian.PutUint32(data[off+36:], ScnCntCode|ScnMemExecute|ScnMemRead)
	}
	return data
}

func TestParseSynthetic(t *testing.T) {
	f, err := Parse(synthPE(1, 0x200, 0x400))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.Machine != MachineAMD64 {
		t.Errorf("machine=0x%X", f.Machine)
	}
	if f.NumberOfSections != 1 || len(f.Sections) != 1 {
		t.Fatalf("sections=%d/%d", f.NumberOfSections, len(f.Sections))
	}
	if f.SectionAlignment != 0x1000 || f.FileAlignment != 0x200 {
		t.Errorf("alignment=%X/%X", f.SectionAlignment, f.FileAlignment)
	}
	if f.Sections[0].Name != ".sec0" {
		t.Errorf("name=%q", f.Sections[0].Name)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse([]byte("not a pe at all, definitely not")); err == nil {
		t.Error("expected error for non-PE input")
	}
	// 可选头 magic 未知时必须报错。
	// （这里原来断言"PE32 必须被拒绝"，那是旧限制：现在 PE32 是**有意支持**的，
	//   见 pe32_test.go 的 TestParsePE32/TestParseRealPE32。）
	d := synthPE(1, 0x200, 0x400)
	binary.LittleEndian.PutUint16(d[0x40+24:], 0x999)
	if _, err := Parse(d); err == nil {
		t.Error("expected error for unknown optional header magic")
	}
	// 而 PE32 的 magic 必须**通过**（解析层不再拒绝它）。
	d2 := synthPE(1, 0x200, 0x400)
	binary.LittleEndian.PutUint16(d2[0x40+24:], OptMagicPE32)
	if _, err := Parse(d2); err != nil {
		t.Errorf("PE32 现在应当能解析，却被拒绝: %v", err)
	}
}

func TestAddSection(t *testing.T) {
	base := synthPE(1, 0x200, 0x400)
	origSec0 := append([]byte(nil), base[0x200:0x300]...)

	f, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}
	sec, err := f.AddSection(".vmp", payload, ScnCntCode|ScnMemExecute|ScnMemRead)
	if err != nil {
		t.Fatalf("AddSection: %v", err)
	}
	if f.NumberOfSections != 2 {
		t.Errorf("NumberOfSections=%d want 2", f.NumberOfSections)
	}
	if sec.VirtualAddress != 0x2000 {
		t.Errorf("rva=0x%X want 0x2000", sec.VirtualAddress)
	}
	if sec.PointerToRawData != 0x400 {
		t.Errorf("raw=0x%X want 0x400", sec.PointerToRawData)
	}
	if sec.SizeOfRawData != 0x200 {
		t.Errorf("rawsize=0x%X want 0x200", sec.SizeOfRawData)
	}
	if sec.VirtualSize != 100 {
		t.Errorf("vsize=%d want 100", sec.VirtualSize)
	}
	if f.SizeOfImage != 0x3000 {
		t.Errorf("sizeofimage=0x%X want 0x3000", f.SizeOfImage)
	}

	// 重新解析必须一致，且原始节内容不能被破坏
	f2, err := Parse(f.Data)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if f2.NumberOfSections != 2 {
		t.Fatalf("reparse sections=%d", f2.NumberOfSections)
	}
	if f2.SizeOfImage != 0x3000 {
		t.Errorf("reparse sizeofimage=0x%X", f2.SizeOfImage)
	}
	if got := f2.Sections[1].Name; got != ".vmp" {
		t.Errorf("reparse name=%q", got)
	}
	if !bytes.Equal(f.Data[0x200:0x300], origSec0) {
		t.Error("original section data was modified")
	}
	// 头部里的 NumberOfSections 字段也要被改写
	if n := binary.LittleEndian.Uint16(f.Data[0x40+6:]); n != 2 {
		t.Errorf("header NumberOfSections=%d want 2", n)
	}

	// RVA -> 偏移并能读回 payload
	off, err := f2.RVAtoOffset(sec.VirtualAddress)
	if err != nil {
		t.Fatalf("RVAtoOffset: %v", err)
	}
	if off != int(sec.PointerToRawData) {
		t.Errorf("offset=0x%X want 0x%X", off, sec.PointerToRawData)
	}
	if !bytes.Equal(f2.Data[off:off+100], payload) {
		t.Error("payload round-trip mismatch")
	}
}

func TestAddSectionNoRoomInHeaders(t *testing.T) {
	// SizeOfHeaders 恰好等于节表末尾 -> 没有空间再放一个节头
	f, err := Parse(synthPE(1, 0x170, 0x400))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.AddSection(".vmp", []byte{1, 2, 3}, ScnMemRead); err == nil {
		t.Fatal("expected 'no room' error")
	}
}

func TestAddTwoSections(t *testing.T) {
	f, err := Parse(synthPE(1, 0x200, 0x400))
	if err != nil {
		t.Fatal(err)
	}
	s1, err := f.AddSection(".vmp", bytes.Repeat([]byte{0xAA}, 16), ScnMemRead|ScnMemExecute)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := f.AddSection(".vmp2", bytes.Repeat([]byte{0xBB}, 4096), ScnMemRead|ScnMemExecute)
	if err != nil {
		t.Fatal(err)
	}
	if s2.VirtualAddress <= s1.VirtualAddress {
		t.Errorf("second section rva 0x%X should follow first 0x%X", s2.VirtualAddress, s1.VirtualAddress)
	}
	if s2.PointerToRawData <= s1.PointerToRawData {
		t.Errorf("second section raw 0x%X should follow first 0x%X", s2.PointerToRawData, s1.PointerToRawData)
	}
	if _, err := Parse(f.Data); err != nil {
		t.Fatalf("reparse after two sections: %v", err)
	}
	if f.SizeOfImage != s2.VirtualAddress+AlignUp(4096, f.SectionAlignment) {
		t.Errorf("sizeofimage=0x%X", f.SizeOfImage)
	}
}

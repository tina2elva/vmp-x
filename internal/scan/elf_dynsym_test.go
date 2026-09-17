package scan

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

const (
	elfDHdr = 64
	elfPHsz = 56
	elfSHsz = 64
)

// 造一个**只有 .dynsym、没有 .symtab** 的最小 ELF64（模拟被 strip 的 .so），
// 用来验证 FindFunctionELF 的 .dynsym 回退路径。
func buildDynsymOnlyELF(t *testing.T, text []byte, funcName string) string {
	t.Helper()
	const textVA = 0x1000
	textOff := elfDHdr + elfPHsz
	dynsymOff := textOff + len(text)
	if dynsymOff%8 != 0 {
		dynsymOff += 8 - dynsymOff%8
	}
	dynstr := append([]byte{0}, append([]byte(funcName), 0)...)
	// 符号表两个条目（0 号占位 + 1 号函数）之后才是字符串表
	dynstrOff := dynsymOff + 2*24
	shstrOff := dynstrOff + len(dynstr)
	shstr := []byte("\x00.text\x00.dynsym\x00.dynstr\x00.shstrtab\x00")
	shoff := shstrOff + len(shstr)
	if shoff%8 != 0 {
		shoff += 8 - shoff%8
	}
	buf := make([]byte, shoff+5*elfSHsz)

	// ELF header
	copy(buf[0:], []byte{0x7F, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(buf[16:], 3)      // e_type = ET_DYN（.so 就是它）
	binary.LittleEndian.PutUint16(buf[18:], 62)     // e_machine = x86-64
	binary.LittleEndian.PutUint32(buf[20:], 1)      // e_version
	binary.LittleEndian.PutUint64(buf[24:], textVA) // e_entry
	binary.LittleEndian.PutUint64(buf[32:], elfDHdr)
	binary.LittleEndian.PutUint64(buf[40:], uint64(shoff))
	binary.LittleEndian.PutUint16(buf[52:], elfDHdr)
	binary.LittleEndian.PutUint16(buf[54:], elfPHsz)
	binary.LittleEndian.PutUint16(buf[56:], 1) // e_phnum
	binary.LittleEndian.PutUint16(buf[58:], elfSHsz)
	binary.LittleEndian.PutUint16(buf[60:], 5) // e_shnum
	binary.LittleEndian.PutUint16(buf[62:], 4) // e_shstrndx

	// 一个 PT_LOAD 覆盖 .text（readVA 靠它）
	ph := buf[elfDHdr:]
	binary.LittleEndian.PutUint32(ph[0:], 1) // PT_LOAD
	binary.LittleEndian.PutUint32(ph[4:], 5) // R+X
	binary.LittleEndian.PutUint64(ph[8:], uint64(textOff))
	binary.LittleEndian.PutUint64(ph[16:], textVA)
	binary.LittleEndian.PutUint64(ph[24:], textVA)
	binary.LittleEndian.PutUint64(ph[32:], uint64(len(text)))
	binary.LittleEndian.PutUint64(ph[40:], uint64(len(text)))
	binary.LittleEndian.PutUint64(ph[48:], 0x1000)

	copy(buf[textOff:], text)

	// .dynsym[1] = 我们的函数
	ds := buf[dynsymOff+24:]                 // 1 号符号
	binary.LittleEndian.PutUint32(ds[0:], 1) // st_name → .dynstr 偏移 1
	ds[4] = 0x12                             // STB_GLOBAL | STT_FUNC
	binary.LittleEndian.PutUint16(ds[6:], 1) // st_shndx = .text
	binary.LittleEndian.PutUint64(ds[8:], textVA)
	binary.LittleEndian.PutUint64(ds[16:], uint64(len(text)))
	copy(buf[dynstrOff:], dynstr)
	copy(buf[shstrOff:], shstr)

	sh := buf[shoff:]
	put := func(i int, name, typ uint32, flags, addr, off, size uint64, link, info uint32) {
		s := sh[i*elfSHsz:]
		binary.LittleEndian.PutUint32(s[0:], name)
		binary.LittleEndian.PutUint32(s[4:], typ)
		binary.LittleEndian.PutUint64(s[8:], flags)
		binary.LittleEndian.PutUint64(s[16:], addr)
		binary.LittleEndian.PutUint64(s[24:], off)
		binary.LittleEndian.PutUint64(s[32:], size)
		binary.LittleEndian.PutUint32(s[40:], link)
		binary.LittleEndian.PutUint32(s[44:], info)
		binary.LittleEndian.PutUint64(s[48:], 1)
		binary.LittleEndian.PutUint64(s[56:], 24)
	}
	put(1, 1, 1, 6, textVA, uint64(textOff), uint64(len(text)), 0, 0) // .text  PROGBITS AX
	put(2, 7, 11, 2, 0, uint64(dynsymOff), 2*24, 3, 1)                // .dynsym DYNSYM → .dynstr
	put(3, 15, 3, 2, 0, uint64(dynstrOff), uint64(len(dynstr)), 0, 0) // .dynstr STRTAB
	put(4, 24, 3, 0, 0, uint64(shstrOff), uint64(len(shstr)), 0, 0)   // .shstrtab

	path := filepath.Join(t.TempDir(), "libstripped.so")
	if err := os.WriteFile(path, buf, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFindFunctionELFViaDynsym(t *testing.T) {
	text := []byte{0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3} // mov $7,%eax ; ret
	p := buildDynsymOnlyELF(t, text, "myfunc")
	got, err := FindFunctionELF(p, 0, "myfunc")
	if err != nil {
		t.Fatalf(".dynsym 回退失败: %v", err)
	}
	if got.RVA != 0x1000 {
		t.Fatalf("RVA 应为 0x1000，得到 0x%X", got.RVA)
	}
	if len(got.Code) == 0 || got.Code[len(got.Code)-1] != 0xC3 {
		t.Fatalf("取到的代码不对: % X", got.Code)
	}
}

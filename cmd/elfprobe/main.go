// elfprobe - 开发用：打印 ELF 结构摘要（段/节/符号），用于规划注入点
package main

import (
	"debug/elf"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: elfprobe <file> [symbol]")
		os.Exit(2)
	}
	f, err := elf.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	defer f.Close()

	fmt.Printf("type=%v machine=%v entry=0x%X class=%v", f.Type, f.Machine, f.Entry, f.Class)
	fmt.Println()
	maxVA := uint64(0)
	noteIdx := -1
	for i, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Vaddr+p.Memsz > maxVA {
			maxVA = p.Vaddr + p.Memsz
		}
		if p.Type == elf.PT_NOTE && noteIdx < 0 {
			noteIdx = i
		}
	}
	fmt.Printf("maxPT_LOADend=0x%X firstPT_NOTE=%d phnum=%d", maxVA, noteIdx, len(f.Progs))
	fmt.Println()
	for i, p := range f.Progs {
		fmt.Printf("  PH[%d] type=%-14v flags=%v off=0x%-8X vaddr=0x%-10X filesz=0x%-8X memsz=0x%-8X align=0x%X",
			i, p.Type, p.Flags, p.Off, p.Vaddr, p.Filesz, p.Memsz, p.Align)
		fmt.Println()
	}
	fmt.Printf("sections=%d", len(f.Sections))
	fmt.Println()
	for i, s := range f.Sections {
		if i < 6 || s.Type == elf.SHT_SYMTAB {
			fmt.Printf("  SH[%d] %-18s type=%-12v addr=0x%-10X off=0x%-8X size=0x%X",
				i, s.Name, s.Type, s.Addr, s.Offset, s.Size)
			fmt.Println()
		}
	}
	if len(os.Args) >= 3 {
		name := os.Args[2]
		syms, serr := f.Symbols()
		if serr != nil {
			fmt.Println("  (no symtab:", serr, ")")
		}
		for _, s := range syms {
			if s.Name == name {
				fmt.Printf("  SYM %s value=0x%X size=%d type=%v shndx=%v",
					s.Name, s.Value, s.Size, elf.ST_TYPE(s.Info), s.Section)
				fmt.Println()
			}
		}
	}
}

// elfobjdump - 开发用：打印 ELF 可重定位目标的节/符号/重定位
package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: elfobjdump <file.o>")
		os.Exit(2)
	}
	f, err := elf.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	defer f.Close()
	fmt.Println("type:", f.Type, "machine:", f.Machine)
	for i, s := range f.Sections {
		fmt.Printf("  SH[%d] %-14s type=%-12v info=%d link=%d size=%d\n", i, s.Name, s.Type, s.Info, s.Link, s.Size)
	}
	syms, _ := f.Symbols()
	fmt.Println("symbols:", len(syms))
	for i, s := range syms {
		fmt.Printf("  SYM[%d] %-20s sec=%v value=%d\n", i, s.Name, s.Section, s.Value)
	}
	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA && s.Type != elf.SHT_REL {
			continue
		}
		data, _ := s.Data()
		step := 24
		if s.Type == elf.SHT_REL {
			step = 16
		}
		for off := 0; off+step <= len(data); off += step {
			rOff := binary.LittleEndian.Uint64(data[off:])
			info := binary.LittleEndian.Uint64(data[off+8:])
			add := int64(0)
			if step == 24 {
				add = int64(binary.LittleEndian.Uint64(data[off+16:]))
			}
			fmt.Printf("  RELA %s: off=0x%X sym=%d type=%d addend=%d\n", s.Name, rOff, info>>32, uint32(info&0xFFFFFFFF), add)
		}
	}
}

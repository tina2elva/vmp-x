// pesyms - 开发用：列出 PE 符号（值/类型/存储类），用于排查函数边界
package main

import (
	"debug/pe"
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pesyms <file> [loHex] [hiHex]")
		os.Exit(2)
	}
	f, err := pe.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	defer f.Close()
	lo, hi := uint64(0), uint64(1<<62)
	if len(os.Args) >= 4 {
		lo, _ = strconv.ParseUint(os.Args[2], 0, 64)
		hi, _ = strconv.ParseUint(os.Args[3], 0, 64)
	}
	for _, s := range f.Symbols {
		if uint64(s.Value) >= lo && uint64(s.Value) < hi {
			fmt.Printf("0x%X type=0x%04X class=%d section=%d name=%s",
				s.Value, s.Type, s.StorageClass, s.SectionNumber, s.Name)
			fmt.Println()
		}
	}
}

package main

import (
	"debug/elf"
	"fmt"
	"os"
)

func main() {
	for _, p := range os.Args[1:] {
		f, err := elf.Open(p)
		if err != nil {
			fmt.Println(p, err)
			continue
		}
		fmt.Printf("== %s ==\n", p)
		for i, pr := range f.Progs {
			fmt.Printf("  PH[%d] type=%-16s flags=%v off=0x%X va=0x%X filesz=0x%X\n",
				i, pr.Type, pr.Flags, pr.Off, pr.Vaddr, pr.Filesz)
		}
		f.Close()
	}
}

package main

import (
	"fmt"
	"os"

	"github.com/vmpx/vmp-x/internal/load/pe"
	"github.com/vmpx/vmp-x/internal/scan"
)

func main() {
	f, err := pe.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	if err := scan.LoadMapFile(os.Args[2]); err != nil {
		panic(err)
	}
	for _, n := range os.Args[3:] {
		found, err := scan.FindFunction(os.Args[1], f, n)
		if err != nil {
			fmt.Printf("%-40s ERR %v\n", n, err)
			continue
		}
		nn := len(found.Code)
		if nn > 6 {
			nn = 6
		}
		fmt.Printf("%-40s RVA=0x%X end=0x%X len=%d first=% X\n", n, found.RVA, found.End, len(found.Code), found.Code[:nn])
	}
}
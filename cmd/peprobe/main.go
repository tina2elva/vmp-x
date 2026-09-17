// peprobe 是一个开发用工具：给任意 PE32+ 追加一个节并写回，
// 用来验证“注入不改坏原程序”这一前提（注入的节不参与执行）。
//
// 用法: peprobe <in.exe> <out.exe> [payloadBytes] [sectionName]
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/vmpx/vmp-x/internal/load/pe"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: peprobe <in.exe> <out.exe> [payloadBytes] [sectionName]\n")
		os.Exit(2)
	}
	in, out := os.Args[1], os.Args[2]
	n := 64
	if len(os.Args) >= 4 {
		v, err := strconv.Atoi(os.Args[3])
		if err != nil || v < 0 {
			fmt.Fprintf(os.Stderr, "bad payloadBytes %q\n", os.Args[3])
			os.Exit(2)
		}
		n = v
	}
	name := ".vmp"
	if len(os.Args) >= 5 {
		name = os.Args[4]
	}

	f, err := pe.Open(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[*] input:")
	fmt.Print(f.Summary())

	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i * 7)
	}

	sec, err := f.AddSection(name, payload, pe.ScnCntCode|pe.ScnMemExecute|pe.ScnMemRead)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] AddSection: %v\n", err)
		os.Exit(1)
	}
	if err := f.Save(out); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Save: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] added %s: RVA=0x%X raw=0x%X rawSize=0x%X vsize=0x%X\n",
		sec.Name, sec.VirtualAddress, sec.PointerToRawData, sec.SizeOfRawData, sec.VirtualSize)
	fmt.Printf("[+] wrote %s (%d bytes)\n", out, len(f.Data))

	// 复核：重新解析输出
	g, err := pe.Open(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] reparse failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[*] output:")
	fmt.Print(g.Summary())
}

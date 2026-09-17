// vmp-lift - 把一个函数的机器码 lift 成 VM 字节码（M1：只翻译，不注入）
//
// 用法: vmp-lift -exe <pe> -func <name> -out <file.vmb> [-v]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/vmpx/vmp-x/internal/lift/x64"
	"github.com/vmpx/vmp-x/internal/load/pe"
	"github.com/vmpx/vmp-x/internal/scan"
	"github.com/vmpx/vmp-x/internal/vm"
)

func main() {
	exe := flag.String("exe", "", "目标 PE")
	fn := flag.String("func", "", "函数名（符号）")
	out := flag.String("out", "", "输出字节码文件")
	verbose := flag.Bool("v", false, "打印 IR 与字节码")
	manPath := flag.String("manifest", "build/vm_interp.json", "blob manifest（用于取 FRAME_SKEW）")
	flag.Parse()

	if *exe == "" || *fn == "" {
		fmt.Fprintln(os.Stderr, "usage: vmp-lift -exe <pe> -func <name> [-out out.vmb] [-v]")
		os.Exit(2)
	}

	f, err := pe.Open(*exe)
	must(err)

	found, err := scan.FindFunction(*exe, f, *fn)
	must(err)

	l := x64.NewLifter(f.ImageBase)
	if *manPath != "" {
		if mb, err := os.ReadFile(*manPath); err == nil {
			var man struct {
				FrameSkew int `json:"frameSkew"`
			}
			if json.Unmarshal(mb, &man) == nil && man.FrameSkew != 0 {
				l.SetFrameSkew(int64(man.FrameSkew))
				fmt.Printf("[*] FRAME_SKEW=%d (来自 %s)", man.FrameSkew, *manPath)
				fmt.Println()
			}
		}
	}
	irFunc, err := l.LiftFunc(*fn, found.Code, found.RVA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v", err)
		for _, u := range irFunc.Unsupported {
			fmt.Fprintf(os.Stderr, "  %s", u)
		}
		fmt.Fprintln(os.Stderr)
		os.Exit(1)
	}

	gen, err := vm.Generate(irFunc)
	must(err)

	fmt.Printf("[*] %s: RVA=0x%X size=%d bytes | %d x86 insns -> %d IR -> %d bytecode bytes",
		found.Name, found.RVA, len(found.Code), found.InstrNum, len(irFunc.Insns), len(gen.Code))
	fmt.Println()

	if *verbose {
		for i := range irFunc.Insns {
			in := &irFunc.Insns[i]
			fmt.Printf("    IR[%02d] %-8s w=%-2d kind=%d dst=%d a=%d b=%d imm=0x%X disp=%d base=%d idx=%d scale=%d target=%d",
				i, in.Op.String(), in.Width, in.Kind, in.Dst, in.A, in.B, in.Imm, in.Disp,
				in.Base, in.Index, in.Scale, in.Target)
			fmt.Println()
		}
		fmt.Printf("    bytecode: % X", gen.Code)
		fmt.Println()
	}

	if *out != "" {
		must(os.WriteFile(*out, gen.Code, 0o644))
		fmt.Printf("[+] wrote %s", *out)
		fmt.Println()
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v", err)
		fmt.Fprintln(os.Stderr)
		os.Exit(1)
	}
}

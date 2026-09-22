// vmp-lift - 把一个函数的机器码 lift 成 VM 字节码（M1：只翻译，不注入）
//
// 用法: vmp-lift -exe <pe> -func <name> -out <file.vmb> [-v]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/vmpx/vmp-x/internal/lift/x64"
	"github.com/vmpx/vmp-x/internal/load/pe"
	"github.com/vmpx/vmp-x/internal/scan"
	"github.com/vmpx/vmp-x/internal/vm"
)

// codeAtRVA 取 RVA 处的一段代码（到指定长度或节尾为止）。
// 为什么需要它：PE32 的 exe 常常没有符号表/没有 MAP，而客户能从自己的 PDB 拿到 RVA。
func codeAtRVA(f *pe.File, rva uint32, n int) ([]byte, error) {
	for i := range f.Sections {
		s := &f.Sections[i]
		if rva < s.VirtualAddress || rva >= s.VirtualAddress+s.VirtualSize {
			continue
		}
		off := int(s.PointerToRawData + (rva - s.VirtualAddress))
		if off < 0 || off >= len(f.Data) {
			return nil, fmt.Errorf("RVA 0x%X 的原始偏移越界", rva)
		}
		end := off + n
		secEnd := int(s.PointerToRawData + s.SizeOfRawData)
		if secEnd > len(f.Data) {
			secEnd = len(f.Data)
		}
		if end > secEnd {
			end = secEnd
		}
		return f.Data[off:end], nil
	}
	return nil, fmt.Errorf("RVA 0x%X 不在任何节里", rva)
}

func main() {
	exe := flag.String("exe", "", "目标 PE")
	fn := flag.String("func", "", "函数名（符号）")
	mode := flag.Int("mode", 64, "解码模式：64（默认）或 32（PE32 客户机）")
	rvaFlag := flag.String("rva", "", "直接指定函数起始 RVA（十六进制，如 0x1234）；用于**没有符号表**的 PE32")
	lenFlag := flag.Int("len", 256, "-rva 模式下的代码长度上限（字节）")
	out := flag.String("out", "", "输出字节码文件")
	verbose := flag.Bool("v", false, "打印 IR 与字节码")
	manPath := flag.String("manifest", "build/vm_interp.json", "blob manifest（用于取 FRAME_SKEW）")
	flag.Parse()

	if *exe == "" || (*fn == "" && *rvaFlag == "") {
		fmt.Fprintln(os.Stderr, "usage: vmp-lift -exe <pe> (-func <name> | -rva 0x... [-len N]) [-mode 32|64] [-out out.vmb] [-v]")
		os.Exit(2)
	}

	f, err := pe.Open(*exe)
	must(err)

	// 目标函数：优先用 -rva（没有符号表的 PE32 只能靠它；客户的 PDB 可以用他们自己的
	// verify.py/dbghelp 枚举出 RVA 再喂进来），否则按 -func 查符号表。
	var code []byte
	var rva uint32
	fnName := *fn
	if *rvaFlag != "" {
		v, perr := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(*rvaFlag, "0x"), "0X"), 16, 32)
		must(perr)
		rva = uint32(v)
		code, err = codeAtRVA(f, rva, *lenFlag)
		must(err)
		fnName = fmt.Sprintf("rva_%X", rva)
	} else {
		found, ferr := scan.FindFunction(*exe, f, *fn)
		must(ferr)
		code, rva = found.Code, found.RVA
	}

	l := x64.NewLifterMode(f.ImageBase, *mode)
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
	irFunc, err := l.LiftFunc(fnName, code, rva)
	if err != nil {
		// 注意：LiftFunc 失败时返回的 irFunc 可能是 nil —— 直接取 .Unsupported 会 panic。
		// （这个 nil 解引用在本工具的 -rva 路径上第一次被踩出来；它正好违反"要么正确、
		// 要么明确拒绝"的底线：拒绝不该把工具自己搞崩。）
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		if irFunc != nil {
			for _, u := range irFunc.Unsupported {
				fmt.Fprintf(os.Stderr, "    %s\n", u)
			}
		}
		os.Exit(1)
	}

	gen, err := vm.Generate(irFunc)
	must(err)

	fmt.Printf("[*] %s: RVA=0x%X size=%d bytes | -> %d IR -> %d bytecode bytes",
		fnName, rva, len(code), len(irFunc.Insns), len(gen.Code))
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

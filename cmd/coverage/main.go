// coverage - 量化真实 PE/ELF 上"能被 lifter 翻译的代码比例"
//
// 用法: coverage <file> [...]
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/vmpx/vmp-x/internal/coverage"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: coverage <file> [...]")
		os.Exit(2)
	}
	var files []string
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, "-func=") {
			coverage.OnlyFuncs = append(coverage.OnlyFuncs, strings.TrimPrefix(a, "-func="))
			continue
		}
		files = append(files, a)
	}
	for _, p := range files {
		r, err := coverage.Analyze(p)
		if err != nil {
			fmt.Printf("== %s ==\n  [!] %v\n", p, err)
			continue
		}
		fmt.Printf("== %s (%s %s) ==\n", r.Path, r.Kind, r.Arch)
		if r.Note != "" {
			fmt.Printf("  %s\n", r.Note)
		}
		if r.Funcs == 0 {
			fmt.Println("  没有可分析的函数")
			continue
		}
		pct := func(a, b int) float64 {
			if b == 0 {
				return 0
			}
			return 100 * float64(a) / float64(b)
		}
		fmt.Printf("  函数 %d：整段可翻译 %d (%.1f%%)、部分 %d、完全不行 %d\n",
			r.Funcs, r.Full, pct(r.Full, r.Funcs), r.Partial, r.None)
		fmt.Printf("  指令 %d：可翻译 %d (%.1f%%)、被拒 %d\n",
			r.FuncInstrs, r.FuncInstrs-r.FuncBad, pct(r.FuncInstrs-r.FuncBad, r.FuncInstrs), r.FuncBad)
		fmt.Println("  被拒助记符 Top:")
		for _, s := range coverage.Top(r.MnemonicTop, 12) {
			fmt.Printf("    %s\n", s)
		}
		if len(r.SPLostTop) > 0 {
			fmt.Println("  弄丢 RSP 跟踪的指令 Top:")
			for _, s := range coverage.Top(r.SPLostTop, 10) {
				fmt.Printf("    %s\n", s)
			}
		}
		fmt.Println("  被拒原因 Top（附具体指令样本）:")
		for _, s := range coverage.Top(r.ReasonTop, 8) {
			fmt.Printf("    %s\n", s)
			// 原因里的键是纯 reason；这里按前缀找出它的样本
			for k, v := range r.Examples {
				if strings.HasPrefix(s, fmt.Sprintf("%-46s", k)) || strings.HasPrefix(s, k) {
					for _, e := range v {
						fmt.Printf("        e.g. %s\n", e)
					}
					break
				}
			}
		}
		if len(r.Sample) > 0 {
			fmt.Println("  样本:")
			for _, s := range r.Sample {
				fmt.Printf("    %-24s %4d 条指令、%d 条被拒  %s\n", s.Name, s.Instrs, s.Bad, s.Note)
			}
		}
		fmt.Println()
	}
}

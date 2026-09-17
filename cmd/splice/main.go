// splice - 开发工具：把文件中 [startMarker, endMarker) 之间的内容替换为另一个文件的内容
// 用法: splice <file> <startMarker> <endMarker> <replacementFile>
// 说明：本环境里 PowerShell 做文件手术会静默失败，所以这类操作统一用 Go 工具做。
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: splice <file> <startMarker> <endMarker> <replacementFile>")
		os.Exit(2)
	}
	path, startMark, endMark, replPath := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	repl, err := os.ReadFile(replPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	s := string(b)
	start := strings.Index(s, startMark)
	if start < 0 {
		fmt.Fprintln(os.Stderr, "[!] 起始标记未找到:", startMark)
		os.Exit(1)
	}
	rel := strings.Index(s[start:], endMark)
	if rel < 0 {
		fmt.Fprintln(os.Stderr, "[!] 结束标记未找到:", endMark)
		os.Exit(1)
	}
	end := start + rel
	out := s[:start] + string(repl) + s[end:]
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	fmt.Printf("已替换 %d 字节\n", end-start)
}

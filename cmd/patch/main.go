// patch - 开发工具：按"补丁说明文件"替换文件中的一段内容。
//
// 说明文件格式（UTF-8）：
//
//	第 1 行：起始标记（原样、不解释）
//	第 2 行：结束标记（原样、不解释）
//	其余   ：替换内容（含换行符原样写入；不会再插入结束标记）
//
// 用法: patch <file> <spec>
//
// 为什么要这个工具：本环境里 PowerShell 把带引号/竖线的参数传给子进程会被吞掉，
// 所以所有"带特殊字符的原地修改"都改成"内容写进文件 + 补丁"。
package main

import (
	"fmt"
	"os"
	"strings"
)

var nl = string(rune(10))

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: patch <file> <spec>")
		os.Exit(2)
	}
	target, specPath := os.Args[1], os.Args[2]
	spec, err := os.ReadFile(specPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	lines := strings.SplitN(string(spec), nl, 3)
	if len(lines) < 3 {
		fmt.Fprintln(os.Stderr, "[!] spec 至少需要 3 行：起始标记 / 结束标记 / 替换内容")
		os.Exit(1)
	}
	startMark := strings.TrimSuffix(lines[0], "")
	endMark := strings.TrimSuffix(lines[1], "")
	repl := lines[2]

	b, err := os.ReadFile(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	s := string(b)
	start := strings.Index(s, startMark)
	if start < 0 {
		fmt.Fprintln(os.Stderr, "[!] 起始标记未找到")
		os.Exit(1)
	}
	rel := strings.Index(s[start:], endMark)
	if rel < 0 {
		fmt.Fprintln(os.Stderr, "[!] 结束标记未找到")
		os.Exit(1)
	}
	end := start + rel
	out := s[:start] + repl + s[end:]
	if err := os.WriteFile(target, []byte(out), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	fmt.Printf("补丁完成：替换 %d 字节 -> %d 字节%s", end-start, len(repl), nl)
}

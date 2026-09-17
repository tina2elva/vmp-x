// trim - 开发工具：删除文件中两个标记之间的内容（含起始标记所在行到结束标记之前）
// 用法: trim <file> <startMarker> <endMarker>
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: trim <file> <startMarker> <endMarker>")
		os.Exit(2)
	}
	path, startMark, endMark := os.Args[1], os.Args[2], os.Args[3]
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	s := string(b)
	start := strings.Index(s, startMark)
	if start < 0 {
		fmt.Println("起始标记未找到，未改动")
		return
	}
	end := strings.Index(s[start:], endMark)
	if end < 0 {
		fmt.Fprintln(os.Stderr, "[!] 结束标记未找到")
		os.Exit(1)
	}
	end += start
	out := s[:start] + s[end:]
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	fmt.Printf("已删除 %d 字节\n", end-start)
}

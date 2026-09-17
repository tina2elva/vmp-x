// replace - 开发工具：在文件里做全局字符串替换
// 用法: replace <file> <old> <new>
// 说明：本环境里 PowerShell 做文件手术会静默失败，统一用 Go 做。
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: replace <file> <old> [new]  (new 省略表示删除)")
		os.Exit(2)
	}
	// 注意：PowerShell 会把**空字符串参数**丢掉，所以 new 必须可省略。
	replacement := ""
	if len(os.Args) >= 4 {
		replacement = os.Args[3]
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	s := string(b)
	n := strings.Count(s, os.Args[2])
	if n == 0 {
		fmt.Println("未找到待替换内容，未改动")
		return
	}
	s = strings.ReplaceAll(s, os.Args[2], replacement)
	if err := os.WriteFile(os.Args[1], []byte(s), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	fmt.Printf("替换 %d 处\n", n)
}

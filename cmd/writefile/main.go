// writefile - 开发工具：把源文件内容复制到目标路径
// 用法: writefile <src> <dst>
// 说明：本环境里 PowerShell 写文件会静默失败，统一用 Go 做。
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: writefile <src> <dst>")
		os.Exit(2)
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[2], b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	fmt.Printf("已写入 %s (%d 字节)\n", os.Args[2], len(b))
}

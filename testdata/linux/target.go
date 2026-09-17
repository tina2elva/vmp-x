// target.go - Linux/amd64 端到端验证用的目标程序
//
// 用法: linux_target <check-key|sum-to> <arg>
//
// 注意：Go 的内部 ABI 把第一个整数参数放在 RAX（不是 C 的 RDI），
// 打包/翻译不需要关心这一点——入口会 1:1 复制宿主寄存器，客户机语义保持一致。
package main

import (
	"fmt"
	"os"
	"strconv"
)

//go:noinline
func checkKey(x uint64) uint64 { return ((x * 7) + 42) ^ 0xFF }

//go:noinline
func sumTo(n int) int {
	s := 0
	for i := 1; i <= n; i++ {
		s += i
	}
	return s
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: linux_target <check-key|sum-to> <arg>")
		os.Exit(2)
	}
	v, err := strconv.ParseUint(os.Args[2], 0, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad arg")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "check-key":
		fmt.Println(checkKey(v))
	case "sum-to":
		fmt.Println(sumTo(int(v)))
	default:
		fmt.Fprintln(os.Stderr, "unknown function")
		os.Exit(2)
	}
}

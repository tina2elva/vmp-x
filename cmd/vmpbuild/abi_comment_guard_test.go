package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 守卫：vm_abi.h 里不允许出现「注释之外以 * 开头的行」。
// 原因是这类头文件会被汇编器预处理，悬空的注释续行会变成汇编语法错误 ——
// 这个坑我在 linux/arm64 与 win/arm64 上各踩过一次（CI 报 junk at end of line /
// unexpected token at start of statement），而本机能提前查出来。
func TestABIHeadersHaveNoDanglingCommentLines(t *testing.T) {
	paths, err := filepath.Glob("../../stub/*/*/vm_abi.h")
	if err != nil || len(paths) == 0 {
		t.Fatalf("找不到 vm_abi.h: %v", err)
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		inComment := false
		for i, line := range strings.Split(string(b), "\n") {
			trimmed := strings.TrimSpace(line)
			if !inComment && strings.HasPrefix(trimmed, "*") {
				t.Errorf("%s:%d 注释之外出现了以 * 开头的行: %q", p, i+1, trimmed)
			}
			if idx := strings.Index(line, "/*"); idx >= 0 {
				if end := strings.Index(line[idx+2:], "*/"); end < 0 {
					inComment = true
				}
			} else if inComment && strings.Contains(line, "*/") {
				inComment = false
			}
		}
	}
}

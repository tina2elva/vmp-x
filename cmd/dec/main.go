// dec - 开发用：用项目自己的解码器反汇编一段十六进制字节，便于定位解码问题
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	x64dec "github.com/vmpx/vmp-x/internal/decode/x64"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dec <hexbytes>")
		os.Exit(2)
	}
	code, err := hex.DecodeString(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	off := 0
	for off < len(code) {
		ins, err := x64dec.Decode(code[off:], uint64(off))
		if err != nil {
			fmt.Printf("+0x%02X: ERROR %v", off, err)
			fmt.Println()
			break
		}
		fmt.Printf("+0x%02X len=%d %s", off, ins.Len(), ins.Text())
		fmt.Println()
		off += ins.Len()
	}
	if off == len(code) {
		fmt.Println("(完整解码)")
	}
}

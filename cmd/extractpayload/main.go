// extractpayload - 从被保护的 ELF 里取出注入的 payload，便于在非 Linux 环境下做执行验证
//
// 用法: extractpayload -elf <packed.elf> -rva <sectionRVA(hex)> -size <size> -thunk <thunkRVA(hex)> -out payload.bin [-va <va(hex)>]
// 输出: VA、payload 大小、thunk 在 payload 内的偏移
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"

	elfload "github.com/vmpx/vmp-x/internal/load/elf"
)

func main() {
	elfPath := flag.String("elf", "", "被保护的 ELF")
	rva := flag.Uint64("rva", 0, "注入段的 RVA")
	size := flag.Int("size", 0, "注入段大小")
	thunkRVA := flag.Uint64("thunk", 0, "thunk 的 RVA")
	out := flag.String("out", "payload.bin", "输出文件")
	flag.Parse()

	f, err := elfload.Open(*elfPath)
	must(err)
	base := f.ImageBase()
	va := base + *rva
	data, err := f.ReadVA(va, *size)
	must(err)
	must(os.WriteFile(*out, data, 0o644))

	thunkOff := *thunkRVA - *rva
	fmt.Printf("payloadVA=0x%X size=0x%X thunkOff=0x%X\n", va, len(data), thunkOff)
	// 顺带把描述符内容打出来（描述符在 thunk 之前 VM_DESC_SIZE=64 字节）
	descOff := int(thunkOff) - 64
	if descOff >= 0 && descOff+64 <= len(data) {
		fmt.Printf("desc magic=0x%X selfRVA=0x%X codeRVA=0x%X codeLen=%d flags=0x%X encLen=%d\n",
			binary.LittleEndian.Uint32(data[descOff:]),
			binary.LittleEndian.Uint32(data[descOff+4:]),
			binary.LittleEndian.Uint32(data[descOff+8:]),
			binary.LittleEndian.Uint32(data[descOff+12:]),
			binary.LittleEndian.Uint32(data[descOff+20:]),
			binary.LittleEndian.Uint32(data[descOff+16:]))
		nonce := data[descOff+32 : descOff+44]
		tag := data[descOff+44 : descOff+60]
		fmt.Printf("desc nonce=%X tag=%X\n", nonce, tag)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
}

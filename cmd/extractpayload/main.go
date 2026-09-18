// extractpayload - 从被保护的 ELF 里取出注入的 payload，便于在非 Linux 环境下做执行验证
//
// 用法: extractpayload -elf <packed.elf> -rva <sectionRVA(hex)> -size <size> -thunk <thunkRVA(hex)> -out payload.bin [-va <va(hex)>]
// 输出: VA、payload 大小、thunk 在 payload 内的偏移
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	elfload "github.com/vmpx/vmp-x/internal/load/elf"
)

func main() {
	elfPath := flag.String("elf", "", "被保护的 ELF")
	rva := flag.Uint64("rva", 0, "注入段的 RVA")
	size := flag.Int("size", 0, "注入段大小")
	thunkRVA := flag.Uint64("thunk", 0, "thunk 的 RVA")
	out := flag.String("out", "payload.bin", "输出文件")
	patchOut := flag.String("patchout", "", "把入口补丁字节（及它相对 payload 起点的偏移）写成文本，供探针在读到\"未映射的目标页\"时也能满足运行期校验")
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
		// 运行期校验要读目标函数入口的补丁字节（pb = d + reserved2，按 ASLR 无关的相对偏移定位）。
		// 探针只映射 payload 段，目标页不在映射里 —— 这里把补丁字节连同偏移导出来，让探针补上这一段，
		// 这样"探针里跑"与"真实 Linux 上跑"对内层校验是等价的。
		flags := binary.LittleEndian.Uint32(data[descOff+20:])
		plen := int((flags >> 8) & 0xFF)
		rel := int32(binary.LittleEndian.Uint32(data[descOff+28:]))
		if *patchOut != "" && plen > 0 {
			off := int32(descOff) + rel
			patch, perr := f.ReadVA(base+*rva+uint64(int64(off)), plen)
			if perr != nil {
				must(perr)
			}
			var sb []string
			sb = append(sb, fmt.Sprintf("%d %s", off, hex.EncodeToString(patch)))
			must(os.WriteFile(*patchOut, []byte(strings.Join(sb, "\n")+"\n"), 0o644))
			fmt.Printf("patch off=0x%X bytes=%X\n", off, patch)
		}
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
}

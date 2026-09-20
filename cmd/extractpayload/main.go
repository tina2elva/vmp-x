// extractpayload - 从被保护的 ELF 里取出注入的 payload，便于在非 Linux 环境下做执行验证
//
// 用法: extractpayload -elf <packed.elf> -rva <sectionRVA(hex)> -size <size> -thunk <thunkRVA(hex)> -out payload.bin [-va <va(hex)>]
// 输出: VA、payload 大小、thunk 在 payload 内的偏移
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vmpx/vmp-x/internal/inject"
	elfload "github.com/vmpx/vmp-x/internal/load/elf"
)

func main() {
	elfPath := flag.String("elf", "", "被保护的 ELF")
	rva := flag.Uint64("rva", 0, "注入段的 RVA")
	size := flag.Int("size", 0, "注入段大小")
	thunkRVA := flag.Uint64("thunk", 0, "thunk 的 RVA")
	out := flag.String("out", "payload.bin", "输出文件")
	patchOut := flag.String("patchout", "", "把入口补丁字节（及它相对 payload 起点的偏移）写成文本，供探针在读到\"未映射的目标页\"时也能满足运行期校验")
	manPath := flag.String("manifest", "", "blob manifest：用于解描述符的**字段掩码**（(3) 起描述符标量不再是明文）")
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
		// (3) 起描述符的 8..32 是加了掩码的（codeRVA/codeLen/encLen/flags/reserved1/reserved2）。
		// 本工具是**诊断工具**，所以拿 manifest 里的主密钥 + 掩码种子把这一段解回来再打印；
		// 不传 -manifest 就只能打印密文 —— 这也顺便证明了"静态读不出来"。
		if *manPath != "" {
			mb, rerr := os.ReadFile(*manPath)
			must(rerr)
			var m struct {
				Key           string `json:"key"`
				FieldMaskSalt uint32 `json:"fieldMaskSalt"`
			}
			must(json.Unmarshal(mb, &m))
			key, kerr := hex.DecodeString(m.Key)
			must(kerr)
			md := inject.FieldMask(key, inject.FieldMaskDomainDesc, m.FieldMaskSalt)
			inject.XorMask(data, descOff+8, 24, md[:24])
			fmt.Println("[*] descriptor scalars decoded with the manifest field mask")
		} else {
			fmt.Println("[!] no -manifest: descriptor scalars below are still masked (not plaintext)")
		}
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
			funcRVA := *rva + uint64(int64(off))
			// 优先**合成**补丁字节：镜像可能被整体加密（-enc-image-elf），
			// 从 .text 里读出来的是密文，会让探针的运行期校验误判（CI run #294 的现场）。
			patch, perr := synthPatch(funcRVA, *thunkRVA, plen)
			if perr != nil {
				// 退路：老办法，从不加密的镜像里读。
				patch, perr = f.ReadVA(base+funcRVA, plen)
				if perr != nil {
					must(perr)
				}
			}
			var sb []string
			sb = append(sb, fmt.Sprintf("%d %s", off, hex.EncodeToString(patch)))
			must(os.WriteFile(*patchOut, []byte(strings.Join(sb, "\n")+"\n"), 0o644))
			fmt.Printf("patch off=0x%X bytes=%X\n", off, patch)
		}
	}
}

// synthPatch 由「函数入口 RVA + thunk RVA」算出入口补丁，语义与 vmpack 写进镜像的完全一致。
// 为什么需要它：整体加密之后 .text 在磁盘上是密文，探针要的补丁字节不能从镜像里读。
func synthPatch(funcRVA, thunkRVA uint64, plen int) ([]byte, error) {
	switch plen {
	case 5: // x86-64：E9 rel32（相对下一条指令）
		rel := int64(thunkRVA) - int64(funcRVA) - 5
		if rel < -0x80000000 || rel > 0x7FFFFFFF {
			return nil, fmt.Errorf("rel32 越界")
		}
		b := make([]byte, 5)
		b[0] = 0xE9
		binary.LittleEndian.PutUint32(b[1:], uint32(int32(rel)))
		return b, nil
	case 8: // arm64：mov x16, x30 ; B imm26（相对本指令 +4 处的那条）
		delta := int64(thunkRVA) - (int64(funcRVA) + 4)
		if delta%4 != 0 {
			return nil, fmt.Errorf("arm64 分支目标未 4 字节对齐")
		}
		imm := delta / 4
		if imm < -(1<<25) || imm >= (1<<25) {
			return nil, fmt.Errorf("arm64 分支超出 ±128MB")
		}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint32(b, 0xAA1E03F0) // mov x16, x30
		binary.LittleEndian.PutUint32(b[4:], 0x14000000|(uint32(imm)&0x03FFFFFF))
		return b, nil
	default:
		return nil, fmt.Errorf("未知的入口补丁长度 %d", plen)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
}

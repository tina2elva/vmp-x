package main

// lic-export：把 JSON 授权导出成**运行期用的二进制授权**（<产物>.vmplic.bin）。
//
// 为什么要有二进制形态：blob 侧没有 JSON 解析器，也不该有；二进制格式让 C 侧只需几十行。
// 布局（全部小端，与 stub/win/x64/vm_interp.c 的 vm_license_check 严格一致）：
//   hdr:  magic(4)=0x564C5043  version(4)=1  vendorHash(4)  count(4)  reserved(8)   = 24 字节
//   item: { productHash(4)  pad(4)  notAfter(i64，Unix 秒，0=永久) } × count            = 16 字节/项
//   sig:  64 字节 ECDSA P-256（r||s），对 hdr+items 全部字节签名
//
// 哈希口径：SHA-256(字符串)[0:4] —— 两侧一致（Go 侧在这里算，C 侧只做 4 字节比较）。

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"time"
)

const licMagic = uint32(0x564C5043)

func base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func licHash4(s string) uint32 {
	h := sha256.Sum256([]byte(s))
	return binary.LittleEndian.Uint32(h[0:4])
}

func cmdLicExport(args []string) {
	fs := flag.NewFlagSet("lic-export", flag.ExitOnError)
	licPath := fs.String("lic", "", "JSON 授权（.vmplic）")
	key := fs.String("key", "", "签发者私钥（.priv）—— 必须与产物里烘进的公钥配对")
	out := fs.String("out", "", "输出二进制授权，命名必须是 <产物全路径>.vmplic.bin")
	fs.Parse(args)
	if *licPath == "" || *key == "" || *out == "" {
		fmt.Println("[!] 需要 --lic --key --out")
		os.Exit(2)
	}
	l := readLicense(*licPath)
	n := 24 + len(l.Items)*16
	buf := make([]byte, n)
	binary.LittleEndian.PutUint32(buf[0:], licMagic)
	binary.LittleEndian.PutUint32(buf[4:], 1)
	binary.LittleEndian.PutUint32(buf[8:], licHash4(l.VendorID))
	binary.LittleEndian.PutUint32(buf[12:], uint32(len(l.Items)))
	for i, it := range l.Items {
		e := buf[24+i*16:]
		binary.LittleEndian.PutUint32(e[0:], licHash4(it.ProductID))
		var notAfter int64
		if it.Expiry != "perpetual" {
			t, err := time.Parse(time.RFC3339, it.Expiry)
			must(err)
			notAfter = t.Unix()
		}
		binary.LittleEndian.PutUint64(e[8:], uint64(notAfter))
	}
	sig := signDetached(loadPriv(*key), buf)
	sigRaw, err := base64Decode(sig)
	must(err)
	must(os.WriteFile(*out, append(buf, sigRaw...), 0o644))
	fmt.Printf("[+] 二进制授权已导出: %s（vendorID=%s，%d 个产品，可写区 %d + 签名 64 字节）\n",
		*out, l.VendorID, len(l.Items), n)
	for _, it := range l.Items {
		fmt.Printf("    %-24s %-24s productHash=%08X\n", it.ProductID, it.Expiry, licHash4(it.ProductID))
	}
	fmt.Println("    部署：放到 <产物全路径>.vmplic.bin（与产物同目录、同名 + 该后缀）")
}

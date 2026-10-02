package cred

// 产物主密钥的「CNG/TPM 包裹」文件格式（<产物>.vmpkey.ncrypt）。
//
// 为什么需要它：<产物>.vmpkey.dpapi 保护的是「磁盘上的密文」——
// 同一用户在本机仍可以调 CryptUnprotectData 解开。这里包裹用的是 CNG
// 持久化密钥（TPM 优先，退软件 KSP）的**公钥**，私钥永远不以可用形式存在于文件里；
// 运行期由 blob 调 NCryptOpenKey + NCryptDecrypt 现场解出 32 字节主密钥。
//
// 格式（小端，运行期 stub/win/x64/vm_interp.c 里是同一份常量）：
//
//	0    8    magic "VMPXNCR1"
//	8    4    u32 nameLen  (1..64)
//	12   4    u32 blobLen  (32..512)
//	16   N    密钥名（ASCII，不含 NUL）
//	16+N C    RSA 密文（PKCS#1 v1.5）
//
// 只能整文对齐：多余的尾巴一律当「文件被动过」拒绝——
// 否则改个字节可能只让密文指针挪一位而静默地从另一处读。

import (
	"encoding/binary"
	"fmt"
)

const (
	// PayloadNCryptMagic：.ncrypt 文件的魔数（8 字节）。
	PayloadNCryptMagic = "VMPXNCR1"
	// PayloadWrapKeyName：包裹用的持久化 RSA 密钥名（默认）。
	// 同一台机器上多个产物共用一把——它只负责「包」，
	// 每个产物的 32 字节主密钥还是各自独立的（密文不同）。
	PayloadWrapKeyName = "vmpx-payload-key-v1"
	// PayloadNCryptSuffix：产物侧后缀（<产物全名>.vmpkey.ncrypt）。
	PayloadNCryptSuffix = ".ncrypt"

	// PayloadNCryptHeaderLen = magic(8) + nameLen(4) + blobLen(4)。
	PayloadNCryptHeaderLen = 16
	// PayloadWrapNameMax / PayloadWrapBlobMax：运行期缓冲区就按这两个上限定义。
	PayloadWrapNameMax = 64
	PayloadWrapBlobMax = 512
)

// CNGTPMProviderName：硬件（TPM）提供程序的名字。
// 其余提供程序（软件 KSP）只能说“私钥不出 CNG 边界”，不能说“私钥不出芯片”。
const CNGTPMProviderName = "Microsoft Platform Crypto Provider"

// CNGIsHardwareProvider 报告这个提供程序名的密钥是否由硬件（TPM）持有。
func CNGIsHardwareProvider(name string) bool { return name == CNGTPMProviderName }

// ValidWrapKeyName 校验包裹密钥名：1..64 个可打印 ASCII。
func ValidWrapKeyName(name string) error {
	if len(name) < 1 || len(name) > PayloadWrapNameMax {
		return fmt.Errorf("密钥名长度必须在 1..%d 之间（实得 %d）", PayloadWrapNameMax, len(name))
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			return fmt.Errorf("密钥名必须是可打印 ASCII（位置 %d）", i)
		}
	}
	return nil
}

// MarshalPayloadNCrypt 把密钥名 + RSA 密文装成 .ncrypt 文件内容。
func MarshalPayloadNCrypt(name string, ct []byte) ([]byte, error) {
	if err := ValidWrapKeyName(name); err != nil {
		return nil, err
	}
	if len(ct) < 32 || len(ct) > PayloadWrapBlobMax {
		return nil, fmt.Errorf("密文长度必须在 32..%d 之间（实得 %d）", PayloadWrapBlobMax, len(ct))
	}
	out := make([]byte, PayloadNCryptHeaderLen+len(name)+len(ct))
	copy(out[0:8], PayloadNCryptMagic)
	binary.LittleEndian.PutUint32(out[8:12], uint32(len(name)))
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(ct)))
	copy(out[PayloadNCryptHeaderLen:], name)
	copy(out[PayloadNCryptHeaderLen+len(name):], ct)
	return out, nil
}

// ParsePayloadNCrypt 解析 .ncrypt 文件内容，返回密钥名与 RSA 密文。
// 与运行期 blob 里的解析**逐条一致**（包括“必须正好用完文件”这一条）。
func ParsePayloadNCrypt(blob []byte) (string, []byte, error) {
	if len(blob) < PayloadNCryptHeaderLen {
		return "", nil, fmt.Errorf("文件太短（%d 字节）", len(blob))
	}
	if string(blob[0:8]) != PayloadNCryptMagic {
		return "", nil, fmt.Errorf("魔数不对（不是 .ncrypt 形态）")
	}
	nl := binary.LittleEndian.Uint32(blob[8:12])
	cl := binary.LittleEndian.Uint32(blob[12:16])
	if nl < 1 || nl > PayloadWrapNameMax {
		return "", nil, fmt.Errorf("密钥名长度超限（%d）", nl)
	}
	if cl < 32 || cl > PayloadWrapBlobMax {
		return "", nil, fmt.Errorf("密文长度超限（%d）", cl)
	}
	want := PayloadNCryptHeaderLen + int(nl) + int(cl)
	if want != len(blob) {
		return "", nil, fmt.Errorf("文件大小与头里声明的不一致（声明 %d，实际 %d）", want, len(blob))
	}
	name := string(blob[PayloadNCryptHeaderLen : PayloadNCryptHeaderLen+int(nl)])
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			return "", nil, fmt.Errorf("密钥名里有非 ASCII 字节（位置 %d）", i)
		}
	}
	ct := make([]byte, cl)
	copy(ct, blob[PayloadNCryptHeaderLen+int(nl):])
	return name, ct, nil
}

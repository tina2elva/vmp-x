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
	// PayloadPlainLen：被包裹的产物主密钥长度（恒定 32 字节）。
	//
	// 为什么它放在这个**无 build tag** 的文件里：payloadwrap.go 的 VerifyWrappedPayload
	// （写文件前的自检，平台无关的那半）要用它。原先这个常量定义在 ncrypt_windows.go
	// （//go:build windows）里 —— 于是 GOOS=linux 的 go build ./... 直接报
	// "undefined: wrapPlainLen"，整条 Linux 半场（tools/wsl_linux.ps1）红。
	// 常量属于**格式**，不是平台能力，所以归到这里。
	PayloadPlainLen = 32
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

// payloadUnwrap 是**自检**要用的解包裹实现。生产里它永远是 CNGUnwrapPayloadBlob，
// 只有 internal/cred 包内的测试会临时换掉它 —— 存在的唯一理由见
// internal/cred/selfcheck_test.go 的长注释：自检失败必须"拒绝写出"，
// 而这条路径在生产里**不可达**（刚做出来的 blob 必然解回原值），
// 于是没有接缝就只剩"读代码"这一种证据。
//
// 刻意的取舍（不引入任何生产开关）：
//   - 它是**包内变量**，不是导出 API，也不是命令行/环境变量开关 —— 部署里没有任何东西能改它；
//   - 唯一的调用点在 VerifyWrappedPayload 里，默认值与生产路径逐字节相同；
//   - 代价是每次调用多一次间接跳转（一次 RSA-2048 解密的噪声量级）；
//   - 收益是"自检不过 ⇒ 拒绝写出"这条规则第一次有了**能失败**的证明。
var payloadUnwrap = CNGUnwrapPayloadBlob

// payloadSelfCheckError 判定"刚做出来的 .ncrypt 内容"能不能通过自检：
//   - 解不开（blob 结构不对/本机没有那把密钥/填充被改）→ 拒绝；
//   - 解得开但长度不是 32 或与输入不逐字节相等 → 拒绝。
//
// 返回 nil 才允许写出。与 cmd/vmpkeywrap 的 wrapNCrypt 是同一套判据
// （那边照抄这段就会分叉，所以判据只留在这里一份）。
func payloadSelfCheckError(blob []byte, want []byte) error {
	back, err := payloadUnwrap(blob)
	if err != nil {
		return fmt.Errorf("刚做出的密文本机解不开: %w", err)
	}
	if len(back) != len(want) || string(back) != string(want) {
		return fmt.Errorf("解回来的主密钥与输入不一致（%d 字节 vs %d 字节）", len(back), len(want))
	}
	return nil
}

// VerifyWrappedPayload：写文件**之前**的自检。cmd/vmpkeywrap 在写出前必须先过这一关；
// 不过就拒绝写出（宁可这里失败，也不要让产物在部署后才炸）。
func VerifyWrappedPayload(blob []byte, want []byte) error {
	if len(want) != PayloadPlainLen {
		return fmt.Errorf("输入主密钥必须是 %d 字节（实得 %d）", PayloadPlainLen, len(want))
	}
	return payloadSelfCheckError(blob, want)
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

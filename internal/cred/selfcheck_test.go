//go:build vmpcredselftest

package cred

// A3：「自检失败就拒绝写出」的**可失败证明**。
//
// 问题：cmd/vmpkeywrap 里那条规则（刚做出来的 .ncrypt 内容解回来必须与输入逐字节一致，
// 否则拒绝写出）在生产里**不可达** —— 工具自己加密、自己解，除非 CNG 坏了，否则永远一致。
// 于是它长期只有"读代码"这一种证据，没有故障注入。
//
// 干净做法（不引入生产开关）：给包内那条判据加一个**测试专用接缝**
// （payloadwrap.go 的 payloadUnwrap：默认就是生产的 CNGUnwrapPayloadBlob），
// 再用一个**能解析、但解回来不一致/解不开**的 blob 去喂 VerifyWrappedPayload。
//
// 为什么整条测试用 build tag 关起来：普通构建（go test ./...）里这个文件根本不参与编译，
// 换接缝的代码不会在任何常规测试里被执行；只有本任务验收时显式带上
// -tags vmpcredselftest 跑一次。生产二进制里没有任何开关能改接缝（见 payloadwrap.go 的注释）。
//
// 用法（在仓库根）：
//
//	go test -tags vmpcredselftest -run TestSelfCheckRefusesToWrite -v ./internal/cred
//
// 校准（证明这条测试能红）：把 cmd/vmpkeywrap 的 wrapNCrypt 里
// "if err := cred.VerifyWrappedPayload(...)" 换成不检查，
// 或把 payloadSelfCheckError 的比较去掉，再按上面的命令跑 —— 测试必须失败。

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// swapUnwrap 临时把自检用的解包裹实现换成给定函数；t.Cleanup 恢复。
func swapUnwrap(t *testing.T, fn func([]byte) ([]byte, error)) {
	t.Helper()
	old := payloadUnwrap
	payloadUnwrap = fn
	t.Cleanup(func() { payloadUnwrap = old })
}

// buildParseableBlob 造一个**能通过 ParsePayloadNCrypt** 的 blob
// （魔数/两个长度/整文对齐都对），但它的"密文"不是真密文 —— 解包裹必然失败。
// 这一步本身也是标定：先断言它真的能被解析，否则下面证明的是"解析失败"，不是"自检拒绝"。
func buildParseableBlob(t *testing.T, name string) []byte {
	t.Helper()
	blob, err := MarshalPayloadNCrypt(name, bytes.Repeat([]byte{0xA5}, 256))
	if err != nil {
		t.Fatalf("造 blob: %v", err)
	}
	if _, _, err := ParsePayloadNCrypt(blob); err != nil {
		t.Fatalf("标定失败：这个 blob 本该能解析，实得 %v", err)
	}
	return blob
}

func TestSelfCheckRefusesToWrite(t *testing.T) {
	raw := bytes.Repeat([]byte{0x42}, PayloadPlainLen)
	blob := buildParseableBlob(t, PayloadWrapKeyName)

	// 先立"正例基线"：如果解包裹返回与输入一致，自检必须放行。
	// 没有这条，下面的拒绝可能只是"任何输入都被拒"（空断言）。
	swapUnwrap(t, func(b []byte) ([]byte, error) { return append([]byte(nil), raw...), nil })
	if err := VerifyWrappedPayload(blob, raw); err != nil {
		t.Fatalf("基线：解回来与输入一致时应放行，实得 %v", err)
	}

	// (1) 解回来**不一致**（能解析、能解开，但值不对）⇒ 必须拒绝写出
	other := bytes.Repeat([]byte{0x43}, PayloadPlainLen)
	swapUnwrap(t, func(b []byte) ([]byte, error) { return append([]byte(nil), other...), nil })
	if err := VerifyWrappedPayload(blob, raw); err == nil {
		t.Fatalf("解回来的主密钥与输入不一致，自检却放行了 —— 写出路径没有拒绝")
	} else {
		t.Logf("拒绝原因（不一致）: %v", err)
	}

	// (2) 解**不开**（能解析，解包裹报错）⇒ 必须拒绝写出
	swapUnwrap(t, func(b []byte) ([]byte, error) { return nil, fmt.Errorf("NCryptDecrypt 失败（注入的故障）") })
	if err := VerifyWrappedPayload(blob, raw); err == nil {
		t.Fatalf("解不开的 blob，自检却放行了 —— 写出路径没有拒绝")
	} else {
		t.Logf("拒绝原因（解不开）: %v", err)
	}

	// (3) 长度不对（32 字节以外的返回）⇒ 同样拒绝
	swapUnwrap(t, func(b []byte) ([]byte, error) { return raw[:16], nil })
	if err := VerifyWrappedPayload(blob, raw); err == nil {
		t.Fatalf("解回来的长度不是 32，自检却放行了")
	}

	// (4) 名里带控制字节的 blob 连解析都不该过（运行期拒绝它的理由，这里再钉一次）
	ctl := buildParseableBlob(t, PayloadWrapKeyName)
	// 把名字的第一个字节改成 0x1f（旧 C 规则会放行、Go 规则必须拒绝）
	ctl[PayloadNCryptHeaderLen] = 0x1f
	// 结构仍然"能解析"吗？Go 的 ParsePayloadNCrypt 会拒绝它 —— 这正是与 C 侧对齐后的行为
	if _, _, err := ParsePayloadNCrypt(ctl); err == nil {
		t.Errorf("名字里有 0x1f 的 blob 不应被解析接受（与运行期 keyname_probe 的规则一致）")
	}

	// 标定：确认自检**真的调用了接缝**（否则上面两条证明的是别的东西）。
	// 手段：给一段连魔数都不对的 blob —— 生产实现（CNGUnwrapPayloadBlob）必然拒绝它；
	// 接缝若被调用，返回值就由接缝决定。先让它返回与输入一致 ⇒ 自检必须**放行**
	// （证明解析被绕过 = 确实走的是接缝）；再让它报错 ⇒ 必须拒绝（同样的 blob，结论随接缝变）。
	junk := make([]byte, 32)
	swapUnwrap(t, func(b []byte) ([]byte, error) { return append([]byte(nil), raw...), nil })
	if err := VerifyWrappedPayload(junk, raw); err != nil {
		t.Fatalf("接缝被调用时应放行（它返回了与输入一致的值），实得 %v —— 接缝没被用上？", err)
	}
	sentinel := errors.New("seam-sentinel")
	swapUnwrap(t, func(b []byte) ([]byte, error) { return nil, sentinel })
	if err := VerifyWrappedPayload(junk, raw); !errors.Is(err, sentinel) {
		t.Fatalf("接缝报错时应原样带出来，实得 %v", err)
	}
	// 顺便钉住"整文对齐"这条：多一个尾巴也必须被拒
	tail := append(append([]byte(nil), blob...), 0x00)
	if _, _, err := ParsePayloadNCrypt(tail); err == nil {
		t.Errorf("多一个尾巴的 blob 不应被解析接受")
	}
}

//go:build vmpcredselftest

package cred

// A3：「自检失败就拒绝写出」的**可失败证明**（判据层）。
//
// 这条规则在生产里天然不可达：工具自己加密、自己解，没有故障就永远一致（见 payloadwrap.go 的
// payloadUnwrap 注释）。所以证据只能靠**测试专用接缝**：本文件用包内的 payloadUnwrap 换掉解包裹
// 实现，再喂一个「能解析、但解回来不一致/解不开/长度不对」的 blob，断言 VerifyWrappedPayload 拒绝。
//
// 事实澄清（此前这里写过两处不成立的话，t7 的 F2 指出，逐条改掉）：
//   1) 本条测试**不是**默认测试集的一部分：它带 `//go:build vmpcredselftest`，所以 `go test ./...`
//      与 CI 都不会跑到它。它要显式带 tag 才跑（命令见下）。**CLI 那条胶水**（cmd/vmpkeywrap 里
//      「自检失败就 os.Exit(1)」）的证据不在这里，而在 `tools/e2e.ps1` 的用例
//      `keywrap/selfcheck-refuse-write`（默认门禁/CI 会跑到它，断言 exit=1 + 输出文件不存在 +
//      stderr 含「自检失败（拒绝写出）」，并配一个未注入的对照 rc=0 + 文件存在）。
//   2) 「cred 依赖 cmd/vmpkeywrap」这种说法是错的：Go 里 main 包不能作为库被 import，
//      而且 cred **根本不 import cmd**。依赖方向本身有一条**可执行**断言：
//      payloadwrap_test.go 的 TestCredDoesNotDependOnCmd（go list -deps，默认 go test 就会跑）。
//
// 用法（在仓库根）：
//
//	go test -tags vmpcredselftest -run TestSelfCheckRefusesToWrite -v ./internal/cred
//
// 校准（证明这条测试**能红**，实测过）：把 payloadSelfCheckError 里那段
// `len(back) != len(want) || string(back) != string(want)` 判据删掉 ⇒ 本测试立刻红在
// 「解回来的主密钥与输入不一致，自检却放行了」。注意：**不能**用「删掉 cmd/vmpkeywrap 的
// os.Exit(1)」来校准这一条 —— 本测试不经过那一层（那一层由 e2e 的用例和它的校准覆盖）。

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

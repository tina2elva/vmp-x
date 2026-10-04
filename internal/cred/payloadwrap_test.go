package cred

// 产物主密钥 .ncrypt 形态的格式测试。
//
// 为什么值得单测：这份格式是**工具侧（Go）与运行期（stub/win/x64/vm_interp.c）**
// 共用的：工具写出来的每一个字节，运行期都要按同一套规则读。工具自检只能证明“解得开”，
// 证不了“头里声明的长度/边界检查一致”——所以那些边界在这里钉死。
// 注意：这里的用例都不触碰 CNG/TPM（那一部分只在 Windows 且依赖本机密钥），
// 所以在任何平台上都能跑。

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestPayloadNCryptRoundTrip(t *testing.T) {
	name := PayloadWrapKeyName
	ct := bytes.Repeat([]byte{0xA5}, 256) // RSA-2048 密文的长度
	blob, err := MarshalPayloadNCrypt(name, ct)
	if err != nil {
		t.Fatalf("MarshalPayloadNCrypt: %v", err)
	}
	if len(blob) != PayloadNCryptHeaderLen+len(name)+len(ct) {
		t.Fatalf("长度不对: %d", len(blob))
	}
	if !bytes.HasPrefix(blob, []byte(PayloadNCryptMagic)) {
		t.Fatalf("魔数不对: % x", blob[:8])
	}
	gotName, gotCT, err := ParsePayloadNCrypt(blob)
	if err != nil {
		t.Fatalf("ParsePayloadNCrypt: %v", err)
	}
	if gotName != name {
		t.Fatalf("密钥名不对: %q", gotName)
	}
	if !bytes.Equal(gotCT, ct) {
		t.Fatalf("密文不对")
	}
}

func TestPayloadNCryptHeaderIsLittleEndian(t *testing.T) {
	// 运行期是按字节拼小端读的（vm_interp.c）：这里钉死字节序，
	// 免得以后改成 encoding/binary.BigEndian 而运行期静默地读错偏移。
	blob, err := MarshalPayloadNCrypt("AB", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatalf("MarshalPayloadNCrypt: %v", err)
	}
	if blob[8] != 2 || blob[9] != 0 || blob[10] != 0 || blob[11] != 0 {
		t.Fatalf("nameLen 字节序不是小端: % x", blob[8:12])
	}
	if blob[12] != 32 || blob[13] != 0 || blob[14] != 0 || blob[15] != 0 {
		t.Fatalf("blobLen 字节序不是小端: % x", blob[12:16])
	}
}

func TestPayloadNCryptRejectsBadInput(t *testing.T) {
	good, err := MarshalPayloadNCrypt("k", bytes.Repeat([]byte{7}, 64))
	if err != nil {
		t.Fatalf("MarshalPayloadNCrypt: %v", err)
	}
	cases := []struct {
		name string
		blob []byte
	}{
		{"nil", nil},
		{"short", good[:10]},
		{"bad magic", append([]byte("XXXXXXXX"), good[8:]...)},
		{"trailing byte", append(append([]byte{}, good...), 0)},
		{"truncated body", good[:len(good)-1]},
	}
	if _, _, err := ParsePayloadNCrypt(cases[0].blob); err == nil {
		t.Errorf("%s: 应该报错", cases[0].name)
	}
	for _, c := range cases[1:] {
		if _, _, err := ParsePayloadNCrypt(c.blob); err == nil {
			t.Errorf("%s: 应该报错", c.name)
		}
	}
	// 字段边界：名字太长 / 非 ASCII，密文太短或太长 —— 都要在**写文件之前**拒绝
	if _, err := MarshalPayloadNCrypt(string(bytes.Repeat([]byte{'x'}, PayloadWrapNameMax+1)), bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Errorf("超长密钥名应该被拒绝")
	}
	if _, err := MarshalPayloadNCrypt("", bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Errorf("空密钥名应该被拒绝")
	}
	if _, err := MarshalPayloadNCrypt("kéy", bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Errorf("非 ASCII 密钥名应该被拒绝")
	}
	if _, err := MarshalPayloadNCrypt("k", bytes.Repeat([]byte{1}, 31)); err == nil {
		t.Errorf("过短密文应该被拒绝")
	}
	if _, err := MarshalPayloadNCrypt("k", bytes.Repeat([]byte{1}, PayloadWrapBlobMax+1)); err == nil {
		t.Errorf("过长密文应该被拒绝")
	}
	// 签名与运行期一致的常量（改了就是改了磁盘格式）
	if PayloadNCryptMagic != "VMPXNCR1" || PayloadNCryptHeaderLen != 16 || PayloadWrapNameMax != 64 || PayloadWrapBlobMax != 512 {
		t.Errorf("格式常量被改动：运行期 vm_interp.c 里是同一份，两边必须一起改")
	}
}

// A1 的 Go 侧那一半：密钥名的字节域必须是**可打印 ASCII**（0x20..0x7e），不许"只拒 0x00 和 >127"。
//
// 为什么单列一条：运行期（stub/win/x64/vm_interp.c）此前只拒 0x00/>127，
// 于是 0x01..0x1f 与 0x7f 在两边被判成不同的东西 —— 而工具侧永远不会写出这种名字，
// 分叉是**静默**的（fail-closed：找不到这样的密钥 → 走硬门）。这条把 Go 的端点逐个钉死，
// C 侧是逐字节同一个区间，由 stub/win/x64/keyname_probe.c（e2e 里编译并运行）钉死。
// 改坏任一侧：这里红（Go 侧）或 keyname_probe 红（C 侧）。
func TestValidWrapKeyNameBoundaries(t *testing.T) {
	// 标定：两端点必须**接受**（能失败的前提是"接受"这件事本身被断言过）
	for _, ok := range []string{" ", "~", "k", "A", "vmpx-payload-key-v1", string([]byte{0x20, 0x7e})} {
		if err := ValidWrapKeyName(ok); err != nil {
			t.Errorf("ValidWrapKeyName(%q) 应接受，实得 %v", ok, err)
		}
	}
	// 每一步都要**拒绝**：0x1f/0x20 与 0x7e/0x7f 是这条规则的两条边界
	for _, bad := range []string{
		"",             // 长度下界
		"\x00",         // NUL（旧规则拒过它，但新规则拒的是整段 <0x20）
		"\x01", "\x09", // TAB 与更低的控制字符：旧 C 规则会**放行**
		"\x1f",                                     // 紧邻 0x20 的下方
		"\x7f",                                     // DEL：紧邻 0x7e 的上方
		"\x80",                                     // 非 ASCII 的最高位
		"k\x00y", "k\x1fy", "k\x7fy", "k\xc3\xa9y", // 夹在名字中间（é 的 UTF-8 两字节）
		"k\xffy",
	} {
		if err := ValidWrapKeyName(bad); err == nil {
			t.Errorf("ValidWrapKeyName(%q) 应拒绝（规则是 0x20..0x7e 的可打印 ASCII）", bad)
		}
	}
	// 整个字节域逐字节断言：接受的**恰好**是 0x20..0x7e，不多不少。
	for c := 0; c < 256; c++ {
		name := "k" + string(rune(byte(c))) + "y"
		err := ValidWrapKeyName(name)
		want := (c >= 0x20 && c <= 0x7e)
		if want && err != nil {
			t.Errorf("字节 0x%02x 应被接受，实得 %v", c, err)
		}
		if !want && err == nil {
			t.Errorf("字节 0x%02x 应被拒绝（运行期 keyname_probe 断言的是同一个区间）", c)
		}
	}
	// 长度：1..64 的边界（与运行期的 nl<1||nl>64 同一对常量）
	if err := ValidWrapKeyName(string(bytes.Repeat([]byte{'x'}, PayloadWrapNameMax))); err != nil {
		t.Errorf("恰好 %d 字节的名字应被接受，实得 %v", PayloadWrapNameMax, err)
	}
	if err := ValidWrapKeyName(string(bytes.Repeat([]byte{'x'}, PayloadWrapNameMax+1))); err == nil {
		t.Errorf("超过 %d 字节的名字应被拒绝", PayloadWrapNameMax)
	}
}

// F4(b2)：把"internal/cred **不依赖** cmd/vmpkeywrap（依赖方向是单向的）"这句话变成**可执行**的。
// 为什么值得钉：包装/自检的判据在这里，而 CLI 只是它的调用方 —— 一旦 cred 反过来 import cmd，
// 就会形成 main 包与库的循环依赖（Go 会直接拒绝编译），也会把"判据只有一份"这件事说反。
// 这里用 go list 的依赖图断言，而不是靠注释里的说法。
func TestCredDoesNotDependOnCmd(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "github.com/vmpx/vmp-x/internal/cred")
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("go list 不可用（跳过依赖方向断言）: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "vmp-x/cmd/") {
			t.Errorf("internal/cred 依赖了 cmd 包（依赖方向被反转）：%s", strings.TrimSpace(line))
		}
	}
}

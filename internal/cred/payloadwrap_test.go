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

package vm

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/poly1305"
)

// Poly1305 单独对拍：定位 AEAD 里到底是 MAC 还是拼接逻辑出错
func TestPoly1305AgainstGoCrypto(t *testing.T) {
	probe := filepath.FromSlash("../../build/crypto_probe.exe")
	if _, err := os.Stat(probe); err != nil {
		t.Skip("缺少 build/crypto_probe.exe")
	}
	lens := []int{0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1000}
	var buf []byte
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(lens)))
	type tc struct {
		key [32]byte
		msg []byte
		tag [16]byte
	}
	var cases []tc
	for _, n := range lens {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		msg := make([]byte, n)
		if _, err := rand.Read(msg); err != nil {
			t.Fatal(err)
		}
		var tag [16]byte
		poly1305.Sum(&tag, msg, &key)
		cases = append(cases, tc{key: key, msg: msg, tag: tag})
		buf = binary.LittleEndian.AppendUint32(buf, uint32(n))
		buf = append(buf, key[:]...)
		buf = append(buf, msg...)
	}
	dir := t.TempDir()
	casesPath := filepath.Join(dir, "cases.bin")
	resPath := filepath.Join(dir, "results.bin")
	if err := os.WriteFile(casesPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(probe, "poly", casesPath, resPath).CombinedOutput()
	if err != nil {
		t.Fatalf("crypto_probe 失败: %v | %s", err, out)
	}
	raw, err := os.ReadFile(resPath)
	if err != nil {
		t.Fatal(err)
	}
	off := 4
	bad := 0
	for _, c := range cases {
		got := raw[off : off+16]
		off += 16
		if string(got) != string(c.tag[:]) {
			bad++
			if bad <= 6 {
				t.Errorf("len=%d: C=%x Go=%x", len(c.msg), got, c.tag)
			}
		}
	}
	if bad == 0 {
		fmt.Printf("Poly1305 对拍：%d 个长度全部一致\n", len(cases))
	} else {
		t.Fatalf("Poly1305 有 %d 个长度不一致", bad)
	}
}

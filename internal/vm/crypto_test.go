package vm

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// 用 golang.org/x/crypto 生成 ChaCha20-Poly1305 向量，交给 blob 里的手写实现解密。
// 这是"手写密码学"的独立参考：C 侧只做 decrypt+verify，正确性由这里判定。
func TestChaCha20Poly1305AgainstGoCrypto(t *testing.T) {
	probe := filepath.FromSlash("../../build/crypto_probe.exe")
	if _, err := os.Stat(probe); err != nil {
		t.Skip("缺少 build/crypto_probe.exe（先运行: gcc -O2 -I stub/win/x64 -o build/crypto_probe.exe stub/win/x64/crypto_probe.c stub/win/x64/vm_crypto.c）")
	}
	aead, err := chacha20poly1305.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	type tc struct {
		key, nonce, ct, tag []byte
		aad                 []byte
		want                []byte
		tamper              bool
	}
	var cases []tc
	lens := []int{0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 200, 1000}
	for _, n := range lens {
		key := make([]byte, 32)
		nonce := make([]byte, aead.NonceSize())
		pt := make([]byte, n)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(pt); err != nil {
			t.Fatal(err)
		}
		a, err := chacha20poly1305.New(key)
		if err != nil {
			t.Fatal(err)
		}
		aad := make([]byte, 8) // 绑定"位置"的 AAD：selfRVA || funcRVA
		binary.LittleEndian.PutUint32(aad[0:], 0x1000+uint32(n))
		binary.LittleEndian.PutUint32(aad[4:], 0x2000+uint32(n))
		sealed := a.Seal(nil, nonce, pt, aad)
		ct := sealed[:len(sealed)-16]
		tag := sealed[len(sealed)-16:]
		cases = append(cases, tc{key: key, nonce: nonce, ct: ct, tag: tag, aad: aad, want: pt})
		// AAD 不匹配（把密文挪到另一个槽位）：必须拒绝
		badAAD := append([]byte(nil), aad...)
		badAAD[0] ^= 0xFF
		cases = append(cases, tc{key: key, nonce: nonce, ct: ct, tag: tag, aad: badAAD, tamper: true})
		// 篡改一个密文字节：C 侧必须拒绝
		if n > 0 {
			bad := append([]byte(nil), ct...)
			bad[0] ^= 0x01
			cases = append(cases, tc{key: key, nonce: nonce, ct: bad, tag: tag, aad: aad, tamper: true})
		}
	}

	var buf []byte
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(cases)))
	for _, c := range cases {
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(c.aad)))
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(c.ct)))
		buf = append(buf, c.key...)
		buf = append(buf, c.nonce...)
		buf = append(buf, c.tag...)
		buf = append(buf, c.aad...)
		buf = append(buf, c.ct...)
	}
	dir := t.TempDir()
	casesPath := filepath.Join(dir, "cases.bin")
	resPath := filepath.Join(dir, "results.bin")
	if err := os.WriteFile(casesPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(probe, casesPath, resPath).CombinedOutput()
	if err != nil {
		t.Fatalf("crypto_probe 失败: %v | %s", err, out)
	}
	raw, err := os.ReadFile(resPath)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(raw) != uint32(len(cases)) {
		t.Fatal("结果数量不符")
	}
	off := 4
	okCount, tamperRejected := 0, 0
	for i, c := range cases {
		ok := binary.LittleEndian.Uint32(raw[off:]) == 1
		off += 4
		if ok {
			got := raw[off : off+len(c.ct)]
			off += len(c.ct)
			if c.tamper {
				t.Errorf("用例 %d: 篡改的密文竟然通过了认证", i)
				continue
			}
			if string(got) != string(c.want) {
				t.Errorf("用例 %d (len=%d): 明文不符", i, len(c.ct))
				continue
			}
			okCount++
		} else {
			if !c.tamper {
				t.Errorf("用例 %d (len=%d): 正确的密文被拒绝", i, len(c.ct))
			} else {
				tamperRejected++
			}
		}
	}
	fmt.Printf("ChaCha20-Poly1305 对拍（含 AAD 绑定）：%d 个向量解密成功，%d 个篡改/AAD 不匹配向量被拒绝\n", okCount, tamperRejected)
}

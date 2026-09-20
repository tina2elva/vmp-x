package inject

// 每条目密钥派生（KDF）。定义必须与 C 侧 stub/win/x64/vm_kdf.c 逐字节一致：
//
//	K_f = ChaCha20_block(key = master(32B), counter = 0, nonce = le32(rva) || le32(salt) || 0^8)[0..32)
//
// 目的：把"一把主密钥解全部条目"改成"每条目一把派生密钥"（见第三方报告 P3.13）。
// 用标准 ChaCha20 块函数（不是 blob 里那套 sigma 随机化的密钥流），因为派生两侧都要能独立复现。
import (
	"encoding/binary"

	"golang.org/x/crypto/chacha20"
)

// KDFEntry 返回某一条目的派生密钥。
func KDFEntry(master []byte, rva uint32, salt uint32) [32]byte {
	var nonce [chacha20.NonceSize]byte // 12 字节
	binary.LittleEndian.PutUint32(nonce[0:], rva)
	binary.LittleEndian.PutUint32(nonce[4:], salt)
	c, err := chacha20.NewUnauthenticatedCipher(master, nonce[:])
	if err != nil {
		panic(err)
	}
	var out [32]byte
	c.XORKeyStream(out[:], out[:]) // 密钥流 ^ 0 = 密钥流
	return out
}

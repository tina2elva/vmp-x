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

// KDFSaltForPlacement 给"字节码条目"算一个派生用 salt。
//
// 背景（STATUS #378 里记的那个待定点）：PE/ELF 的整体加密表有 salt 字段，
// 但**函数描述符没有** —— 而 KDF 需要一个两侧一致的 salt。这里不改描述符格式，
// 直接用描述符里本来就有的三个字段派生（FNV-1a-32，与运行期补丁校验同一套常量）：
//
//	salt_f = FNV1a32("VMPXKDF\x00" || le32(selfRVA) || le32(codeRVA) || le32(codeLen))
//
// 这样每条目 salt 互不相同（同一镜像里不会有两条 selfRVA 相同），且两侧都能独立算出来。
func KDFSaltForPlacement(selfRVA, codeRVA, codeLen uint32) uint32 {
	const (
		off = 2166136261
		pri = 16777619
	)
	h := uint32(off)
	mix := func(b byte) { h ^= uint32(b); h *= pri }
	for _, c := range []byte("VMPXKDF\x00") {
		mix(c)
	}
	for _, v := range []uint32{selfRVA, codeRVA, codeLen} {
		for i := 0; i < 4; i++ {
			mix(byte(v >> (8 * i)))
		}
	}
	return h
}

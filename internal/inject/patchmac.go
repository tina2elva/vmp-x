package inject

import (
	"encoding/binary"

	"golang.org/x/crypto/poly1305"
)

// PatchMACConst 是 MAC 密钥的**域分离**常量：MAC 密钥与加解密密钥必须不同。
// Poly1305 是一次性 MAC，和 ChaCha20 复用同一把密钥是明确的误用（见 STATUS #382）。
const PatchMACConst = uint32(0x9E3779B9)

// PatchMAC 计算"入口补丁 + 描述符身份"的带密钥 MAC，截断到 4 字节：
//
//	key   = KDFEntry(master, funcRVA, salt ^ PatchMACConst)
//	msg   = patch || le32(selfRVA) || le32(funcRVA) || le32(codeLen)
//	check = le32(Poly1305(key, msg)[0:4])
//
// 运行期有两个使用点（描述符 pad[0..3] 与加载期校验表的 check），它们都必须用同一算式，
// 因此两侧都有 KAT 盯着：C 侧是 stub/win/x64/kdf_kat.c 那套向量 + internal/inject 的单测，
// blob 级由 stub/win/x64/kdf_blob_kat.c 兜底。
//
// 为什么不是 FNV-1a（改造前）：那个是**无盐**的、密钥只是主密钥前 8 字节，且 FNV 有可延展的
// 代数结构（给定一个 (patch, tag) 可以直接算出扩展消息的 tag）。换成 Poly1305 后，没有主密钥
// 就算不出校验值，"按函数尾声把入口字节补回来"这条绕过会直接撞在 trap 上。
func PatchMAC(master []byte, salt, selfRVA, funcRVA, codeLen uint32, patch []byte) uint32 {
	key := KDFEntry(master, funcRVA, salt^PatchMACConst)
	msg := make([]byte, 0, len(patch)+12)
	msg = append(msg, patch...)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], selfRVA)
	msg = append(msg, b[:]...)
	binary.LittleEndian.PutUint32(b[:], funcRVA)
	msg = append(msg, b[:]...)
	binary.LittleEndian.PutUint32(b[:], codeLen)
	msg = append(msg, b[:]...)
	var tag [16]byte
	poly1305.Sum(&tag, msg, &key)
	return binary.LittleEndian.Uint32(tag[:4])
}

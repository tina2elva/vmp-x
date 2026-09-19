/* vm_crypto.h - blob 内置的最小密码学：ChaCha20-Poly1305 (RFC 8439)
 *
 * 定位（不夸大）：密钥最终在 blob 里，因此对**有能力的攻击者**不是密码学级保护；
 * 它挡住的是静态字节码分析/特征扫描。真正的密码学级需要根信任
 * （TPM/TEE/远程证明 + 服务端密钥），见 docs/DESIGN.md §2 与 KeyProvider。
 *
 * 正确性由 Go 侧对拍保证：internal/vm/crypto_test.go 用 golang.org/x/crypto 的
 * chacha20poly1305 生成密文与标签，交给这里的实现验证/解密。
 */
#ifndef VM_CRYPTO_H
#define VM_CRYPTO_H

#include "vm_types.h"

/* ChaCha20 流加密：in/out 可以相同；counter 从 1 开始用于 AEAD 的密文部分 */
void vm_chacha20_xor(const u8 key[32], u32 counter, const u8 nonce[12], const u8 *in, u8 *out, u32 len);

/* Poly1305 一次性 MAC（RFC 8439 §2.5） */
void vm_poly1305(const u8 key[32], const u8 *m, u32 len, u8 tag[16]);

/* AEAD 解密+验签：成功返回 1，失败返回 0（标签不符）
 * nonce 12 字节；密文长度 len；标签 16 字节。
 * aad 用于把密文**绑定到具体位置**（函数入口/描述符 RVA）：换槽位粘贴会导致验签失败。 */
int vm_aead_open_aad(const u8 key[32], const u8 nonce[12], const u8 *aad, u32 aadLen,
                     const u8 *ct, u32 len, const u8 tag[16], u8 *out);

/* 只生成一个 64 字节密钥流块（AEAD 的数据流从 counter>=1 开始）。
 * 流式取指用它按块还原字节码明文，宿主内存里因此不需要任何明文缓冲。 */
void vm_chacha20_keystream(const u8 key[32], u32 counter, const u8 nonce[12], u8 out[64]);

/* 只验签、**不解密**：Poly1305 认证的是**密文**，所以完整性校验可以在
 * 不产生任何明文字节的前提下完成（这是"内存里不留明文"的前提）。 */
int vm_aead_verify_aad(const u8 key[32], const u8 nonce[12], const u8 *aad, u32 aadLen,
                       const u8 *ct, u32 len, const u8 tag[16]);

/* 无 AAD 的简化形式（保留给调试与旧向量） */
int vm_aead_open(const u8 key[32], const u8 nonce[12], const u8 *ct, u32 len, const u8 tag[16], u8 *out);

#endif
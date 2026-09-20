/* vm_kdf.c - 每条目密钥派生（KDF）。**标准 ChaCha20 块函数**，刻意不复用 vm_crypto.c 里那套
 * "sigma 按构建随机化"的密钥流实现 —— 派生必须是可跨语言逐字节复现的固定定义：
 *     K_f = ChaCha20_block(key = master(32B), counter = 0, nonce = le32(rva) || le32(salt) || 0^8)[0..32)
 * 这样打包端（Go）与运行期（C）能各自算，且可以用 KAT 钉住一致性。
 * 无外部依赖，可单独编译做主机端 KAT。
 * KAT（master = 0x10..0x2F，见 kdf_kat.c；与 internal/inject/kdf_test.go 的期望值一致）：
 *   rva=0x1670  salt=0x11223344 -> 03504d6e5b8919be8be4810bcfa62727fde35898e3050c9438777953a8a04fc1
 *   rva=0x16A0  salt=0x11223344 -> 4bbdfb88dc35a67a794a1b620eeeb4c4da95a0cf77461ae1983bffd93d8538ce
 *   rva=0x93000 salt=0xAABBCCDD -> 1966610b4c9164cb8a8ddff7b28736395af1fd503ccb5947aa1c0e137d41e149
 */
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

static u32 kdf_rotl(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

static void kdf_qr(u32 *a, u32 *b, u32 *c, u32 *d) {
    *a += *b; *d ^= *a; *d = kdf_rotl(*d, 16);
    *c += *d; *b ^= *c; *b = kdf_rotl(*b, 12);
    *a += *b; *d ^= *a; *d = kdf_rotl(*d, 8);
    *c += *d; *b ^= *c; *b = kdf_rotl(*b, 7);
}

static u32 kdf_ld32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* 一个标准 ChaCha20 块（20 轮 = 10 次双轮），取出前 32 字节作为派生密钥。 */
void vm_kdf_entry(const u8 master[32], u32 rva, u32 salt, u8 out[32]) {
    u32 st[16];
    st[0] = 0x61707865u; st[1] = 0x3320646eu; st[2] = 0x79622d32u; st[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) st[4 + i] = kdf_ld32(master + 4 * i);
    st[12] = 0;          /* counter */
    st[13] = rva;        /* nonce[0] */
    st[14] = salt;       /* nonce[1] */
    st[15] = 0;          /* nonce[2] */
    u32 w[16];
    for (int i = 0; i < 16; i++) w[i] = st[i];
    for (int i = 0; i < 10; i++) {
        kdf_qr(&w[0], &w[4], &w[8], &w[12]);
        kdf_qr(&w[1], &w[5], &w[9], &w[13]);
        kdf_qr(&w[2], &w[6], &w[10], &w[14]);
        kdf_qr(&w[3], &w[7], &w[11], &w[15]);
        kdf_qr(&w[0], &w[5], &w[10], &w[15]);
        kdf_qr(&w[1], &w[6], &w[11], &w[12]);
        kdf_qr(&w[2], &w[7], &w[8], &w[13]);
        kdf_qr(&w[3], &w[4], &w[9], &w[14]);
    }
    for (int i = 0; i < 8; i++) {
        u32 v = w[i] + st[i];
        out[4 * i + 0] = (u8)(v & 0xff);
        out[4 * i + 1] = (u8)((v >> 8) & 0xff);
        out[4 * i + 2] = (u8)((v >> 16) & 0xff);
        out[4 * i + 3] = (u8)((v >> 24) & 0xff);
    }
}

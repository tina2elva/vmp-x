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

/* 与 vm_crypto.c 的 Poly1305 实现对接（同一个 blob；单独编主机 KAT 时把 vm_crypto.c 一起编进来）。
 * 这里只做声明，保持 vm_kdf.c 对头文件没有额外依赖。 */
void vm_poly1305(const u8 key[32], const u8 *m, u32 len, u8 tag[16]);

/* 入口补丁的**带密钥 MAC**（与 Go 侧 internal/inject/patchmac.go 的 PatchMAC 逐字节一致）：
 *   key   = KDFEntry(master, funcRVA, salt ^ 0x9E3779B9)   <- 与加解密密钥域分离
 *   msg   = patch || le32(selfRVA) || le32(funcRVA) || le32(codeLen)
 *   check = le32(Poly1305(key, msg)[0:4])
 * 打包端（写进描述符 pad 与加载期校验表的 check）与运行期两个使用点都走这一个函数，
 * 所以只要它在，两边就不可能各改一半。 */
u32 vm_patch_mac(const u8 master[32], u32 salt, u32 selfRVA, u32 funcRVA, u32 codeLen,
                 const u8 *patch, u32 len) {
    u8 mk[32];
    vm_kdf_entry(master, funcRVA, salt ^ 0x9E3779B9u, mk);
    u8 msg[64];
    u32 n = 0;
    if (len > 48u) len = 48u;
    for (u32 i = 0; i < len; i++) msg[n++] = patch[i];
    msg[n++] = (u8)(selfRVA);        msg[n++] = (u8)(selfRVA >> 8);
    msg[n++] = (u8)(selfRVA >> 16);  msg[n++] = (u8)(selfRVA >> 24);
    msg[n++] = (u8)(funcRVA);        msg[n++] = (u8)(funcRVA >> 8);
    msg[n++] = (u8)(funcRVA >> 16);  msg[n++] = (u8)(funcRVA >> 24);
    msg[n++] = (u8)(codeLen);        msg[n++] = (u8)(codeLen >> 8);
    msg[n++] = (u8)(codeLen >> 16);  msg[n++] = (u8)(codeLen >> 24);
    u8 tag[16];
    vm_poly1305(mk, msg, n, tag);
    return (u32)tag[0] | ((u32)tag[1] << 8) | ((u32)tag[2] << 16) | ((u32)tag[3] << 24);
}

/* 与 Go 侧 internal/inject/kdf.go 的 KDFSaltForPlacement 逐字节一致：
 *   salt = FNV1a32("VMPXKDF\x00" || le32(selfRVA) || le32(codeRVA) || le32(codeLen))
 * （描述符里没有 salt 字段，用它自己已有的三个字段派生；两侧必须一致，故单独钉 KAT。） */
u32 vm_kdf_salt(u32 selfRVA, u32 codeRVA, u32 codeLen) {
    u32 h = 2166136261u;
    /* 字符串字面量可以放心用：vmpbuild 解析重定位时按**符号索引**取符号值
     * （见 cmd/vmpbuild/blob.go 与 objfile.go 的 objReloc.SymValue）。
     * 曾经按符号**名字**查，而 ld -r 合并后同一节会有多个同名节符号（.rdata 值 0 与 0x80），
     * 于是本文件里的字符串被解析到 .rdata 的起点、salt 全错 —— 门禁里那条 blob KAT
     * （stub/win/x64/kdf_blob_kat.c）就是为钉住这类"blob 内布局"缺陷加的。 */
    const char *tag = "VMPXKDF";
    for (const char *p = tag; *p; p++) { h ^= (u32)(u8)*p; h *= 16777619u; }
    h ^= 0u; h *= 16777619u; /* 结尾的 \x00 */
    u32 v[3];
    v[0] = selfRVA; v[1] = codeRVA; v[2] = codeLen;
    for (int i = 0; i < 3; i++) {
        for (int b = 0; b < 4; b++) { h ^= (u32)((v[i] >> (8 * b)) & 0xff); h *= 16777619u; }
    }
    return h;
}

/* crypto_probe.c - 开发/验证工具：把 vm_crypto.c 的 AEAD 解密跑成批处理，
 * 供 internal/vm/crypto_test.go 用 golang.org/x/crypto 生成的向量做对拍。
 *
 * 用法: crypto_probe <casesFile> <resultsFile>
 *   casesFile:   u32 count; 每个用例 u32 len, u8 key[32], u8 nonce[12], u8 tag[16], u8 ct[len]
 *   resultsFile: u32 count; 每个用例 u32 ok, u8 pt[len]
 */
#include <stdio.h>
#include <stdlib.h>

#include "vm_crypto.h"

static int read_exact(void *p, size_t sz, FILE *f) { return fread(p, 1, sz, f) == sz; }

static int poly_mode(const char *casesPath, const char *resPath) {
    FILE *cf = fopen(casesPath, "rb");
    FILE *rf = fopen(resPath, "wb");
    if (!cf || !rf) return 2;
    unsigned int count = 0;
    if (!read_exact(&count, 4, cf)) return 2;
    fwrite(&count, 4, 1, rf);
    unsigned char *msg = malloc(1 << 20);
    if (!msg) return 2;
    for (unsigned int i = 0; i < count; i++) {
        unsigned int len = 0;
        unsigned char key[32], tag[16];
        if (!read_exact(&len, 4, cf) || len > (1 << 20)) return 2;
        if (!read_exact(key, 32, cf) || !read_exact(msg, len, cf)) return 2;
        vm_poly1305(key, msg, len, tag);
        fwrite(tag, 1, 16, rf);
    }
    fclose(cf);
    fclose(rf);
    printf("crypto_probe(poly1305): %u cases\n", count);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 4 && argv[1][0] == 'p') {
        return poly_mode(argv[2], argv[3]);
    }
    if (argc < 3) {
        fprintf(stderr, "usage: crypto_probe <cases> <results>\n");
        return 2;
    }
    FILE *cf = fopen(argv[1], "rb");
    if (!cf) { fprintf(stderr, "[!] cannot open cases\n"); return 2; }
    FILE *rf = fopen(argv[2], "wb");
    if (!rf) { fprintf(stderr, "[!] cannot create results\n"); return 2; }

    unsigned int count = 0;
    if (!read_exact(&count, 4, cf)) { fprintf(stderr, "[!] bad cases\n"); return 2; }
    fwrite(&count, 4, 1, rf);

    unsigned char *ct = malloc(1 << 20);
    unsigned char *pt = malloc(1 << 20);
    if (!ct || !pt) return 2;

    unsigned char *aad = malloc(1 << 20);
    if (!aad) return 2;
    for (unsigned int i = 0; i < count; i++) {
        unsigned int len = 0, aadLen = 0;
        unsigned char key[32], nonce[12], tag[16];
        if (!read_exact(&aadLen, 4, cf) || !read_exact(&len, 4, cf) || len > (1 << 20) || aadLen > (1 << 20)) {
            fprintf(stderr, "[!] bad case %u\n", i);
            return 2;
        }
        if (!read_exact(key, 32, cf) || !read_exact(nonce, 12, cf) || !read_exact(tag, 16, cf) ||
            !read_exact(aad, aadLen, cf) || !read_exact(ct, len, cf)) {
            fprintf(stderr, "[!] short case %u\n", i);
            return 2;
        }
        int ok = vm_aead_open_aad(key, nonce, aad, aadLen, ct, len, tag, pt);
        unsigned int okv = (unsigned int)(ok ? 1 : 0);
        fwrite(&okv, 4, 1, rf);
        if (ok) fwrite(pt, 1, len, rf);
    }
    fclose(cf);
    fclose(rf);
    printf("crypto_probe: %u cases\n", count);
    return 0;
}
/* payload_probe.c - linux/arm64（AAPCS64）：把注入的 payload 映射到指定 VA 并调用 thunk
 *
 * 作用：在 CI 里用 qemu-aarch64 跑通"ARM64 入口 stub + 解释器 + 客户机语义 + 寄存器还原"整条链。
 * 与 Windows 版的区别：这里用 mmap 而不是 VirtualAlloc，且 aarch64 的 I/D cache 不保证一致，
 * 写完代码后必须 __builtin___clear_cache。
 *
 * 用法: payload_probe <payload.bin> <va(hex)> <thunkOff(hex)> [arg0]
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

typedef uint64_t (*thunk_fn)(uint64_t);

static unsigned char *read_file(const char *p, long *n) {
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = (unsigned char *)malloc((size_t)*n);
    if (*n && fread(b, 1, (size_t)*n, f) != (size_t)*n) {
        fclose(f);
        return NULL;
    }
    fclose(f);
    return b;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: payload_probe <payload.bin> <va(hex)> <thunkOff(hex)> [arg0]\n");
        return 2;
    }
    long n = 0;
    unsigned char *payload = read_file(argv[1], &n);
    if (!payload) {
        fprintf(stderr, "[!] cannot read %s\n", argv[1]);
        return 2;
    }
    uint64_t va = strtoull(argv[2], NULL, 0);
    uint64_t thunkOff = strtoull(argv[3], NULL, 0);
    uint64_t arg0 = (argc > 4) ? strtoull(argv[4], NULL, 0) : 0;

    uint64_t page = 4096;
    uint64_t base = va & ~(page - 1);
    uint64_t off = va - base;
    uint64_t len = ((off + (uint64_t)n + page - 1) / page) * page;

    void *p = mmap((void *)base, len, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED || (uint64_t)p != base) {
        /* 老内核没有 MAP_FIXED_NOREPLACE：退回 MAP_FIXED */
        p = mmap((void *)base, len, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (p == MAP_FAILED || (uint64_t)p != base) {
            fprintf(stderr, "[!] mmap at 0x%llX failed\n", (unsigned long long)base);
            return 2;
        }
    }
    memcpy((void *)(base + off), payload, (size_t)n);
    __builtin___clear_cache((char *)(base + off), (char *)(base + off + n));

    thunk_fn f = (thunk_fn)(base + off + thunkOff);
    uint64_t r = f(arg0);
    printf("%llu\n", (unsigned long long)r);
    return 0;
}

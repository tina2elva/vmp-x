/* blob_probe.c - 把 vmpbuild 生成的 blob 加载到任意地址，执行指定字节码。
 *
 * 用途：差分测试 —— Go lifter 生成的字节码在这里执行，
 * 结果与同一函数的原生执行结果对比。
 *
 * 用法: runbc <blob.bin> <entryOff> <bytecode.vmb> <arg>
 * 输出: rax=<十进制>  rc=<0|1>  flags=0x<hex>
 */
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vm_types.h"
#include "vm_opcodes.h"

typedef int (*run_fn_t)(vm_ctx_t *);

static u8 emu_stack[1 << 20]; /* 1MB 模拟栈：足够 M1 的叶子函数 */

static unsigned char *read_file(const char *path, long *size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[!] cannot open %s\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char *)malloc((size_t)n);
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "[!] short read on %s\n", path);
        fclose(f);
        free(buf);
        return NULL;
    }
    fclose(f);
    *size = n;
    return buf;
}


/* ============================================================
 * batch 模式：一次进程内跑大量用例，用于 Go 参考实现与 C 解释器的交叉验证
 *
 *   runbc batch <blob> <entryOff> <casesFile> <resultsFile>
 *
 * casesFile:
 *   u32 count
 *   每个用例: u32 codeLen; u64 regs[18]; u8 code[codeLen]
 * resultsFile:
 *   u64 bufBase; u32 bufLen(固定 VM_BATCH_BUFLEN)
 *   每个用例: u32 rc; u32 flags; u64 regs[18]; u8 mem[VM_BATCH_BUFLEN]
 *
 * 内存窗口固定映射在 VM_BATCH_BUF_BASE：Go 侧用同一地址模拟，
 * 这样寄存器/内存状态可以逐字节比对。
 * ============================================================ */
#define VM_BATCH_BUF_BASE 0x10000000ULL
#define VM_BATCH_BUFLEN   256

static void batch_fill_pattern(u8 *p, size_t n) {
    for (size_t i = 0; i < n; i++) p[i] = (u8)((i * 7 + 3) & 0xFF);
}

static int run_batch(const char *blobPath, long entryOff, const char *casesPath, const char *resPath) {
    long blobSize = 0;
    unsigned char *blob = read_file(blobPath, &blobSize);
    if (!blob) return 2;
    void *code = VirtualAlloc(NULL, (SIZE_T)blobSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!code) { fprintf(stderr, "[!] VirtualAlloc(code) failed\n"); return 2; }
    memcpy(code, blob, (size_t)blobSize);
    FlushInstructionCache(GetCurrentProcess(), code, (SIZE_T)blobSize);

    void *buf = VirtualAlloc((LPVOID)VM_BATCH_BUF_BASE, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if ((unsigned long long)buf != VM_BATCH_BUF_BASE) {
        fprintf(stderr, "[!] 无法把内存窗口映射到 0x%llX (got %p)\n",
                (unsigned long long)VM_BATCH_BUF_BASE, buf);
        return 2;
    }

    FILE *cf = fopen(casesPath, "rb");
    if (!cf) { fprintf(stderr, "[!] cannot open %s\n", casesPath); return 2; }
    FILE *rf = fopen(resPath, "wb");
    if (!rf) { fprintf(stderr, "[!] cannot create %s\n", resPath); return 2; }

    u32 count = 0;
    if (fread(&count, 4, 1, cf) != 1) { fprintf(stderr, "[!] bad cases file\n"); return 2; }

    u64 base = VM_BATCH_BUF_BASE;
    u32 blen = VM_BATCH_BUFLEN;
    fwrite(&base, 8, 1, rf);
    fwrite(&blen, 4, 1, rf);

    run_fn_t fn = (run_fn_t)((unsigned char *)code + entryOff);
    u8 *codBuf = (u8 *)malloc(1 << 20);
    if (!codBuf) return 2;

    for (u32 i = 0; i < count; i++) {
        u32 len = 0;
        if (fread(&len, 4, 1, cf) != 1 || len > (1 << 20)) { fprintf(stderr, "[!] bad case %u\n", i); return 2; }
        u64 regs[VM_REG_COUNT];
        if (fread(regs, 8, VM_REG_COUNT, cf) != VM_REG_COUNT) { fprintf(stderr, "[!] short regs at case %u\n", i); return 2; }
        if (fread(codBuf, 1, len, cf) != len) { fprintf(stderr, "[!] short code at case %u\n", i); return 2; }

        batch_fill_pattern((u8 *)buf, 65536);

        vm_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        for (int r = 0; r < VM_REG_COUNT; r++) ctx.regs[r] = regs[r];
        ctx.code = codBuf;
        ctx.codeLen = len;

        int rc = fn(&ctx);

        fwrite(&rc, 4, 1, rf);
        fwrite(&ctx.flags, 4, 1, rf);
        fwrite(ctx.regs, 8, VM_REG_COUNT, rf);
        fwrite(buf, 1, VM_BATCH_BUFLEN, rf);
    }

    free(codBuf);
    fclose(cf);
    fclose(rf);
    printf("batch: %u cases -> %s (bufBase=0x%llX)\n", count, resPath, (unsigned long long)VM_BATCH_BUF_BASE);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 6 && strcmp(argv[1], "batch") == 0) {
        return run_batch(argv[2], strtol(argv[3], NULL, 0), argv[4], argv[5]);
    }
    if (argc < 5) {
        fprintf(stderr, "usage: runbc <blob.bin> <entryOff> <bytecode.vmb> <arg>\n");
        return 2;
    }
    const char *blobPath = argv[1];
    long entryOff = strtol(argv[2], NULL, 0);
    const char *bcPath = argv[3];
    u64 arg = (u64)strtoull(argv[4], NULL, 0);

    long blobSize = 0, bcSize = 0;
    unsigned char *blob = read_file(blobPath, &blobSize);
    unsigned char *bc = read_file(bcPath, &bcSize);
    if (!blob || !bc) return 2;
    if (entryOff < 0 || entryOff >= blobSize) {
        fprintf(stderr, "[!] entry offset 0x%lX out of range\n", entryOff);
        return 2;
    }

    void *mem = VirtualAlloc(NULL, (SIZE_T)blobSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        fprintf(stderr, "[!] VirtualAlloc failed\n");
        return 2;
    }
    memcpy(mem, blob, (size_t)blobSize);
    FlushInstructionCache(GetCurrentProcess(), mem, (SIZE_T)blobSize);

    vm_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.code = bc;
    ctx.codeLen = (u32)bcSize;
    ctx.regs[VRCX] = arg;                                  /* Win64 第一个整数参数 */
    ctx.regs[VRSP] = (u64)(emu_stack + sizeof(emu_stack));  /* 模拟栈顶 */
    ctx.regs[VRBASE] = 0;                                  /* M1 叶子函数用不到 */

    run_fn_t fn = (run_fn_t)((unsigned char *)mem + entryOff);
    int rc = fn(&ctx);

    printf("rax=%llu rc=%d flags=0x%X\n",
           (unsigned long long)ctx.regs[VRAX], rc, ctx.flags);

    VirtualFree(mem, 0, MEM_RELEASE);
    free(blob);
    free(bc);
    return rc == 0 ? 0 : 1;
}
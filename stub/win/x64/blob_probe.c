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

/* 诊断用：未处理异常过滤器 —— 直接把异常码/出错地址/访问违例的目标地址写进日志。
 * 没有它的时候，i686 上跑 blob 只能看到一个 0xC0000005，完全看不出崩在哪。 */
static void *g_blob_base;      /* 映射基址：崩溃时把出错地址换算成 blob 内偏移 */
static long g_entry_off;
static LONG WINAPI crash_filter(EXCEPTION_POINTERS *ep) {
    FILE *g = fopen("build/probe_chk.log", "a");
    if (g) {
        fprintf(g, "!! exception code=0x%08lX address=%p",
                (unsigned long)ep->ExceptionRecord->ExceptionCode,
                (void *)ep->ExceptionRecord->ExceptionAddress);
        if (ep->ExceptionRecord->ExceptionCode == 0xC0000005 && ep->ExceptionRecord->NumberParameters >= 2) {
            fprintf(g, " av_kind=%lu av_addr=%p",
                    (unsigned long)ep->ExceptionRecord->ExceptionInformation[0],
                    (void *)ep->ExceptionRecord->ExceptionInformation[1]);
        }
        if (g_blob_base) {
            fprintf(g, " blob_offset=0x%lX offset_in_entry=0x%lX",
                    (unsigned long)((unsigned char *)ep->ExceptionRecord->ExceptionAddress - (unsigned char *)g_blob_base),
                    (unsigned long)((unsigned char *)ep->ExceptionRecord->ExceptionAddress -
                                    ((unsigned char *)g_blob_base + g_entry_off)));
        }
        /* 寄存器转储只在 i386 构建里做：CONTEXT 的成员名 x64 是 Rip/Rsp/Rax...，
         * 直接写 Eip 会让 x64 探针编译不过（踩过）。 */
#if defined(__i386__) || defined(_M_IX86)
        if (ep->ContextRecord) {
            CONTEXT *c = ep->ContextRecord;
            fprintf(g, " eip=%p esp=%p eax=%p ebx=%p ecx=%p edx=%p esi=%p edi=%p ebp=%p",
                    (void *)(size_t)c->Eip, (void *)(size_t)c->Esp, (void *)(size_t)c->Eax,
                    (void *)(size_t)c->Ebx, (void *)(size_t)c->Ecx, (void *)(size_t)c->Edx,
                    (void *)(size_t)c->Esi, (void *)(size_t)c->Edi, (void *)(size_t)c->Ebp);
            if (g_blob_base && c->Esp) {
                const unsigned int *sp = (const unsigned int *)(size_t)c->Esp;
                unsigned int k;
                fprintf(g, " stack:");
                for (k = 0; k < 8; k++) {
                    unsigned int v = 0;
                    if (!IsBadReadPtr((const void *)(sp + k), 4)) v = sp[k];
                    fprintf(g, " [%u]=0x%X", k, v);
                }
            }
        }
#endif
        fprintf(g, "\n");
        fclose(g);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}


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
    SetUnhandledExceptionFilter(crash_filter);
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

    /* 多映射 0x4000：thunk 模式要在 blob 之后放描述符与字节码（打包后的真实形态）。 */
    void *mem = VirtualAlloc(NULL, (SIZE_T)blobSize + 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        fprintf(stderr, "[!] VirtualAlloc failed\n");
        return 2;
    }
    g_blob_base = mem;
    g_entry_off = entryOff;
    memcpy(mem, blob, (size_t)blobSize);
    FlushInstructionCache(GetCurrentProcess(), mem, (SIZE_T)blobSize);
    /* 可选第 5 个参数：vm_reloc_tab 在 blob 里的偏移（0/缺省 = 无表；x64 侧不需要）。
     * i386 的绝对引用（DIR32）在字段里存的是「blob 相对偏移」，必须加上**加载基址**才有效。
     * 表格式：[u32 count][count × u32 站点偏移]。注意要补丁**映射后的副本**（mem），
     * 基址就是 mem 本身。 */
    if (argc >= 6) {
        long tabOff = strtol(argv[5], NULL, 0);
        if (tabOff >= 0 && tabOff + 4 <= blobSize) {
            const unsigned char *tbl = (const unsigned char *)mem + tabOff;
            unsigned int n = (unsigned int)tbl[0] | ((unsigned int)tbl[1] << 8) |
                             ((unsigned int)tbl[2] << 16) | ((unsigned int)tbl[3] << 24);
            unsigned int i;
            unsigned long base = (unsigned long)(size_t)mem;
            /* 用 stderr：stdout 重定向到管道时是全缓冲，崩溃会把输出丢掉（踩过）。 */
            fprintf(stderr, "[*] base relocations: %u site(s), base=0x%lX\n", n, base);
            for (i = 0; i < n; i++) {
                long pos = tabOff + 4 + (long)i * 4;
                unsigned int site, v;
                unsigned char *f;
                if (pos + 4 > blobSize) break;
                site = (unsigned int)tbl[4 + i * 4] | ((unsigned int)tbl[5 + i * 4] << 8) |
                       ((unsigned int)tbl[6 + i * 4] << 16) | ((unsigned int)tbl[7 + i * 4] << 24);
                if ((long)site + 4 > blobSize) continue;
                f = (unsigned char *)mem + site;
                v = (unsigned int)f[0] | ((unsigned int)f[1] << 8) |
                    ((unsigned int)f[2] << 16) | ((unsigned int)f[3] << 24);
                if (i < 2) {
                    fprintf(stderr, "[*]   site[%u] off=0x%X before=0x%X -> after=0x%X\n",
                            i, site, v, (unsigned int)(v + (unsigned int)base));
                }
                v = (unsigned int)(v + (unsigned int)base);
                f[0] = (unsigned char)(v & 0xFF);
                f[1] = (unsigned char)((v >> 8) & 0xFF);
                f[2] = (unsigned char)((v >> 16) & 0xFF);
                f[3] = (unsigned char)((v >> 24) & 0xFF);
            }
        }
    }


    /* 可选："like" 模式 —— 把 ctx 逐项做成**打包路径**的样子（不动描述符/加密）：
     *   · VRSP 用蹦床的算式：esp - (16 + VM_MARGIN)（VM_MARGIN=0x4000）
     *   · VRBASE 非零（打包时是 imageBase）
     *   · 初始 GPR 非零（打包时来自调用方）
     * 用途：在同一份字节码上分辨"是 ctx 的哪一项让带栈访问的函数算错"。 */
    if (argc >= 7 && strcmp(argv[6], "like") == 0) {
        vm_ctx_t c;
        int r;
        memset(&c, 0, sizeof(c));
        c.code = bc;
        c.codeLen = (u32)bcSize;
        c.regs[VRSP] = (u64)(size_t)(emu_stack + sizeof(emu_stack)) - 16u - 0x4000u;
        c.regs[VRBASE] = 0x400000u;
        /* 二分用：把初始 GPR 置零，只保留 VRSP/VRBASE 两项"打包特征"。
         * （实测：三特征同时开启时会崩在
         *  `mov %eax,(%ecx)`，写 0x11110000 —— 说明有寄存器被当成了地址。） */
        /* 二分用的开关：argv[6]="like"，argv[7] 是逗号分隔的特征集：
         *   regs=1 初值非零 · sp=1 打包式 VRSP · base=1 VRBASE 非零。默认全 1。 */
        {
            int wantRegs = 1, wantSp = 1, wantBase = 1;
            if (argc >= 8) {
                const char *f = argv[7];
                wantRegs = strstr(f, "regs=0") == NULL;
                wantSp = strstr(f, "sp=0") == NULL;
                wantBase = strstr(f, "base=0") == NULL;
            }
            for (r = 0; r < 8; r++) c.regs[r] = wantRegs ? (0x11110000u + (u64)r) : 0;
            if (!wantSp) c.regs[VRSP] = (u64)(size_t)(emu_stack + sizeof(emu_stack));
            if (!wantBase) c.regs[VRBASE] = 0;
            fprintf(stderr, "[*] like mode: regs=%d sp=%d base=%d rsp=0x%llX vbase=0x%llX\n",
                    wantRegs, wantSp, wantBase, (unsigned long long)c.regs[VRSP],
                    (unsigned long long)c.regs[VRBASE]);
        }
        fprintf(stderr, "[*] like mode: rsp=0x%llX vbase=0x%llX\n",
                (unsigned long long)c.regs[VRSP], (unsigned long long)c.regs[VRBASE]);
        {
            int (*fn2)(vm_ctx_t *) = (int (*)(vm_ctx_t *))((unsigned char *)mem + entryOff);
            int rc2 = fn2(&c);
            printf("like: rax=%llu rc=%d flags=0x%X\n",
                   (unsigned long long)c.regs[VRAX], rc2, c.flags);
        }
        VirtualFree(mem, 0, MEM_RELEASE);
        free(blob); free(bc);
        return 0;
    }
    vm_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.code = bc;
    ctx.codeLen = (u32)bcSize;
    ctx.regs[VRCX] = arg;                                  /* Win64 第一个整数参数 */
    ctx.regs[VRSP] = (u64)(emu_stack + sizeof(emu_stack));  /* 模拟栈顶 */
    ctx.regs[VRBASE] = 0;                                  /* M1 叶子函数用不到 */

    /* 可选：按**打包后的真实调用形态**跑一遍 —— 在映射区里造一个描述符 + 5 字节 thunk，
     * 然后 call thunk（thunk 靠返回地址反推描述符）。这样就能把"注入后"的路径
     * （desc != NULL、code/codeLen 来自描述符、经蹦床进入）在 probe 里复现，
     * 而 probe 是带异常过滤器的。用法：第 6 个参数写 thunk。 */
    if (argc >= 7 && strcmp(argv[6], "thunk") == 0) {
        unsigned long descOff = ((unsigned long)blobSize + 0x3FUL) & ~0x3FUL;
        unsigned long bcOff = descOff + 0x100UL;
        unsigned char *d;
        unsigned char *t;
        if (bcOff + (unsigned long)bcSize + 64UL > (unsigned long)blobSize + 0x4000UL) {
            fprintf(stderr, "[!] blob 不够大，放不下描述符/字节码\n");
            return 2;
        }
        d = (unsigned char *)mem + descOff;
        memset(d, 0, 64);
        *(unsigned int *)(d + 0) = 0x4B504D56u; /* 魔数（自己造的） */
        *(unsigned int *)(d + 4) = (unsigned int)(size_t)d; /* selfRVA = 描述符地址 ⇒ base = 0 */
        *(unsigned int *)(d + 8) = (unsigned int)(bcOff - descOff); /* codeRVA：相对描述符 */
        *(unsigned int *)(d + 12) = (unsigned int)bcSize;
        memcpy((unsigned char *)mem + bcOff, bc, (size_t)bcSize);
        t = (unsigned char *)mem + descOff + 64;
        t[0] = 0xE8;
        *(int *)(t + 1) = (int)(((unsigned char *)mem + entryOff) - (t + 5)); /* call vm_entry */
        fprintf(stderr, "[*] thunk mode: desc=+0x%lX thunk=+0x%lX code=+0x%lX\n",
                descOff, descOff + 64, bcOff - descOff);
        {
            int (*tf)(void) = (int (*)(void))t;
            int rc2 = tf();
            printf("thunk: guest_eax=%u rc=%d\n", (unsigned)ctx.regs[VRAX], rc2);
        }
        VirtualFree(mem, 0, MEM_RELEASE);
        free(blob);
        free(bc);
        return 0;
    }

    run_fn_t fn = (run_fn_t)((unsigned char *)mem + entryOff);
    int rc = fn(&ctx);

    printf("rax=%llu rc=%d flags=0x%X\n",
           (unsigned long long)ctx.regs[VRAX], rc, ctx.flags);

    VirtualFree(mem, 0, MEM_RELEASE);
    free(blob);
    free(bc);
    return rc == 0 ? 0 : 1;
}

/* payload_probe_arm64.c - 在 Linux/arm64 本机上验证被保护 ELF 的 payload 能否执行
 *
 * 与 x86-64 版等价：把注入段按 ELF 里的原始 VA 映射成可执行内存，再按客户机约定
 * （ARM64：参数在 X0、thunk 无参数）直接调用 thunk。用来把「payload 自身」与
 * 「入口补丁/加载器」这两半分开 —— x86-64 那个谜题正是靠这个探针定位到映射顺序的。
 *
 * 用法: payload_probe_arm64 <payload.bin> <va(hex)> <thunkOff(hex)> <arg>...
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <signal.h>
#include <ucontext.h>

static unsigned char *g_payload;
static unsigned long g_ring_off;

/* 崩溃时把解释器留在 .bss 里的「最近 16 条 (pc, op)」环形缓冲打出来（magic=VMRING01），
 * 这样「客户机是在哪条字节码上跳飞」就不需要猜了。 */
static void fault_handler(int sig, siginfo_t *si, void *uc) {
    (void)si; (void)uc;
    fprintf(stderr, "[!] signal %d；环形缓冲在 payload+0x%lX", sig, g_ring_off);
    unsigned long long *hdr = (unsigned long long *)(g_payload + g_ring_off);
    if (hdr[0] == 0x564D52494E473031ULL) {
        unsigned long long cnt = hdr[1];
        unsigned long long *ring = hdr + 2;
        fprintf(stderr, "[!] 环形缓冲:");
        for (unsigned long long k = (cnt > 12 ? cnt - 12 : 0); k < cnt; k++) {
            unsigned long long *e = ring + (k % 16) * 2;
            fprintf(stderr, " pc=0x%llX/op=0x%llX", e[0], e[1]); /* 同一行：CI 注解只保留前 12 条 [!] 行 */
        }
    } else {
        fprintf(stderr, "[!]   环形缓冲 magic 不对（hdr[0]=0x%llX）", hdr[0]);
    }
    _exit(97);
}

static unsigned long long call_thunk(void *thunk, unsigned long long arg) {
    unsigned long long ret = 0;
    __asm__ volatile(
        "mov x0, %[arg]\n\t"
        "mov x9, %[th]\n\t"
        "blr x9\n\t"
        "mov %[ret], x0\n\t"
        : [ret] "=r"(ret)
        : [arg] "r"(arg), [th] "r"(thunk)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
          "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x30", "memory");
    return ret;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: payload_probe_arm64 <payload.bin> <va> <thunkOff> <arg>...");
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "[!] cannot open %s", argv[1]); return 2; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *payload = (unsigned char *)malloc((size_t)n);
    if (fread(payload, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "[!] short read"); return 2; }
    fclose(f);

    unsigned long long va = strtoull(argv[2], NULL, 0);
    unsigned long long thunkOff = strtoull(argv[3], NULL, 0);
    /* 不要用 ELF 里的原 VA：这个探针自己是静态链接的 aarch64 程序，而 arm64 目标很小、
     * payload 的 VA 可能只有 0x401000 —— MAP_FIXED 会把探针自己的映像盖掉，
     * 于是"payload 崩了"其实是探针被自己覆盖（第一次的结果正是 SIGILL）。
     * payload 是位置无关的（描述符靠 X30 反推、VBASE 运行期算），所以换一块高位内存即可。 */
    unsigned long long mapAt = va; /* 必须用原 VA：VBASE = 描述符地址 - selfRVA，换地址会算出错误的模块基址 */
    void *mem = mmap((void *)(uintptr_t)mapAt, (size_t)n, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mem == MAP_FAILED) { fprintf(stderr, "[!] mmap failed"); return 2; }
    fprintf(stderr, "[*] payload 映射在 0x%llX（原 VA 0x%llX，仅作参考）", mapAt, va);
    memcpy(mem, payload, (size_t)n);
    g_payload = (unsigned char *)mem;
    if (argc > 4) g_ring_off = strtoul(argv[4], NULL, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    void *thunk = (unsigned char *)mem + thunkOff;
    for (int i = 5; i < argc; i++) {
        unsigned long long a = strtoull(argv[i], NULL, 0);
        printf("  check_key(%llu) = %llu\n", a, call_thunk(thunk, a));
    }
    return 0;
}
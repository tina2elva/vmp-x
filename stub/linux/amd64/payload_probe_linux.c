/* payload_probe_linux.c - 在 Linux 本机上验证"被保护 ELF 的 payload 能否执行"
 *
 * 与 Windows 版（stub/linux/amd64/payload_probe.c，用 VirtualAlloc）等价：把注入段里的机器码
 * （解释器 blob + 描述符 + thunk + 字节码）按 ELF 里的原始 VA 映射成可执行内存，再按客户机约定
 * 调用 thunk。这样就把"到底哪一环坏"切成两半：payload 本身 vs 加载器把控制权交给被补丁入口。
 *
 * 用法: payload_probe_linux <payload.bin> <va(hex)> <thunkOff(hex)> <vm_runOff(hex)> <vm_entryOff(hex)> <arg>...
 *
 * CI 上它曾以 SIGILL(132) 退出 —— 说明问题在 payload 侧（Windows 上同形状的 payload 是好的）。
 * 所以这里装了 SIGILL/SIGSEGV/SIGBUS 处理器：把故障 PC、它属于哪个 blob 内符号、以及该处字节打出来，
 * 用于定位到底是哪条指令。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>

static unsigned char *g_payload;
static unsigned long g_len;
static struct { const char *name; unsigned long off; } g_syms[4];
static int g_nsyms;

static void fault_handler(int sig, siginfo_t *si, void *uc) {
    (void)si;
    ucontext_t *u = (ucontext_t *)uc;
    unsigned long pc = (unsigned long)u->uc_mcontext.gregs[REG_RIP];
    fprintf(stderr, "[!] signal %d at PC=0x%lX" "
", sig, pc);
    if (pc >= (unsigned long)g_payload && pc < (unsigned long)g_payload + g_len) {
        unsigned long off = pc - (unsigned long)g_payload;
        const char *who = "blob";
        unsigned long base = 0;
        for (int i = 0; i < g_nsyms; i++) {
            if (off >= g_syms[i].off) { who = g_syms[i].name; base = g_syms[i].off; }
        }
        fprintf(stderr, "[!] PC 在 payload 内: %s+0x%lX" "
", who, off - base);
        fprintf(stderr, "[!] 该处字节(前后各若干):");
        long start = (long)off - 8;
        for (long p = start; p < start + 24; p++) {
            if (p >= 0 && p < (long)g_len) fprintf(stderr, " %02x", g_payload[p]);
            else fprintf(stderr, " --");
        }
        fprintf(stderr, "" "
");
    } else {
        fprintf(stderr, "[!] PC 不在 payload 内（可能在探针自身或客户机代码）" "
");
    }
    _exit(99);
}

/* 客户机是 Go 编译的 Linux 二进制：第一个参数在 RAX（Go 的寄存器 ABI）。 */
static unsigned long long call_thunk(void *thunk, unsigned long long arg) {
    unsigned long long ret = 0;
    __asm__ volatile(
        "movq %[thunk], %%rcx
"
        "movq %[arg], %%rax
"
        "call *%%rcx
"
        : "=a"(ret)
        : [thunk] "r"(thunk), [arg] "r"(arg)
        : "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "memory");
    return ret;
}

static unsigned char *read_file(const char *p, long *n) {
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = (unsigned char *)malloc((size_t)*n);
    if (*n && fread(b, 1, (size_t)*n, f) != (size_t)*n) { fclose(f); free(b); return NULL; }
    fclose(f);
    return b;
}

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr, "usage: payload_probe_linux <payload.bin> <va> <thunkOff> <vm_runOff> <vm_entryOff> <arg>..." "
");
        return 2;
    }
    long n = 0;
    unsigned char *payload = read_file(argv[1], &n);
    if (!payload) { fprintf(stderr, "[!] cannot read %s" "
", argv[1]); return 2; }
    unsigned long long va = strtoull(argv[2], NULL, 0);
    unsigned long long thunkOff = strtoull(argv[3], NULL, 0);
    const char *names[2] = {"vm_run", "vm_entry"};
    g_nsyms = 0;
    for (int k = 0; k < 2; k++) {
        g_syms[g_nsyms].name = names[k];
        g_syms[g_nsyms].off = strtoul(argv[4 + k], NULL, 0);
        g_nsyms++;
    }

    /* payload 必须落在 ELF 里的原始 VA 上：VMBASE = 描述符地址 - selfRVA。 */
    void *mem = mmap((void *)(uintptr_t)va, (size_t)n, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "[!] mmap(0x%llX, %ld) 失败（VMBASE 会不准）" "
", va, n);
        return 2;
    }
    memcpy(mem, payload, (size_t)n);
    g_payload = (unsigned char *)mem;
    g_len = (unsigned long)n;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    void *thunk = (unsigned char *)mem + thunkOff;
    printf("payload @ %p (va=0x%llX, %ld bytes), thunk @ %p" "
", mem, va, n, thunk);
    for (int i = 6; i < argc; i++) {
        unsigned long long arg = strtoull(argv[i], NULL, 0);
        unsigned long long got = call_thunk(thunk, arg);
        printf("  checkKey(%llu) = %llu" "
", arg, got);
    }
    return 0;
}

/* payload_probe_linux.c - 在 Linux 本机上验证"被保护 ELF 的 payload 能否执行"
 *
 * 与 Windows 版（stub/linux/amd64/payload_probe.c，用 VirtualAlloc）等价：
 * 把注入段里的机器码（解释器 blob + 描述符 + thunk + 字节码）按 ELF 里的原始 VA 映射成可执行内存，
 * 再按客户机约定传参调用 thunk。这样就把"到底哪一环坏"切成两半：
 *   payload（blob/描述符/thunk/SysV 入口/字节码）  vs  加载器把控制权交给被补丁的入口。
 *
 * 用法: payload_probe_linux <payload.bin> <va(hex)> <thunkOff(hex)> <arg> [arg2 ...]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

/* 客户机是 Go 编译的 Linux 二进制：第一个参数在 RAX（Go 的寄存器 ABI），
 * thunk 本身不接受参数，所以这里只用内联汇编把这些寄存器摆好再 call。 */
static unsigned long long call_thunk(void *thunk, unsigned long long arg) {
    unsigned long long ret = 0;
    __asm__ volatile(
        "movq %[thunk], %%rcx\n\t"
        "movq %[arg], %%rax\n\t"
        "call *%%rcx\n"
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
    if (*n && fread(b, 1, (size_t)*n, f) != (size_t)*n) {
        fclose(f);
        free(b);
        return NULL;
    }
    fclose(f);
    return b;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: payload_probe_linux <payload.bin> <va(hex)> <thunkOff(hex)> <arg>...");
        fprintf(stderr, "%s", "");
        return 2;
    }
    long n = 0;
    unsigned char *payload = read_file(argv[1], &n);
    if (!payload) {
        fprintf(stderr, "[!] cannot read %s", argv[1]);
        return 2;
    }
    unsigned long long va = strtoull(argv[2], NULL, 0);
    unsigned long long thunkOff = strtoull(argv[3], NULL, 0);

    /* Linux 可以按精确地址映射（不需要 Windows 那种 64KB 粒度补偿）。
     * VMBASE = 描述符地址 - selfRVA，所以 payload 必须落在 ELF 里的原始 VA 上。 */
    void *mem = mmap((void *)(uintptr_t)va, (size_t)n, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "[!] mmap(0x%llX, %ld) 失败（VMBASE 会不准）", va, n);
        return 2;
    }
    memcpy(mem, payload, (size_t)n);

    void *thunk = (unsigned char *)mem + thunkOff;
    printf("payload @ %p (va=0x%llX, %ld bytes), thunk @ %p", mem, va, n, thunk);
    for (int i = 4; i < argc; i++) {
        unsigned long long arg = strtoull(argv[i], NULL, 0);
        unsigned long long got = call_thunk(thunk, arg);
        printf("  checkKey(%llu) = %llu", arg, got);
    }
    return 0;
}

/* payload_probe.c - 在非 Linux 环境下验证“被保护 ELF 的 payload 能否正确执行”
 *
 * 思路：注入段里的机器码（解释器 blob + 描述符 + thunk + 字节码）是位置无关的 x86-64，
 * 与宿主内核无关。把它们按 ELF 中的 VA 映射成可执行内存，然后按客户机约定传参调用 thunk，
 * 即可验证“payload 内容 + 描述符 + thunk + SysV 入口 + 字节码”整条链——
 * 剩下的不可验证部分只有“Linux 加载器映射该段并把控制权交给被补丁的函数入口”。
 *
 * 用法: payload_probe <payload.bin> <va(hex)> <thunkOff(hex)> <arg> [arg2 ...]
 */
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 客户机（本用例是 Go 编译的 Linux 二进制）把第一个参数放在 RAX */
static unsigned long long call_thunk(void *thunk, unsigned long long arg) {
    unsigned long long ret = 0;
    __asm__ volatile(
        "movq %[thunk], %%rcx\n\t"
        "movq %[arg], %%rax\n\t"
        "call *%%rcx\n\t"
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
        return NULL;
    }
    fclose(f);
    return b;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: payload_probe <payload.bin> <va(hex)> <thunkOff(hex)> <arg>...\n");
        return 2;
    }
    long n = 0;
    unsigned char *payload = read_file(argv[1], &n);
    if (!payload) {
        fprintf(stderr, "[!] cannot read %s\n", argv[1]);
        return 2;
    }
    unsigned long long va = strtoull(argv[2], NULL, 0);
    unsigned long long thunkOff = strtoull(argv[3], NULL, 0);

    /* 必须让 payload 落在 ELF 里的原始 VA 上：VMBASE = 描述符地址 - selfRVA。
     * 注意 Windows 的保留粒度是 64KB，hint 会被向下取整，因此要补偿偏移。 */
    unsigned long long gran = 0x10000ULL;
    unsigned long long hint = va & ~(gran - 1);
    unsigned long long off = va - hint;
    void *region = VirtualAlloc((LPVOID)(uintptr_t)hint, (SIZE_T)(n + off + gran),
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!region) {
        fprintf(stderr, "[!] 无法在 0x%llX 处保留内存（VMBASE 会不准）\n", hint);
        return 2;
    }
    void *mem = (unsigned char *)region + off;
    memcpy(mem, payload, (size_t)n);
    FlushInstructionCache(GetCurrentProcess(), mem, (SIZE_T)n);

    void *thunk = (unsigned char *)mem + thunkOff;
    printf("payload @ %p (va=0x%llX, %ld bytes), thunk @ %p\n", mem, va, n, thunk);
    for (int i = 4; i < argc; i++) {
        unsigned long long arg = strtoull(argv[i], NULL, 0);
        unsigned long long got = call_thunk(thunk, arg);
        printf("  checkKey(%llu) = %llu\n", arg, got);
    }
    return 0;
}

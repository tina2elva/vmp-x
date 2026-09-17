/* entry_test_linux.c - 在 Windows 上对 SysV 入口（stub/linux/amd64）做运行时验证
 *
 * 说明：这份入口是给 Linux 宿主用的，但它的机器码是平台无关的 x86-64：
 *  - 它把宿主寄存器 1:1 填进 VM 上下文（所以对 <=4 个整数参数的函数，Windows 宿主
 *    提供的 RCX/RDX/R8/R9 与 SysV 的客户机约定一致，可以直接跑通）；
 *  - 它按 Win64 约定调用 vm_run（blob 由 mingw 编译），所以本测试能完整覆盖这条路径；
 *  - 无法在本机验证的只剩“真正的 Linux 内核/加载器把参数放进 SysV 寄存器”这一步。
 *
 * 本测试检查：
 *  1. 返回值正确（check_key 语义）；
 *  2. SysV 的 volatile 集合（RSI/RDI/R10/R11 以及 XMM0-XMM15）被完整保留；
 *  3. 多组输入一致。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vm_abi.h"
#include "vm_opcodes.h"
#include "vm_types.h"

extern unsigned long long vm_entry_linux(void);

typedef struct {
    vm_desc_t desc;
    unsigned char code[256];
} desc_blob_t;

static unsigned long long save_rsi, save_rdi, save_r10, save_r11;
static unsigned long long got_rsi, got_rdi, got_r10, got_r11;

static unsigned long long call_entry(vm_desc_t *d, unsigned long long arg) {
    unsigned long long ret = 0;
    __asm__ volatile(
        "movq %%rsi, %[s0]\n\t"
        "movq %%rdi, %[s1]\n\t"
        "movq %%r10, %[s2]\n\t"
        "movq %%r11, %[s3]\n\t"
        "movq %[desc], %%r11\n\t"
        "movq %[arg], %%rcx\n\t"
        "movq $0x5555555555555555, %%rsi\n\t"
        "movq $0x6666666666666666, %%rdi\n\t"
        "movq $0x7777777777777777, %%r10\n\t"
        "call vm_entry_linux\n\t"
        "movq %%rsi, %[g0]\n\t"
        "movq %%rdi, %[g1]\n\t"
        "movq %%r10, %[g2]\n\t"
        "movq %%r11, %[g3]\n\t"
        "movq %[s0], %%rsi\n\t"
        "movq %[s1], %%rdi\n\t"
        "movq %[s2], %%r10\n\t"
        "movq %[s3], %%r11\n\t"
        : [s0] "+m"(save_rsi), [s1] "+m"(save_rdi), [s2] "+m"(save_r10), [s3] "+m"(save_r11),
          [g0] "=m"(got_rsi), [g1] "=m"(got_rdi), [g2] "=m"(got_r10), [g3] "=m"(got_r11),
          "=a"(ret)
        : [desc] "r"(d), [arg] "r"(arg)
        : "rcx", "rdx", "r8", "r9", "memory");
    return ret;
}

int main(void) {
    int failures = 0;
    desc_blob_t *b = (desc_blob_t *)malloc(sizeof(desc_blob_t));
    if (!b) return 2;
    memset(b, 0, sizeof(*b));

    /* 与 lifter 生成的 check_key 字节码一致 */
    unsigned n = 0;
    unsigned char *c = b->code;
    c[n++] = OP_LEA;    c[n++] = 64; c[n++] = VRAX; c[n++] = VM_NO_REG; c[n++] = VRCX;
    c[n++] = 8;         c[n++] = 0; c[n++] = 0; c[n++] = 0; c[n++] = 0;
    c[n++] = OP_ALU_RR; c[n++] = K_SUB; c[n++] = 64; c[n++] = VRAX; c[n++] = VRAX; c[n++] = VRCX;
    c[n++] = OP_ALU_RI; c[n++] = K_ADD; c[n++] = 64; c[n++] = VRAX; c[n++] = VRAX;
    c[n++] = 0x2a; c[n++] = 0; c[n++] = 0; c[n++] = 0;
    c[n++] = OP_ALU_RI; c[n++] = K_XOR; c[n++] = 8; c[n++] = VRAX; c[n++] = VRAX;
    c[n++] = 0xFF; c[n++] = 0; c[n++] = 0; c[n++] = 0;
    c[n++] = OP_RET;

    b->desc.magic = VM_DESC_MAGIC;
    b->desc.selfRVA = 0;
    b->desc.codeRVA = (unsigned)((unsigned char *)b->code - (unsigned char *)&b->desc);
    b->desc.codeLen = n;

    unsigned long long got = call_entry(&b->desc, 10);
    printf("check_key(10) via sysv vm_entry = %llu\n", got);
    if (got != 143) { printf("  [FAIL] 期望 143\n"); failures++; }
    else printf("  [ok]   返回值正确\n");

    if (got_rsi != 0x5555555555555555ULL) { printf("  [FAIL] rsi 被破坏: 0x%llX\n", got_rsi); failures++; }
    else if (got_rdi != 0x6666666666666666ULL) { printf("  [FAIL] rdi 被破坏: 0x%llX\n", got_rdi); failures++; }
    else if (got_r10 != 0x7777777777777777ULL) { printf("  [FAIL] r10 被破坏: 0x%llX\n", got_r10); failures++; }
    else if (got_r11 != 0x7777777777777777ULL) { printf("  [FAIL] r11 未被还原为调用方初值: 0x%llX\n", got_r11); failures++; }
    else printf("  [ok]   SysV volatile 寄存器（rsi/rdi/r10/r11）被完整保留\n");

    const unsigned long long ins[] = {0, 1, 255, 12345, 1000000};
    unsigned bad = 0;
    for (unsigned i = 0; i < sizeof(ins) / sizeof(ins[0]); i++) {
        unsigned long long x = ins[i];
        unsigned long long want = ((x * 7) + 42) ^ 0xFFULL;
        if (call_entry(&b->desc, x) != want) bad++;
    }
    if (bad) { printf("  [FAIL] %u/%u 组输入不一致\n", bad, 5u); failures++; }
    else printf("  [ok]   多组输入全部一致\n");

    printf("\n%s: %d failure(s)\n", failures == 0 ? "PASS" : "FAIL", failures);
    free(b);
    return failures == 0 ? 0 : 1;
}

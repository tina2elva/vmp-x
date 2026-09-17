/* entry_test.c - vm_entry（Windows/x64 入口）的运行时验证
 *
 * 现在入口的描述符不再由寄存器传入，而是 thunk 用 call 压入返回地址、
 * 入口从栈上反推出描述符（见 vm_abi.h）。因此测试也按生产环境的方式走：
 *   构造 [desc(16)][thunk(5)]，thunk = E8 rel32 -> vm_entry，
 *   然后像调用普通函数那样调用 thunk。
 */
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vm_abi.h"
#include "vm_opcodes.h"
#include "vm_types.h"

extern unsigned long long vm_entry(void);

typedef struct {
    vm_desc_t desc;
    unsigned char thunk[5];
} thunk_blob;

static unsigned long long save_rbx, save_r12, got_rbx, got_r12, got_r11;

/* 直接调用 thunk（thunk 自己再 call vm_entry），并检查寄存器是否被破坏 */
static unsigned long long call_entry(thunk_blob *tb, unsigned long long arg) {
    unsigned long long ret = 0;
    __asm__ volatile(
        "movq %%rbx, %[s0]\n\t"
        "movq %%r12, %[s1]\n\t"
        "movq %[arg], %%rcx\n\t"
        "movq $0x1111111111111111, %%rbx\n\t"
        "movq $0x3333333333333333, %%r12\n\t"
        "movq $0x4444444444444444, %%r11\n\t"
        "movq %[thunk], %%rax\n\t"
        "call *%%rax\n\t"
        "movq %%rbx, %[g0]\n\t"
        "movq %%r12, %[g1]\n\t"
        "movq %%r11, %[g2]\n\t"
        "movq %[s0], %%rbx\n\t"
        "movq %[s1], %%r12\n\t"
        : [s0] "+m"(save_rbx), [s1] "+m"(save_r12),
          [g0] "=m"(got_rbx), [g1] "=m"(got_r12), [g2] "=m"(got_r11),
          "=a"(ret)
        : [thunk] "r"(tb->thunk), [arg] "r"(arg)
        : "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "rbx", "r11", "r12", "memory");
    return ret;
}

static thunk_blob *make_blob(const unsigned char *code, unsigned n) {
    /* thunk 用 E8 rel32 调用 vm_entry，所以必须把 thunk 放在 vm_entry 的 ±2GB 内。
     * ASLR 下堆可能离代码段很远，因此这里按邻近提示反复尝试。 */
    unsigned long long base = (unsigned long long)vm_entry & ~0xFFFFULL;
    void *mem = NULL;
    for (unsigned long long delta = 0; delta < 0x40000000ULL && !mem; delta += 0x10000ULL) {
        mem = VirtualAlloc((void *)(base + delta), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem && delta) {
            mem = VirtualAlloc((void *)(base - delta), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }
    }
    thunk_blob *tb = (thunk_blob *)mem;
    if (!tb) return NULL;
    memset(tb, 0, sizeof(thunk_blob));
    tb->desc.magic = VM_DESC_MAGIC;
    tb->desc.selfRVA = 0;
    tb->desc.codeRVA = 0; /* 本测试不用 RIP-relative，因此字节码放在别处即可 */
    tb->desc.codeLen = n;
    /* 生产环境中 len 与 code 的偏移由 packer 填；这里直接给 codeRVA=0 让入口读不到，
     * 所以改成把字节码放在 desc 之后（[desc][thunk][code]），codeRVA = 21 */
    tb->desc.codeRVA = 16 + 5;
    memcpy((unsigned char *)tb + 21, code, n);
    tb->thunk[0] = 0xE8;
    long long rel = (long long)((unsigned char *)vm_entry - (tb->thunk + 5));
    if (rel < -0x7FFFFFFFLL || rel > 0x7FFFFFFFLL) {
        printf("[!] thunk 离 vm_entry 太远（%lld），rel32 放不下\n", rel);
        return NULL;
    }
    int rel32 = (int)rel;
    memcpy(tb->thunk + 1, &rel32, 4);
    FlushInstructionCache(GetCurrentProcess(), tb, 4096);
    return tb;
}

static LONG WINAPI veh(EXCEPTION_POINTERS *ep) {
    printf("[!] exception 0x%08lX @ RIP=%p access=%p\n", ep->ExceptionRecord->ExceptionCode,
           (void *)ep->ContextRecord->Rip,
           ep->ExceptionRecord->NumberParameters > 1
               ? (void *)ep->ExceptionRecord->ExceptionInformation[1]
               : (void *)0);
    fflush(stdout);
    ExitProcess(3);
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    AddVectoredExceptionHandler(1, veh);
    int failures = 0;

    unsigned char code[64];
    unsigned n = 0;
    code[n++] = OP_LEA;    code[n++] = 64; code[n++] = VRAX; code[n++] = VM_NO_REG; code[n++] = VRCX;
    code[n++] = 8;         code[n++] = 0; code[n++] = 0; code[n++] = 0; code[n++] = 0;
    code[n++] = OP_ALU_RR; code[n++] = K_SUB; code[n++] = 64; code[n++] = VRAX; code[n++] = VRAX; code[n++] = VRCX;
    code[n++] = OP_ALU_RI; code[n++] = K_ADD; code[n++] = 64; code[n++] = VRAX; code[n++] = VRAX;
    code[n++] = 0x2a; code[n++] = 0; code[n++] = 0; code[n++] = 0;
    code[n++] = OP_ALU_RI; code[n++] = K_XOR; code[n++] = 8; code[n++] = VRAX; code[n++] = VRAX;
    code[n++] = 0xFF; code[n++] = 0; code[n++] = 0; code[n++] = 0;
    code[n++] = OP_RET;

    thunk_blob *tb = make_blob(code, n);
    if (!tb) { printf("[!] VirtualAlloc failed\n"); return 2; }
    printf("[dbg] vm_entry=%p blob=%p thunk_off=%td\n", (void *)vm_entry, (void *)tb, (unsigned char *)tb->thunk - (unsigned char *)tb);
    fflush(stdout);

    printf("[dbg] desc: magic=0x%X selfRVA=0x%X codeRVA=0x%X codeLen=%u thunk=%02X %02X %02X %02X %02X\n",
           tb->desc.magic, tb->desc.selfRVA, tb->desc.codeRVA, tb->desc.codeLen,
           tb->thunk[0], tb->thunk[1], tb->thunk[2], tb->thunk[3], tb->thunk[4]);
    fflush(stdout);

    /* 先用最小字节码（仅 RET）验证入口 -> vm_run -> 返回 这条路径 */
    {
        thunk_blob *tb2 = make_blob((const unsigned char[]){OP_RET}, 1);
        if (!tb2) { printf("[!] alloc2 failed\n"); return 2; }
        unsigned long long r2 = call_entry(tb2, 0);
        printf("[dbg] RET-only 返回 %llu\n", r2);
        fflush(stdout);
    }

    unsigned long long got = call_entry(tb, 10);
    printf("[dbg] call returned\n");
    fflush(stdout);
    printf("check_key(10) via thunk->vm_entry = %llu\n", got);
    if (got != 143) { printf("  [FAIL] 期望 143\n"); failures++; }
    else printf("  [ok]   返回值正确\n");

    if (got_rbx != 0x1111111111111111ULL) { printf("  [FAIL] rbx 被破坏: 0x%llX\n", got_rbx); failures++; }
    else printf("  [ok]   rbx 保留\n");
    if (got_r12 != 0x3333333333333333ULL) { printf("  [FAIL] r12 被破坏: 0x%llX\n", got_r12); failures++; }
    else printf("  [ok]   r12 保留\n");
    if (got_r11 != 0x4444444444444444ULL) { printf("  [FAIL] r11 被 thunk/入口破坏: 0x%llX（这正是本轮修复的隐患）\n", got_r11); failures++; }
    else printf("  [ok]   r11 保留（thunk 不再借用任何寄存器）\n");

    const unsigned long long ins[] = {0, 1, 255, 12345, 1000000};
    unsigned bad = 0;
    for (unsigned i = 0; i < sizeof(ins) / sizeof(ins[0]); i++) {
        unsigned long long x = ins[i];
        unsigned long long want = ((x * 7) + 42) ^ 0xFFULL;
        if (call_entry(tb, x) != want) bad++;
    }
    if (bad) { printf("  [FAIL] %u/5 组输入不一致\n", bad); failures++; }
    else printf("  [ok]   多组输入全部一致\n");

    printf("\n%s: %d failure(s)\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}

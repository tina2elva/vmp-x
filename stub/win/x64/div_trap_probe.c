/* div_trap_probe.c - DIV/IDIV 的 **trap 语义**最小复现 + 对照（STATUS #611）。
 *
 * 为什么要单独一个探针：DIV 是唯一会"改变 rc 语义"的指令类 —— 除零 / 商放不下时，
 * C 解释器直接 __builtin_trap()（x86 的 #DE），而 Go 参考实现 refDiv 是 panic。两侧都**响亮失败**，
 * 绝不静默给错值。但**批量对拍表达不了 trap**（一个进程跑几千条，一条 trap 全挂），所以
 * 随机程序里只喂安全输入（见 STATUS #610），trap 这一类改用**进程级断言**：本探针 +
 * tools/harness.ps1（Windows：断言异常终止）/ tools/e2e_elf_image.sh（Linux：断言精确退出码）。
 *
 * 三个模式：
 *   0  除零（RDX=0, RAX=100, 除数=0）        ⇒ 期望 trap
 *   1  商溢出（RDX=1, RAX=0xFFFF...FF, 除数=1）⇒ 期望 trap（128 位商放不进 64 位）
 *   2  对照（RDX=0, RAX=100, 除数=7）        ⇒ 期望正常跑完：商 14、余 2
 *
 * 用法：div_trap_probe <0|1|2>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyname_probe_key.h"
#include "vm_interp.c"

int main(int argc, char **argv) {
    const int mode = (argc > 1) ? atoi(argv[1]) : 2;
    const u64 rdx = (mode == 1) ? 1ull : 0ull;
    const u64 rax = (mode == 1) ? 0xFFFFFFFFFFFFFFFFull : 100ull;
    const u64 dv = (mode == 0) ? 0ull : ((mode == 1) ? 1ull : 7ull);
    u8 code[64];
    u32 n = 0;
    vm_ctx_t vm;
    int rc;

    /* MOV64 RDX, rdx */
    code[n++] = OP_MOV_RI; code[n++] = 64; code[n++] = 2;
    for (int i = 0; i < 8; i++) code[n++] = (u8)(rdx >> (8 * i));
    /* MOV64 RAX, rax */
    code[n++] = OP_MOV_RI; code[n++] = 64; code[n++] = 0;
    for (int i = 0; i < 8; i++) code[n++] = (u8)(rax >> (8 * i));
    /* MOV64 RCX, dv  (RCX = 除数寄存器) */
    code[n++] = OP_MOV_RI; code[n++] = 64; code[n++] = 1;
    for (int i = 0; i < 8; i++) code[n++] = (u8)(dv >> (8 * i));
    /* ALU_U K_DIVU width=64 dst=0(RCX 只是占位) a=1(RCX) */
    code[n++] = OP_ALU_U; code[n++] = (u8)K_DIVU; code[n++] = 64; code[n++] = 0; code[n++] = 1;
    code[n++] = OP_RET;

    memset(&vm, 0, sizeof(vm));
    vm.code = code;
    vm.codeLen = n;
    rc = vm_run(&vm);
    printf("rc=%d rax=%llu rdx=%llu\n", rc,
           (unsigned long long)vm.regs[VRAX], (unsigned long long)vm.regs[VRDX]);
    return 0;
}

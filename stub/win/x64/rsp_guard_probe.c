/* rsp_guard_probe.c - 解释器对"客户机栈被写坏"的硬门（rc=97 / ud2）的最小复现 + 对照。
 *
 * 来由（STATUS #606.3）：把随机字节码程序接进 C-vs-Go 参考 VM 的差分对拍之后，第一天就有一条
 * 程序让 C 解释器以 0xC000001D 走硬门，而 Go 参考 VM 能跑完。二分定位到那条程序里有一句
 * "MOV16 RSP, RAX"。定性之后确认：**这不是 bug**，是 vm_interp.c 里有意为之的客户机栈守卫：
 *
 *     if (rsp_start - vm->regs[VRSP] > VM_MARGIN) return 99;   // 压栈越过给它的栈下界
 *     if (vm->regs[VRSP] > rsp_start)             return 97;   // 弹出过多：SP 高过进入值
 *
 * 理由（97 那段的自述）是"SP 高过进入值 ⇒ 返回地址会取错 ⇒ 会跳到任意地址"，属于 fail-closed。
 * Go 参考 VM 不建模这条：它验的是**指令语义**，而这条守卫是 harness 级契约（SP 必须回到进入值）。
 *
 * ⚠️ **实测（STATUS #607.2）：模式 0 命中的是 99，不是 97。** SP 高过进入值时，
 *    'rsp_start - SP' 在无符号下溢成≈2^64 ⇒ 先满足第一条 ⇒ 97 那条**永远走不到（死分支）**。
 *    两条独立证据：① 把 97 那段删掉，模式 0 行为**完全不变**（仍异常终止）；
 *
 *    ② Linux 侧实测（硬门 = exit_group(0xC0DE0000|code)，低 8 位就是 code）⇒ mode 0 的 rc = **99**。
 *
 * 用法： rsp_guard_probe 0   把 SP 写到**进入值之上** ⇒ 期望走硬门（进程异常终止、无输出）
 *        rsp_guard_probe 1   把 SP 写成**与进入值相同** ⇒ 期望正常跑完并打印 rc
 *
 * 这条也是"每条硬门分支都要有测试真的走到它"的一例（STATUS #602.5）：谁把 2573 行那段删掉，
 * 模式 0 就不再异常终止，tools/harness.ps1 里的断言随即变红。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyname_probe_key.h"
#include "vm_interp.c"

int main(int argc, char **argv) {
    const u64 rsp_start = 0x1000;
    /* 模式 0：写到进入值之上（触发 rc=97）；模式 1：写成与进入值相同（对照，应当正常跑完）。 */
    const u64 target = (argc > 1 && atoi(argv[1]) == 0) ? 0x2000 : rsp_start;
    u8 code[32];
    u32 n = 0;
    u32 i;
    code[n++] = OP_MOV_RI;
    code[n++] = 64;
    code[n++] = VRAX;
    for (i = 0; i < 8; i++) code[n++] = (u8)(target >> (8 * i));
    /* MOV16 VRSP, VRAX：x86-64 里写 16 位寄存器会零扩展到 64 位 */
    code[n++] = OP_MOV_RR;
    code[n++] = 16;
    code[n++] = (u8)VRSP;
    code[n++] = VRAX;
    code[n++] = OP_RET;

    vm_ctx_t vm;
    int rc;
    memset(&vm, 0, sizeof(vm));
    vm.code = code;
    vm.codeLen = n;
    vm.regs[VRSP] = rsp_start;
    rc = vm_run(&vm);
    printf("rc=%d sp=0x%llX (start=0x%llX)\n", rc, (unsigned long long)vm.regs[VRSP],
           (unsigned long long)rsp_start);
    return 0;
}

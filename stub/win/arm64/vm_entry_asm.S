/* vm_entry_asm.S - Windows/arm64（AArch64，Windows 变体）VM 入口封装
 *
 * 职责与 x86-64 版一致：保存客户机（= 本机 ISA）寄存器到 ctx、从 LR 反推描述符、
 * 设置模拟 SP、调用 vm_run、还原寄存器并返回 X0。
 *
 * 与 x86-64 版的差别：
 *   - thunk 用 BL（4 字节）→ 返回地址在 X30；描述符 = X30 - 4 - VM_DESC_TO_THUNK；
 *   - 模拟 SP = (分配帧后的 SP) - VM_MARGIN，VM_FRAME_SKEW = FRAME + MARGIN（EXTRA=0）；
 *   - 标志位：mrs nzcv 得到 N/Z/C/V 在 bit31..28，而 VM 内部用 N=1,Z=2,C=4,V=8
 *     → rbit 反转位序；还原时反向；
 *   - 帧大小超过 add/sub 的 imm12 范围（4688 > 4095），所以借 x9 先装载常量。
 *
 * Windows 变体的差别只有：没有 shadow space（本入口也不调用任何系统 API），x18 不使用。
 *
 * 注意：本地没有 aarch64-windows 工具链，本文件的编译验证在 CI 里用 clang 做。
 */
#include "vm_abi.h"

    .text
#ifndef VM_ENTRY_SYMBOL
#define VM_ENTRY_SYMBOL vm_entry
#endif
    .globl  VM_ENTRY_SYMBOL
    .p2align 4
VM_ENTRY_SYMBOL:
    /* ---- 分配帧（16 字节对齐）；两个 LR 都要留下 ----
     *   X30 = thunk 里 BL 留下的返回地址（thunk+4）→ 用来反推描述符；
     *   X16 = 入口补丁（mov x16,x30 ; b thunk）保存的**调用方返回地址**
     *         → 它才是客户机语义下的 LR，也是本入口最后 ret 的目标。
     * 必须这样绕一下的原因：thunk 的 BL 会覆盖 LR，而客户机的 X30 正是"返回地址"。 */
    mov     x9, #VM_FRAME_SIZE
    sub     sp, sp, x9
    str     x30, [sp, #VM_SAVE_LR]
    str     x16, [sp, #VM_SAVE_GUEST_LR]

    /* ---- 客户机（= 宿主）X0..X29 写进 ctx；X30 用 x16 ---- */
    .irp r, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29
        str     x\r, [sp, #(VM_CTX_OFF_REGS + 8*\r)]
    .endr
    str     x16, [sp, #(VM_CTX_OFF_REGS + 8*30)]

    /* ---- 标志位：NZCV（bit31..28）→ VM 位序（N=1,Z=2,C=4,V=8） ---- */
    mrs     x9, nzcv
    rbit    w9, w9
    lsr     w9, w9, #28
    str     w9, [sp, #VM_CTX_FLAGS]

    /* ---- 从 LR 反推描述符：X30 = thunk + 4 ---- */
    ldr     x11, [sp, #VM_SAVE_LR]
    sub     x11, x11, #(VM_THUNK_SIZE + VM_DESC_TO_THUNK)
    movz    w10, #0x4D56
    movk    w10, #0x4B50, lsl #16
    ldr     w9, [x11]
    cmp     w9, w10
    csel    x11, x11, xzr, eq

    cbz     x11, 1f
    /* ---- 描述符存在：VBASE / code / codeLen / desc ---- */
    ldr     w9, [x11, #4]        /* selfRVA */
    sub     x9, x11, x9
    str     x9, [sp, #(VM_CTX_OFF_REGS + 8*32)]  /* VBASE */
    ldr     w9, [x11, #8]        /* codeRVA */
    add     x9, x11, x9
    str     x9, [sp, #VM_CTX_CODE]
    ldr     w9, [x11, #12]       /* codeLen（明文长度） */
    str     w9, [sp, #VM_CTX_CODELEN]
    str     x11, [sp, #VM_CTX_DESC]
1:
    /* ---- 解密缓冲（帧内）与 VSCRATCH ---- */
    add     x9, sp, #VM_SCRATCH_OFF
    str     x9, [sp, #VM_CTX_SCRATCH]
    mov     w9, #VM_SCRATCH_SIZE
    str     w9, [sp, #VM_CTX_SCRATCHLEN]
    str     xzr, [sp, #(VM_CTX_OFF_REGS + 8*33)]

    /* ---- 模拟 SP：放在 vm_run 栈帧之下 VM_MARGIN 处 ---- */
    mov     x9, #VM_MARGIN
    sub     x9, sp, x9
    str     x9, [sp, #(VM_CTX_OFF_REGS + 8*31)]

    /* ---- 状态清零 ---- */
    str     wzr, [sp, #VM_CTX_PC]
    str     wzr, [sp, #VM_CTX_RESERVED]

    /* ---- 调用 vm_run(ctx) ---- */
    mov     x0, sp
    bl      vm_run

    /* ---- 返回 X0 来自 ctx；X1..X29 从保存区还原；X30 = 调用方返回地址 ---- */
    ldr     x10, [sp, #VM_CTX_OFF_REGS]
    .irp r, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29
        ldr     x\r, [sp, #(VM_SAVE_BASE + 8*(\r - 1))]
    .endr
    ldr     x30, [sp, #VM_SAVE_GUEST_LR]

    /* ---- 标志位还原：VM 位序 → NZCV ---- */
    ldr     w9, [sp, #VM_CTX_FLAGS]
    lsl     w9, w9, #28
    rbit    w9, w9
    msr     nzcv, x9

    mov     x9, #VM_FRAME_SIZE
    add     sp, sp, x9
    mov     x0, x10
    ret
/* vm_entry_asm.S - VM 入口封装（被 thunk jmp 进入）
 *
 * 职责：
 *   1. 建立自己的栈帧；
 *   2. 保存**所有** volatile 寄存器（GPR + XMM0-5）与 callee-saved；
 *   3. 从真实寄存器填 ctx（参数 RCX/RDX/R8/R9），设置模拟 RSP 与模块基址；
 *   4. 调 vm_run(ctx)，取回 ctx.regs[RAX] 作为返回值；
 *   5. 还原寄存器（RAX 用返回值覆盖）并 ret 回真正的调用方。
 *
 * 为什么连 volatile 也要存：调用方可能依据它对原函数寄存器用法的分析，
 * 把活跃值放在 volatile 寄存器里跨调用使用（IPA 优化，非 ABI 保证）。
 * 替换后的实现必须“破坏的寄存器不多于”原函数，最稳妥的做法是什么都不破坏。
 */
#include "vm_abi.h"

    .text
    .globl  vm_entry
    .p2align 4
vm_entry:
    subq    $VM_FRAME_SIZE, %rsp

    /* ---- 保存调用方 callee-saved ---- */
    movq    %rbx, VM_SAVE_RBX(%rsp)
    movq    %rbp, VM_SAVE_RBP(%rsp)
    movq    %rsi, VM_SAVE_RSI(%rsp)
    movq    %rdi, VM_SAVE_RDI(%rsp)
    movq    %r12, VM_SAVE_R12(%rsp)
    movq    %r13, VM_SAVE_R13(%rsp)
    movq    %r14, VM_SAVE_R14(%rsp)
    movq    %r15, VM_SAVE_R15(%rsp)

    /* ---- 保存调用方 volatile GPR（r11 在保存后仍是描述符指针） ---- */
    movq    %rcx, VM_SAVE_RCX(%rsp)
    movq    %rdx, VM_SAVE_RDX(%rsp)
    movq    %r8,  VM_SAVE_R8(%rsp)
    movq    %r9,  VM_SAVE_R9(%rsp)
    movq    %r10, VM_SAVE_R10(%rsp)
    movq    %r11, VM_SAVE_R11(%rsp)

    /* ---- 保存调用方 volatile XMM ---- */
    movups  %xmm0, VM_SAVE_XMM0(%rsp)
    movups  %xmm1, VM_SAVE_XMM1(%rsp)
    movups  %xmm2, VM_SAVE_XMM2(%rsp)
    movups  %xmm3, VM_SAVE_XMM3(%rsp)
    movups  %xmm4, VM_SAVE_XMM4(%rsp)
    movups  %xmm5, VM_SAVE_XMM5(%rsp)

    /* ---- 用真实寄存器填 ctx ---- */
    movq    %rax, VM_CTX_RAX(%rsp)
    movq    %rcx, VM_CTX_RCX(%rsp)
    movq    %rdx, VM_CTX_RDX(%rsp)
    movq    %rbx, VM_CTX_RBX(%rsp)
    movq    %rbp, VM_CTX_RBP(%rsp)
    movq    %rsi, VM_CTX_RSI(%rsp)
    movq    %rdi, VM_CTX_RDI(%rsp)
    movq    %r8,  VM_CTX_R8(%rsp)
    movq    %r9,  VM_CTX_R9(%rsp)
    movq    %r10, VM_CTX_R10(%rsp)
    movq    %r11, VM_CTX_R11(%rsp)
    movq    %r12, VM_CTX_R12(%rsp)
    movq    %r13, VM_CTX_R13(%rsp)
    movq    %r14, VM_CTX_R14(%rsp)
    movq    %r15, VM_CTX_R15(%rsp)

    /* ---- 模拟 RSP：放在 vm_run 栈帧之下 ---- */
    leaq    -(8 + VM_MARGIN)(%rsp), %rax
    movq    %rax, VM_CTX_RSP(%rsp)

    /* ---- 模块基址 = 描述符地址 - selfRVA ---- */
    /* ---- 从栈上反推描述符（必须在填完 ctx 之后：此时可以随便用寄存器） ----
     * thunk 用 call 压入的返回地址在 [rsp + FRAME]（入口 RSP = E-8-FRAME），等于 thunk+5；
     * 描述符位于 thunk 之前 VM_DESC_TO_THUNK 字节 → 描述符 = 返回地址 - 5 - VM_DESC_TO_THUNK。
     * 注意：直接调用 vm_entry（没有经过 thunk）时这个"描述符"是垃圾，因此校验 magic，
     * 不匹配就置 0——否则 vm_run 会去解引用一个非法指针。
     */
    movq    VM_FRAME_SIZE(%rsp), %r11
    subq    $(VM_THUNK_SIZE + VM_DESC_TO_THUNK), %r11
    xorl    %eax, %eax
    cmpl    $VM_DESC_MAGIC, (%r11)
    cmoveq  %r11, %rax
    movq    %rax, %r11
    testq   %r11, %r11
    jne     1f
    /* 不是 thunk 调用：没有描述符，code 由调用方（如测试宿主）直接给出 */
    jmp     2f
1:
    movl    4(%r11), %eax
    movq    %r11, %rcx
    subq    %rax, %rcx
    movq    %rcx, VM_CTX_VBASE(%rsp)
    movq    $0, VM_CTX_VSCRATCH(%rsp)

    /* ---- 字节码指针与长度来自描述符 ---- */
    movl    8(%r11), %eax
    addq    %r11, %rax
    movq    %rax, VM_CTX_CODE(%rsp)
    movl    12(%r11), %eax
    movl    %eax, VM_CTX_CODELEN(%rsp)

    /* ---- 加密支持：描述符指针 + 帧内的解密缓冲 ---- */
    movq    %r11, VM_CTX_DESC(%rsp)

2:
    /* ---- 其余状态清零 ---- */
    movl    $0, VM_CTX_FLAGS(%rsp)
    movl    $0, VM_CTX_PC(%rsp)
    movl    $0, VM_CTX_RESERVED(%rsp)

    /* ---- vm_run(ctx)：Win64 要求调用方预留 32 字节 shadow space ---- */
    subq    $32, %rsp
    leaq    32(%rsp), %rcx
    call    vm_run
    addq    $32, %rsp

    /* ---- 还原调用方 volatile GPR ---- */
    movq    VM_SAVE_RCX(%rsp), %rcx
    movq    VM_SAVE_RDX(%rsp), %rdx
    movq    VM_SAVE_R8(%rsp), %r8
    movq    VM_SAVE_R9(%rsp), %r9
    movq    VM_SAVE_R10(%rsp), %r10
    movq    VM_SAVE_R11(%rsp), %r11

    /* ---- 还原调用方 volatile XMM ---- */
    movups  VM_SAVE_XMM0(%rsp), %xmm0
    movups  VM_SAVE_XMM1(%rsp), %xmm1
    movups  VM_SAVE_XMM2(%rsp), %xmm2
    movups  VM_SAVE_XMM3(%rsp), %xmm3
    movups  VM_SAVE_XMM4(%rsp), %xmm4
    movups  VM_SAVE_XMM5(%rsp), %xmm5

    /* ---- 还原调用方 callee-saved ---- */
    movq    VM_SAVE_RBX(%rsp), %rbx
    movq    VM_SAVE_RBP(%rsp), %rbp
    movq    VM_SAVE_RSI(%rsp), %rsi
    movq    VM_SAVE_RDI(%rsp), %rdi
    movq    VM_SAVE_R12(%rsp), %r12
    movq    VM_SAVE_R13(%rsp), %r13
    movq    VM_SAVE_R14(%rsp), %r14
    movq    VM_SAVE_R15(%rsp), %r15

    /* ---- 返回值（必须在释放帧之前读） ---- */
    movq    VM_CTX_RAX(%rsp), %rax
    addq    $VM_FRAME_SIZE, %rsp
    addq    $8, %rsp
    ret
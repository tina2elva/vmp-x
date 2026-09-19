/* vm_entry_asm.S - Linux/amd64??ystem V??M ??????
 *
 * ??Windows ???????? *   - ??? ABI ??System V?????? RDI/RSI/RDX/RCX/R8/R9??allee-saved ??RBX/RBP/R12-R15?? *     XMM0-XMM15 ??? volatile?? *   - ?????????????????????????????????????????????RAX ?????GPR ???/????? *     XMM0-XMM15 ?????????
 *   - **blob ??? mingw ???**??indows ABI ????????????????vm_run ?????? Win64 ????? *     ctx ?????RCX?????call ?????32 ??? shadow space?? *     ?????????????????????????????????????-include ?????? vm_abi.h ????? */
#include "vm_abi.h"

    .text
#ifndef VM_ENTRY_SYMBOL
#define VM_ENTRY_SYMBOL vm_entry
#endif
    .globl  VM_ENTRY_SYMBOL
    .p2align 4
VM_ENTRY_SYMBOL:
    subq    $VM_FRAME_SIZE, %rsp

    /* ---- ??? callee-saved ---- */
    movq    %rbx, VM_SAVE_RBX(%rsp)
    movq    %rbp, VM_SAVE_RBP(%rsp)
    movq    %r12, VM_SAVE_R12(%rsp)
    movq    %r13, VM_SAVE_R13(%rsp)
    movq    %r14, VM_SAVE_R14(%rsp)
    movq    %r15, VM_SAVE_R15(%rsp)

    /* ---- ??? volatile GPR ---- */
    movq    %rcx, VM_SAVE_RCX(%rsp)
    movq    %rdx, VM_SAVE_RDX(%rsp)
    movq    %rsi, VM_SAVE_RSI(%rsp)
    movq    %rdi, VM_SAVE_RDI(%rsp)
    movq    %r8,  VM_SAVE_R8(%rsp)
    movq    %r9,  VM_SAVE_R9(%rsp)
    movq    %r10, VM_SAVE_R10(%rsp)
    movq    %r11, VM_SAVE_R11(%rsp)

    /* ---- ??? volatile XMM ---- */
    movups  %xmm0,  VM_SAVE_XMM0(%rsp)
    movups  %xmm1,  VM_SAVE_XMM1(%rsp)
    movups  %xmm2,  VM_SAVE_XMM2(%rsp)
    movups  %xmm3,  VM_SAVE_XMM3(%rsp)
    movups  %xmm4,  VM_SAVE_XMM4(%rsp)
    movups  %xmm5,  VM_SAVE_XMM5(%rsp)
    movups  %xmm6,  VM_SAVE_XMM6(%rsp)
    movups  %xmm7,  VM_SAVE_XMM7(%rsp)
    movups  %xmm8,  VM_SAVE_XMM8(%rsp)
    movups  %xmm9,  VM_SAVE_XMM9(%rsp)
    movups  %xmm10, VM_SAVE_XMM10(%rsp)
    movups  %xmm11, VM_SAVE_XMM11(%rsp)
    movups  %xmm12, VM_SAVE_XMM12(%rsp)
    movups  %xmm13, VM_SAVE_XMM13(%rsp)
    movups  %xmm14, VM_SAVE_XMM14(%rsp)
    movups  %xmm15, VM_SAVE_XMM15(%rsp)

    /* ---- ???????????ctx??????????????x86-64 SysV ??1:1??---- */
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

    /* ---- ??? RSP?????vm_run ?????? ---- */
    leaq    -(8 + VM_MARGIN)(%rsp), %rax
    /* no alignment mask here: guest RSP%16==8 is the designed value; masking it shifts the
     * fixed distance to the caller frame that VM_FRAME_SKEW depends on (E2E framed case). */
    movq    %rax, VM_CTX_RSP(%rsp)

    /* ---- ????????????????????? ctx ????????????????????? ----
     * thunk ??call ?????????????[rsp + FRAME]?????RSP = E-8-FRAME?????? thunk+5??     * ????????thunk ??? 16 ??? ???????= ?????? - 5 - 16??     */
    movq    VM_FRAME_SIZE(%rsp), %r11
    subq    $(VM_THUNK_SIZE + VM_DESC_TO_THUNK), %r11
    movl    4(%r11), %eax
    movq    %r11, %rcx
    subq    %rax, %rcx
    movq    %rcx, VM_CTX_VBASE(%rsp)
    movq    $0, VM_CTX_VSCRATCH(%rsp)

    /* ---- ???????????? ---- */
    movl    8(%r11), %eax
    addq    %r11, %rax
    movq    %rax, VM_CTX_CODE(%rsp)
    movl    12(%r11), %eax
    movl    %eax, VM_CTX_CODELEN(%rsp)

    /* ---- ??????????????? + ???????????---- */
    movq    %r11, VM_CTX_DESC(%rsp)

    /* ---- ???????---- */
    movl    $0, VM_CTX_FLAGS(%rsp)
    movl    $0, VM_CTX_PC(%rsp)
    movl    $0, VM_CTX_RESERVED(%rsp)

    /* ---- ??? vm_run ----
     * blob ?????????????????????
     *   mingw ?????mpbuild ?????VM_BLOB_USES_WIN64??? RCX + 32B shadow
     *   ??? Linux gcc ??? ??System V??DI??? shadow
     */
#ifdef VM_BLOB_USES_WIN64
    subq    $32, %rsp
    leaq    32(%rsp), %rcx
    call    vm_run
    addq    $32, %rsp
#else
    movq    %rsp, %rdi
    call    vm_run
#endif

    /* ---- ??? volatile GPR ---- */
    movq    VM_SAVE_RCX(%rsp), %rcx
    movq    VM_SAVE_RDX(%rsp), %rdx
    movq    VM_SAVE_RSI(%rsp), %rsi
    movq    VM_SAVE_RDI(%rsp), %rdi
    movq    VM_SAVE_R8(%rsp), %r8
    movq    VM_SAVE_R9(%rsp), %r9
    movq    VM_SAVE_R10(%rsp), %r10
    movq    VM_SAVE_R11(%rsp), %r11

    /* ---- ??? volatile XMM ---- */
    movups  VM_SAVE_XMM0(%rsp),  %xmm0
    movups  VM_SAVE_XMM1(%rsp),  %xmm1
    movups  VM_SAVE_XMM2(%rsp),  %xmm2
    movups  VM_SAVE_XMM3(%rsp),  %xmm3
    movups  VM_SAVE_XMM4(%rsp),  %xmm4
    movups  VM_SAVE_XMM5(%rsp),  %xmm5
    movups  VM_SAVE_XMM6(%rsp),  %xmm6
    movups  VM_SAVE_XMM7(%rsp),  %xmm7
    movups  VM_SAVE_XMM8(%rsp),  %xmm8
    movups  VM_SAVE_XMM9(%rsp),  %xmm9
    movups  VM_SAVE_XMM10(%rsp), %xmm10
    movups  VM_SAVE_XMM11(%rsp), %xmm11
    movups  VM_SAVE_XMM12(%rsp), %xmm12
    movups  VM_SAVE_XMM13(%rsp), %xmm13
    movups  VM_SAVE_XMM14(%rsp), %xmm14
    movups  VM_SAVE_XMM15(%rsp), %xmm15

    /* ---- ??? callee-saved ---- */
    movq    VM_SAVE_RBX(%rsp), %rbx
    movq    VM_SAVE_RBP(%rsp), %rbp
    movq    VM_SAVE_R12(%rsp), %r12
    movq    VM_SAVE_R13(%rsp), %r13
    movq    VM_SAVE_R14(%rsp), %r14
    movq    VM_SAVE_R15(%rsp), %r15

    /* ---- ?????---- */
    movq    VM_CTX_RAX(%rsp), %rax
    addq    $VM_FRAME_SIZE, %rsp
    addq    $8, %rsp
    ret

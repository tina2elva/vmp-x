/* vm_entry_asm.S - 32-bit (i686) entry thunk for the VM blob.
 *
 * Sibling of stub/win/x64/vm_entry_asm.S. Same job:
 *   1. build our own frame below the caller's stack;
 *   2. save every register the caller might be keeping live values in
 *      (callee-saved + volatile GPR + XMM) so that replacing the function body
 *      with the VM does not destroy more state than the original did;
 *   3. copy the guest registers into vm_ctx_t and compute the simulated ESP;
 *   4. recover the descriptor from the return address, then call vm_run(ctx);
 *   5. restore the caller's registers; the guest return value is whatever
 *      vm_run left in EAX (a u64 return uses EDX:EAX on i686, and a 32-bit
 *      guest only cares about EAX).
 *
 * cdecl specifics (why this file is not just a s/rax/eax/ of the x64 one):
 *   - at vm_entry esp % 16 == 12 (the caller's `call` pushed 4 bytes), so
 *     VM_FRAME_SIZE is congruent to 12 mod 16 (652) to reach 0 after the sub;
 *   - the simulated ESP is esp - (4 + VM_MARGIN): the 4 is the size of the
 *     return address cdecl leaves at [esp];
 *   - arguments are on the stack, not in registers, so nothing needs to be
 *     marshalled here - the lifter reads [esp+N] through the simulated stack;
 *   - a call to vm_run must push its argument and keep esp % 16 == 0 at the
 *     call site: hence the extra `subl $12` before the push (0 - 12 = 4, and
 *     4 - 4 = 0).
 */
#include "vm_abi.h"

    .text
    .globl  vm_entry
    .p2align 4
vm_entry:
    subl    $VM_FRAME_SIZE, %esp
    /* hand the frame base to the interpreter (used by the XMM boundary sync) */
    movl    %esp, VM_CTX_FRAME(%esp)

    /* ---- callee-saved ---- */
    movl    %ebx, VM_SAVE_EBX(%esp)
    movl    %ebp, VM_SAVE_EBP(%esp)
    movl    %esi, VM_SAVE_ESI(%esp)
    movl    %edi, VM_SAVE_EDI(%esp)

    /* ---- volatile GPR (GCC IPA may keep live values in these across a call) ---- */
    movl    %eax, VM_SAVE_EAX(%esp)
    movl    %ecx, VM_SAVE_ECX(%esp)
    movl    %edx, VM_SAVE_EDX(%esp)

    /* ---- volatile XMM ---- */
    movups  %xmm0, VM_SAVE_XMM0(%esp)
    movups  %xmm1, VM_SAVE_XMM1(%esp)
    movups  %xmm2, VM_SAVE_XMM2(%esp)
    movups  %xmm3, VM_SAVE_XMM3(%esp)
    movups  %xmm4, VM_SAVE_XMM4(%esp)
    movups  %xmm5, VM_SAVE_XMM5(%esp)

    /* ---- guest registers into the ctx (i686 has no r8-r15: zero those slots) ---- */
    movl    %eax, VM_CTX_RAX(%esp)
    movl    %ecx, VM_CTX_RCX(%esp)
    movl    %edx, VM_CTX_RDX(%esp)
    movl    %ebx, VM_CTX_RBX(%esp)
    movl    %ebp, VM_CTX_RBP(%esp)
    movl    %esi, VM_CTX_RSI(%esp)
    movl    %edi, VM_CTX_RDI(%esp)
    movl    $0, VM_CTX_R8(%esp)
    movl    $0, VM_CTX_R9(%esp)
    movl    $0, VM_CTX_R10(%esp)
    movl    $0, VM_CTX_R11(%esp)
    movl    $0, VM_CTX_R12(%esp)
    movl    $0, VM_CTX_R13(%esp)
    movl    $0, VM_CTX_R14(%esp)
    movl    $0, VM_CTX_R15(%esp)

    /* ---- simulated ESP = esp - (4 + VM_MARGIN) ---- */
    leal    -(4 + VM_MARGIN)(%esp), %eax
    movl    %eax, VM_CTX_RSP(%esp)

    /* ---- descriptor = return address - VM_THUNK_SIZE - VM_DESC_TO_THUNK ---- */
    movl    VM_FRAME_SIZE(%esp), %ecx
    subl    $(VM_THUNK_SIZE + VM_DESC_TO_THUNK), %ecx
    xorl    %eax, %eax
    cmpl    $VM_DESC_MAGIC, (%ecx)
    cmovel  %ecx, %eax
    testl   %eax, %eax
    je      2f
    movl    %eax, %ecx
    /* module base = descriptor - selfRVA */
    movl    4(%eax), %edx
    subl    %edx, %ecx
    movl    %ecx, VM_CTX_VBASE(%esp)
    movl    $0, VM_CTX_VSCRATCH(%esp)
    /* code = descriptor + codeRVA */
    movl    8(%eax), %edx
    addl    %eax, %edx
    movl    %edx, VM_CTX_CODE(%esp)
    movl    12(%eax), %edx
    movl    %edx, VM_CTX_CODELEN(%esp)
    movl    %eax, VM_CTX_DESC(%esp)
2:
    movl    $0, VM_CTX_FLAGS(%esp)
    movl    $0, VM_CTX_PC(%esp)
    movl    $0, VM_CTX_RESERVED(%esp)

    /* ---- call vm_run(ctx): cdecl, one pushed argument, esp % 16 == 0 at the call ---- */
    /* At vm_entry esp % 16 == 12 and VM_FRAME_SIZE % 16 == 0, so esp is still 12 after
     * the sub. `subl $8` brings it to 4 and the push brings it to 0 - exactly what cdecl
     * wants at the call site (the callee then sees 12 once its return address is pushed). */
    subl    $8, %esp
    leal    8(%esp), %eax
    pushl   %eax
    call    vm_run
    addl    $12, %esp

    /* ---- restore volatile GPR (note: EAX is deliberately NOT restored - it
     * carries the guest return value from vm_run) ---- */
    movl    VM_SAVE_ECX(%esp), %ecx
    movl    VM_SAVE_EDX(%esp), %edx

    /* ---- restore volatile XMM: the exit boundary sync already overwrote these
     * slots with the guest's values, so this writes the guest's XMM0 back to the
     * real register (that is how a double return value gets out) ---- */
    movups  VM_SAVE_XMM0(%esp), %xmm0
    movups  VM_SAVE_XMM1(%esp), %xmm1
    movups  VM_SAVE_XMM2(%esp), %xmm2
    movups  VM_SAVE_XMM3(%esp), %xmm3
    movups  VM_SAVE_XMM4(%esp), %xmm4
    movups  VM_SAVE_XMM5(%esp), %xmm5

    /* ---- restore callee-saved ---- */
    movl    VM_SAVE_EBX(%esp), %ebx
    movl    VM_SAVE_EBP(%esp), %ebp
    movl    VM_SAVE_ESI(%esp), %esi
    movl    VM_SAVE_EDI(%esp), %edi

    addl    $VM_FRAME_SIZE, %esp
    ret

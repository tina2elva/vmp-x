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
    /* hand the frame base to the interpreter (used by the XMM boundary sync).
     * vm_ctx_t.frame is a u64, so clear its HIGH dword too: on i686 the surrounding
     * writes are 32-bit, and a stale high half would turn vm->frame into a wild pointer
     * the moment the XMM sync is enabled for this platform (it dereferences
     * (u8 *)(u64)vm->frame). Measured: the high half WAS non-zero garbage before this. */
    movl    %esp, VM_CTX_FRAME(%esp)
    movl    $0, (VM_CTX_FRAME + 4)(%esp)

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
    /* ---- clear the HIGH half of every u64 register slot ----
     * vm_ctx_t.regs[] is u64 even for a 32-bit guest, but every store above is a
     * 32-bit `movl`: without this the upper 4 bytes keep whatever the stack held.
     * The interpreter reads the full u64 (notably the UNSIGNED stack guard
     * `rsp_start - regs[VRSP] > VM_MARGIN`), so stale garbage there showed up as a
     * wild SP (measured: off by exactly 0x10000) and a bogus rc=99.
     * Offsets are the raw +4 dwords of slots 0..17 (16 GPR + VBASE + VSCRATCH)
     * so this cannot depend on any name mapping. No register is touched. */
    movl    $0, 4(%esp)
    movl    $0, 12(%esp)
    movl    $0, 20(%esp)
    movl    $0, 28(%esp)
    movl    $0, 36(%esp)
    movl    $0, 44(%esp)
    movl    $0, 52(%esp)
    movl    $0, 60(%esp)
    movl    $0, 68(%esp)
    movl    $0, 76(%esp)
    movl    $0, 84(%esp)
    movl    $0, 92(%esp)
    movl    $0, 100(%esp)
    movl    $0, 108(%esp)
    movl    $0, 116(%esp)
    movl    $0, 124(%esp)
    movl    $0, 132(%esp)
    movl    $0, 140(%esp)

    /* ---- simulated ESP = esp - (16 + VM_MARGIN) ----
     * 这个 16 必须与 vm_abi.h 的 VM_FRAME_SKEW_EXTRA 一致（lifter 用 FRAME_SIZE+EXTRA+MARGIN 做栈偏移换算）。
     * 踩坑：原来写 4（只算"thunk 的 E8 + 客户机返回地址"各 4 字节），而 EXTRA 是 16 ⇒
     * skew 差 12 ⇒ 每条栈访问都偏 12 ⇒ 用栈的函数（如带循环的 vm32_loop）算出错值，
     * 不用栈的函数（vm32_sum10）看起来正常 —— 极难查。16 还顺带保证了 ≡0 mod 16 的对齐。 */
    leal    -(16 + VM_MARGIN)(%esp), %eax
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

    /* 客户机返回值：从 ctx 取回（与 x64 蹦床一致；vm_run 的 u64 返回值低半也在 EAX，但显式取回更稳）。 */
    movl    VM_CTX_RAX(%esp), %eax
    addl    $VM_FRAME_SIZE, %esp
    /* **跳过 thunk 自己的返回地址**：进入时栈顶是描述符 thunk 里那条 `E8 vm_entry` 压的返回地址，
     * 客户机真正的返回地址在它上面。x64 蹦床同样有 `addq $8`（见 vm_entry_asm.S 结尾）；
     * 少了这一步 ret 会落到 thunk 之后的填充字节（全 0 = `add %al,(%eax)`）⇒ 写 [eax] ⇒ 0xC0000005。 */
    addl    $4, %esp
    ret

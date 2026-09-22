/* vm_abi.h - entry ABI for the **32-bit (i686) Windows** host blob.
 *
 * This is the 32-bit sibling of stub/win/x64/vm_abi.h. Differences that matter:
 *   - pointers are 4 bytes and (mingw/MSVC ABI) u64 is 8-byte aligned,
 *     so sizeof(vm_ctx_t) is 192 (see the ctx offsets below);
 *   - cdecl: arguments are on the stack, the return address is [esp],
 *     and at vm_entry esp % 16 == 12 (the caller pushed 4), so VM_FRAME_SIZE
 *     must be congruent to 12 mod 16 (the x64 header needs 8 mod 16);
 *   - the simulated stack sits at esp - (4 + VM_MARGIN): the 4 is the size of
 *     the return address that cdecl leaves at [esp] (x64 uses 8);
 *   - no XMM argument registers (double arguments are on the stack); XMM0 still
 *     carries a floating-point return value, so it is saved/restored.
 *
 * Entering vm_entry (the caller did `jmp thunk`, the thunk did `call vm_entry`):
 *   [esp]     = return address into the thunk  (thunk = [esp] - 5)
 *   [esp+4]   = guest return address
 *   [esp+8..] = guest arguments (cdecl)
 */
#ifndef VM_ABI_H
#define VM_ABI_H

/* ---- vm_ctx_t field offsets (static assertions in vm_interp.c keep them honest) ---- */
#if defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 8
#error "stub/win/x86 is the 32-bit platform; compile it with a 32-bit compiler"
#endif
#define VM_CTX_SIZE     192
#define VM_CTX_RAX      0
#define VM_CTX_RCX      8
#define VM_CTX_RDX      16
#define VM_CTX_RBX      24
#define VM_CTX_RSP      32
#define VM_CTX_RBP      40
#define VM_CTX_RSI      48
#define VM_CTX_RDI      56
#define VM_CTX_R8       64
#define VM_CTX_R9       72
#define VM_CTX_R10      80
#define VM_CTX_R11      88
#define VM_CTX_R12      96
#define VM_CTX_R13      104
#define VM_CTX_R14      112
#define VM_CTX_R15      120
#define VM_CTX_VBASE    128
#define VM_CTX_VSCRATCH 136
#define VM_CTX_FLAGS    144
#define VM_CTX_PC       148
#define VM_CTX_CODELEN  152
#define VM_CTX_RESERVED 156
#define VM_CTX_CODE     160
#define VM_CTX_DESC       164
#define VM_CTX_SCRATCH    168
#define VM_CTX_SCRATCHLEN 172
/* 184, not 180: mingw/MSVC align u64 to 8, so 176+4 rounds up to 184. */
#define VM_CTX_FRAME      184

/* ---- callee-saved save area (4-byte slots) ---- */
#define VM_SAVE_EBX     192
#define VM_SAVE_EBP     196
#define VM_SAVE_ESI     200
#define VM_SAVE_EDI     204

/* ---- volatile GPR save area: the caller (GCC IPA) may keep live values here ---- */
#define VM_SAVE_EAX     208
#define VM_SAVE_ECX     212
#define VM_SAVE_EDX     216

/* ---- volatile XMM save area (16-byte slots, 16-byte aligned) ---- */
#define VM_SAVE_XMM0    224
#define VM_SAVE_XMM1    240
#define VM_SAVE_XMM2    256
#define VM_SAVE_XMM3    272
#define VM_SAVE_XMM4    288
#define VM_SAVE_XMM5    304
#define VM_SAVE_TOP     (VM_SAVE_XMM5 + 16) /* end of the last save slot = 320 */

/* Decryption scratch lives in the frame; each call gets its own copy. */
#define VM_SCRATCH_OFF  320
#define VM_SCRATCH_SIZE 4096
/* Must stay 16-aligned: vm_interp.c asserts VM_FRAME_SIZE % 16 == 0. The frame only holds
 * the save slots (the decryption scratch lives in .bss), so 640 is plenty. The cdecl
 * call-site alignment is handled in vm_entry_asm.S instead of by changing this value. */
#define VM_FRAME_SIZE   640

/* ---- stack margin for vm_run and its callees (the simulated stack lives below) ---- */
#define VM_MARGIN       0x4000

/* ---- distance between the simulated ESP and the native ESP (used by the lifter) ---- */
/* 16, not 8, and that matters for a real reason: cdecl callers keep esp 16-byte aligned
 * at the call site, and a native callee may use aligned SSE stores into its frame. The
 * simulated stack is `original_esp - VM_FRAME_SKEW`, so for the callee to still see a
 * 16-byte aligned esp we need VM_FRAME_SKEW % 16 == 0. With EXTRA=8 it was 0x4188 (=8 mod 16)
 * and every native call would have been misaligned by 8. (4+4=8 is the byte count; the extra
 * 8 is padding to keep the congruence.) */
#define VM_FRAME_SKEW_EXTRA 16
#define VM_FRAME_SKEW   (VM_FRAME_SIZE + VM_FRAME_SKEW_EXTRA + VM_MARGIN)

/* ---- function descriptor (lives in .vmp) ---- */
#ifndef __ASSEMBLER__
typedef struct {
    unsigned int magic;
    unsigned int selfRVA;
    unsigned int codeRVA;
    unsigned int codeLen;
    unsigned int encLen;
    unsigned int flags;
    unsigned int reserved1;
    unsigned int reserved2;
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char pad[4];
} vm_desc_t;
#endif

#define VM_DESC_FLAG_ENC 1u
#define VM_DESC_SIZE 64
#ifndef VM_DESC_MAGIC
#define VM_DESC_MAGIC 0x4B504D56u
#endif

/* thunk layout: E8 <disp32>  call vm_entry  (5 bytes) */
#define VM_THUNK_SIZE    5
#define VM_DESC_TO_THUNK 64 /* the descriptor sits VM_DESC_SIZE bytes before the thunk */

#endif /* VM_ABI_H */

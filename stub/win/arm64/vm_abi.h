/* vm_abi.h - Windows/arm64（AArch64 + Windows 变体）VM 入口 ABI
 *
 * 与 amd64 版的差别：
 *   - 宿主 ABI 是 AAPCS64：参数在 X0-X7，返回 X0，callee-saved 是 X19-X29 + SP；
 *   - **客户机也是 ARM64**：槽位映射 X0-X30 = 0..30、SP = 31、VBASE = 32、VSCRATCH = 33、ZR = 34，
 *     因此 ctx 的 regs 数组是 35 槽（编译时用 -DVM_REG_COUNT=35），字段偏移与 x86-64 版**不同**，
 *     由 vm_interp.c 的静态断言校验；
 *   - thunk 是 4 字节的 BL，返回地址在 X30（LR）里 → 描述符 = LR - 4 - VM_DESC_TO_THUNK；
 *   - 标志位用 ARM64 的位序：N=1, Z=2, C=4, V=8（入口用 rbit 把 NZCV 反过来填）。
 *
 * 本地没有 aarch64 工具链，本文件与 vm_entry_asm.S 的编译/执行验证在 CI（qemu-user）里做。
 */
#ifndef VM_ABI_H
#define VM_ABI_H

/* ---- ctx 字段偏移（35 槽位布局；由静态断言保证与 vm_ctx_t 一致） ---- */
#define VM_CTX_OFF_REGS   0
#define VM_CTX_X(n)       (VM_CTX_OFF_REGS + 8 * (n))
#define VM_CTX_SP         VM_CTX_X(31)
#define VM_CTX_FLAGS      280
#define VM_CTX_PC         284
#define VM_CTX_CODELEN    288
#define VM_CTX_RESERVED   292
#define VM_CTX_CODE       296
#define VM_CTX_DESC       304
#define VM_CTX_SCRATCH    312
#define VM_CTX_SCRATCHLEN 320
#define VM_CTX_RESERVED2  324
#define VM_CTX_SIZE       336

/* ---- 帧布局：ctx + 保存区 + 解密缓冲 ---- */
#define VM_SAVE_BASE   336
#define VM_SAVE_X(n)   (VM_SAVE_BASE + 8 * ((n) - 1)) /* 保存 X1..X30 */
#define VM_SAVE_LR     576                            /* thunk 的 BL 留下的返回地址（X30 = thunk+4），用来反推描述符 */
#define VM_SAVE_GUEST_LR 584                          /* 客户机的 LR：入口补丁先把调用方返回地址放进 X16 */
#define VM_SCRATCH_OFF 592
#define VM_SCRATCH_SIZE 4096
#define VM_FRAME_SIZE  4688 /* = VM_SCRATCH_OFF + VM_SCRATCH_SIZE，≡ 0 (mod 16) */
#define VM_SAVE_TOP    (VM_SCRATCH_OFF)

/* ---- 栈余量与 skew ---- */
#define VM_MARGIN       0x2000 /* 8KB：守卫要求 margin > 解释器最大帧 + 512（aarch64 上已能测出 4688），
                                   * 8KB 有充裕余量；再大只是白占宿主栈（宿主栈通常 MB 级，改了也不影响语义）。 */
                                  * 于是 margin > maxFrame+512 的检查形同虚设。
                                  * 若解释器真实帧大于 margin，客户机的模拟栈就会与解释器自己的帧重叠 ——
                                  * 现象正好是"vm_run 返回后第一条 ldr [sp] 就 SIGSEGV"。
                                  * arm64 目标跑在大栈上，放宽 margin 没有 x86-Go 那种 goroutine 限制。 */
/* BL 不压栈（返回地址在 LR 里），因此没有 x86 那种"返回地址额外 8 字节" */
#define VM_FRAME_SKEW_EXTRA 0
#define VM_FRAME_SKEW   (VM_FRAME_SIZE + VM_FRAME_SKEW_EXTRA + VM_MARGIN)

/* ---- 函数描述符（与 x86-64 版同布局，64 字节） ---- */
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
#define VM_DESC_MAGIC 0x4B504D56u /* "VMPK" */

/* ---- thunk：4 字节 BL 到 vm_entry（描述符在其前 64 字节） ---- */
#define VM_THUNK_SIZE    4
#define VM_DESC_TO_THUNK 64

/* ---- 入口对齐要求（AAPCS64 要求 SP 16 字节对齐） ---- */
#if (VM_FRAME_SIZE % 16) != 0
#error "VM_FRAME_SIZE 必须是 16 的倍数（AAPCS64 的 SP 对齐）"
#endif

#endif /* VM_ABI_H */
/* vm_abi_linux.h - Linux/amd64（System V ABI）宿主入口的栈布局与常量
 *
 * 与 Windows 版的区别只在**宿主寄存器约定**，客户机 ISA 仍然是 x86-64：
 *
 *   System V AMD64 ABI
 *     参数寄存器 : RDI, RSI, RDX, RCX, R8, R9   （与客户机一致 → ctx 可 1:1 拷贝）
 *     callee-saved: RBX, RBP, R12, R13, R14, R15
 *     volatile    : RAX, RCX, RDX, RSI, RDI, R8-R11, XMM0-XMM15（全部）
 *
 * 仍然沿用“替换后的实现破坏的寄存器不多于原函数”这一原则：
 * 除了返回值 RAX 之外，**所有** GPR 都保存/还原；XMM0-XMM15 也全部保存
 * （SysV 下 XMM 全是 volatile，但调用方同样可能依据对原函数的分析而跨界使用它们）。
 *
 * vm_ctx_t 的布局与 Windows 版完全相同（同一个结构体），因此 VM_CTX_* 偏移不变。
 */
#ifndef VM_ABI_H
#define VM_ABI_H

/* ---- vm_ctx_t 字段偏移（与 vm_types.h 一致，由静态断言保证） ---- */
#define VM_CTX_SIZE     200
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
#define VM_CTX_DESC     168 /* 描述符指针（入口写入） */
#define VM_CTX_SCRATCH  176 /* 解密缓冲指针（入口写入，指向帧内可写区） */
#define VM_CTX_SCRATCHLEN 184

/* ---- callee-saved 保存区（RBX/RBP/R12-R15） ---- */
#define VM_SAVE_RBX     208
#define VM_SAVE_RBP     216
#define VM_SAVE_R12     224
#define VM_SAVE_R13     232
#define VM_SAVE_R14     240
#define VM_SAVE_R15     248

/* ---- volatile GPR 保存区（RCX/RDX/RSI/RDI/R8/R9/R10/R11） ---- */
#define VM_SAVE_RCX     256
#define VM_SAVE_RDX     264
#define VM_SAVE_RSI     272
#define VM_SAVE_RDI     280
#define VM_SAVE_R8     288
#define VM_SAVE_R9     296
#define VM_SAVE_R10     304
#define VM_SAVE_R11     312

/* ---- volatile XMM 保存区（16 字节对齐） ---- */
#define VM_SAVE_XMM0     320
#define VM_SAVE_XMM1     336
#define VM_SAVE_XMM2     352
#define VM_SAVE_XMM3     368
#define VM_SAVE_XMM4     384
#define VM_SAVE_XMM5     400
#define VM_SAVE_XMM6     416
#define VM_SAVE_XMM7     432
#define VM_SAVE_XMM8     448
#define VM_SAVE_XMM9     464
#define VM_SAVE_XMM10     480
#define VM_SAVE_XMM11     496
#define VM_SAVE_XMM12     512
#define VM_SAVE_XMM13     528
#define VM_SAVE_XMM14     544
#define VM_SAVE_XMM15     560

/* 解密缓冲放在帧内：每次调用都有自己的副本 → 嵌套调用/递归不会互相覆盖。 */
#define VM_SCRATCH_OFF  448
#define VM_SCRATCH_SIZE 4096
#define VM_FRAME_SIZE   4544 /* = VM_SCRATCH_OFF + VM_SCRATCH_SIZE，≡ 0 (mod 16) */
#define VM_SAVE_TOP     (VM_SAVE_XMM15 + 16) /* 最后一个保存槽的结束偏移 */

/* ---- vm_run 及其调用者可用的栈余量（模拟栈在其下方） ---- */
#define VM_MARGIN       0x2000 /* 8KB */

#define VM_FRAME_SKEW_EXTRA 16 /* thunk 用 call 压入返回地址带来的额外 8 字节（另有 8 字节见 vm_entry） */
#define VM_FRAME_SKEW   (VM_FRAME_SIZE + VM_FRAME_SKEW_EXTRA + VM_MARGIN)

#ifndef __ASSEMBLER__
typedef struct {
    unsigned int magic;
    unsigned int selfRVA;
    unsigned int codeRVA;
    unsigned int codeLen;  /* 明文长度 */
    unsigned int encLen;   /* 密文长度 */
    unsigned int flags;    /* bit0 = VM_DESC_FLAG_ENC */
    unsigned int reserved1;
    unsigned int reserved2;
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char pad[4]; /* 对齐到 64 字节 */
} vm_desc_t;

#endif

/* 入口汇编也要用这些：放在守卫外面 */
#define VM_DESC_FLAG_ENC 1u
#define VM_DESC_SIZE 64
#define VM_DESC_MAGIC 0x4B504D56u /* "VMPK" */

/* ---- thunk（5 字节）：E8 <disp32> call vm_entry；描述符在其前 16 字节 ----
 * 用 call 而不是寄存器传描述符：调用方可能把活跃值放在 volatile 寄存器里跨调用
 * 使用（实测 RDX/R8/R11 都出现过），用寄存器必然破坏其中一个。
 */
#define VM_THUNK_SIZE    5
#define VM_DESC_TO_THUNK 64

#endif /* VM_ABI_H */
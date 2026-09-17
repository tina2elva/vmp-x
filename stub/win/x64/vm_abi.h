/* vm_abi.h - vm_entry 入口 ABI：栈布局、描述符布局、thunk 布局
 *
 * 单一事实来源：vm_entry_asm.S 用 C 预处理器展开这里的常量；
 * vm_interp.c 用编译期断言校验它们与 vm_ctx_t 的真实布局一致；
 * cmd/vmpbuild 解析本文件并把 frame/skew 写进 manifest，Go 侧据此工作。
 *
 * ---- 关键教训（实测发现）----
 * 调用方（例如 GCC 生成的循环）可能基于**它对原函数寄存器使用情况的分析**
 * 而把活跃值放在 volatile 寄存器里跨调用使用（这不是 ABI 保证，是 IPA 优化）。
 * 我们把函数体换成了 VM，如果 VM 顺手清掉了这些寄存器，调用方的循环就可能失控。
 * 因此 vm_entry **额外保存/还原所有 volatile 寄存器**（GPR + XMM0-XMM5），
 * 使得替换后的实现“破坏的寄存器不多于”原函数。
 *
 * ---- 进入 vm_entry 时的栈 ----
 *   RSP = E, [E] = 调用方返回地址（本函数是被 jmp 进来的）
 *   Win64 参数：RCX, RDX, R8, R9；其余参数在 E+8 之上
 *   R11 = vm_desc_t 指针（thunk 用 lea 给出）
 *
 * ---- 自建帧（VM_FRAME_SIZE，必须 ≡ 8 mod 16）----
 *   [0   .. 167]  vm_ctx_t
 *   [176 .. 239]  调用方 callee-saved（rbx/rbp/rsi/rdi/r12-r15）
 *   [240 .. 295]  调用方 volatile GPR（rcx/rdx/r8/r9/r10/r11）
 *   [304 .. 399]  调用方 volatile XMM（xmm0-xmm5）
 *   [400 .. 407]  对齐填充
 *
 * ---- 模拟栈位置 ----
 *   模拟 RSP = (rsp_after_sub) - (8 + VM_MARGIN)，位于 vm_run 栈帧之下，
 *   两者互不重叠。lifter 对“相对进入时 RSP 偏移 >= 0”的内存操作数需要补 VM_FRAME_SKEW。
 */
#ifndef VM_ABI_H
#define VM_ABI_H

/* ---- vm_ctx_t 字段偏移（静态断言保证一致） ---- */
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
#ifdef VM_GUEST_ARM64
/* ARM64 客户机：槽位 32/33（见 vm_types.h 的说明） */
#define VM_CTX_VBASE    256
#define VM_CTX_VSCRATCH 264
#else
#define VM_CTX_VBASE    128
#define VM_CTX_VSCRATCH 136
#endif
#define VM_CTX_FLAGS    144
#define VM_CTX_PC       148
#define VM_CTX_CODELEN  152
#define VM_CTX_RESERVED 156
#define VM_CTX_CODE     160
#define VM_CTX_DESC     168 /* 描述符指针（入口写入） */
#define VM_CTX_SCRATCH  176 /* 解密缓冲指针（入口写入，指向帧内可写区） */
#define VM_CTX_SCRATCHLEN 184

/* ---- callee-saved 保存区 ---- */
#define VM_SAVE_RBX     208
#define VM_SAVE_RBP     216
#define VM_SAVE_RSI     224
#define VM_SAVE_RDI     232
#define VM_SAVE_R12     240
#define VM_SAVE_R13     248
#define VM_SAVE_R14     256
#define VM_SAVE_R15     264

/* ---- volatile GPR 保存区 ---- */
#define VM_SAVE_RCX     272
#define VM_SAVE_RDX     280
#define VM_SAVE_R8     288
#define VM_SAVE_R9     296
#define VM_SAVE_R10     304
#define VM_SAVE_R11     312

/* ---- volatile XMM 保存区（16 字节对齐） ---- */
#define VM_SAVE_XMM0     336
#define VM_SAVE_XMM1     352
#define VM_SAVE_XMM2     368
#define VM_SAVE_XMM3     384
#define VM_SAVE_XMM4     400
#define VM_SAVE_XMM5     416

/* 解密缓冲放在帧内：每次调用都有自己的副本 → 嵌套调用/递归不会互相覆盖。 */
#define VM_SCRATCH_OFF  448
#define VM_SCRATCH_SIZE 4096
#define VM_FRAME_SIZE   640 /* 解密缓冲已搬到 .bss 的池里：帧只需覆盖保存槽（VM_SAVE_TOP≈576） */
#define VM_SAVE_TOP     (VM_SAVE_XMM5 + 16) /* 最后一个保存槽的结束偏移 */

/* ---- vm_run 及其调用者可用的栈余量（模拟栈在其下方） ---- */
#define VM_MARGIN       0x1C00 /* 7KB：总深度 640+16+7168 = 7824 < 8KB，同时给客户机留 7KB 自己的栈 */

/* ---- 模拟 RSP 与原生 RSP 的差值（lifter 用） ---- */
#define VM_FRAME_SKEW_EXTRA 16 /* thunk 用 call 压入返回地址带来的额外 8 字节（另有 8 字节见 vm_entry） */
#define VM_FRAME_SKEW   (VM_FRAME_SIZE + VM_FRAME_SKEW_EXTRA + VM_MARGIN)

/* ---- 函数描述符（放在 .vmp 里） ---- */
#ifndef __ASSEMBLER__
typedef struct {
    unsigned int magic;   /* VM_DESC_MAGIC */
    unsigned int selfRVA; /* 自身 RVA：模块基址 = 描述符地址 - selfRVA */
    unsigned int codeRVA; /* 字节码（或密文）相对本描述符的偏移 */
    unsigned int codeLen; /* **明文**长度 */
    unsigned int encLen;  /* 密文长度（未加密时等于 codeLen） */
    unsigned int flags;   /* bit0 = VM_DESC_FLAG_ENC */
    unsigned int reserved1;
    unsigned int reserved2;
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char pad[4]; /* 对齐到 64 字节 */
} vm_desc_t;

#endif /* !__ASSEMBLER__ */

/* 入口汇编也要用这些：放在守卫外面 */
#define VM_DESC_FLAG_ENC 1u
#define VM_DESC_SIZE 64
#define VM_DESC_MAGIC 0x4B504D56u /* "VMPK" */

/* ---- thunk 布局（5 字节，紧跟描述符之后） ----
 *   E8 <disp32>   call vm_entry    ; disp = vm_entry - (thunk + 5)
 *
 * 为什么是 call 而不是“lea r11 + jmp”：
 *   调用方（GCC 的 IPA 优化）会把活跃值放在 volatile 寄存器里跨调用使用——
 *   实测 RDX/R8/R11 都出现过。用寄存器传描述符必然破坏其中一个。
 *   改成 call 后，入口可以**先把所有寄存器存进 ctx**，再从栈上读回返回地址反推描述符
 *   （thunk = 返回地址 - 5，描述符 = thunk - 16），进入时完全不破坏 guest 寄存器。
 *
 * 被保护函数入口：E9 <disp32>  jmp thunk    ; disp = thunk - (func + 5)
 */
#define VM_THUNK_SIZE    5
#define VM_DESC_TO_THUNK 64 /* 描述符位于 thunk 之前 16 字节 */

#endif /* VM_ABI_H */
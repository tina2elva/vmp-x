/* vm_types.h - VM 上下文与类型（Windows/x64 宿主解释器） */
#ifndef VM_TYPES_H
#define VM_TYPES_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char i8;
typedef short i16;
typedef int i32;
typedef long long i64;

/* 规范 x86-64 寄存器编号 */
#ifdef VM_GUEST_ARM64
/* ARM64 客户机：X0-X30 = 0..30、SP = 31、VBASE = 32、VSCRATCH = 33、ZR = 34。
 * 这里必须用 32/33：早先无条件写成 16/17，与 X16 撞车，导致 ARM64 客户机的所有内存
 * 操作都以错误基址执行（解释器直接 rc=1）。ARM64 入口 stub 也按 32/33 填槽。 */
enum {
    VRAX = 0, VRCX, VRDX, VRBX, VRSP, VRBP, VRSI, VRDI,
    VR8, VR9, VR10, VR11, VR12, VR13, VR14, VR15,
    VRBASE = 32,
    VRSCRATCH = 33,
    VM_REG_COUNT_X64 = 35
};
#else
enum {
    VRAX = 0, VRCX, VRDX, VRBX, VRSP, VRBP, VRSI, VRDI,
    VR8, VR9, VR10, VR11, VR12, VR13, VR14, VR15,
    VRBASE = 16,      /* 本模块运行时基址（由入口封装填写） */
    VRSCRATCH = 17,   /* 仅 VM 可见的暂存寄存器（不映射到任何 x86 寄存器） */
    VM_REG_COUNT_X64 = 18
};
#endif

/* 寄存器槽位总数必须可被平台/客户机覆盖：
 *   x86-64 宿主+客户机：18（16 GPR + VBASE + VSCRATCH）
 *   ARM64 客户机：35（X0-X30 + SP + VBASE + VSCRATCH + ZR），由 -DVM_REG_COUNT=35 指定
 * 数组大小因此成为客户机的一部分，静态断言保证它与入口 stub 填槽数一致。 */
#ifndef VM_REG_COUNT
#define VM_REG_COUNT VM_REG_COUNT_X64
#endif

/* ARM64 客户机的零寄存器槽位（XZR/WZR）：写入被丢弃、读取恒 0 */
#define VRARM64_ZR 34

/* 真实标志位：语义与 x86 的 ZF/SF/CF/OF 一一对应 */
#define VM_FL_Z 1u  /* ZF */
#define VM_FL_N 2u  /* SF */
#define VM_FL_C 4u  /* CF */
#define VM_FL_V 8u  /* OF */
#define VM_FL_P 16u /* PF（低字节偶校验），让 JP/JNP 也能精确实现 */

/* vm_desc_t（函数描述符）定义在平台的 vm_abi.h 里——入口 stub 与解释器都从那里取。 */

typedef struct {
    u64 regs[VM_REG_COUNT];
    u32 flags;
    u32 pc;
    u32 codeLen;
    u32 reserved;
    const u8 *code;
    /* 加密支持：描述符指针 + 入口提供的一段**可写**缓冲（用于解密后的字节码） */
    const void *desc; /* 指向 vm_desc_t（定义在平台 vm_abi.h） */
    u8 *scratch;
    u32 scratchLen;
    u32 reserved2;
    u8 pad[8]; /* 让结构体大小是 16 的倍数，保持后续 ABI 偏移整洁 */
} vm_ctx_t;

#endif /* VM_TYPES_H */
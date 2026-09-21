/* vm_opcodes.h - M1 编码表
 *
 * 设计原则（对应真实 x86-64 语义需求）：
 *  - 每条 ALU 运算都带 width(8/16/32/64)：x86 的 32 位运算会把结果零扩展到 64 位，
 *    且标志位必须按 32 位结果计算；8/16 位运算是局部寄存器写。
 *  - 比较与 ALU 分开（CMP/TEST 只写标志）。
 *  - 标志位语义在解释器里是真实 NZCV（CF=进位/借位、OF=有符号溢出）。
 *
 * M2 起这些固定编码会由 cmd/vmpbuild 生成构建期随机映射。
 */
#ifndef VM_OPCODES_H
#define VM_OPCODES_H

/* 通用 ALU 子操作 */
enum {
    K_ADD = 0, K_SUB, K_AND, K_OR, K_XOR, K_MUL,
    K_SHL, K_SHR, K_SAR, K_ROL, K_ROR,
    /* 带进位形式（x86 的 ADC/SBB）；值必须与 internal/ir 的 Kind 一致 */
    K_ADC = 0x0B, K_SBB = 0x0C,
    K_MULHI = 0x0D, /* 无符号乘法的**高半**（x86 的 MUL 用它写 RDX，并给出正确的 CF/OF） */
    K_BT = 0x0E,    /* 位测试（x86 的 BT）：只改 CF，其余标志位保持不动 */
    K_BSF = 0x0F,   /* 位扫描（x86 的 BSF）：最低置位位下标，只改 ZF */
    K_BSR = 0x10,   /* 位扫描（x86 的 BSR）：最高置位位下标，只改 ZF */
    K_TZCNT = 0x11, /* BMI1 TZCNT：源为 0 时结果为位宽，且置 CF/ZF */
    K_LZCNT = 0x12, /* BMI1 LZCNT：同上 */
    K_MULHIS = 0x13, /* 有符号乘法的高半（单操作数 IMUL）：CF=OF=(高半不是低半的符号扩展) */
    K_DIVU = 0x14,   /* x86 DIV （单操作数，无符号）：被除数 DX:AX 族，商→AX 族、余→DX 族 */
    K_DIVS = 0x15    /* x86 IDIV（单操作数，有符号）：同上；除零/商溢出由解释器直接 trap */
};
/* 原子子操作（OP_ATOMIC 的 kind 字节；bit7 仍表示 keep-flags） */
enum {
    KA_XCHG = 0, /* XCHG [mem], reg（隐含 lock）：mem ← reg，reg ← 旧值 */
    KA_ADD,      /* LOCK ADD  [mem], reg */
    KA_SUB, KA_AND, KA_OR, KA_XOR,
    KA_INC, KA_DEC, /* LOCK INC/DEC [mem] */
    KA_CMPXCHG   /* LOCK CMPXCHG [mem], reg（与 RAX 比较） */
};

/* 浮点子操作（OP_FP 的 kind 字节） */
enum {
    KF_ADD = 0, KF_SUB, KF_MUL, KF_DIV, KF_MIN, KF_MAX, KF_SQRT,
    KF_CVTSI2F, /* 整数（RAX）→ 浮点 */
    KF_CVTTF2SI, /* 浮点 → 整数（RAX，截断） */
    KF_UCOMI,    /* 比较（按 SDM 设置 ZF/PF/CF） */
    KF_CVTDQ2PD  /* CVTDQ2PD：源的低 64 位（两个 int32）→ 两个 double（写满目标 128 位） */
};

/* 一元子操作 */
enum { KU_NEG = 0, KU_NOT, KU_INC, KU_DEC };
/* 比较子操作 */
enum { KC_CMP = 0, KC_TEST };

/* 宽度编码 */
enum { W8 = 8, W16 = 16, W32 = 32, W64 = 64 };

/* 寄存器“不存在”哨兵（用于 LEA 的 base/index） */
#define VM_NO_REG 0xFF
#define VM_REG_COUNT_FULL 17 /* 16 个 x86 寄存器 + 模块基址 */

/* 编码值来自 vm_opcode_values.h：默认固定，vmpbuild 会替换成构建期随机映射 */
#include "vm_opcode_values.h"

enum {
    OP_HALT = VM_OP_HALT, /* [1] */
    OP_NOP = VM_OP_NOP,   /* [1] */
    OP_RET = VM_OP_RET,   /* [1] */

    /* 数据移动 */
    OP_MOV_RR = VM_OP_MOV_RR,     /* [op][width][dst][src]                      4B */
    OP_MOV_RI = VM_OP_MOV_RI,     /* [op][width][dst][imm64]                   11B */
    OP_MOV_RI32 = VM_OP_MOV_RI32, /* [op][dst][imm32]   (32 位 mov, 零扩展)      6B */
    OP_LEA = VM_OP_LEA,           /* [op][width][dst][base][index][scale][disp32] 10B */

    /* 二元 ALU */
    /* kind 字节的 bit7 = VM_ALU_KEEP_FLAGS：执行运算但**不修改标志位**。
     * 这是为 ARM64 准备的：ARM64 的 ADD/SUB 等不带 S 时不设置标志位，而 x86 的同类
     * 指令一定设置——同一个 opcode 靠这一位区分，x86-64 侧现有字节码该位恒为 0。 */
#define VM_ALU_KEEP_FLAGS 0x80u

    OP_ALU_RR = VM_OP_ALU_RR, /* [op][kind][width][dst][a][b]               6B */
    OP_ALU_RI = VM_OP_ALU_RI, /* [op][kind][width][dst][a][imm32]          9B */
    OP_ALU_U = VM_OP_ALU_U,   /* [op][kind][width][dst][a]                 5B */
    OP_CMP_RR = VM_OP_CMP_RR, /* [op][kind][width][a][b]                   6B (只写标志) */
    OP_CMP_RI = VM_OP_CMP_RI, /* [op][kind][width][a][imm32]               8B (只写标志) */

    /* 扩展 */
    OP_EXT = VM_OP_EXT, /* [op][kind][srcw][dst][src]  5B  kind:0=zx 1=sx (结果 64 位) */

    /* 内存 */
    OP_LOAD = VM_OP_LOAD,   /* [op][kind][width][dst][base][index][scale][disp32] 11B */
    OP_STORE = VM_OP_STORE, /* [op][width][base][index][scale][disp32][src]       10B */
    /* 原子读改写（x86 的 XCHG [mem] 与 LOCK 前缀系列）：真用宿主硬件的原子指令实现 */
    OP_ATOMIC = VM_OP_ATOMIC, /* [op][kind][width][dst][src][base][idx][scale][disp32] 12B */
    OP_FP = VM_OP_FP,         /* [op][kind][w][dstOff][aOff][bOff] 15B（浮点标量，偏移相对 VMBASE）*/

    /* 栈 */
    OP_PUSH_R = VM_OP_PUSH_R, /* [op][reg]    2B */
    OP_PUSH_I = VM_OP_PUSH_I, /* [op][imm32]  5B */
    OP_POP_R = VM_OP_POP_R,   /* [op][reg]    2B */

    /* 控制流 */
    OP_JCC = VM_OP_JCC, /* [op][cond][target32]  6B */
    OP_JMP = VM_OP_JMP, /* [op][target32]        5B */
    /* 以下两条按**寄存器是否为零**分支，且**不修改标志位**——
     * ARM64 的 CBZ/CBNZ/TBZ/TBNZ 必须是这种语义（它们不影响 NZCV），
     * 用 CMP+JCC 实现会破坏客户机的标志位。 */
    OP_JBZ = VM_OP_JBZ,   /* [op][reg][target32]   6B */
    OP_JBNZ = VM_OP_JBNZ, /* [op][reg][target32]   6B */
    OP_CALLN = VM_OP_CALLN, /* [op][imm64]           9B (调用原生函数) */
    OP_CALLR = VM_OP_CALLR  /* [op][reg]             2B (间接调用：寄存器里是客户机地址) */
};

/* x86 条件码（与 x86asm 的 Cond 编号一致：O/NO/B/AE/E/NE/BE/A/S/NS/P/NP/L/GE/LE/G） */
enum {
    CC_O = 0, CC_NO, CC_B, CC_AE, CC_E, CC_NE, CC_BE, CC_A,
    CC_S, CC_NS, CC_P, CC_NP, CC_L, CC_GE, CC_LE, CC_G
};

#endif /* VM_OPCODES_H */
/* guest_semantics_arm64.h - ARM64 客户机的标志位与条件码语义
 *
 * 为什么单独一个模块：ARM64 的 C 位语义与 x86-64 **相反**（ARM64 里 C=1 表示
 * "无借位/无符号大于等于"，x86 里 CF=1 表示借位），移位类指令的 C/V 规则也不同。
 * 这些规则是模拟器最容易写错、又最难在端到端里暴露的部分（错一位就会静默算错），
 * 因此单独成模块，并与一份独立的 Go 参考实现做大规模对拍。
 *
 * 标志位布局（与 x86-64 客户机共用同一个 32 位 flags 字段，含义按客户机 ISA 解释）：
 *   bit0 = N, bit1 = Z, bit2 = C, bit3 = V
 * ARM64 没有 PF，x86-64 那边另有 bit4 = P。
 */
#ifndef GUEST_SEMANTICS_ARM64_H
#define GUEST_SEMANTICS_ARM64_H

#include "vm_types.h"

#define ARM64_FL_N 1u
#define ARM64_FL_Z 2u
#define ARM64_FL_C 4u
#define ARM64_FL_V 8u

u64 arm64_mask_w(u32 w);
u32 arm64_flags_add(u64 a, u64 b, u64 r, u32 w);
u32 arm64_flags_sub(u64 a, u64 b, u64 r, u32 w);
u32 arm64_flags_logic(u64 r, u32 w);
u32 arm64_flags_mul(u64 r, u32 w);
/* 旗标设置型移位：cnt==0 时 C 保持不变；cnt!=0 时 C = 最后移出的位；V 永远不变 */
u32 arm64_flags_shift(u64 r, u64 last_bit_out, u32 w, u32 cnt, u32 old_flags);
/* 条件成立返回 1；cond 取值 0..15（EQ..LE），14=AL，15=NV（ARM64 里也当作 AL） */
int arm64_cond_holds(u32 cond, u32 flags);

#endif

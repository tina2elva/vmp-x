/* vm_opcode_values.h - VM 指令的**编码值**（单一来源）
 *
 * 默认是固定编码；cmd/vmpbuild 在 staging 阶段会把这份文件**替换成构建期随机映射**
 * （每个 blob 一套独立的操作码编码），解释器因此用编译期常量分发，运行时零开销。
 *
 * 注意：名字列表与 internal/vm/opcodes.go 的表、以及 manifest 里的 opcodeMap 必须一致；
 * Go/C 交叉校验测试会解析本文件来验证这一点。
 */
#ifndef VM_OPCODE_VALUES_H
#define VM_OPCODE_VALUES_H

#define VM_OP_HALT 0x00
#define VM_OP_NOP 0x01
#define VM_OP_RET 0x02

#define VM_OP_MOV_RR 0x10
#define VM_OP_MOV_RI 0x11
#define VM_OP_MOV_RI32 0x12
#define VM_OP_LEA 0x13

#define VM_OP_ALU_RR 0x20
#define VM_OP_ALU_RI 0x21
#define VM_OP_ALU_U 0x22
#define VM_OP_CMP_RR 0x23
#define VM_OP_CMP_RI 0x24

#define VM_OP_EXT 0x30

#define VM_OP_LOAD 0x40
#define VM_OP_STORE 0x41

#define VM_OP_PUSH_R 0x50
#define VM_OP_PUSH_I 0x51
#define VM_OP_POP_R 0x52

#define VM_OP_JCC 0x60
#define VM_OP_JMP 0x61
#define VM_OP_JBZ 0x62
#define VM_OP_JBNZ 0x63

#define VM_OP_CALLN 0x70
#define VM_OP_CALLR 0x71
#define VM_OP_ATOMIC 0x42
#define VM_OP_FP 0x43

#endif
package vm

import (
	"encoding/binary"
	"fmt"
)

// opInfo 操作码信息（必须与 stub/win/x64/vm_interp.c 的 vm_insn_size 一致，
// 由 disasm_test.go 交叉校验）
type opInfo struct {
	Name string
	Size int
}

var opTable = map[byte]opInfo{
	OpHalt:    {"HALT", 1},
	OpNop:     {"NOP", 1},
	OpRet:     {"RET", 1},
	OpMovRR:   {"MOV_RR", 4},
	OpMovRI:   {"MOV_RI", 11},
	OpMovRI32: {"MOV_RI32", 6},
	OpLea:     {"LEA", 10},
	OpAluRR:   {"ALU_RR", 6},
	OpAluRI:   {"ALU_RI", 9},
	OpAluU:    {"ALU_U", 5},
	OpCmpRR:   {"CMP_RR", 5},
	OpCmpRI:   {"CMP_RI", 8},
	OpExt:     {"EXT", 5},
	OpLoad:    {"LOAD", 11},
	OpStore:   {"STORE", 10},
	OpPushR:   {"PUSH_R", 2},
	OpPushI:   {"PUSH_I", 5},
	OpPopR:    {"POP_R", 2},
	OpJcc:     {"JCC", 6},
	OpJmp:     {"JMP", 5},
	OpJbz:     {"JBZ", 6},
	OpJbnz:    {"JBNZ", 6},
	OpCallN:   {"CALL", 9},
	OpCallR:   {"CALLR", 2},
	OpAtomic:  {"ATOMIC", 12},
	OpFp:      {"FP", 15},
}

// InsnSize 返回指定 opcode 的指令长度（0 表示未知）
func InsnSize(op byte) int {
	if info, ok := opTable[op]; ok {
		return info.Size
	}
	return 0
}

// OpcodeName 操作码名称
func OpcodeName(op byte) string {
	if info, ok := opTable[op]; ok {
		return info.Name
	}
	return fmt.Sprintf("UNKNOWN(0x%02X)", op)
}

var aluKinds = [...]string{"ADD", "SUB", "AND", "OR", "XOR", "MUL", "SHL", "SHR", "SAR", "ROL", "ROR"}
var unKinds = [...]string{"NEG", "NOT", "INC", "DEC"}
var cmpKinds = [...]string{"CMP", "TEST"}
var condNames = [...]string{"O", "NO", "B", "AE", "E", "NE", "BE", "A", "S", "NS", "P", "NP", "L", "GE", "LE", "G"}
var regNames = [...]string{"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
	"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "VBASE", "VSCR"}

func rn(b byte) string {
	if b == 0xFF {
		return "none"
	}
	if int(b) < len(regNames) {
		return regNames[b]
	}
	return fmt.Sprintf("R%d", b)
}

func kindName(k byte, table []string) string {
	if int(k) < len(table) {
		return table[k]
	}
	return fmt.Sprintf("K%d", k)
}

// DisasmOne 反汇编一条指令，返回文本与消耗的字节数
func DisasmOne(code []byte, pc int) (string, int) {
	if pc >= len(code) {
		return "EOF", 0
	}
	op := code[pc]
	info, known := opTable[op]
	if !known {
		return fmt.Sprintf("%04X: UNKNOWN 0x%02X", pc, op), 1
	}
	if info.Size > len(code)-pc {
		return fmt.Sprintf("%04X: %s (truncated)", pc, info.Name), len(code) - pc
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(code[pc+off:]) }

	switch op {
	case OpLea:
		return fmt.Sprintf("%04X: LEA w=%d %s = [%s + %s*%d + %d]",
			pc, code[pc+1], rn(code[pc+2]), rn(code[pc+3]), rn(code[pc+4]), code[pc+5], int32(u32(6))), info.Size
	case OpAluRR:
		return fmt.Sprintf("%04X: %s%d %s, %s, %s",
			pc, kindName(code[pc+1], aluKinds[:]), code[pc+2], rn(code[pc+3]), rn(code[pc+4]), rn(code[pc+5])), info.Size
	case OpAluRI:
		return fmt.Sprintf("%04X: %s%d %s, %s, 0x%X",
			pc, kindName(code[pc+1], aluKinds[:]), code[pc+2], rn(code[pc+3]), rn(code[pc+4]), u32(5)), info.Size
	case OpAluU:
		return fmt.Sprintf("%04X: %s%d %s, %s",
			pc, kindName(code[pc+1], unKinds[:]), code[pc+2], rn(code[pc+3]), rn(code[pc+4])), info.Size
	case OpCmpRR:
		return fmt.Sprintf("%04X: %s%d %s, %s",
			pc, kindName(code[pc+1], cmpKinds[:]), code[pc+2], rn(code[pc+3]), rn(code[pc+4])), info.Size
	case OpCmpRI:
		return fmt.Sprintf("%04X: %s%d %s, 0x%X",
			pc, kindName(code[pc+1], cmpKinds[:]), code[pc+2], rn(code[pc+3]), u32(4)), info.Size
	case OpMovRR:
		return fmt.Sprintf("%04X: MOV%d %s, %s", pc, code[pc+1], rn(code[pc+2]), rn(code[pc+3])), info.Size
	case OpLoad:
		return fmt.Sprintf("%04X: LOAD%s w=%d %s, [%s + %s*%d %+d]",
			pc, map[byte]string{0: "ZX", 1: "SX"}[code[pc+1]], code[pc+2], rn(code[pc+3]),
			rn(code[pc+4]), rn(code[pc+5]), code[pc+6], int32(u32(7))), info.Size
	case OpStore:
		return fmt.Sprintf("%04X: STORE%d [%s + %s*%d %+d], %s", pc, code[pc+1], rn(code[pc+2]),
			rn(code[pc+3]), code[pc+4], int32(u32(5)), rn(code[pc+9])), info.Size
	case OpExt:
		return fmt.Sprintf("%04X: EXT %s from w=%d %s, %s",
			pc, map[byte]string{0: "zx", 1: "sx"}[code[pc+1]], code[pc+2], rn(code[pc+3]), rn(code[pc+4])), info.Size
	case OpJcc:
		return fmt.Sprintf("%04X: J%s 0x%04X", pc, condNames[code[pc+1]&15], u32(2)), info.Size
	case OpJmp:
		return fmt.Sprintf("%04X: JMP 0x%04X", pc, u32(1)), info.Size
	case OpJbz:
		return fmt.Sprintf("%04X: JBZ %s -> 0x%04X", pc, rn(code[pc+1]), u32(2)), info.Size
	case OpJbnz:
		return fmt.Sprintf("%04X: JBNZ %s -> 0x%04X", pc, rn(code[pc+1]), u32(2)), info.Size
	case OpPushR:
		return fmt.Sprintf("%04X: PUSH %s", pc, rn(code[pc+1])), info.Size
	case OpPopR:
		return fmt.Sprintf("%04X: POP %s", pc, rn(code[pc+1])), info.Size
	case OpPushI:
		return fmt.Sprintf("%04X: PUSH 0x%X", pc, int32(u32(1))), info.Size
	case OpCallR:
		return fmt.Sprintf("%04X: CALLR %s", pc, rn(code[pc+1])), info.Size
	case OpFp:
		return fmt.Sprintf("%04X: FP kind=%d w=%d dst=+0x%X a=+0x%X b=+0x%X", pc, code[pc+1], code[pc+2],
			binary.LittleEndian.Uint32(code[pc+3:]), binary.LittleEndian.Uint32(code[pc+7:]),
			binary.LittleEndian.Uint32(code[pc+11:])), info.Size
	case OpAtomic:
		return fmt.Sprintf("%04X: ATOMIC kind=%d w=%d %s, [%s+%s*%d+0x%X]", pc, code[pc+1], code[pc+2],
			rn(code[pc+3]), rn(code[pc+5]), rn(code[pc+6]), code[pc+7], u32(pc+8)), info.Size
	case OpCallN:
		return fmt.Sprintf("%04X: CALL rva=0x%X", pc, binary.LittleEndian.Uint64(code[pc+1:])), info.Size
	case OpMovRI:
		return fmt.Sprintf("%04X: MOV%d %s, 0x%X", pc, code[pc+1], rn(code[pc+2]), binary.LittleEndian.Uint64(code[pc+3:])), info.Size
	case OpMovRI32:
		return fmt.Sprintf("%04X: MOV32 %s, 0x%X", pc, rn(code[pc+1]), u32(2)), info.Size
	}
	return fmt.Sprintf("%04X: %s", pc, info.Name), info.Size
}

// DisasmAll 反汇编整个字节码（遇到未知/截断即停止）
func DisasmAll(code []byte) []string {
	var out []string
	pc := 0
	for pc < len(code) {
		line, n := DisasmOne(code, pc)
		if n == 0 {
			break
		}
		out = append(out, line)
		pc += n
	}
	return out
}

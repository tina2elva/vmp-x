// Package arm64 是 A64（ARM64）解码层。
//
// 设计取舍与 x86-64 侧一致：**解码本身不是难点，lifter 才是**，因此复用经过验证的
// 参考解码器（golang.org/x/arch/arm64/arm64asm），本层只做三件参考实现不保证的事：
//
//  1. 严格输入检查：A64 定长 4 字节，长度不是 4 的倍数或无法识别的编码一律报错，
//     绝不返回"大概是什么"；
//  2. **编码分类**（Class）：arm64asm 给的是**别名**（MOV/CMN/CMP/TST…），
//     别名会把底层编码（MOVZ/MOVN/MOVK、ORR-imm、ADDS…）藏起来，而 lifter 必须知道
//     真实语义。分类完全基于原始编码字，按 ARM ARM 的 A64 编码树判定；
//  3. 便于 lifter 使用的字段提取（寄存器号、立即数、条件码、分支目标）。
//
// 说明：分类只覆盖我们计划 lift 的指令族；未覆盖的编码返回 ClassUnknown，
// lifter 据此**拒绝翻译**（fail-fast），而不是猜。
package arm64

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"
)

// Class 是 A64 顶层编码分类（面向 lift 的粒度）
type Class uint8

const (
	ClassUnknown Class = iota
	ClassAddSubImm
	ClassAddSubShifted
	ClassAddSubExtended
	ClassLogicalImm
	ClassLogicalShifted
	ClassMoveWide
	ClassBitfield
	ClassCondSelect
	ClassDataProc2
	ClassDataProc3 // 三操作数：MADD/MSUB
	ClassBranchImm
	ClassBranchCond
	ClassCompareBranch
	ClassTestBranch
	ClassBranchReg
	ClassPCRel
	ClassLoadStore
	ClassLoadStorePair
	ClassLoadLiteral // LDR (literal)：PC 相对取常量
	ClassFPVec       // SIMD/FP：已识别但**不 lift**
	ClassMisc
)

var className = map[Class]string{
	ClassUnknown:        "Unknown",
	ClassAddSubImm:      "AddSubImm",
	ClassAddSubShifted:  "AddSubShifted",
	ClassAddSubExtended: "AddSubExtended",
	ClassLogicalImm:     "LogicalImm",
	ClassLogicalShifted: "LogicalShifted",
	ClassMoveWide:       "MoveWide",
	ClassBitfield:       "Bitfield",
	ClassCondSelect:     "CondSelect",
	ClassDataProc2:      "DataProc2",
	ClassDataProc3:      "DataProc3",
	ClassBranchImm:      "BranchImm",
	ClassBranchCond:     "BranchCond",
	ClassCompareBranch:  "CompareBranch",
	ClassTestBranch:     "TestBranch",
	ClassBranchReg:      "BranchReg",
	ClassPCRel:          "PCRel",
	ClassLoadStore:      "LoadStore",
	ClassLoadStorePair:  "LoadStorePair",
	ClassLoadLiteral:    "LoadLiteral",
	ClassFPVec:          "FPVec",
	ClassMisc:           "Misc",
}

func (c Class) String() string {
	if s, ok := className[c]; ok {
		return s
	}
	return fmt.Sprintf("Class(%d)", uint8(c))
}

// Insn 一条已解码的 A64 指令
type Insn struct {
	PC    uint64
	Raw   uint32
	Op    arm64asm.Op
	Args  arm64asm.Args
	Class Class
}

// Len A64 定长
func (i *Insn) Len() int { return 4 }

func (i *Insn) Text() string { return i.Op.String() + " " + argsText(i.Args) }

func argsText(a arm64asm.Args) string {
	s := ""
	for _, arg := range a {
		if arg == nil {
			break
		}
		if s != "" {
			s += ", "
		}
		s += arg.String()
	}
	return s
}

func (i *Insn) String() string {
	return fmt.Sprintf("0x%X: %08X  %-14s %s", i.PC, i.Raw, i.Op.String(), argsText(i.Args))
}

// Decode 解码一条指令；长度不足或编码非法时返回错误
func Decode(code []byte, pc uint64) (Insn, error) {
	if len(code) < 4 {
		return Insn{}, fmt.Errorf("A64 指令必须是 4 字节，只剩 %d 字节", len(code))
	}
	raw := binary.LittleEndian.Uint32(code)
	inst, err := arm64asm.Decode(code[:4])
	if err != nil {
		return Insn{}, fmt.Errorf("0x%X: 无法解码 %08X: %w", pc, raw, err)
	}
	return Insn{PC: pc, Raw: raw, Op: inst.Op, Args: inst.Args, Class: Classify(raw)}, nil
}

// DecodeRange 解码一段代码；A64 定长，所以不需要"猜长度"
func DecodeRange(code []byte, base uint64, maxInsns int) ([]Insn, error) {
	if len(code)%4 != 0 {
		return nil, fmt.Errorf("代码长度 %d 不是 4 的倍数（A64 定长）", len(code))
	}
	n := len(code) / 4
	if maxInsns > 0 && n > maxInsns {
		n = maxInsns
	}
	out := make([]Insn, 0, n)
	for i := 0; i < n; i++ {
		ins, err := Decode(code[i*4:], base+uint64(i)*4)
		if err != nil {
			return out, err
		}
		out = append(out, ins)
	}
	return out, nil
}

// Classify 按 ARM ARM 的 A64 编码树对原始编码分类（只看位，不看别名）
func Classify(w uint32) Class {
	switch {
	// ---- 分支与地址 ----
	case w&0x7C000000 == 0x14000000: // B / BL
		return ClassBranchImm
	case w&0xFF000000 == 0x54000000: // B.cond（bit4 = 0）
		return ClassBranchCond
	case w&0x7E000000 == 0x34000000: // CBZ / CBNZ
		return ClassCompareBranch
	case w&0x7E000000 == 0x36000000: // TBZ / TBNZ
		return ClassTestBranch
	case w&0xFE000000 == 0xD6000000: // BR / BLR / RET / ERET
		return ClassBranchReg
	case w&0x1F000000 == 0x10000000: // ADR / ADRP
		return ClassPCRel

	// ---- 数据处理（立即数） ----
	case w&0x1F800000 == 0x11000000: // ADD/SUB (immediate)
		return ClassAddSubImm
	case w&0x1F800000 == 0x12000000: // AND/ORR/EOR/ANDS (immediate)
		return ClassLogicalImm
	case w&0x1F800000 == 0x12800000: // MOVN/MOVZ/MOVK
		return ClassMoveWide
	case w&0x1F800000 == 0x13000000: // SBFM/BFM/UBFM
		return ClassBitfield

	// ---- 数据处理（寄存器） ----
	case w&0x1F200000 == 0x0B000000: // ADD/SUB (shifted register)
		return ClassAddSubShifted
	case w&0x1F200000 == 0x0B200000: // ADD/SUB (extended register)
		return ClassAddSubExtended
	case w&0x1F000000 == 0x0A000000: // logical (shifted register)
		return ClassLogicalShifted
	case w&0x1FE00000 == 0x1A800000: // CSEL/CSINC/CSINV/CSNEG
		return ClassCondSelect
	case w&0x1FE00000 == 0x1AC00000: // UDIV/SDIV/LSLV/LSRV/ASRV/RORV
		return ClassDataProc2
	case w&0x1F000000 == 0x1B000000: // MADD/MSUB（含 MUL/MNEG 别名）
		return ClassDataProc3

	// ---- 加载/存储 ----
	case w&0x3A000000 == 0x28000000: // LDP/STP 及其前/后索引形式
		if (w>>26)&1 == 1 {
			return ClassFPVec // SIMD/FP 的 LDP/STP
		}
		return ClassLoadStorePair
	// ---- 加载/存储 ----
	// 注意：字面量组是 bits[29:27]=011，寄存器组是 111，寄存器对是 101 ——
	// 早期我把 011 和 111 混在一起、又用 bits[25:24]=11 判字面量，导致
	// "LDR Wt, label" 被当成未缩放访存（差分测试抓到了这个错误）。
	case (w>>27)&7 == 0b011: // 字面量加载
		if (w>>26)&1 == 1 {
			return ClassFPVec
		}
		return ClassLoadLiteral
	case (w>>27)&7 == 0b111: // 寄存器加载/存储（含未缩放/前索引/后索引/寄存器偏移）
		if (w>>26)&1 == 1 {
			return ClassFPVec
		}
		return ClassLoadStore
	case (w>>27)&7 == 0b101: // 寄存器对
		if (w>>26)&1 == 1 {
			return ClassFPVec
		}
		return ClassLoadStorePair
	case w&0x0E000000 == 0x0E000000: // SIMD/FP 数据处理空间（bits[27:25] = 111）
		return ClassFPVec

	// ---- 其它已识别但不 lift ----
	case w == 0xD503201F: // NOP
		return ClassMisc
	case w&0xFF000000 == 0xD5000000: // hints / barriers / sys
		return ClassMisc
	}
	return ClassUnknown
}

// classifyLoadStore 细分加载/存储空间的编码（bits[29:27] 为 011 或 111）
//
//	v = bit26：0 = 通用寄存器，1 = SIMD/FP
//	bits[25:24]：01 = 无符号偏移，10 = 寄存器偏移，00 = 未缩放/前索引/后索引，11 = 字面量
func classifyLoadStore(w uint32) Class {
	v := (w >> 26) & 1
	switch (w >> 24) & 0x3 {
	case 0b11:
		if v == 0 {
			return ClassLoadLiteral // LDR W/X, label
		}
		return ClassFPVec // LDR S/D/Q, label
	case 0b01, 0b10, 0b00:
		if v == 1 {
			return ClassFPVec
		}
		return ClassLoadStore
	}
	return ClassUnknown
}

// ---- 字段提取（lifter 用） ----

// Reg 取第 i 个参数里的**通用寄存器编号**（X0-X30 / W0-W30 → 0..30；
// SP / WSP / XZR / WZR 一律返回 31，由调用方按指令语义区分 SP 还是 ZR）。
//
// 注意：参考解码器的 Reg 常量**不是**按名字编号的——W0..W30 是 0..30，
// 而 X0..X30 在另一个区间（X0=32…），直接 int(r) 会得到 32+ 的错误编号
// （这正是"有符号加载把目标寄存器写成暂存槽"的根因）。因此这里按**名字**解析。
func (i *Insn) Reg(idx int) int {
	if idx < 0 || idx >= len(i.Args) {
		return -1
	}
	var name string
	switch r := i.Args[idx].(type) {
	case arm64asm.Reg:
		name = r.String()
	case arm64asm.RegSP:
		name = r.String()
	default:
		return -1
	}
	switch name {
	case "SP", "WSP", "XZR", "WZR":
		return 31
	}
	if len(name) >= 2 && (name[0] == 'X' || name[0] == 'W') {
		n := 0
		for k := 1; k < len(name); k++ {
			if name[k] < '0' || name[k] > '9' {
				return -1
			}
			n = n*10 + int(name[k]-'0')
		}
		if n <= 30 {
			return n
		}
	}
	return -1
}

// RegWidth 取第 i 个参数里寄存器的宽度（X/SP → 64，W/WSP → 32，其它 → 0）
//
// 加载指令的目标宽度以**汇编写出的寄存器名**为准（LDRSH Wt 与 LDRSH Xt 是不同编码），
// 所以 lifter 直接按名字取宽度，而不是自己去推 opc。
func (i *Insn) RegWidth(idx int) uint32 {
	if idx < 0 || idx >= len(i.Args) {
		return 0
	}
	var name string
	switch r := i.Args[idx].(type) {
	case arm64asm.Reg:
		name = r.String()
	case arm64asm.RegSP:
		name = r.String()
	default:
		return 0
	}
	if name == "" {
		return 0
	}
	switch name {
	case "SP", "XZR":
		return 64
	case "WSP", "WZR":
		return 32
	}
	switch name[0] {
	case 'X':
		return 64
	case 'W':
		return 32
	}
	return 0
}

// Imm 取第 i 个参数里的立即数
func (i *Insn) Imm(idx int) (int64, bool) {
	if idx < 0 || idx >= len(i.Args) {
		return 0, false
	}
	switch v := i.Args[idx].(type) {
	case arm64asm.Imm:
		return int64(v.Imm), true
	case arm64asm.Imm64:
		return int64(v.Imm), true
	case arm64asm.PCRel:
		return int64(v), true
	}
	return 0, false
}

// Cond 取条件码（0..15，ARM64 编码；AL/NV 均为 14/15）
func (i *Insn) Cond() (uint32, bool) {
	for _, a := range i.Args {
		if c, ok := a.(arm64asm.Cond); ok {
			// A64 的条件字段就是标准 4 位条件码（EQ=0, NE=1, CS=2 …）
			return uint32(c.Value), true
		}
	}
	return 0, false
}

// IsBranch 是否是控制流指令（lifter 据此切断基本块）
func (i *Insn) IsBranch() bool {
	switch i.Class {
	case ClassBranchImm, ClassBranchCond, ClassCompareBranch, ClassTestBranch, ClassBranchReg:
		return true
	}
	return false
}

// PCRelTarget 计算 B/BL/B.cond 的目标地址
func (i *Insn) PCRelTarget() (uint64, bool) {
	for _, a := range i.Args {
		if v, ok := a.(arm64asm.PCRel); ok {
			return i.PC + uint64(int64(v)), true
		}
	}
	return 0, false
}

// Package ir 定义与 ISA 无关的线性中间表示。
//
// 设计取舍：这不是 SSA。对“把一段机器码翻成栈式 VM 字节码”这个目标来说，
// 线性三地址 IR + 显式标志语义已经足够，而且更容易逐条对照原始指令、
// 也更容易做“哪条 x86 指令不支持”的 fail-fast 报告。
//
// 关键点：标志位不做隐式假设 —— 每个 ALU 指令的 width 明确，
// 32 位运算零扩展、8/16 位是局部写，与 x86-64 语义一致。
package ir

// Reg 是规范化的 x86-64 寄存器编号 0..15（RAX..R15）；
// 另有 VMBASE / VMSRC 由 VM 内部使用。
type Reg uint8

const (
	NoReg Reg = 0xFF

	RAX Reg = 0
	RCX Reg = 1
	RDX Reg = 2
	RBX Reg = 3
	RSP Reg = 4
	RBP Reg = 5
	RSI Reg = 6
	RDI Reg = 7
	R8  Reg = 8
	R9  Reg = 9
	R10 Reg = 10
	R11 Reg = 11
	R12 Reg = 12
	R13 Reg = 13
	R14 Reg = 14
	R15 Reg = 15

	VMBASE Reg = 16 // 模块运行时基址
	VMSCR  Reg = 17 // VM 专用暂存
)

// String 便于诊断输出
func (r Reg) String() string {
	switch r {
	case NoReg:
		return "none"
	case VMBASE:
		return "VMBASE"
	case VMSCR:
		return "VMSCR"
	}
	names := [...]string{"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
		"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	if int(r) < len(names) {
		return names[r]
	}
	return "R?"
}

// Width 操作宽度（位）
type Width uint8

const (
	W8  Width = 8
	W16 Width = 16
	W32 Width = 32
	W64 Width = 64
)

// Kind 二元 ALU 子操作（与 C 侧 K_* 一一对应）
type Kind uint8

const (
	Add Kind = iota
	Sub
	And
	Or
	Xor
	Mul
	Shl
	Shr
	Sar
	Rol
	Ror
	// 带进位形式（x86 的 ADC/SBB）与乘法高半（x86 的 MUL）：值必须与 C 侧 K_* 一致
	Adc
	Sbb
	MulHi // 无符号乘法的**高半**：dst = (a*b) >> width，且 CF=OF=(高半!=0)（x86 MUL 的语义）
	Bt    // 位测试（x86 的 BT）：只看 a 的第 (b mod width) 位，**只改 CF**，其余标志位保持
	Bsf   // 位扫描（x86 的 BSF/BSR）：结果 = 最低/最高置位位的下标，**只改 ZF**（源为 0 时 ZF=1）
	Bsr
	Tzcnt // BMI1 的 TZCNT/LZCNT：与 BSF/BSR 相同，但源为 0 时结果是操作数位宽，且同时置 CF
	Lzcnt
	MulHiS // **有符号**乘法的高半（x86 单操作数 IMUL）：CF=OF 表示高半不是低半的符号扩展
	// x86 单操作数 DIV/IDIV：被除数是**隐含的 DX:AX 族**，商→AX 族、余→DX 族，
	// 所以复用 ir.AluU 编码（A = 除数，Dst 不用）。标志位按 x86 规定是「未定义」，我们不动。
	// arm64 客户机不产生这两个 kind（arm64 的 SDIV/UDIV 目前也不在 lifter 支持范围内）。
	DivU
	DivS
)

// KeepFlags 是 ALU kind 字节的 bit7：执行运算但**不修改标志位**。
// ARM64 不带 S 的算术/逻辑指令用它；x86-64 侧恒为 0（向后兼容）。
// 必须与 C 侧的 VM_ALU_KEEP_FLAGS 一致。
const KeepFlags uint8 = 0x80

// UnKind 一元子操作
type UnKind uint8

const (
	Neg UnKind = iota
	Not
	Inc
	Dec
)

// CmpKind 比较子操作
type CmpKind uint8

const (
	Cmp CmpKind = iota
	Test
)

// ExtKind 扩展方式
type ExtKind uint8

const (
	ZeroExt ExtKind = iota
	SignExt
)

// Cond x86 条件码（与 C 侧 CC_* 一致）
type Cond uint8

const (
	O Cond = iota
	No
	B
	AE
	E
	NE
	BE
	A
	S
	NS
	P
	NP
	L
	GE
	LE
	G
)

// Op IR 操作码
// ARM64 条件码（A64 编码值；x86 客户机用上面的 O/No/B/... 那一组）。
// 条件码的**含义按客户机解释**，VM 只是把 cond 字节交给对应客户机的求值器。
const (
	ArmEQ Cond = 0
	ArmNE Cond = 1
	ArmCS Cond = 2
	ArmCC Cond = 3
	ArmMI Cond = 4
	ArmPL Cond = 5
	ArmVS Cond = 6
	ArmVC Cond = 7
	ArmHI Cond = 8
	ArmLS Cond = 9
	ArmGE Cond = 10
	ArmLT Cond = 11
	ArmGT Cond = 12
	ArmLE Cond = 13
	ArmAL Cond = 14
	ArmNV Cond = 15
)

type Op uint8

const (
	Nop Op = iota
	MovRR
	MovRI
	Lea
	AluRR
	AluRI
	AluU
	CmpRR
	CmpRI
	Ext
	Load
	Store
	Atomic // 原子内存读改写（x86 的 XCHG [mem] / LOCK 前缀系列）
	Fp     // 浮点标量运算（x86 的 ADDSD/MULSD/CVTSI2SD/UCOMISD…）：操作数是**相对 VMBASE 的偏移**
	//   Disp = 目标偏移，Imm = 第一操作数偏移，Imm2 = 第二操作数偏移（0 = 不用）
	PushR
	PushI
	PopR
	Jmp
	Jcc
	CallN
	JRegZ  // 寄存器为零则跳转（不修改标志位）
	JRegNZ // 寄存器非零则跳转（不修改标志位）
	Ret
	Halt
	CallR // 间接调用：调用寄存器里的原生地址（虚调用/函数指针）
)

// Insn 一条 IR 指令
type Insn struct {
	Op    Op
	Kind  uint8 // ALU/CMP/EXT/LOAD 的子操作
	Width Width // 运算宽度
	SrcW  Width // 源操作数宽度（Ext/Load）
	Dst   Reg
	A     Reg
	B     Reg
	Base  Reg
	Index Reg
	Scale uint8
	Disp  int32
	Imm   uint64
	Imm2  uint64 // 第二个 u64 立即数（Fp 用：第二操作数偏移）
	Cond  Cond

	Target    int    // 分支目标：IR 指令下标（lift 后解析）
	TargetOff uint32 // 分支目标：x86 中的函数内偏移（原始信息）
	SrcOff    uint32 // 来源 x86 指令的函数内偏移
	Text      string // 来源指令文本（诊断用）
}

// Func 一个被 lift 的函数
type Func struct {
	Name        string
	Addr        uint64 // 链接期 VA
	RVA         uint32
	Size        int
	Insns       []Insn
	Unsupported []string
}

// String 便于调试
func (o Op) String() string {
	switch o {
	case Nop:
		return "NOP"
	case MovRR:
		return "MOV_RR"
	case MovRI:
		return "MOV_RI"
	case Lea:
		return "LEA"
	case AluRR:
		return "ALU_RR"
	case AluRI:
		return "ALU_RI"
	case AluU:
		return "ALU_U"
	case CmpRR:
		return "CMP_RR"
	case CmpRI:
		return "CMP_RI"
	case Ext:
		return "EXT"
	case Load:
		return "LOAD"
	case Store:
		return "STORE"
	case PushR:
		return "PUSH_R"
	case PushI:
		return "PUSH_I"
	case PopR:
		return "POP_R"
	case Jmp:
		return "JMP"
	case Jcc:
		return "JCC"
	case CallN:
		return "CALL"
	case JRegZ:
		return "JBZ"
	case JRegNZ:
		return "JBNZ"
	case Ret:
		return "RET"
	case Halt:
		return "HALT"
	}
	return "?"
}

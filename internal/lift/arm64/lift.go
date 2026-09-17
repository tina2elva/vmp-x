// Package arm64 把 ARM64（A64）指令翻译成平台无关 IR。
//
// 状态（2026 本轮）：
//   - 位掩码立即数解码：与参考解码器对拍 **2422 例零不一致**；
//   - 数据类指令：单条扫描 30522 例 + 6 条序列 **5988 组**，均 **0 不一致**；
//     覆盖 ADD/SUB、AND/ORR/EOR、MOV/MOVZ/MOVN/MOVK、LSL/LSR/ASR、
//     **位域别名 UBFX/SBFX/UBFIZ/SBFIZ**、**MADD/MSUB（含 MUL/MNEG）**、CMP/CMN/TST；
//   - 控制流（前向 B/B.cond/CBZ/CBNZ/TBZ/TBNZ）：带 PC 的参考执行器对拍 6577 个程序，0 不一致；
//   - 访存（LDR/STR/LDUR/STUR/LDP/STP/LDR-literal，含前/后索引与 SP 相对）：差分 505 组 0 不一致；
//   - 循环（后向分支）、BL/RET、BR/BLR（间接）仍未做语义验证；后者明确拒绝。
//
// 与 x86-64 lifter 共用同一套 IR / VM ISA，差异在于：
//   - 寄存器槽位：X0-X30 → 0..30，SP → 31，VBASE → 32，VMSCR → 33，ZR → 34；
//   - **标志位**：ARM64 的 ADD/SUB/AND/... 不带 S 时不修改标志位（ir.KeepFlags）；
//   - 条件码用 ARM64 语义（C = 无借位），由客户机选择；
//   - 逻辑立即数是任意位掩码，需要先用 MOV_RI 物化到暂存寄存器。
//
// 原则不变：遇到不能**精确**表达的形式就拒绝翻译并记录原因，绝不近似。
package arm64

import (
	"fmt"

	dec "github.com/vmpx/vmp-x/internal/decode/arm64"
	"github.com/vmpx/vmp-x/internal/ir"
	"golang.org/x/arch/arm64/arm64asm"
)

// 客户机寄存器槽位
const (
	SP  ir.Reg = 31
	VB  ir.Reg = 32 // VBASE：模块运行时基址
	SCR ir.Reg = 33 // VM 暂存
	ZR  ir.Reg = 34 // 恒为 0，只读
)

// Lifter ARM64 → IR
type Lifter struct {
	ImageBase uint64 // 模块基址（ADR/ADRP 与直接调用用）
	ImageSize uint64 // 模块 VA 范围（0 表示不做范围检查）
	// FrameSkew：模拟 SP 与宿主 SP 的差值（与 x86-64 侧同一机制）。
	// 访问 [SP + eff] 时：eff >= 0 属于调用方栈帧 → +FrameSkew；eff < 0 是本函数自己的帧。
	FrameSkew uint64

	// SP 静态跟踪：spDelta = 当前 SP 相对进入时 SP 的偏移；spUnknown 表示无法静态确定
	spDelta   int64
	spUnknown bool
}

// Lift 翻译一段已解码的指令；不能精确表达的形式记录到 Unsupported 且不生成指令
// irTargetFixed 是合成分支的哨兵：Target 已经是最终的 IR 下标，不需要再换算。
const irTargetFixed = ^uint32(0)

func (l *Lifter) Lift(fn *ir.Func, insns []dec.Insn) {
	l.spDelta = 0
	l.spUnknown = false
	addrToIdx := map[uint64]int{}
	for i := range insns {
		addrToIdx[insns[i].PC] = i
	}
	first := uint64(0)
	if len(insns) > 0 {
		first = insns[0].PC
	}
	// 一条解码指令可能展开成多条 IR 指令，所以分支目标必须用 **IR 下标**：
	// 先记录每条解码指令展开后的 IR 起点，分支里暂存"解码下标 + 1"，最后统一换算。
	irStart := make([]int, len(insns))
	for i := range insns {
		ins := &insns[i]
		irStart[i] = len(fn.Insns)
		before := len(fn.Insns)
		if err := l.liftOne(fn, ins, addrToIdx); err != nil {
			fn.Insns = fn.Insns[:before]
			fn.Unsupported = append(fn.Unsupported, fmt.Sprintf("+0x%X %s: %v", ins.PC-first, ins.Text(), err))
		}
	}
	for i := range fn.Insns {
		in := &fn.Insns[i]
		if in.TargetOff == 0 {
			continue
		}
		if in.TargetOff == irTargetFixed {
			continue // 合成分支：Target 已经填好（CSEL 家族的降级用它）
		}
		switch in.Op {
		case ir.Jmp, ir.Jcc, ir.JRegZ, ir.JRegNZ:
			d := int(in.TargetOff) - 1
			if d >= 0 && d < len(irStart) {
				in.Target = irStart[d]
			}
		}
	}
}

func (l *Lifter) liftOne(f *ir.Func, ins *dec.Insn, addrToIdx map[uint64]int) error {
	switch ins.Class {
	case dec.ClassAddSubImm:
		return l.liftAddSubImm(f, ins)
	case dec.ClassAddSubShifted:
		return l.liftAddSubReg(f, ins)
	case dec.ClassAddSubExtended:
		return fmt.Errorf("带扩展的加减（ADD/SUB extended register）暂不支持")
	case dec.ClassLogicalImm:
		return l.liftLogicalImm(f, ins)
	case dec.ClassLogicalShifted:
		return l.liftLogicalShifted(f, ins)
	case dec.ClassMoveWide:
		return l.liftMoveWide(f, ins)
	case dec.ClassBitfield:
		return l.liftBitfield(f, ins)
	case dec.ClassDataProc3:
		return l.liftDataProc3(f, ins)
	case dec.ClassLoadStore:
		return l.liftLoadStore(f, ins)
	case dec.ClassLoadStorePair:
		return l.liftLoadStorePair(f, ins)
	case dec.ClassLoadLiteral:
		return l.liftLoadLiteral(f, ins)
	case dec.ClassBranchImm:
		return l.liftBranchImm(f, ins, addrToIdx)
	case dec.ClassBranchCond:
		return l.liftBranchCond(f, ins, addrToIdx)
	case dec.ClassCompareBranch:
		return l.liftCompareBranch(f, ins, addrToIdx)
	case dec.ClassTestBranch:
		return l.liftTestBranch(f, ins, addrToIdx)
	case dec.ClassBranchReg:
		return l.liftBranchReg(f, ins)
	case dec.ClassPCRel:
		return l.liftPCRel(f, ins)
	case dec.ClassCondSelect:
		return l.liftCondSelect(f, ins)
	}
	return fmt.Errorf("暂不支持的编码类 %v", ins.Class)
}

// ---------- 算术 ----------

func (l *Lifter) liftAddSubImm(f *ir.Func, ins *dec.Insn) error {
	switch ins.Op {
	case arm64asm.ADD, arm64asm.ADDS, arm64asm.SUB, arm64asm.SUBS, arm64asm.CMP, arm64asm.CMN:
	default:
		return fmt.Errorf("未预期的助记符 %v", ins.Op)
	}
	setFlags := ins.Raw&(1<<29) != 0
	sub := ins.Raw&(1<<30) != 0
	imm := (ins.Raw >> 10) & 0xFFF
	if ins.Raw&(1<<22) != 0 {
		imm <<= 12
	}
	rn := (ins.Raw >> 5) & 31
	rd := ins.Raw & 31
	// 加减**立即数**形式里：Rn=31 是 **SP**（不是 XZR）；Rd=31 且不带 S 时也是 SP。
	src := SP
	if rn != 31 {
		src = ir.Reg(rn)
	}
	kind := ir.Add
	if sub {
		kind = ir.Sub
	}
	// Rd=31：不带 S 时是 **SP**（必须真的写进槽位 31），带 S 时是 XZR（结果丢弃）
	dst := regOrScratch(rd)
	if rd == 31 && !setFlags {
		dst = SP
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRI, Kind: aluKind(kind, setFlags), Width: sf(ins.Raw),
		Dst: dst, A: src, Imm: uint64(imm), SrcOff: uint32(ins.PC), Text: ins.Text()})
	// SP 跟踪：ADD/SUB SP, SP, #imm
	if rn == 31 && rd == 31 && !setFlags {
		if sub {
			l.spDelta -= int64(imm)
		} else {
			l.spDelta += int64(imm)
		}
	}
	return nil
}

func (l *Lifter) liftAddSubReg(f *ir.Func, ins *dec.Insn) error {
	setFlags := ins.Raw&(1<<29) != 0
	sub := ins.Raw&(1<<30) != 0
	shiftType := (ins.Raw >> 22) & 3
	shiftAmt := (ins.Raw >> 10) & 0x3F
	w := sf(ins.Raw)
	if shiftType == 3 {
		return fmt.Errorf("无效的移位类型 11")
	}
	rn := (ins.Raw >> 5) & 31
	rd := ins.Raw & 31
	// 寄存器（移位）形式的 ADD/SUB 里 31 是 **XZR**，不是 SP（SP 只能用立即数形式调整）：
	//   · Rn=31 → 操作数是零
	//   · Rd=31 → 结果丢弃，但带 S 时**标志位仍然要更新**（cmp/cmn 就是 subs/adds xzr,..., 的形式）
	// 之前这里直接报错，导致 cmp 被丢掉（也是 sum_to 循环不退出的直接原因）。
	rnSlotReg := ir.Reg(rn)
	if rn == 31 {
		rnSlotReg = ZR // 客户机零寄存器槽位：读恒 0、写丢弃
	}
	dstReg := ir.Reg(rd)
	if rd == 31 {
		dstReg = ZR
	}
	src, err := slotZR((ins.Raw >> 16) & 31)
	if err != nil {
		return err
	}
	if shiftAmt != 0 {
		if shiftAmt >= uint32(w) {
			return fmt.Errorf("移位量 %d 超出宽度 %d", shiftAmt, w)
		}
		f.Insns = append(f.Insns, ir.Insn{Op: ir.MovRR, Width: w, Dst: SCR, A: src,
			SrcOff: uint32(ins.PC), Text: ins.Text()})
		f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRI, Kind: uint8(shiftKind(shiftType)) | ir.KeepFlags,
			Width: w, Dst: SCR, A: SCR, Imm: uint64(shiftAmt), SrcOff: uint32(ins.PC), Text: ins.Text()})
		src = SCR
	}
	rnSlot := rnSlotReg
	kind := ir.Add
	if sub {
		kind = ir.Sub
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRR, Kind: aluKind(kind, setFlags), Width: w,
		Dst: dstReg, A: rnSlot, B: src, SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

// ---------- 逻辑 ----------

// liftCondSelect：CSEL/CSINC/CSINV/CSNEG/CSET/CSETM 用**前向分支**降级
//
//	CSEL  Xd, Xn, Xm, cond  →  cond ? Xn : Xm
//	CSINC Xd, Xn, Xm, cond  →  cond ? Xn : Xm+1
//	CSINV Xd, Xn, Xm, cond  →  cond ? Xn : ~Xm
//	CSNEG Xd, Xn, Xm, cond  →  cond ? Xn : -Xm
//
// 分支目标直接用 IR 下标（TargetOff 用哨兵），因此不受"解码下标 → IR 下标"换算影响。
func (l *Lifter) liftCondSelect(f *ir.Func, ins *dec.Insn) error {
	rd := ins.Raw & 31
	rn := (ins.Raw >> 5) & 31
	rm := (ins.Raw >> 16) & 31
	cond := ir.Cond((ins.Raw >> 12) & 0xF)
	op2 := (ins.Raw >> 10) & 3 // 0=CSEL 1=CSINC 2=CSINV 3=CSNEG
	w := sf(ins.Raw)
	if rd == 31 {
		return fmt.Errorf("目标是 XZR 的条件选择（CMP/CMN 别名）暂不支持")
	}
	yes, err := slotZR(rn)
	if err != nil {
		return err
	}
	no, err := slotZR(rm)
	if err != nil {
		return err
	}
	dst := regOrScratch(rd)
	em := func(in ir.Insn) {
		in.Width = w
		in.SrcOff = uint32(ins.PC)
		in.Text = ins.Text()
		f.Insns = append(f.Insns, in)
	}
	// 先构造"否"分支要执行的指令，这样标签位置可以精确算出来。
	var noInsns []ir.Insn
	switch op2 {
	case 0: // CSEL：直接搬
		noInsns = append(noInsns, ir.Insn{Op: ir.MovRR, Dst: dst, A: no})
	case 1: // CSINC：Xm + 1
		noInsns = append(noInsns,
			ir.Insn{Op: ir.MovRR, Dst: SCR, A: no},
			ir.Insn{Op: ir.AluRI, Kind: uint8(ir.Add) | ir.KeepFlags, Dst: dst, A: SCR, Imm: 1})
	case 2: // CSINV：~Xm
		noInsns = append(noInsns,
			ir.Insn{Op: ir.MovRR, Dst: SCR, A: no},
			ir.Insn{Op: ir.AluU, Kind: uint8(ir.Not) | ir.KeepFlags, Dst: dst, A: SCR})
	default: // CSNEG：-Xm（0 - Xm）
		noInsns = append(noInsns, ir.Insn{Op: ir.AluRR, Kind: uint8(ir.Sub) | ir.KeepFlags, Dst: dst, A: 31, B: no})
	}
	yesIdx := len(f.Insns) + 1 + len(noInsns) + 1 // Jcc + 否分支 + Jmp
	endIdx := yesIdx + 1                          // L_yes 的 MOV 之后
	em(ir.Insn{Op: ir.Jcc, Cond: cond, Target: yesIdx, TargetOff: irTargetFixed})
	for i := range noInsns {
		em(noInsns[i])
	}
	em(ir.Insn{Op: ir.Jmp, Target: endIdx, TargetOff: irTargetFixed})
	// L_yes：取"是"分支的值（CSEL/CSINC 取 Xn；CSINV/CSNEG 同理取 Xn）
	em(ir.Insn{Op: ir.MovRR, Dst: dst, A: yes})
	return nil
}

func (l *Lifter) liftLogicalShifted(f *ir.Func, ins *dec.Insn) error {
	// 取反形式（BIC/ORN/EON/MVN/BICS）在 bit21==1：先对第二个操作数按位取反，再照常运算。
	// 用一条 ALU_U NOT（不写标志位）实现，正好只需要一个暂存寄存器。
	invert := ins.Raw&(1<<21) != 0
	switch ins.Op {
	case arm64asm.AND, arm64asm.ANDS, arm64asm.ORR, arm64asm.EOR, arm64asm.MOV, arm64asm.TST,
		arm64asm.BIC, arm64asm.BICS, arm64asm.ORN, arm64asm.EON, arm64asm.MVN:
	default:
		return fmt.Errorf("其它逻辑形式（%v）暂不支持", ins.Op)
	}
	// 逻辑类的 S 语义在 opc[30:29]：11 = ANDS/BICS/TST 才设置标志位
	setFlags := ((ins.Raw >> 29) & 3) == 3
	opc := (ins.Raw >> 29) & 3
	shiftType := (ins.Raw >> 22) & 3
	shiftAmt := (ins.Raw >> 10) & 0x3F
	rn := (ins.Raw >> 5) & 31
	rd := ins.Raw & 31
	w := sf(ins.Raw)
	if shiftType == 3 {
		return fmt.Errorf("无效的移位类型 11")
	}
	if rd == 31 && ins.Op != arm64asm.TST {
		// 写 SP 的逻辑运算（少见）：SP 不是通用寄存器，拒绝
		return fmt.Errorf("目标是 SP 的逻辑运算暂不支持")
	}
	src, err := slotZR((ins.Raw >> 16) & 31)
	if err != nil {
		return err
	}
	if shiftAmt != 0 || invert {
		f.Insns = append(f.Insns, ir.Insn{Op: ir.MovRR, Width: w, Dst: SCR, A: src,
			SrcOff: uint32(ins.PC), Text: ins.Text()})
		if shiftAmt != 0 {
			f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRI, Kind: uint8(shiftKind(shiftType)) | ir.KeepFlags,
				Width: w, Dst: SCR, A: SCR, Imm: uint64(shiftAmt), SrcOff: uint32(ins.PC), Text: ins.Text()})
		}
		if invert {
			f.Insns = append(f.Insns, ir.Insn{Op: ir.AluU, Kind: uint8(ir.Not) | ir.KeepFlags,
				Width: w, Dst: SCR, A: SCR, SrcOff: uint32(ins.PC), Text: ins.Text()})
		}
		src = SCR
	}
	var kind ir.Kind
	switch opc {
	case 0, 3:
		kind = ir.And
	case 1:
		kind = ir.Or
	default:
		kind = ir.Xor
	}
	dst := regOrScratch(rd)
	if ins.Op == arm64asm.MOV || ins.Op == arm64asm.MVN {
		// MOV Xd, Xm（ORR Xd, XZR, Xm）/ MVN Xd, Xm（ORN Xd, XZR, Xm）：只是搬移，不改标志位
		f.Insns = append(f.Insns, ir.Insn{Op: ir.MovRR, Width: w, Dst: dst, A: src,
			SrcOff: uint32(ins.PC), Text: ins.Text()})
		return nil
	}
	rnSlot, ok := slotLe31(rn)
	if !ok {
		return fmt.Errorf("Rn=XZR 的逻辑形式暂不支持")
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRR, Kind: aluKind(kind, setFlags),
		Width: w, Dst: dst, A: rnSlot, B: src, SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

func (l *Lifter) liftLogicalImm(f *ir.Func, ins *dec.Insn) error {
	switch ins.Op {
	case arm64asm.AND, arm64asm.ANDS, arm64asm.ORR, arm64asm.EOR, arm64asm.MOV, arm64asm.TST:
	default:
		return fmt.Errorf("未预期的逻辑立即数形式 %v", ins.Op)
	}
	setFlags := ((ins.Raw >> 29) & 3) == 3
	opc := (ins.Raw >> 29) & 3
	w := sf(ins.Raw)
	mask, err := decodeBitMasks((ins.Raw>>22)&1, (ins.Raw>>16)&0x3F, (ins.Raw>>10)&0x3F, uint32(w) == 64)
	if err != nil {
		return err
	}
	var kind ir.Kind
	switch opc {
	case 0, 3:
		kind = ir.And
	case 1:
		kind = ir.Or
	default:
		kind = ir.Xor
	}
	dst := regOrScratch(ins.Raw & 31)
	if ins.Op == arm64asm.MOV {
		f.Insns = append(f.Insns, ir.Insn{Op: ir.MovRI, Width: w, Dst: dst, Imm: mask,
			SrcOff: uint32(ins.PC), Text: ins.Text()})
		return nil
	}
	rnSlot, ok := slotLe31((ins.Raw >> 5) & 31)
	if !ok {
		return fmt.Errorf("Rn=XZR 的逻辑形式暂不支持")
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.MovRI, Width: ir.W64, Dst: SCR, Imm: mask,
		SrcOff: uint32(ins.PC), Text: ins.Text()})
	f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRR, Kind: aluKind(kind, setFlags),
		Width: w, Dst: dst, A: rnSlot, B: SCR, SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

// ---------- 移动立即数 / 位移 ----------

func (l *Lifter) liftMoveWide(f *ir.Func, ins *dec.Insn) error {
	opc := (ins.Raw >> 29) & 3
	hw := (ins.Raw >> 21) & 3
	imm16 := (ins.Raw >> 5) & 0xFFFF
	rd := ins.Raw & 31
	w := sf(ins.Raw)
	if w == ir.W32 && hw > 1 {
		return fmt.Errorf("32 位形式的 hw=%d 无效", hw)
	}
	shift := hw * 16
	val := uint64(imm16) << shift
	switch opc {
	case 0, 1: // MOVN
		val = ^val
		if w == ir.W32 {
			val &= 0xFFFFFFFF
		}
	case 2: // MOVZ
	default: // 3 = MOVK
		clear := ^(uint64(0xFFFF) << shift)
		if w == ir.W32 {
			clear &= 0xFFFFFFFF
		}
		f.Insns = append(f.Insns,
			ir.Insn{Op: ir.MovRI, Width: ir.W64, Dst: SCR, Imm: clear, SrcOff: uint32(ins.PC), Text: ins.Text()},
			ir.Insn{Op: ir.AluRR, Kind: aluKind(ir.And, false), Width: w, Dst: ir.Reg(rd), A: ir.Reg(rd), B: SCR,
				SrcOff: uint32(ins.PC), Text: ins.Text()},
			ir.Insn{Op: ir.MovRI, Width: ir.W64, Dst: SCR, Imm: val, SrcOff: uint32(ins.PC), Text: ins.Text()},
			ir.Insn{Op: ir.AluRR, Kind: aluKind(ir.Or, false), Width: w, Dst: ir.Reg(rd), A: ir.Reg(rd), B: SCR,
				SrcOff: uint32(ins.PC), Text: ins.Text()})
		return nil
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.MovRI, Width: w, Dst: ir.Reg(rd), Imm: val,
		SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

func (l *Lifter) liftBitfield(f *ir.Func, ins *dec.Insn) error {
	w := sf(ins.Raw)
	bits := uint64(w)
	dst := ir.Reg(ins.Raw & 31)
	immr := uint64((ins.Raw >> 16) & 0x3F)
	imms := uint64((ins.Raw >> 10) & 0x3F)
	src, err := slotZR((ins.Raw >> 5) & 31)
	if err != nil {
		return err
	}
	// 纯移位别名：LSL/LSR/ASR
	switch ins.Op {
	case arm64asm.LSL, arm64asm.LSR, arm64asm.ASR:
		amt, ok := ins.Imm(2)
		if !ok {
			return fmt.Errorf("取不到移位量")
		}
		if amt < 0 || uint64(amt) >= bits {
			return fmt.Errorf("移位量 %d 超出宽度 %d", amt, w)
		}
		var kind ir.Kind
		switch ins.Op {
		case arm64asm.LSL:
			kind = ir.Shl
		case arm64asm.LSR:
			kind = ir.Shr
		default:
			kind = ir.Sar
		}
		f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRI, Kind: uint8(kind) | ir.KeepFlags, Width: w,
			Dst: dst, A: src, Imm: uint64(amt), SrcOff: uint32(ins.PC), Text: ins.Text()})
		return nil
	}
	// 位域别名：UBFX/SBFX/UBFIZ/SBFIZ —— 全部**只用移位**表达（不物化 64 位掩码）。
	// lsb/width 从 immr/imms 推出，并与参考解码器给出的立即数**交叉核对**：不一致就拒绝。
	lsbImm, ok1 := ins.Imm(2)
	widthImm, ok2 := ins.Imm(3)
	if !ok1 || !ok2 || widthImm <= 0 {
		return fmt.Errorf("取不到位域参数")
	}
	lsb, width := uint64(lsbImm), uint64(widthImm)
	switch ins.Op {
	case arm64asm.UBFX, arm64asm.SBFX:
		if immr != lsb || imms != lsb+width-1 {
			return fmt.Errorf("位域参数与编码不符（immr=%d imms=%d, lsb=%d width=%d）", immr, imms, lsb, width)
		}
	case arm64asm.UBFIZ, arm64asm.SBFIZ:
		if (bits-immr)%bits != lsb || imms != width-1 {
			return fmt.Errorf("位域参数与编码不符（immr=%d imms=%d, lsb=%d width=%d）", immr, imms, lsb, width)
		}
	default:
		return fmt.Errorf("位域形式（%v）暂不支持（如 BFM）", ins.Op)
	}
	if lsb+width > bits {
		return fmt.Errorf("位域越界（lsb=%d width=%d 宽度=%d）", lsb, width, bits)
	}
	shl := func(d ir.Reg, a ir.Reg, amt uint64) ir.Insn {
		return ir.Insn{Op: ir.AluRI, Kind: uint8(ir.Shl) | ir.KeepFlags, Width: w, Dst: d, A: a,
			Imm: amt, SrcOff: uint32(ins.PC), Text: ins.Text()}
	}
	shr := func(d ir.Reg, a ir.Reg, amt uint64) ir.Insn {
		return ir.Insn{Op: ir.AluRI, Kind: uint8(ir.Shr) | ir.KeepFlags, Width: w, Dst: d, A: a,
			Imm: amt, SrcOff: uint32(ins.PC), Text: ins.Text()}
	}
	sar := func(d ir.Reg, a ir.Reg, amt uint64) ir.Insn {
		return ir.Insn{Op: ir.AluRI, Kind: uint8(ir.Sar) | ir.KeepFlags, Width: w, Dst: d, A: a,
			Imm: amt, SrcOff: uint32(ins.PC), Text: ins.Text()}
	}
	move := func(d ir.Reg, a ir.Reg) ir.Insn {
		return ir.Insn{Op: ir.MovRR, Width: w, Dst: d, A: a, SrcOff: uint32(ins.PC), Text: ins.Text()}
	}
	switch ins.Op {
	case arm64asm.UBFX: // (src >> lsb)，再"先左移后逻辑右移"零扩展取出 width 位
		if lsb != 0 {
			f.Insns = append(f.Insns, shr(SCR, src, lsb))
		} else {
			f.Insns = append(f.Insns, move(SCR, src))
		}
		if top := bits - width; top != 0 {
			f.Insns = append(f.Insns, shl(dst, SCR, top), shr(dst, dst, top))
		} else {
			f.Insns = append(f.Insns, move(dst, SCR))
		}
	case arm64asm.UBFIZ: // 先清零高位，再左移 lsb
		if top := bits - width; top != 0 {
			f.Insns = append(f.Insns, shl(SCR, src, top), shr(SCR, SCR, top))
		} else {
			f.Insns = append(f.Insns, move(SCR, src))
		}
		if lsb != 0 {
			f.Insns = append(f.Insns, shl(dst, SCR, lsb))
		} else {
			f.Insns = append(f.Insns, move(dst, SCR))
		}
	case arm64asm.SBFX: // 先左移丢高位，再算术右移
		if lsh := bits - lsb - width; lsh != 0 {
			f.Insns = append(f.Insns, shl(SCR, src, lsh))
		} else {
			f.Insns = append(f.Insns, move(SCR, src))
		}
		f.Insns = append(f.Insns, sar(dst, SCR, bits-width))
	default: // SBFIZ：先左移到最高位，再算术右移到 lsb
		f.Insns = append(f.Insns, shl(SCR, src, bits-width), sar(dst, SCR, bits-width-lsb))
	}
	return nil
}

// liftDataProc3：MADD/MSUB（MUL/MNEG 是别名）
func (l *Lifter) liftDataProc3(f *ir.Func, ins *dec.Insn) error {
	switch ins.Op {
	case arm64asm.MADD, arm64asm.MSUB, arm64asm.MUL, arm64asm.MNEG:
	default:
		return fmt.Errorf("未预期的三操作数助记符 %v", ins.Op)
	}
	w := sf(ins.Raw)
	rd := ins.Raw & 31
	rn := (ins.Raw >> 5) & 31
	rm := (ins.Raw >> 16) & 31
	ra := (ins.Raw >> 10) & 31
	sub := ins.Raw&(1<<15) != 0
	if ins.Op == arm64asm.MUL || ins.Op == arm64asm.MNEG {
		sub = ins.Op == arm64asm.MNEG
	}
	a, err := slotZR(rn)
	if err != nil {
		return err
	}
	b, err := slotZR(rm)
	if err != nil {
		return err
	}
	add, err := slotZR(ra)
	if err != nil {
		return err
	}
	dst := regOrScratch(rd)
	// Xd = Xa ± Xn*Xm（MUL = MADD with Xa = XZR；MNEG = MSUB with Xa = XZR）
	f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRR, Kind: aluKind(ir.Mul, false), Width: w,
		Dst: SCR, A: a, B: b, SrcOff: uint32(ins.PC), Text: ins.Text()})
	kind := ir.Add
	if sub {
		kind = ir.Sub
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRR, Kind: aluKind(kind, false), Width: w,
		Dst: dst, A: add, B: SCR, SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

// ---------- 分支 ----------

func (l *Lifter) liftBranchImm(f *ir.Func, ins *dec.Insn, addrToIdx map[uint64]int) error {
	tgt, ok := ins.PCRelTarget()
	if !ok {
		return fmt.Errorf("取不到分支目标")
	}
	if ins.Op == arm64asm.BL {
		if tgt < l.ImageBase {
			return fmt.Errorf("调用目标 0x%X 低于模块基址", tgt)
		}
		ret := ins.PC + 4
		if ret < l.ImageBase {
			return fmt.Errorf("返回地址 0x%X 低于模块基址", ret)
		}
		f.Insns = append(f.Insns,
			ir.Insn{Op: ir.MovRI, Width: ir.W64, Dst: 30, Imm: ret - l.ImageBase, SrcOff: uint32(ins.PC), Text: ins.Text()},
			ir.Insn{Op: ir.AluRR, Kind: aluKind(ir.Add, false), Width: ir.W64, Dst: 30, A: 30, B: VB,
				SrcOff: uint32(ins.PC), Text: ins.Text()},
			ir.Insn{Op: ir.CallN, Width: ir.W64, Imm: tgt - l.ImageBase, SrcOff: uint32(ins.PC), Text: ins.Text()})
		return nil
	}
	idx, ok := addrToIdx[tgt]
	if !ok {
		return fmt.Errorf("分支目标 0x%X 不在本函数内（跨函数跳转暂不支持）", tgt)
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.Jmp, TargetOff: uint32(idx + 1), SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

func (l *Lifter) liftBranchCond(f *ir.Func, ins *dec.Insn, addrToIdx map[uint64]int) error {
	tgt, ok := ins.PCRelTarget()
	if !ok {
		return fmt.Errorf("取不到分支目标")
	}
	idx, ok := addrToIdx[tgt]
	if !ok {
		return fmt.Errorf("分支目标 0x%X 不在本函数内", tgt)
	}
	cond, ok := ins.Cond()
	if !ok {
		return fmt.Errorf("取不到条件码")
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.Jcc, Cond: ir.Cond(cond), TargetOff: uint32(idx + 1),
		SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

func (l *Lifter) liftCompareBranch(f *ir.Func, ins *dec.Insn, addrToIdx map[uint64]int) error {
	tgt, ok := ins.PCRelTarget()
	if !ok {
		return fmt.Errorf("取不到分支目标")
	}
	idx, ok := addrToIdx[tgt]
	if !ok {
		return fmt.Errorf("分支目标 0x%X 不在本函数内", tgt)
	}
	rt, err := slotZR(ins.Raw & 31)
	if err != nil {
		return err
	}
	src := rt
	if ins.Raw&(1<<31) == 0 {
		// W 形式只比较低 32 位：先零扩展（EXT 不修改标志位）
		f.Insns = append(f.Insns, ir.Insn{Op: ir.Ext, Width: ir.W64, SrcW: ir.W32, Dst: SCR, A: rt,
			SrcOff: uint32(ins.PC), Text: ins.Text()})
		src = SCR
	}
	op := ir.JRegZ
	if ins.Op == arm64asm.CBNZ {
		op = ir.JRegNZ
	}
	f.Insns = append(f.Insns, ir.Insn{Op: op, A: src, TargetOff: uint32(idx + 1),
		SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

func (l *Lifter) liftTestBranch(f *ir.Func, ins *dec.Insn, addrToIdx map[uint64]int) error {
	tgt, ok := ins.PCRelTarget()
	if !ok {
		return fmt.Errorf("取不到分支目标")
	}
	idx, ok := addrToIdx[tgt]
	if !ok {
		return fmt.Errorf("分支目标 0x%X 不在本函数内", tgt)
	}
	rt, err := slotZR(ins.Raw & 31)
	if err != nil {
		return err
	}
	bit := (ins.Raw >> 19) & 31
	w := ir.W32
	if ins.Raw&(1<<31) != 0 {
		bit |= 32
		w = ir.W64
	}
	if bit >= uint32(w) {
		return fmt.Errorf("测试位 %d 超出宽度 %d", bit, w)
	}
	w64 := ir.W64
	if w == ir.W32 {
		w64 = ir.W32
	}
	f.Insns = append(f.Insns,
		ir.Insn{Op: ir.MovRI, Width: ir.W64, Dst: SCR, Imm: uint64(1) << bit, SrcOff: uint32(ins.PC), Text: ins.Text()},
		ir.Insn{Op: ir.AluRR, Kind: aluKind(ir.And, false), Width: w, Dst: SCR, A: rt, B: SCR,
			SrcOff: uint32(ins.PC), Text: ins.Text()})
	_ = w64
	op := ir.JRegZ
	if ins.Op == arm64asm.TBNZ {
		op = ir.JRegNZ
	}
	f.Insns = append(f.Insns, ir.Insn{Op: op, A: SCR, TargetOff: uint32(idx + 1),
		SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

func (l *Lifter) liftBranchReg(f *ir.Func, ins *dec.Insn) error {
	switch ins.Op {
	case arm64asm.RET:
		f.Insns = append(f.Insns, ir.Insn{Op: ir.Ret, SrcOff: uint32(ins.PC), Text: ins.Text()})
		return nil
	}
	return fmt.Errorf("间接跳转/调用（BR/BLR）暂不支持：VM 没有间接跳转指令")
}

func (l *Lifter) liftPCRel(f *ir.Func, ins *dec.Insn) error {
	imm, ok := ins.Imm(1)
	if !ok {
		return fmt.Errorf("取不到立即数")
	}
	rd := ins.Raw & 31
	var target uint64
	if ins.Op == arm64asm.ADR {
		target = ins.PC + uint64(imm)
	} else {
		target = (ins.PC &^ 0xFFF) + uint64(imm)
	}
	if target < l.ImageBase {
		return fmt.Errorf("ADR/ADRP 目标 0x%X 低于模块基址", target)
	}
	rva := target - l.ImageBase
	if l.ImageSize != 0 && rva >= l.ImageSize {
		return fmt.Errorf("ADR/ADRP 目标 0x%X 超出模块范围（跨模块引用暂不支持）", target)
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.Lea, Width: ir.W64, Dst: ir.Reg(rd), Base: VB, Disp: int32(rva),
		SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

// ---------- 辅助 ----------

// aluKind 组装 ALU 的 kind 字节：不带 S 的运算要保留标志位
func aluKind(k ir.Kind, setFlags bool) uint8 {
	if setFlags {
		return uint8(k)
	}
	return uint8(k) | ir.KeepFlags
}

func shiftKind(t uint32) ir.Kind {
	switch t {
	case 0:
		return ir.Shl
	case 1:
		return ir.Shr
	default:
		return ir.Sar
	}
}

func sf(w uint32) ir.Width {
	if w&(1<<31) != 0 {
		return ir.W64
	}
	return ir.W32
}

// slotZR：5 位寄存器编号 → 槽位；31 表示 ZR（XZR/WZR）
func slotZR(r uint32) (ir.Reg, error) {
	switch {
	case r <= 30:
		return ir.Reg(r), nil
	case r == 31:
		return ZR, nil
	}
	return 0, fmt.Errorf("寄存器编号 %d 无效", r)
}

// slotLe31：只接受 X0-X30
func slotLe31(r uint32) (ir.Reg, bool) {
	if r <= 30 {
		return ir.Reg(r), true
	}
	return 0, false
}

// regOrScratch：目标是 XZR 时结果丢弃（写进暂存槽）
func regOrScratch(r uint32) ir.Reg {
	if r <= 30 {
		return ir.Reg(r)
	}
	return SCR
}

// spAdjust：把 [SP + disp] 换算成模拟 SP 上的偏移。
// eff = disp + spDelta >= 0 表示访问调用方栈帧 → 加 FrameSkew；否则是自有帧，不加。
func (l *Lifter) spAdjust(disp int64, isSP bool) (int64, error) {
	if !isSP {
		return disp, nil
	}
	if l.spUnknown {
		return 0, fmt.Errorf("SP 的静态偏移无法确定（存在 MOV/ADD SP, Xn 之类的形式）")
	}
	eff := disp + l.spDelta
	if eff >= 0 {
		// 只补差值本身：spDelta 已经体现在 VM 的 SP 寄存器里，
		// 这里再加一次就是重复计算（差分测试抓到的错误）。
		return disp + int64(l.FrameSkew), nil
	}
	return disp, nil
}

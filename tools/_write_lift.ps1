$ErrorActionPreference = "Stop"
Set-Location "D:\vmp-x"
$content = @'
// Package arm64 把 ARM64（A64）指令翻译成平台无关 IR。
//
// 与 x86-64 lifter 共用同一套 IR / VM ISA，差异在于：
//   - 寄存器槽位：X0-X30 → 0..30，SP → 31，VBASE → 32，VMSCR → 33，ZR → 34；
//   - **标志位**：ARM64 的 ADD/SUB/AND/... 不带 S 时不修改标志位，
//     因此这些形式用 VM 的 "keep flags" 位（ir.KeepFlags）发射；
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
}

// Lift 翻译一段已解码的指令；不能精确表达的形式记录到 Unsupported 且不生成指令
func (l *Lifter) Lift(fn *ir.Func, insns []dec.Insn) {
	addrToIdx := map[uint64]int{}
	for i := range insns {
		addrToIdx[insns[i].PC] = i
	}
	first := uint64(0)
	if len(insns) > 0 {
		first = insns[0].PC
	}
	for i := range insns {
		ins := &insns[i]
		before := len(fn.Insns)
		if err := l.liftOne(fn, ins, addrToIdx); err != nil {
			fn.Insns = fn.Insns[:before]
			fn.Unsupported = append(fn.Unsupported, fmt.Sprintf("+0x%X %s: %v", ins.PC-first, ins.Text(), err))
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
	w := sf(ins.Raw)
	src, err := slotZR(rn)
	if err != nil {
		return err
	}
	kind := ir.Add
	if sub {
		kind = ir.Sub
	}
	dst := regOrScratch(ins.Raw & 31)
	f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRI, Kind: aluKind(kind, setFlags), Width: w,
		Dst: dst, A: src, Imm: uint64(imm), SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

func (l *Lifter) liftAddSubReg(f *ir.Func, ins *dec.Insn) error {
	setFlags := ins.Raw&(1<<29) != 0
	sub := ins.Raw&(1<<30) != 0
	shiftType := (ins.Raw >> 22) & 3
	shiftAmt := (ins.Raw >> 10) & 0x3F
	rm := (ins.Raw >> 16) & 31
	rn := (ins.Raw >> 5) & 31
	w := sf(ins.Raw)
	if shiftType == 3 {
		return fmt.Errorf("无效的移位类型 11")
	}
	src, err := slotZR(rm)
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
	rnSlot, err := slotZR(rn)
	if err != nil {
		return err
	}
	kind := ir.Add
	if sub {
		kind = ir.Sub
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRR, Kind: aluKind(kind, setFlags), Width: w,
		Dst: regOrScratch(ins.Raw & 31), A: rnSlot, B: src, SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

// ---------- 逻辑 ----------

func (l *Lifter) liftLogicalShifted(f *ir.Func, ins *dec.Insn) error {
	switch ins.Op {
	case arm64asm.AND, arm64asm.ANDS, arm64asm.ORR, arm64asm.EOR, arm64asm.MOV, arm64asm.TST:
	default:
		return fmt.Errorf("取反/其它逻辑形式（%v）暂不支持", ins.Op)
	}
	if ins.Raw&(1<<21) != 0 {
		return fmt.Errorf("取反形式（BIC/ORN/EON/MVN）暂不支持")
	}
	setFlags := ins.Raw&(1<<29) != 0
	opc := (ins.Raw >> 29) & 3
	shiftType := (ins.Raw >> 22) & 3
	shiftAmt := (ins.Raw >> 10) & 0x3F
	rm := (ins.Raw >> 16) & 31
	rn := (ins.Raw >> 5) & 31
	w := sf(ins.Raw)
	if shiftType == 3 {
		return fmt.Errorf("无效的移位类型 11")
	}
	src, err := slotZR(rm)
	if err != nil {
		return err
	}
	if shiftAmt != 0 {
		f.Insns = append(f.Insns, ir.Insn{Op: ir.MovRR, Width: w, Dst: SCR, A: src,
			SrcOff: uint32(ins.PC), Text: ins.Text()})
		f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRI, Kind: uint8(shiftKind(shiftType)) | ir.KeepFlags,
			Width: w, Dst: SCR, A: SCR, Imm: uint64(shiftAmt), SrcOff: uint32(ins.PC), Text: ins.Text()})
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
	dst := regOrScratch(ins.Raw & 31)
	if ins.Op == arm64asm.MOV {
		f.Insns = append(f.Insns, ir.Insn{Op: ir.MovRR, Width: w, Dst: dst, A: src,
			SrcOff: uint32(ins.PC), Text: ins.Text()})
		return nil
	}
	rnSlot, ok := slotLe31(rn)
	if !ok {
		return fmt.Errorf("Rn=XZR 的逻辑形式暂不支持")
	}
	sf2 := setFlags
	if ins.Op == arm64asm.TST {
		sf2 = true // TST 是 ANDS 的别名，设置标志位
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRR, Kind: aluKind(kind, sf2),
		Width: w, Dst: dst, A: rnSlot, B: src, SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

func (l *Lifter) liftLogicalImm(f *ir.Func, ins *dec.Insn) error {
	switch ins.Op {
	case arm64asm.AND, arm64asm.ANDS, arm64asm.ORR, arm64asm.EOR, arm64asm.MOV, arm64asm.TST:
	default:
		return fmt.Errorf("未预期的逻辑立即数形式 %v", ins.Op)
	}
	setFlags := ins.Raw&(1<<29) != 0
	opc := (ins.Raw >> 29) & 3
	n := (ins.Raw >> 22) & 1
	immr := (ins.Raw >> 16) & 0x3F
	imms := (ins.Raw >> 10) & 0x3F
	rn := (ins.Raw >> 5) & 31
	w := sf(ins.Raw)
	mask, err := decodeBitMasks(n, immr, imms, uint32(w) == 64)
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
	rnSlot, ok := slotLe31(rn)
	if !ok {
		return fmt.Errorf("Rn=XZR 的逻辑形式暂不支持")
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.MovRI, Width: ir.W64, Dst: SCR, Imm: mask,
		SrcOff: uint32(ins.PC), Text: ins.Text()})
	sf2 := setFlags
	if ins.Op == arm64asm.TST {
		sf2 = true
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRR, Kind: aluKind(kind, sf2),
		Width: w, Dst: dst, A: rnSlot, B: SCR, SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

// ---------- 移动立即数 ----------

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
		keep := uint64(0xFFFF) << shift
		clear := ^keep
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

// ---------- 位移 ----------

func (l *Lifter) liftBitfield(f *ir.Func, ins *dec.Insn) error {
	switch ins.Op {
	case arm64asm.LSL, arm64asm.LSR, arm64asm.ASR:
	default:
		return fmt.Errorf("位域形式（UBFM/SBFM/BFM 及其别名）暂不支持")
	}
	w := sf(ins.Raw)
	rd := ins.Raw & 31
	rn := (ins.Raw >> 5) & 31
	amt, ok := ins.Imm(2)
	if !ok {
		return fmt.Errorf("取不到移位量")
	}
	if amt < 0 || uint64(amt) >= uint64(w) {
		return fmt.Errorf("移位量 %d 超出宽度 %d", amt, w)
	}
	src, err := slotZR(rn)
	if err != nil {
		return err
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
		Dst: ir.Reg(rd), A: src, Imm: uint64(amt), SrcOff: uint32(ins.PC), Text: ins.Text()})
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
	f.Insns = append(f.Insns, ir.Insn{Op: ir.Jmp, Target: idx, SrcOff: uint32(ins.PC), Text: ins.Text()})
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
	f.Insns = append(f.Insns, ir.Insn{Op: ir.Jcc, Cond: ir.Cond(cond), Target: idx,
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
	f.Insns = append(f.Insns, ir.Insn{Op: ir.CmpRI, Kind: uint8(ir.Cmp), Width: sf(ins.Raw), A: rt, Imm: 0,
		SrcOff: uint32(ins.PC), Text: ins.Text()})
	cond := ir.ArmEQ
	if ins.Op == arm64asm.CBNZ {
		cond = ir.ArmNE
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.Jcc, Cond: cond, Target: idx, SrcOff: uint32(ins.PC), Text: ins.Text()})
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
	f.Insns = append(f.Insns,
		ir.Insn{Op: ir.MovRI, Width: ir.W64, Dst: SCR, Imm: uint64(1) << bit, SrcOff: uint32(ins.PC), Text: ins.Text()},
		ir.Insn{Op: ir.AluRR, Kind: aluKind(ir.And, false), Width: w, Dst: SCR, A: rt, B: SCR,
			SrcOff: uint32(ins.PC), Text: ins.Text()},
		ir.Insn{Op: ir.CmpRI, Kind: uint8(ir.Cmp), Width: w, A: SCR, Imm: 0, SrcOff: uint32(ins.PC), Text: ins.Text()})
	cond := ir.ArmEQ
	if ins.Op == arm64asm.TBNZ {
		cond = ir.ArmNE
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.Jcc, Cond: cond, Target: idx, SrcOff: uint32(ins.PC), Text: ins.Text()})
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

'@
[System.IO.File]::WriteAllText("internal\lift\arm64\lift.go", $content)
Write-Output ("written " + $content.Length)

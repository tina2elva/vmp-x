package arm64

import (
	"fmt"

	dec "github.com/vmpx/vmp-x/internal/decode/arm64"
	"github.com/vmpx/vmp-x/internal/ir"
)

// 内存访问的 lift。
//
// 关键点：
//   - 基址寄存器编号 31 在内存操作里表示 **SP**（不是 ZR）；
//   - SP 相关访问要用 spAdjust 加 FrameSkew：访问调用方栈帧（eff >= 0）要加，
//     访问本函数自有帧（eff < 0）不加（与 x86-64 侧同一机制）；
//   - 前/后索引的写回必须显式发射（VM 的 LOAD/STORE 不改基址）；
//   - 有符号加载（LDRSB/LDRSH/LDRSW）需要"零扩展加载 + 符号扩展"两步；
//   - 寻址方式**直接从原始编码字解析**（参考解码器把 imm 字段设为私有，读不到）。
//
// 编码速查（load/store register）：
//   size(2) 111 V 00 opc(2)
//     bits[25:24]=01 → 无符号偏移 imm12（按 size 缩放）
//     bits[25:24]=00 且 bit21=0 → imm9 形式：bits[11:10] = 00 未缩放 / 01 后索引 / 11 前索引
//     bits[25:24]=00 且 bit21=1 → 寄存器偏移（option/S）
//   load/store pair：opc(2) 101 V 0 bits[24:23] L imm7 Rt2 Rn Rt
//     bits[24:23] = 00 no-alloc / 01 后索引 / 10 偏移 / 11 前索引；imm7 按 size 缩放

type addrMode uint8

const (
	amOffset addrMode = iota
	amPreIndex
	amPostIndex
)

type memOperand struct {
	base   uint32
	isSP   bool
	disp   int64
	idxReg int
	scale  uint8
	mode   addrMode
}

func signExtendN(v uint32, n uint) int64 {
	// 必须在**有符号**域里做减法：uint32 下的 (v^sign)-sign 会下溢成 0xFFFFFFxx，
	// 于是"负偏移"被当成 +2^32-|d|（差分测试抓到的错误）。
	sign := uint32(1) << (n - 1)
	if v&sign != 0 {
		return int64(v) - int64(uint32(1)<<n)
	}
	return int64(v)
}

// parseSingleMem 解析单寄存器加载/存储的寻址方式
func parseSingleMem(raw uint32) (memOperand, error) {
	var op memOperand
	op.idxReg = -1
	op.scale = 1
	size := (raw >> 30) & 3
	switch {
	case (raw>>24)&1 == 1: // 无符号偏移 imm12
		imm12 := (raw >> 10) & 0xFFF
		op.base = (raw >> 5) & 31
		op.isSP = op.base == 31
		op.disp = int64(imm12) << size
		op.mode = amOffset
	case (raw>>21)&1 == 1: // 寄存器偏移
		rm := (raw >> 16) & 31
		option := (raw >> 13) & 7
		s := (raw >> 12) & 1
		op.base = (raw >> 5) & 31
		op.isSP = op.base == 31
		op.mode = amOffset
		if option != 3 { // 只支持 LSL/UXTX 形式
			return op, fmt.Errorf("寄存器偏移的扩展形式（option=%d）暂不支持", option)
		}
		if rm <= 30 {
			op.idxReg = int(rm)
		} else {
			op.idxReg = -2 // XZR：索引恒为 0，用 NoReg 处理
		}
		op.scale = uint8(1) << s
	default: // imm9 形式
		imm9 := (raw >> 12) & 0x1FF
		kind := (raw >> 10) & 3
		op.base = (raw >> 5) & 31
		op.isSP = op.base == 31
		op.disp = signExtendN(imm9, 9)
		switch kind {
		case 0, 2: // 未缩放 / 特权形式（LDUR/STUR、LDTR/STTR）
			op.mode = amOffset
		case 1:
			op.mode = amPostIndex
		case 3:
			op.mode = amPreIndex
		}
	}
	return op, nil
}

func baseSlot(op memOperand) (ir.Reg, error) {
	if op.isSP {
		return SP, nil
	}
	if op.base <= 30 {
		return ir.Reg(op.base), nil
	}
	return 0, fmt.Errorf("基址寄存器编号 %d 无效", op.base)
}

func accessWidth(size uint32) ir.Width {
	switch size {
	case 0:
		return ir.W8
	case 1:
		return ir.W16
	case 2:
		return ir.W32
	default:
		return ir.W64
	}
}

func idxOf(op memOperand) ir.Reg {
	switch {
	case op.idxReg < 0:
		return ir.NoReg
	case op.idxReg <= 30:
		return ir.Reg(op.idxReg)
	default:
		return ZR
	}
}

// liftLoadStore：LDR/STR/LDUR/STUR + 前/后索引 + 寄存器偏移
func (l *Lifter) liftLoadStore(f *ir.Func, ins *dec.Insn) error {
	raw := ins.Raw
	size := (raw >> 30) & 3
	opc := (raw >> 22) & 3
	if opc == 3 && size == 3 {
		return fmt.Errorf("PRFM（预取）不支持")
	}
	op, err := parseSingleMem(raw)
	if err != nil {
		return err
	}
	rt := int(ins.Reg(0))
	if rt < 0 {
		return fmt.Errorf("取不到目标寄存器")
	}
	w := accessWidth(size)
	base, err := baseSlot(op)
	if err != nil {
		return err
	}
	// 后索引（[Xn], #imm）的访问地址就是 Xn 本身，立即数**只用于写回**；
	// 前索引（[Xn, #imm]!）与偏移形式才把立即数算进访问地址。
	accDisp := op.disp
	if op.mode == amPostIndex {
		accDisp = 0
	}
	disp, err := l.spAdjust(accDisp, op.isSP)
	if err != nil {
		return err
	}
	if disp < -0x80000000 || disp > 0x7FFFFFFF {
		return fmt.Errorf("偏移 %d 超出 VM 的 disp32 范围", disp)
	}
	if opc == 0 { // 存储
		src, err := slotZR(uint32(rt))
		if err != nil {
			return err
		}
		f.Insns = append(f.Insns, ir.Insn{Op: ir.Store, Width: w, Base: base, Index: idxOf(op), Scale: op.scale,
			Disp: int32(disp), A: src, SrcOff: uint32(ins.PC), Text: ins.Text()})
	} else {
		dst := regOrScratch(uint32(rt))
		if opc == 2 || opc == 3 { // 有符号加载（opc=3 → 扩展到 64 位）
			dstW := ir.W32
			if rw := ins.RegWidth(0); rw == 64 {
				dstW = ir.W64 // 目标写成 Xt（含 LDRSW / 所有 opc=3 形式）
			}
			f.Insns = append(f.Insns,
				ir.Insn{Op: ir.Load, Width: w, Kind: 0, Base: base, Index: idxOf(op), Scale: op.scale,
					Disp: int32(disp), Dst: SCR, SrcOff: uint32(ins.PC), Text: ins.Text()},
				ir.Insn{Op: ir.Ext, Width: dstW, SrcW: w, Kind: uint8(ir.SignExt), Dst: dst, A: SCR,
					SrcOff: uint32(ins.PC), Text: ins.Text()})
		} else if size == 3 || ins.RegWidth(0) == 64 { // 64 位目标：零扩展即原值
			f.Insns = append(f.Insns, ir.Insn{Op: ir.Load, Width: ir.W64, Kind: 0, Base: base, Index: idxOf(op),
				Scale: op.scale, Disp: int32(disp), Dst: dst, SrcOff: uint32(ins.PC), Text: ins.Text()})
		} else {
			f.Insns = append(f.Insns,
				ir.Insn{Op: ir.Load, Width: w, Kind: 0, Base: base, Index: idxOf(op), Scale: op.scale,
					Disp: int32(disp), Dst: SCR, SrcOff: uint32(ins.PC), Text: ins.Text()},
				ir.Insn{Op: ir.MovRR, Width: ir.W32, Dst: dst, A: SCR, SrcOff: uint32(ins.PC), Text: ins.Text()})
		}
	}
	if op.mode == amPreIndex || op.mode == amPostIndex {
		if err := l.emitBaseUpdate(f, ins, base, op.disp, op.isSP); err != nil {
			return err
		}
	}
	return nil
}

// emitBaseUpdate 发射前/后索引写回：base = base ± |disp|（不改标志位）
func (l *Lifter) emitBaseUpdate(f *ir.Func, ins *dec.Insn, base ir.Reg, disp int64, isSP bool) error {
	if disp == 0 {
		return nil
	}
	kind := ir.Add
	amt := disp
	if disp < 0 {
		kind = ir.Sub
		amt = -disp
	}
	f.Insns = append(f.Insns, ir.Insn{Op: ir.AluRI, Kind: aluKind(kind, false), Width: ir.W64,
		Dst: base, A: base, Imm: uint64(amt), SrcOff: uint32(ins.PC), Text: ins.Text()})
	if isSP {
		l.spDelta += disp
	}
	return nil
}

// liftLoadStorePair：LDP/STP（偏移/前索引/后索引）
func (l *Lifter) liftLoadStorePair(f *ir.Func, ins *dec.Insn) error {
	raw := ins.Raw
	size := (raw >> 30) & 3
	load := raw&(1<<22) != 0
	var w ir.Width
	switch size {
	case 0:
		w = ir.W32
	case 2:
		w = ir.W64
	default:
		return fmt.Errorf("LDP/STP 的 size=%d 暂不支持（含 LDPSW）", size)
	}
	base := (raw >> 5) & 31
	isSP := base == 31
	imm7 := signExtendN((raw>>15)&0x7F, 7)
	disp := imm7 * int64(w/8)
	rt := int(ins.Reg(0))
	rt2 := int(ins.Reg(1))
	if rt < 0 || rt2 < 0 {
		return fmt.Errorf("取不到寄存器对")
	}
	baseReg, err := baseSlot(memOperand{base: base, isSP: isSP})
	if err != nil {
		return err
	}
	// 后索引（[Xn], #imm）：访问偏移为 0，立即数只用于写回；
	// 前索引/偏移形式才把立即数算进访问地址。
	acc := disp
	if (raw>>23)&3 == 1 {
		acc = 0
	}
	adj, err := l.spAdjust(acc, isSP)
	if err != nil {
		return err
	}
	if adj < -0x80000000 || adj > 0x7FFFFFFF || adj+int64(w/8) > 0x7FFFFFFF {
		return fmt.Errorf("偏移 %d 超出 disp32", adj)
	}
	if raw>>23&3 == 0 {
		return fmt.Errorf("no-allocate 形式的 LDP/STP（STNP/LDNP）暂不支持")
	}
	// 前/后索引对单次访问等价：统一"先访问、后写回"（先写回会让地址用错）
	if load {
		f.Insns = append(f.Insns,
			ir.Insn{Op: ir.Load, Width: w, Kind: 0, Base: baseReg, Index: ir.NoReg, Scale: 1,
				Disp: int32(adj), Dst: regOrScratch(uint32(rt)), SrcOff: uint32(ins.PC), Text: ins.Text()},
			ir.Insn{Op: ir.Load, Width: w, Kind: 0, Base: baseReg, Index: ir.NoReg, Scale: 1,
				Disp: int32(adj) + int32(w/8), Dst: regOrScratch(uint32(rt2)), SrcOff: uint32(ins.PC), Text: ins.Text()})
	} else {
		s1, err := slotZR(uint32(rt))
		if err != nil {
			return err
		}
		s2, err := slotZR(uint32(rt2))
		if err != nil {
			return err
		}
		f.Insns = append(f.Insns,
			ir.Insn{Op: ir.Store, Width: w, Base: baseReg, Index: ir.NoReg, Scale: 1,
				Disp: int32(adj), A: s1, SrcOff: uint32(ins.PC), Text: ins.Text()},
			ir.Insn{Op: ir.Store, Width: w, Base: baseReg, Index: ir.NoReg, Scale: 1,
				Disp: int32(adj) + int32(w/8), A: s2, SrcOff: uint32(ins.PC), Text: ins.Text()})
	}
	if m := (raw >> 23) & 3; m == 1 || m == 3 { // 后索引 / 前索引：写回
		if err := l.emitBaseUpdate(f, ins, baseReg, disp, isSP); err != nil {
			return err
		}
	}
	return nil
}

// liftLoadLiteral：LDR Xt, label —— PC 相对取常量（基址用 VBASE，单条 LOAD）
func (l *Lifter) liftLoadLiteral(f *ir.Func, ins *dec.Insn) error {
	raw := ins.Raw
	size := (raw >> 30) & 3
	tgt, ok := ins.PCRelTarget()
	if !ok {
		return fmt.Errorf("取不到字面量地址")
	}
	rt := int(ins.Reg(0))
	if rt < 0 {
		return fmt.Errorf("取不到目标寄存器")
	}
	if tgt < l.ImageBase {
		return fmt.Errorf("字面量地址 0x%X 低于模块基址", tgt)
	}
	rva := tgt - l.ImageBase
	if l.ImageSize != 0 && rva >= l.ImageSize {
		return fmt.Errorf("字面量地址 0x%X 超出模块范围（跨模块引用暂不支持）", tgt)
	}
	if rva > 0x7FFFFFFF {
		return fmt.Errorf("字面量偏移 0x%X 超出 disp32", rva)
	}
	w := accessWidth(size)
	dst := regOrScratch(uint32(rt))
	if size == 3 {
		f.Insns = append(f.Insns, ir.Insn{Op: ir.Load, Width: ir.W64, Kind: 0, Base: VB, Index: ir.NoReg,
			Scale: 1, Disp: int32(rva), Dst: dst, SrcOff: uint32(ins.PC), Text: ins.Text()})
		return nil
	}
	f.Insns = append(f.Insns,
		ir.Insn{Op: ir.Load, Width: w, Kind: 0, Base: VB, Index: ir.NoReg, Scale: 1,
			Disp: int32(rva), Dst: SCR, SrcOff: uint32(ins.PC), Text: ins.Text()},
		ir.Insn{Op: ir.MovRR, Width: ir.W32, Dst: dst, A: SCR, SrcOff: uint32(ins.PC), Text: ins.Text()})
	return nil
}

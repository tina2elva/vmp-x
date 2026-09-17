package arm64

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"

	dec "github.com/vmpx/vmp-x/internal/decode/arm64"
	arm64sem "github.com/vmpx/vmp-x/internal/guest/arm64"
	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
	"golang.org/x/arch/arm64/arm64asm"
)

// ---------- 参考实现：按 ARM ARM 直接求值（独立于 lifter 的 IR 映射） ----------

type refMachine struct {
	regs  [35]uint64
	flags uint32
}

func (m *refMachine) readZR(r uint32) uint64 {
	if r == 31 {
		return 0 // XZR/WZR
	}
	return m.regs[r]
}

func (m *refMachine) write(r uint32, w ir.Width, v uint64) {
	if r == 31 { // XZR：丢弃
		return
	}
	if w == ir.W32 {
		m.regs[r] = v & 0xFFFFFFFF
		return
	}
	m.regs[r] = v
}

func widthMask64(v uint64, w ir.Width) uint64 {
	if w == ir.W32 {
		return v & 0xFFFFFFFF
	}
	return v
}

// step 直接执行一条数据类指令（只覆盖 lifter 声称支持的形式）
func (m *refMachine) step(ins *dec.Insn) error {
	raw := ins.Raw
	w := ir.W64
	if raw&(1<<31) == 0 {
		w = ir.W32
	}
	switch ins.Class {
	case dec.ClassAddSubImm:
		imm := uint64((raw >> 10) & 0xFFF)
		if raw&(1<<22) != 0 {
			imm <<= 12
		}
		rn := (raw >> 5) & 31
		rd := raw & 31
		// 立即数形式里 31 表示 **SP**（不是 XZR）——lifter 也是这样处理的，参考实现必须一致
		a := m.regs[31]
		if rn != 31 {
			a = m.regs[rn]
		}
		sub := raw&(1<<30) != 0
		var r uint64
		if sub {
			r = widthMask64(a-imm, w)
		} else {
			r = widthMask64(a+imm, w)
		}
		if raw&(1<<29) != 0 { // S
			if sub {
				m.flags = arm64sem.FlagsSub(a, imm, r, uint32(w))
			} else {
				m.flags = arm64sem.FlagsAdd(a, imm, r, uint32(w))
			}
		}
		// Rd=31：带 S 时是 XZR（丢弃），不带 S 时是 **SP**
		if rd == 31 && raw&(1<<29) == 0 {
			if w == ir.W32 {
				m.regs[31] = r & 0xFFFFFFFF
			} else {
				m.regs[31] = r
			}
			return nil
		}
		m.write(rd, w, r)
		return nil

	case dec.ClassAddSubShifted:
		shiftType := (raw >> 22) & 3
		shiftAmt := (raw >> 10) & 0x3F
		rn := (raw >> 5) & 31
		rm := (raw >> 16) & 31
		rd := raw & 31
		if shiftType == 3 {
			return fmt.Errorf("无效移位")
		}
		b := m.readZR(rm)
		mask := widthMask64(^uint64(0), w)
		switch shiftType {
		case 0:
			b = widthMask64(b<<shiftAmt, w)
		case 1:
			b = widthMask64(b, w) >> shiftAmt
		default:
			signed := int64(b << (64 - uint32(w)))
			signed >>= 64 - uint32(w)
			b = widthMask64(uint64(signed>>shiftAmt), w)
		}
		_ = mask
		a := m.readZR(rn)
		sub := raw&(1<<30) != 0
		var r uint64
		if sub {
			r = widthMask64(a-b, w)
		} else {
			r = widthMask64(a+b, w)
		}
		if raw&(1<<29) != 0 {
			if sub {
				m.flags = arm64sem.FlagsSub(a, b, r, uint32(w))
			} else {
				m.flags = arm64sem.FlagsAdd(a, b, r, uint32(w))
			}
		}
		m.write(rd, w, r)
		return nil

	case dec.ClassLogicalImm:
		// 立即数取自参考解码器打印的文本（避免与 lifter 共用同一份解码代码）
		mask, ok := refImmFromText(ins.Text())
		if !ok {
			return fmt.Errorf("取不到立即数: %s", ins.Text())
		}
		rn := (raw >> 5) & 31
		rd := raw & 31
		a := m.readZR(rn)
		var r uint64
		switch (raw >> 29) & 3 {
		case 0, 3:
			r = widthMask64(a&mask, w)
		case 1:
			r = widthMask64(a|mask, w)
		default:
			r = widthMask64(a^mask, w)
		}
		if (raw>>29)&3 == 3 {
			m.flags = arm64sem.FlagsLogic(r, uint32(w))
		}
		m.write(rd, w, r)
		return nil

	case dec.ClassCondSelect:
		rd := raw & 31
		rn := (raw >> 5) & 31
		rm := (raw >> 16) & 31
		cond := (raw >> 12) & 0xF
		op2 := (raw >> 10) & 3
		yes := m.readZR(rn) & widthMask64(^uint64(0), w)
		no := m.readZR(rm) & widthMask64(^uint64(0), w)
		var r uint64
		if arm64sem.CondHolds(uint32(cond), m.flags) {
			r = yes
		} else {
			switch op2 {
			case 0:
				r = no
			case 1:
				r = widthMask64(no+1, w)
			case 2:
				r = widthMask64(^no, w)
			default:
				r = widthMask64(uint64(-int64(no)), w)
			}
		}
		m.write(rd, w, widthMask64(r, w))
		return nil

	case dec.ClassLogicalShifted:
		// bit21 = 取反第二个操作数（BIC/ORN/EON/MVN/BICS）
		invert := raw&(1<<21) != 0
		shiftType := (raw >> 22) & 3
		shiftAmt := (raw >> 10) & 0x3F
		rn := (raw >> 5) & 31
		rm := (raw >> 16) & 31
		rd := raw & 31
		if shiftType == 3 {
			return fmt.Errorf("无效移位")
		}
		b := m.readZR(rm)
		switch shiftType {
		case 0:
			b = widthMask64(b<<shiftAmt, w)
		case 1:
			b = widthMask64(b, w) >> shiftAmt
		default:
			signed := int64(b << (64 - uint32(w)))
			signed >>= 64 - uint32(w)
			b = widthMask64(uint64(signed>>shiftAmt), w)
		}
		if invert {
			b = widthMask64(^b, w)
		}
		a := m.readZR(rn)
		var r uint64
		switch (raw >> 29) & 3 {
		case 0, 3:
			r = widthMask64(a&b, w)
		case 1:
			r = widthMask64(a|b, w)
		default:
			r = widthMask64(a^b, w)
		}
		if (raw>>29)&3 == 3 {
			m.flags = arm64sem.FlagsLogic(r, uint32(w))
		}
		m.write(rd, w, r)
		return nil

	case dec.ClassDataProc3:
		rn := (raw >> 5) & 31
		rm := (raw >> 16) & 31
		ra := (raw >> 10) & 31
		sub := raw&(1<<15) != 0
		a := m.readZR(rn) & MaskW64(uint32(w))
		b := m.readZR(rm) & MaskW64(uint32(w))
		acc := m.readZR(ra) & MaskW64(uint32(w))
		prod := widthMask64(a*b, w)
		if sub {
			m.write(raw&31, w, widthMask64(acc-prod, w))
		} else {
			m.write(raw&31, w, widthMask64(acc+prod, w))
		}
		return nil

	case dec.ClassMoveWide:
		opc := (raw >> 29) & 3
		hw := (raw >> 21) & 3
		imm16 := (raw >> 5) & 0xFFFF
		rd := raw & 31
		if w == ir.W32 && hw > 1 {
			return fmt.Errorf("hw 无效")
		}
		shift := hw * 16
		switch opc {
		case 0, 1:
			v := ^(uint64(imm16) << shift)
			m.write(rd, w, widthMask64(v, w))
		case 2:
			m.write(rd, w, uint64(imm16)<<shift)
		default:
			cur := m.regs[rd]
			if rd == 31 {
				cur = 0
			}
			v := (cur & ^(uint64(0xFFFF) << shift)) | (uint64(imm16) << shift)
			m.write(rd, w, widthMask64(v, w))
		}
		return nil

	case dec.ClassBitfield:
		switch ins.Op {
		case arm64asm.LSL, arm64asm.LSR, arm64asm.ASR:
		case arm64asm.UBFX, arm64asm.SBFX, arm64asm.UBFIZ, arm64asm.SBFIZ:
			lsbImm, ok1 := ins.Imm(2)
			wImm, ok2 := ins.Imm(3)
			if !ok1 || !ok2 || wImm <= 0 {
				return fmt.Errorf("位域参数")
			}
			lsb, width := uint64(lsbImm), uint64(wImm)
			bits := uint64(w)
			if lsb+width > bits {
				return fmt.Errorf("位域越界")
			}
			mask := MaskW64(uint32(w))
			a := m.readZR((raw>>5)&31) & mask
			field := (a >> lsb) & (uint64(1)<<width - 1) // UBFX/SBFX：从 lsb 开始取位
			lo := a & (uint64(1)<<width - 1)             // UBFIZ/SBFIZ：取**低** width 位
			// 取出的 width 位按**有符号数**解释（符号扩展），全部在操作宽度内完成
			signExt := func(v uint64) uint64 {
				if width == bits {
					return v & mask
				}
				if v&(uint64(1)<<(width-1)) != 0 {
					return (v | ^(uint64(1)<<width - 1)) & mask
				}
				return v & mask
			}
			var r uint64
			switch ins.Op {
			case arm64asm.UBFX:
				r = field
			case arm64asm.UBFIZ:
				r = lo << lsb
			case arm64asm.SBFX:
				r = signExt(field)
			default: // SBFIZ
				r = (signExt(lo) << lsb) & mask
			}
			m.write(ins.Raw&31, w, r)
			return nil
		default:
			return fmt.Errorf("位域形式")
		}
		amt, ok := ins.Imm(2)
		if !ok {
			return fmt.Errorf("取不到移位量")
		}
		rn := (raw >> 5) & 31
		rd := raw & 31
		a := m.readZR(rn) & MaskW64(uint32(w))
		var r uint64
		switch ins.Op {
		case arm64asm.LSL:
			r = widthMask64(a<<uint(amt), w)
		case arm64asm.LSR:
			r = widthMask64(a, w) >> uint(amt)
		default:
			signed := int64(a << (64 - uint32(w)))
			signed >>= 64 - uint32(w)
			r = widthMask64(uint64(signed>>uint(amt)), w)
		}
		m.write(rd, w, r)
		return nil
	}
	return fmt.Errorf("参考实现不支持 %v", ins.Class)
}

// refImmFromText 从参考解码器打印的文本里取立即数
func refImmFromText(text string) (uint64, bool) {
	i := strings.LastIndex(text, "#")
	if i < 0 {
		return 0, false
	}
	s := strings.TrimSpace(text[i+1:])
	if j := strings.IndexAny(s, " ,"); j >= 0 {
		s = s[:j]
	}
	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ---------- 生成可精确控制的编码 ----------

func genDataInsn(rng *rand.Rand) uint32 {
	rd := func() uint32 { return uint32(rng.Intn(31)) } // 0..30，避免写 ZR 带来的歧义
	rn := func() uint32 { return uint32(rng.Intn(32)) } // 31 = XZR
	sfBit := func() uint32 {
		if rng.Intn(2) == 0 {
			return 0
		}
		return 1 << 31
	}
	switch rng.Intn(10) {
	case 0: // ADD/SUB (immediate)
		w := uint32(0x11000000) | (sfBit()) | (rn() << 5) | rd() | (uint32(rng.Intn(0x1000)) << 10)
		if rng.Intn(2) == 0 {
			w |= 1 << 30 // SUB
		}
		if rng.Intn(2) == 0 {
			w |= 1 << 29 // S
		}
		if rng.Intn(4) == 0 {
			w |= 1 << 22 // LSL #12
		}
		return w
	case 1: // ADD/SUB (shifted register)
		w := uint32(0x0B000000) | sfBit() | (rn() << 5) | rd() | ((rng.Uint32() & 31) << 16)
		if rng.Intn(2) == 0 {
			w |= 1 << 30
		}
		if rng.Intn(2) == 0 {
			w |= 1 << 29
		}
		st := uint32(rng.Intn(3))
		amt := uint32(rng.Intn(31))
		w |= st << 22
		w |= amt << 10
		return w
	case 2: // Logical (immediate)：用参考解码器筛掉保留编码
		w := uint32(0x12000000) | sfBit() | (rn() << 5) | rd() | (rng.Uint32() & 0x1FFFE0)
		w |= uint32(rng.Intn(4)) << 29
		return w
	case 3: // Logical (shifted register)
		w := uint32(0x0A000000) | sfBit() | (rn() << 5) | rd() | ((rng.Uint32() & 31) << 16)
		w |= uint32(rng.Intn(4)) << 29
		st := uint32(rng.Intn(3))
		amt := uint32(rng.Intn(31))
		w |= st << 22
		w |= amt << 10
		return w
	case 4: // Move wide
		opc := uint32(rng.Intn(4))
		hw := uint32(rng.Intn(4))
		imm16 := uint32(rng.Intn(0x10000))
		w := uint32(0x12800000) | sfBit() | (opc << 29) | (hw << 21) | (imm16 << 5) | rd()
		return w
	case 8: // 取反形式的逻辑（BIC/BICS/ORN/EON/MVN）
		sfBit := uint32(0)
		if rng.Intn(2) == 0 {
			sfBit = 1 << 31
		}
		w := uint32(0x0A000000) | sfBit | (1 << 21) // Rd = Rn op ~(Rm shift)
		w |= (uint32(rng.Intn(3)) << 29)            // opc：0=AND 1=ORR 2=EOR（BIC/ORN/EON）
		if rng.Intn(3) == 0 {
			w |= (3 << 29) // BICS
		}
		w |= (uint32(rng.Intn(3)) << 22) | (uint32(rng.Intn(31)) << 10)
		w |= (rn() << 5) | rd()
		return w
	case 9: // 条件选择：CSEL/CSINC/CSINV/CSNEG
		sfBit := uint32(0)
		if rng.Intn(2) == 0 {
			sfBit = 1 << 31
		}
		rm := 1 + uint32(rng.Intn(30))
		rdv := uint32(rng.Intn(31))
		return uint32(0x1A800000) | sfBit | (rm << 16) | (uint32(rng.Intn(16)) << 12) |
			(uint32(rng.Intn(4)) << 10) | (19+uint32(rng.Intn(10)))<<5 | rdv
	case 6: // 位域别名 UBFX/SBFX/UBFIZ/SBFIZ
		is64 := rng.Intn(2) == 0
		var bits, sfBit, ubase, sbase uint32
		if is64 {
			bits, sfBit, ubase, sbase = 64, 1<<31, 0xD3400000, 0x93400000
		} else {
			bits, sfBit, ubase, sbase = 32, 0, 0x53000000, 0x13000000
		}
		var w uint32
		switch rng.Intn(4) {
		case 0, 1: // UBFX/SBFX：immr = lsb, imms = lsb+width-1
			lsb := uint32(rng.Intn(int(bits)))
			width := uint32(1 + rng.Intn(int(bits)-int(lsb)))
			w = ubase | sfBit | (lsb << 16) | ((lsb + width - 1) << 10)
			if rng.Intn(2) == 0 {
				w = sbase | sfBit | (lsb << 16) | ((lsb + width - 1) << 10)
			}
		default: // UBFIZ/SBFIZ：immr = (bits-lsb)%bits, imms = width-1
			width := uint32(1 + rng.Intn(int(bits)))
			maxLsb := int(bits) - int(width)
			lsb := uint32(0)
			if maxLsb > 0 {
				lsb = uint32(rng.Intn(maxLsb + 1))
			}
			w = ubase | sfBit | (((bits - lsb) % bits) << 16) | ((width - 1) << 10)
			if rng.Intn(2) == 0 {
				w = sbase | sfBit | (((bits - lsb) % bits) << 16) | ((width - 1) << 10)
			}
		}
		w |= ((19 + uint32(rng.Intn(10))) << 5) | uint32(rng.Intn(31))
		return w
	case 7: // MADD/MSUB（含 MUL/MNEG 别名）
		sfBit := uint32(0)
		if rng.Intn(2) == 0 {
			sfBit = 1 << 31
		}
		w := uint32(0x1B000000) | sfBit | ((19 + uint32(rng.Intn(10))) << 16) | (uint32(rng.Intn(31)) << 10) |
			((19 + uint32(rng.Intn(10))) << 5) | uint32(rng.Intn(31))
		if rng.Intn(2) == 0 {
			w |= 1 << 15 // MSUB
		}
		return w
	default: // 位域别名 LSL/LSR/ASR
		is64 := rng.Intn(2) == 0
		var w uint32
		var bits uint32
		if is64 {
			w = 0x53000000 | (1 << 31) // UBFM 64
			bits = 64
		} else {
			w = 0x53000000
			bits = 32
		}
		amt := uint32(rng.Intn(int(bits)))
		switch rng.Intn(3) {
		case 0: // LSL #amt
			w |= ((bits - amt) % bits) << 16
			w |= (bits - 1 - amt) << 10
		case 1: // LSR #amt
			w |= amt << 16
			w |= (bits - 1) << 10
		default: // ASR #amt（SBFM）
			w |= 0x04000000 // opc=00 -> SBFM
			w |= amt << 16
			w |= (bits - 1) << 10
		}
		w |= (rn() << 5) | rd()
		return w
	}
}

// ---------- 差分：lift + 在 Go 参考 VM 里执行  vs  直接语义 ----------

func TestArm64LiftDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(777))
	const iterations = 20000
	const seqLen = 6
	checked, bad := 0, 0
	var skipDecode, skipRef, skipLift int
	for it := 0; it < iterations; it++ {
		words := make([]uint32, seqLen)
		for i := range words {
			words[i] = genDataInsn(rng)
		}
		var code []byte
		for _, w := range words {
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, w)
			code = append(code, b...)
		}
		insns, err := dec.DecodeRange(code, 0x1000, 0)
		if err != nil {
			skipDecode++
			continue
		}
		var regs [35]uint64
		for i := 0; i < 31; i++ {
			regs[i] = rng.Uint64()
		}
		ref := &refMachine{regs: regs}
		refOK := true
		for i := range insns {
			if err := ref.step(&insns[i]); err != nil {
				refOK = false
				break
			}
		}
		if !refOK {
			skipRef++
			continue
		}
		fn := &ir.Func{}
		(&Lifter{ImageBase: 0}).Lift(fn, insns)
		if len(fn.Unsupported) > 0 {
			skipLift++
			continue
		}
		fn.Insns = append(fn.Insns, ir.Insn{Op: ir.Ret})
		res, err := vm.Generate(fn)
		if err != nil {
			t.Fatalf("codegen 失败: %v", err)
		}
		st := &vm.RefState{Guest: vm.GuestARM64, Mem: map[uint64]byte{}}
		st.Regs = regs
		if rc, err := st.Run(res.Code, 4096); err != nil || rc != 0 {
			t.Fatalf("VM 执行失败: rc=%d err=%v", rc, err)
		}
		diff := ""
		for i := 0; i < 31; i++ {
			if st.Regs[i] != ref.regs[i] {
				diff = fmt.Sprintf("R%d: vm=0x%X ref=0x%X", i, st.Regs[i], ref.regs[i])
				break
			}
		}
		if diff == "" && st.Flags != ref.flags {
			diff = fmt.Sprintf("flags: vm=0x%X ref=0x%X", st.Flags, ref.flags)
		}
		if diff != "" {
			bad++
			if bad <= 4 {
				t.Errorf("用例 %d: %s", it, diff)
				for i := range insns {
					t.Logf("   src[%d] %s", i, insns[i].Text())
				}
				for i := range fn.Insns {
					in := &fn.Insns[i]
					t.Logf("   IR[%d] %v kind=0x%X w=%d dst=%d a=%d b=%d imm=0x%X", i, in.Op, in.Kind, in.Width, in.Dst, in.A, in.B, in.Imm)
				}
			}
			continue
		}
		checked++
	}
	t.Logf("ARM64 lift 差分：校验 %d 组（每组 %d 条），不一致 %d 组；跳过：解码失败 %d、参考不支持 %d、lifter 拒绝 %d",
		checked, seqLen, bad, skipDecode, skipRef, skipLift)
	if bad != 0 {
		t.Fatalf("不一致 %d 组", bad)
	}
}

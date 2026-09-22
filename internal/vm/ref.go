package vm

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"

	arm64sem "github.com/vmpx/vmp-x/internal/guest/arm64"
)

// RefState 是 VM 字节码的 Go 参考实现状态。
//
// 目的：用**第二份独立实现**去交叉验证 C 解释器（stub/win/x64/vm_interp.c）。
// 两份实现在随机/组合生成的字节码上必须给出完全一致的寄存器、标志与内存结果；
// 一旦不一致，说明至少有一边错了——这正是我们想要的“响亮地失败”。
//
// 内存模型：只允许访问 [BufBase, BufBase+BufSize)，用稀疏 map 表示，
// 这样测试永远不会因为野指针而崩溃。
// stackSlotBits 返回客户机的栈槽宽度（位）：x86-32 是 32 位，其余是 64 位。
func (s *RefState) stackSlotBits() uint32 {
	if s.Guest == GuestX8632 {
		return 32
	}
	return 64
}

// Guest 选择客户机 ISA：寄存器个数、标志位与条件码语义都随它变化。
// 与 C 侧一致：x86-64 用 18 个槽位（16 GPR + VBASE + VSCRATCH），
// ARM64 用 35 个（X0-X30 + SP + VBASE + VSCRATCH + ZR）。
type Guest uint8

const (
	GuestX86 Guest = iota
	GuestARM64
	// GuestX8632 是 32 位 x86 客户机：标志位/条件码/算术规则与 GuestX86 **完全一致**
	// （x86 家族本来就一致），唯一的语义差别是**栈槽 4 字节**（push/pop/call/ret）。
	// 每条 IR 自带运算宽度，所以运算部分不需要为它特判。
	GuestX8632
)

type RefState struct {
	Guest Guest
	// Map 是本 blob 的操作码编码表；nil 表示默认编码
	Map     *OpcodeMap
	Regs    [RefMaxRegs]uint64
	Flags   uint32
	Mem     map[uint64]byte
	BufBase uint64
	BufSize uint64
}

const VMRegCount = 18

// RefMaxRegs 覆盖两种客户机的最大槽位数，x86-64 只用前 18 个
const RefMaxRegs = 35

// Flag bits（与 C 侧一致）
const (
	FlagZ uint32 = 1
	FlagN uint32 = 2
	FlagC uint32 = 4
	FlagV uint32 = 8
	FlagP uint32 = 16
)

func widthMask(w uint32) uint64 {
	if w >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << w) - 1
}

func signExtendW(v uint64, w uint32) int64 {
	if w >= 64 {
		return int64(v)
	}
	m := widthMask(w)
	x := v & m
	sign := uint64(1) << (w - 1)
	return int64((x ^ sign) - sign)
}

func parityFlag(r uint64) uint32 {
	b := byte(r)
	ones := 0
	for i := 0; i < 8; i++ {
		ones += int((b >> uint(i)) & 1)
	}
	if ones&1 == 0 {
		return FlagP
	}
	return 0
}

func flagsAdd(x, y, r uint64, w uint32) uint32 {
	m := widthMask(w)
	sign := uint64(1) << (w - 1)
	var f uint32
	if r&m == 0 {
		f |= FlagZ
	}
	if r&sign != 0 {
		f |= FlagN
	}
	if w >= 64 {
		if r < x {
			f |= FlagC
		}
	} else if x+y > m {
		f |= FlagC
	}
	if ((^(x ^ y)) & (x ^ r) & sign) != 0 {
		f |= FlagV
	}
	return f | parityFlag(r)
}

func flagsSub(x, y, r uint64, w uint32) uint32 {
	m := widthMask(w)
	sign := uint64(1) << (w - 1)
	var f uint32
	if r&m == 0 {
		f |= FlagZ
	}
	if r&sign != 0 {
		f |= FlagN
	}
	if x < y {
		f |= FlagC
	}
	if ((x ^ y) & (x ^ r) & sign) != 0 {
		f |= FlagV
	}
	return f | parityFlag(r)
}

// flagsAdc：x86 的 ADC 语义（x + y + cin），标志位与硬件一致
func flagsAdc(x, y uint64, cin uint32, r uint64, w uint32) uint32 {
	m := widthMask(w)
	sign := uint64(1) << (w - 1)
	var f uint32
	if r&m == 0 {
		f |= FlagZ
	}
	if r&sign != 0 {
		f |= FlagN
	}
	if w >= 64 {
		t := x + y
		if t < x || (cin != 0 && t == ^uint64(0)) {
			f |= FlagC
		}
	} else if x+y+uint64(cin) > m {
		f |= FlagC
	}
	if ((^(x ^ y)) & (x ^ r) & sign) != 0 {
		f |= FlagV
	}
	return f | parityFlag(r)
}

// flagsSbb：x86 的 SBB 语义（x - y - cin）
func flagsSbb(x, y uint64, cin uint32, r uint64, w uint32) uint32 {
	m := widthMask(w)
	sign := uint64(1) << (w - 1)
	var f uint32
	if r&m == 0 {
		f |= FlagZ
	}
	if r&sign != 0 {
		f |= FlagN
	}
	if x < y || (cin != 0 && x == y) {
		f |= FlagC
	}
	if ((x ^ y) & (x ^ r) & sign) != 0 {
		f |= FlagV
	}
	return f | parityFlag(r)
}

func flagsLogic(r uint64, w uint32) uint32 {
	m := widthMask(w)
	sign := uint64(1) << (w - 1)
	var f uint32
	if r&m == 0 {
		f |= FlagZ
	}
	if r&sign != 0 {
		f |= FlagN
	}
	return f | parityFlag(r)
}

// mul128Signed 计算 a*b 的 128 位有符号乘积，返回 (hi, lo)
func mul128Signed(a, b int64) (int64, uint64) {
	neg := false
	ua := uint64(a)
	if a < 0 {
		ua = uint64(-(a + 1)) + 1 // 避免 -MinInt64 溢出
		neg = !neg
	}
	ub := uint64(b)
	if b < 0 {
		ub = uint64(-(b + 1)) + 1
		neg = !neg
	}
	hi, lo := bits.Mul64(ua, ub)
	if neg {
		// 128 位取负 = 取反加一
		hi, lo = ^hi, ^lo
		var carry uint64
		lo, carry = bits.Add64(lo, 1, 0)
		hi += carry
	}
	return int64(hi), lo
}

func flagsMul(x, y, r uint64, w uint32) uint32 {
	a := signExtendW(x, w)
	b := signExtendW(y, w)
	hi, lo := mul128Signed(a, b)
	se := signExtendW(r, w)
	var wantHi int64
	if se < 0 {
		wantHi = -1
	}
	var f uint32
	if r&widthMask(w) == 0 {
		f |= FlagZ
	}
	if r&(uint64(1)<<(w-1)) != 0 {
		f |= FlagN
	}
	if hi != wantHi || lo != uint64(se) {
		f |= FlagC | FlagV
	}
	return f | parityFlag(r)
}

func flagsShift(x, r uint64, w, kind, cnt uint32) uint32 {
	sign := uint64(1) << (w - 1)
	var f uint32
	if r&widthMask(w) == 0 {
		f |= FlagZ
	}
	if r&sign != 0 {
		f |= FlagN
	}
	switch kind {
	case KShl:
		if cnt-1 < 64 && x&(sign>>(cnt-1)) != 0 {
			f |= FlagC
		}
		if cnt == 1 && ((r^x)&sign) != 0 {
			f |= FlagV
		}
	case KShr:
		if cnt-1 < 64 && x&(uint64(1)<<(cnt-1)) != 0 {
			f |= FlagC
		}
		if cnt == 1 && x&sign != 0 {
			f |= FlagV
		}
	default: // SAR
		if cnt-1 < 64 && x&(uint64(1)<<(cnt-1)) != 0 {
			f |= FlagC
		}
	}
	return f | parityFlag(r)
}

// ALU 子操作编号（与 vm_opcodes.h 一致）
const (
	KAdd = iota
	KSub
	KAnd
	KOr
	KXor
	KMul
	KShl
	KShr
	KSar
	KRol
	KRor
	// 带进位形式（x86 的 ADC/SBB）与乘法高半（x86 的 MUL）：值必须与 C 侧 K_* 一致
	KAdc
	KSbb
	KMulHi
	KBt
	KBsf
	KBsr
	KTzcnt
	KLzcnt
	KMulHiS // 值与 IR/C 侧的对应关系靠顺序维持
	KDivU
	KDivS // x86 DIV/IDIV：隐含寄存器 + 双输出，与下面 alu(kind,a,b,width)->单值 的形状不符
)

// 浮点子操作（与 C 侧 KF_* 一致）
const (
	KFAdd = iota
	KFSub
	KFMul
	KFDiv
	KFMin
	KFMax
	KFSqrt
	KFCvtsi2f
	KFCvttf2si
	KFUcomi
	KFCvtDQ2PD // CVTDQ2PD：两个 int32 → 两个 double（与 C 侧 KF_* 顺序一致）
)

// 原子子操作（与 C 侧 KA_* 一致）
const (
	KAXchg = iota
	KAAdd
	KASub
	KAAnd
	KAOr
	KAXor
	KAInc
	KADec
	KACmpxchg
)

// 一元子操作
const (
	KUNeg = iota
	KUNot
	KUInc
	KUDec
)

// 比较子操作
const (
	KCmp = iota
	KTest
)

// AluKeepFlags：kind 字节的 bit7。ARM64 不带 S 的运算必须保留标志位。
const AluKeepFlags uint32 = 0x80

// x86-64 的寄存器槽位（与 ir/vm_types.h 一致）：RAX=0、RDX=2。
const (
	refRAX = 0
	refRDX = 2
)

// refDiv 是 x86 单操作数 DIV/IDIV 的参考语义（慢但直白，用 math/big 避免微妙的符号问题）：
//
//	8 位     ：被除数 AH:AL（= RAX 低 16 位），商→AL、余→AH
//	16/32/64 ：被除数 DX:AX 族，商→AX 族、余→DX 族
//
// 除零 / 商放不下 ⇒ x86 的 #DE：这里用 panic 表示（宁可响亮失败，也不静默给错值）。
func refDiv(s *RefState, kind uint32, a uint64, width uint32) {
	m := widthMask(width)
	var n, dv *big.Int
	if width == 8 {
		n = new(big.Int).SetUint64(s.Regs[refRAX] & 0xFFFF)
		dv = new(big.Int).SetUint64(a & 0xFF)
	} else {
		lo := new(big.Int).SetUint64(s.Regs[refRAX] & m)
		hi := new(big.Int).SetUint64(s.Regs[refRDX] & m)
		n = lo.Add(lo, hi.Lsh(hi, uint(width)))
		dv = new(big.Int).SetUint64(a & m)
	}
	if kind == KDivS {
		n = twosToSigned(n, 2*width)
		dv = twosToSigned(dv, width)
	}
	if dv.Sign() == 0 {
		panic("ref: DIV/IDIV 除零（x86 #DE）")
	}
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(n, dv, r) // 向零截断，与 x86 一致
	lim := new(big.Int).Lsh(big.NewInt(1), uint(width))
	if kind == KDivS {
		half := new(big.Int).Rsh(lim, 1)
		loLim := new(big.Int).Neg(half)
		hiLim := new(big.Int).Sub(half, big.NewInt(1))
		if q.Cmp(loLim) < 0 || q.Cmp(hiLim) > 0 {
			panic("ref: DIV/IDIV 商溢出（x86 #DE）")
		}
	} else if q.Cmp(lim) >= 0 {
		panic("ref: DIV/IDIV 商溢出（x86 #DE）")
	}
	bitMask := new(big.Int).Sub(lim, big.NewInt(1))
	qm := new(big.Int).And(q, bitMask).Uint64()
	rm := new(big.Int).And(r, bitMask).Uint64()
	switch width {
	case 8:
		s.Regs[refRAX] = (s.Regs[refRAX] &^ 0xFFFF) | (rm&0xFF)<<8 | (qm & 0xFF)
	case 16:
		s.Regs[refRAX] = (s.Regs[refRAX] &^ 0xFFFF) | (qm & 0xFFFF)
		s.Regs[refRDX] = (s.Regs[refRDX] &^ 0xFFFF) | (rm & 0xFFFF)
	default:
		s.Regs[refRAX] = qm
		s.Regs[refRDX] = rm
	}
}

// twosToSigned 把 width 位的补码无符号值解释成有符号（就地修改传入的 big.Int）。
func twosToSigned(v *big.Int, width uint32) *big.Int {
	w := new(big.Int).Lsh(big.NewInt(1), uint(width))
	half := new(big.Int).Rsh(w, 1)
	if v.Cmp(half) >= 0 {
		return v.Sub(v, w)
	}
	return v
}

func (s *RefState) aluApply(kind, width uint32, a, b uint64) uint64 {
	k := kind &^ AluKeepFlags
	keep := kind&AluKeepFlags != 0
	saved := s.Flags
	defer func() {
		if keep {
			s.Flags = saved
		}
	}()
	kind = k
	m := widthMask(width)
	x, y := a&m, b&m
	arm := s.Guest == GuestARM64
	var r uint64
	switch kind {
	case KAdd:
		r = x + y
		if arm {
			s.Flags = arm64sem.FlagsAdd(x, y, r, width)
		} else {
			s.Flags = flagsAdd(x, y, r, width)
		}
	case KTzcnt, KLzcnt:
		// BMI1：源为 0 时结果是位宽，并置 CF/ZF；其它标志位保持
		v := x & m
		if v == 0 {
			s.Flags = (s.Flags &^ (FlagZ | FlagC)) | FlagZ | FlagC
			return uint64(width) & m
		}
		s.Flags &^= FlagZ | FlagC
		if kind == KTzcnt {
			if width >= 64 {
				return uint64(bits.TrailingZeros64(v)) & m
			}
			return uint64(bits.TrailingZeros32(uint32(v))) & m
		}
		if width >= 64 {
			return uint64(63-bits.LeadingZeros64(v)) & m
		}
		return uint64(31-bits.LeadingZeros32(uint32(v))) & m
	case KBsf, KBsr:
		// x86 BSF/BSR：只有 ZF 被改写（源为 0 时 ZF=1、结果定为 0）
		v := x & m
		if v == 0 {
			s.Flags |= FlagZ
			return 0
		}
		s.Flags &^= FlagZ
		if kind == KBsf {
			if width >= 64 {
				return uint64(bits.TrailingZeros64(v)) & m
			}
			return uint64(bits.TrailingZeros32(uint32(v))) & m
		}
		if width >= 64 {
			return uint64(63-bits.LeadingZeros64(v)) & m
		}
		return uint64(31-bits.LeadingZeros32(uint32(v))) & m
	case KBt:
		// x86 BT：把 a 的第 (b mod width) 位送进 CF，其它标志位保持不变
		n := uint(y & uint64(width-1))
		bit := (x >> n) & 1
		if bit == 1 {
			s.Flags = (s.Flags &^ FlagC) | FlagC
		} else {
			s.Flags &^= FlagC
		}
		return 0
	case KDivU, KDivS:
		// x86 单操作数 DIV/IDIV：被除数是隐含的 DX:AX 族（8 位是 AH:AL），商→AX 族、余→DX 族。
		// 返回单值的形状装不下两个输出，所以这里直接写 s.Regs；
		// 除零 / 商溢出按 x86 的 #DE 语义 —— 用 panic 表示（宁可响亮失败，也不要静默给错值）。
		// 正常情况下 div 由 OpAluU 分支直接处理（见上面）；走到 aluApply 说明路由错了 ——
		// 这里刻意 panic，绝不让它静默产生错值。
		panic("ref: KDivU/KDivS 不该走 aluApply（它们由 OpAluU 分支直接处理）")
	case KMulHiS:
		// 单操作数 IMUL 的高半（有符号）；CF=OF 表示高半不是低半的符号扩展
		mm := widthMask(width)
		var lo, hi uint64
		if width >= 64 {
			ai, bi := int64(x), int64(y)
			uh, ul := bits.Mul64(uint64(ai), uint64(bi))
			s := uh
			if ai < 0 {
				s -= uint64(bi)
			}
			if bi < 0 {
				s -= uint64(ai)
			}
			lo, hi = ul, s
		} else {
			p := int64(signExtendW(x, width)) * int64(signExtendW(y, width))
			lo = uint64(p) & mm
			hi = (uint64(p) >> width) & mm
		}
		var want uint64
		if int64(signExtendW(lo, width)) < 0 {
			want = mm
		}
		var f uint32
		if lo == 0 {
			f |= FlagZ
		}
		if lo&(mm^(mm>>1)) != 0 {
			f |= FlagN
		}
		if hi != want {
			f |= FlagC | FlagV
		}
		s.Flags = f | parityFlag(lo)
		return lo & mm
	case KMulHi:
		// MUL 的高半：CF=OF=(高半!=0)（x86 语义），其余标志位按高半算（硬件未定义）
		var hi uint64
		if width >= 64 {
			hi, _ = bits.Mul64(x, y)
		} else {
			hi = ((x & m) * (y & m)) >> width
		}
		var nf uint32
		if hi != 0 {
			nf |= FlagC | FlagV
		}
		s.Flags = nf | flagsLogic(hi, width)
		return hi & m
	case KAdc:
		cin := uint32(0)
		if s.Flags&FlagC != 0 {
			cin = 1
		}
		// 注意：ARM64 lifter 目前不会发出 ADC/SBB（它的 ADC/SBC 语义按 C=无借位解释），
		// 所以这里只实现 x86-64 客户机的语义。
		r = x + y + uint64(cin)
		s.Flags = flagsAdc(x, y, cin, r, width)
	case KSbb:
		cin := uint32(0)
		if s.Flags&FlagC != 0 {
			cin = 1
		}
		r = x - y - uint64(cin)
		s.Flags = flagsSbb(x, y, cin, r, width)
	case KSub:
		r = x - y
		if arm {
			s.Flags = arm64sem.FlagsSub(x, y, r, width)
		} else {
			s.Flags = flagsSub(x, y, r, width)
		}
	case KAnd:
		r = x & y
		if arm {
			s.Flags = arm64sem.FlagsLogic(r, width)
		} else {
			s.Flags = flagsLogic(r, width)
		}
	case KOr:
		r = x | y
		if arm {
			s.Flags = arm64sem.FlagsLogic(r, width)
		} else {
			s.Flags = flagsLogic(r, width)
		}
	case KXor:
		r = x ^ y
		if arm {
			s.Flags = arm64sem.FlagsLogic(r, width)
		} else {
			s.Flags = flagsLogic(r, width)
		}
	case KMul:
		r = uint64(signExtendW(x, width) * signExtendW(y, width))
		if arm {
			s.Flags = arm64sem.FlagsMul(r, width)
		} else {
			s.Flags = flagsMul(x, y, r, width)
		}
	case KShl, KShr, KSar:
		cnt := uint32(y & uint64(width-1))
		if cnt == 0 {
			return a
		}
		switch kind {
		case KShl:
			r = x << cnt
		case KShr:
			r = x >> cnt
		default:
			r = uint64(signExtendW(x, width) >> cnt)
		}
		if arm {
			lastOut := (x >> (width - cnt)) & 1
			s.Flags = arm64sem.FlagsShift(r, lastOut, width, cnt, s.Flags)
		} else {
			s.Flags = flagsShift(x, r, width, kind, cnt)
		}
	case KRol:
		cnt := uint32(y & uint64(width-1))
		if cnt == 0 {
			return a
		}
		r = ((x << cnt) | (x >> ((width - cnt) & (width - 1)))) & m
		if arm {
			s.Flags = arm64sem.FlagsLogic(r, width)
		} else {
			s.Flags = flagsLogic(r, width)
			if r&1 != 0 {
				s.Flags |= FlagC
			}
		}
	case KRor:
		cnt := uint32(y & uint64(width-1))
		if cnt == 0 {
			return a
		}
		r = ((x >> cnt) | (x << ((width - cnt) & (width - 1)))) & m
		if arm {
			s.Flags = arm64sem.FlagsLogic(r, width)
		} else {
			s.Flags = flagsLogic(r, width)
			if r&(uint64(1)<<(width-1)) != 0 {
				s.Flags |= FlagC
			}
		}
	}
	return r & m
}

func (s *RefState) aluUnary(kind, width uint32, a uint64) uint64 {
	keep := kind&AluKeepFlags != 0
	saved := s.Flags
	defer func() {
		if keep {
			s.Flags = saved
		}
	}()
	kind = kind &^ AluKeepFlags
	switch kind {
	case KUNeg:
		return s.aluApply(KSub, width, 0, a)
	case KUNot:
		// NOT / MVN 本身不改变标志位（x86 的 NOT 如此；ARM64 的 MVN = ORN 由
		// 随后的逻辑运算设置标志位，lifter 会那样发射）——保持客户机无关。
		return (^a) & widthMask(width)
	case KUInc:
		return s.aluApply(KAdd, width, a, 1)
	default:
		return s.aluApply(KSub, width, a, 1)
	}
}

func (s *RefState) writeReg(r, width uint32, val uint64) {
	// ARM64 客户机的槽位 34 是 ZR（XZR/WZR）：**只读**，写入被忽略。
	if s.Guest == GuestARM64 && r == 34 {
		return
	}
	if r >= RefMaxRegs {
		return // 畸形字节码防御（真正的保证在 codegen）
	}
	if width >= 64 {
		s.Regs[r] = val
		return
	}
	if width == 32 {
		s.Regs[r] = val & 0xFFFFFFFF
		return
	}
	m := widthMask(width)
	s.Regs[r] = (s.Regs[r] &^ m) | (val & m)
}

// ucomiFlags 按 SDM 的 UCOMISD/COMISD 表设置 ZF/PF/CF
func ucomiFlags(less, equal, unordered bool) uint32 {
	if unordered {
		return FlagZ | FlagP | FlagC
	}
	if less {
		return FlagC
	}
	if equal {
		return FlagZ
	}
	return 0
}

// cvtFloatToInt64 模拟 x86 的 CVTTSD2SI：超出范围给不定值 0x8000000000000000
func cvtFloatToInt64(f float64) int64 {
	if f != f || f >= 9223372036854775808.0 || f < -9223372036854775808.0 {
		return -9223372036854775808
	}
	return int64(f)
}

func (s *RefState) condHolds(cond uint32) bool {
	if s.Guest == GuestARM64 {
		return arm64sem.CondHolds(cond, s.Flags)
	}
	f := s.Flags
	z := f&FlagZ != 0
	n := f&FlagN != 0
	c := f&FlagC != 0
	v := f&FlagV != 0
	p := f&FlagP != 0
	switch cond & 15 {
	case 0:
		return v
	case 1:
		return !v
	case 2:
		return c
	case 3:
		return !c
	case 4:
		return z
	case 5:
		return !z
	case 6:
		return c || z
	case 7:
		return !c && !z
	case 8:
		return n
	case 9:
		return !n
	case 10:
		return p
	case 11:
		return !p
	case 12:
		return n != v
	case 13:
		return n == v
	case 14:
		return z || (n != v)
	default:
		return !z && (n == v)
	}
}

func (s *RefState) load(addr uint64, width uint32) (uint64, error) {
	if addr < s.BufBase || addr+uint64(width/8) > s.BufBase+s.BufSize {
		return 0, fmt.Errorf("参考实现拒绝越界读: 0x%X (w=%d)", addr, width)
	}
	var v uint64
	for i := uint32(0); i < width/8; i++ {
		v |= uint64(s.Mem[addr+uint64(i)]) << (8 * i)
	}
	return v, nil
}

func (s *RefState) store(addr uint64, width uint32, v uint64) error {
	if addr < s.BufBase || addr+uint64(width/8) > s.BufBase+s.BufSize {
		return fmt.Errorf("参考实现拒绝越界写: 0x%X (w=%d)", addr, width)
	}
	for i := uint32(0); i < width/8; i++ {
		s.Mem[addr+uint64(i)] = byte(v >> (8 * i))
	}
	return nil
}

// Run 执行字节码，返回 rc（0=RET，1=HALT/错误/步数超限）
func (s *RefState) Run(code []byte, maxSteps int) (int, error) {
	pc := uint32(0)
	rd32 := func(off uint32) uint32 {
		return uint32(code[off]) | uint32(code[off+1])<<8 | uint32(code[off+2])<<16 | uint32(code[off+3])<<24
	}
	rd64 := func(off uint32) uint64 {
		return uint64(rd32(off)) | uint64(rd32(off+4))<<32
	}
	for step := 0; step < maxSteps; step++ {
		if pc >= uint32(len(code)) {
			return 1, nil
		}
		op, ok := s.Map.Decode(code[pc])
		if !ok {
			return 1, fmt.Errorf("未知操作码 0x%02X @+0x%X", code[pc], pc)
		}
		_ = ok
		switch op {
		case OpHalt:
			return 1, nil
		case OpNop:
			pc++
		case OpRet:
			return 0, nil
		case OpMovRR:
			s.writeReg(uint32(code[pc+2]), uint32(code[pc+1]), s.Regs[code[pc+3]])
			pc += 4
		case OpMovRI:
			s.writeReg(uint32(code[pc+2]), uint32(code[pc+1]), rd64(pc+3))
			pc += 11
		case OpMovRI32:
			s.Regs[code[pc+1]] = uint64(rd32(pc + 2))
			pc += 6
		case OpLea:
			width := uint32(code[pc+1])
			dst := code[pc+2]
			base, idx := code[pc+3], code[pc+4]
			scale := uint64(code[pc+5])
			disp := int64(int32(rd32(pc + 6)))
			addr := uint64(disp)
			if base != 0xFF {
				addr += s.Regs[base]
			}
			if idx != 0xFF {
				addr += s.Regs[idx] * scale
			}
			s.writeReg(uint32(dst), width, addr)
			pc += 10
		case OpAluRR:
			kind, width := uint32(code[pc+1]), uint32(code[pc+2])
			dst := code[pc+3]
			a, b := s.Regs[code[pc+4]], s.Regs[code[pc+5]]
			s.writeReg(uint32(dst), width, s.aluApply(kind, width, a, b))
			pc += 6
		case OpAluRI:
			kind, width := uint32(code[pc+1]), uint32(code[pc+2])
			// 注意：立即数的符号扩展判断必须**屏蔽 KeepFlags 位**，
			// 否则带 keep-flags 的 ADD/SUB 会被当成"零扩展立即数"（负偏移会变成 +2^32）
			kindCore := kind &^ AluKeepFlags
			dst := code[pc+3]
			a := s.Regs[code[pc+4]]
			raw := rd32(pc + 5)
			var b uint64
			if kindCore == KAdd || kindCore == KSub || kindCore == KMul || kindCore == KAdc || kindCore == KSbb {
				b = uint64(int64(int32(raw)))
			} else {
				b = uint64(raw)
			}
			s.writeReg(uint32(dst), width, s.aluApply(kind, width, a, b))
			pc += 9
		case OpAluU:
			kind, width := uint32(code[pc+1]), uint32(code[pc+2])
			dst := code[pc+3]
			a := s.Regs[code[pc+4]]
			// DIV/IDIV 复用 AluU 的编码，但语义是"隐含寄存器 + 双输出"，走不了 aluUnary。
			// 之前漏了这一支 ⇒ 参考执行器会静默算出错值（正是我们要消灭的失败模式）。
			if k := kind &^ AluKeepFlags; k == KDivU || k == KDivS {
				refDiv(s, k, a, width)
				pc += 5
				break
			}
			s.writeReg(uint32(dst), width, s.aluUnary(kind, width, a))
			pc += 5
		case OpCmpRR:
			kind, width := uint32(code[pc+1]), uint32(code[pc+2])
			m := widthMask(width)
			x := s.Regs[code[pc+3]] & m
			y := s.Regs[code[pc+4]] & m
			if kind == KTest {
				s.Flags = flagsLogic(x&y, width)
			} else {
				s.Flags = flagsSub(x, y, x-y, width)
			}
			pc += 5
		case OpCmpRI:
			kind, width := uint32(code[pc+1]), uint32(code[pc+2])
			m := widthMask(width)
			x := s.Regs[code[pc+3]] & m
			raw := rd32(pc + 4)
			var y uint64
			if kind == KTest {
				y = uint64(raw)
			} else {
				y = uint64(int64(int32(raw)))
			}
			y &= m
			if kind == KTest {
				s.Flags = flagsLogic(x&y, width)
			} else {
				s.Flags = flagsSub(x, y, x-y, width)
			}
			pc += 8
		case OpExt:
			kind, srcw := uint32(code[pc+1]), uint32(code[pc+2])
			dst := code[pc+3]
			v := s.Regs[code[pc+4]]
			if kind == 1 {
				s.Regs[dst] = uint64(signExtendW(v, srcw))
			} else {
				s.Regs[dst] = v & widthMask(srcw)
			}
			pc += 5
		case OpLoad:
			kind, width := uint32(code[pc+1]), uint32(code[pc+2])
			dst := code[pc+3]
			base, idx := code[pc+4], code[pc+5]
			scale := uint64(code[pc+6])
			disp := int64(int32(rd32(pc + 7)))
			addr := s.Regs[base] + uint64(disp)
			if idx != 0xFF {
				addr += s.Regs[idx] * scale
			}
			v, err := s.load(addr, width)
			if err != nil {
				return 1, err
			}
			if kind == 1 {
				s.Regs[dst] = uint64(signExtendW(v, width))
			} else {
				s.Regs[dst] = v & widthMask(width)
			}
			pc += 11
		case OpStore:
			width := uint32(code[pc+1])
			base, idx := code[pc+2], code[pc+3]
			scale := uint64(code[pc+4])
			disp := int64(int32(rd32(pc + 5)))
			src := code[pc+9]
			addr := s.Regs[base] + uint64(disp)
			if idx != 0xFF {
				addr += s.Regs[idx] * scale
			}
			if err := s.store(addr, width, s.Regs[src]); err != nil {
				return 1, err
			}
			pc += 10
		case OpFp:
			// 浮点标量：操作数是相对 VMBASE 的偏移（Disp=目标、Imm=第一操作数、Imm2=第二操作数）
			fk := uint32(code[pc+1])
			fw := uint32(code[pc+2])
			dstOff := uint64(rd32(pc + 3))
			aOff := uint64(rd32(pc + 7))
			bOff := uint64(rd32(pc + 11))
			vbase := s.Regs[16]
			abits, aerr := s.load(vbase+aOff, fw)
			if aerr != nil {
				return 1, aerr
			}
			var bbits uint64
			if bOff != 0 {
				var berr error
				bbits, berr = s.load(vbase+bOff, fw)
				if berr != nil {
					return 1, berr
				}
			}
			store := func(bits uint64) error { return s.store(vbase+dstOff, fw, bits) }
			if fw == 32 {
				af := math.Float32frombits(uint32(abits))
				bf := math.Float32frombits(uint32(bbits))
				var r float32
				switch fk {
				case KFAdd:
					r = af + bf
				case KFSub:
					r = af - bf
				case KFMul:
					r = af * bf
				case KFDiv:
					r = af / bf
				case KFMin:
					if af < bf {
						r = af
					} else {
						r = bf
					}
				case KFMax:
					if af > bf {
						r = af
					} else {
						r = bf
					}
				case KFSqrt:
					r = float32(math.Sqrt(float64(af)))
				case KFCvtsi2f:
					r = float32(int64(abits))
				case KFCvttf2si:
					if serr := s.store(vbase+dstOff, 64, uint64(cvtFloatToInt64(float64(af)))); serr != nil {
						return 1, serr
					}
					pc += 15
					continue
				case KFUcomi:
					s.Flags = (s.Flags &^ (FlagZ | FlagP | FlagC | FlagN | FlagV)) | ucomiFlags(af < bf, af == bf, af != af || bf != bf)
					pc += 15
					continue
				}
				if serr := store(uint64(math.Float32bits(r))); serr != nil {
					return 1, serr
				}
			} else {
				af := math.Float64frombits(abits)
				bf := math.Float64frombits(bbits)
				var r float64
				switch fk {
				case KFAdd:
					r = af + bf
				case KFSub:
					r = af - bf
				case KFMul:
					r = af * bf
				case KFDiv:
					r = af / bf
				case KFMin:
					if af < bf {
						r = af
					} else {
						r = bf
					}
				case KFMax:
					if af > bf {
						r = af
					} else {
						r = bf
					}
				case KFSqrt:
					r = math.Sqrt(af)
				case KFCvtsi2f:
					r = float64(int64(abits))
				case KFCvttf2si:
					if serr := s.store(vbase+dstOff, 64, uint64(cvtFloatToInt64(af))); serr != nil {
						return 1, serr
					}
					pc += 15
					continue
				case KFUcomi:
					s.Flags = (s.Flags &^ (FlagZ | FlagP | FlagC | FlagN | FlagV)) | ucomiFlags(af < bf, af == bf, af != af || bf != bf)
					pc += 15
					continue
				}
				if serr := store(math.Float64bits(r)); serr != nil {
					return 1, serr
				}
			}
			pc += 15
		case OpAtomic:
			// 参考实现是单线程的：语义与 C 侧一致（真正的原子性由 E2E 的多线程用例覆盖）
			ak := uint32(code[pc+1]) &^ AluKeepFlags
			keep := uint32(code[pc+1])&AluKeepFlags != 0
			aw := uint32(code[pc+2])
			dst := code[pc+3]
			src := code[pc+4]
			base := code[pc+5]
			idx := code[pc+6]
			scale := uint32(code[pc+7])
			disp := int32(rd32(pc + 8))
			addr := s.Regs[base] + uint64(int64(disp))
			if idx != 0xFF {
				addr += s.Regs[idx] * uint64(scale)
			}
			saved := s.Flags
			old, lerr := s.load(addr, aw)
			if lerr != nil {
				return 1, lerr
			}
			mask := widthMask(aw)
			sv := s.Regs[src] & mask
			switch ak {
			case KAXchg:
				if serr := s.store(addr, aw, sv); serr != nil {
					return 1, serr
				}
				if dst != 0xFF {
					s.Regs[dst] = old & mask
				}
			case KACmpxchg:
				if s.Regs[4]&mask == old { // 4 = RAX
					if serr := s.store(addr, aw, sv); serr != nil {
						return 1, serr
					}
					s.Flags |= FlagZ
				} else {
					s.Flags &^= FlagZ
					s.Regs[4] = old & mask
				}
			default:
				var res uint64
				switch ak {
				case KAAdd:
					res = old + sv
					s.Flags = flagsAdd(old, sv, res, aw)
				case KASub:
					res = old - sv
					s.Flags = flagsSub(old, sv, res, aw)
				case KAAnd:
					res = old & sv
					s.Flags = flagsLogic(res, aw)
				case KAOr:
					res = old | sv
					s.Flags = flagsLogic(res, aw)
				case KAXor:
					res = old ^ sv
					s.Flags = flagsLogic(res, aw)
				case KAInc:
					res = old + 1
					s.Flags = flagsAdd(old, 1, res, aw)
				case KADec:
					res = old - 1
					s.Flags = flagsSub(old, 1, res, aw)
				}
				if serr := s.store(addr, aw, res); serr != nil {
					return 1, serr
				}
				if dst != 0xFF {
					s.Regs[dst] = old & mask
				}
			}
			if keep {
				s.Flags = saved
			}
			pc += 12
		case OpPushR:
			r := code[pc+1]
			slot := s.stackSlotBits()
			s.Regs[4] -= uint64(slot / 8)
			// 注意：load/store 的 width 单位是**位**（内部按 width/8 取字节数），
			// 这里曾误传 8 → 只压了 1 个字节（“压栈 8 字节”退化成 1 字节）。
			if err := s.store(s.Regs[4], slot, s.Regs[r]); err != nil {
				return 1, err
			}
			pc += 2
		case OpPushI:
			slot := s.stackSlotBits()
			s.Regs[4] -= uint64(slot / 8)
			if err := s.store(s.Regs[4], slot, uint64(int64(int32(rd32(pc+1))))); err != nil {
				return 1, err
			}
			pc += 5
		case OpPopR:
			r := code[pc+1]
			slot := s.stackSlotBits()
			v, err := s.load(s.Regs[4], slot)
			if err != nil {
				return 1, err
			}
			s.Regs[4] += uint64(slot / 8)
			s.Regs[r] = v
			pc += 2
		case OpJbz, OpJbnz:
			// 按寄存器是否为零分支，**不修改标志位**（ARM64 的 CBZ/TBZ 语义）
			r := code[pc+1]
			isZero := s.Regs[r] == 0
			take := isZero
			if op == OpJbnz {
				take = !isZero
			}
			if take {
				pc = rd32(pc + 2)
			} else {
				pc += 6
			}
		case OpJcc:
			cond := uint32(code[pc+1])
			if s.condHolds(cond) {
				pc = rd32(pc + 2)
			} else {
				pc += 6
			}
		case OpJmp:
			pc = rd32(pc + 1)
		case OpCallN, OpCallR:
			return 1, fmt.Errorf("参考实现不支持 CALL（由 E2E 覆盖）")
		default:
			return 1, fmt.Errorf("参考实现遇到未知操作码 0x%02X", op)
		}
	}
	return 1, fmt.Errorf("步数超过 %d（疑似死循环）", maxSteps)
}

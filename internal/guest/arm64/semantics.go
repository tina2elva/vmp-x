// Package arm64 提供 ARM64 客户机语义的 Go 参考实现。
//
// 它存在的唯一目的：与 stub/arm64/guest_semantics_arm64.c（会被编译进 blob 的 C 实现）
// 做**大规模对拍**。ARM64 的 C 位语义与 x86-64 相反（C=1 表示无借位），移位类指令的
// C/V 规则也与 x86 不同——这些是最容易写错、又最难在端到端里暴露的部分。
package arm64

// 标志位（与 C 侧一致；bit4 = PF 只属于 x86-64 客户机）
const (
	FlagN uint32 = 1
	FlagZ uint32 = 2
	FlagC uint32 = 4
	FlagV uint32 = 8
)

// MaskW 宽度掩码
func MaskW(w uint32) uint64 {
	if w >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << w) - 1
}

func nz(r uint64, w uint32) uint32 {
	var f uint32
	if r&MaskW(w) == 0 {
		f |= FlagZ
	}
	if r&(uint64(1)<<(w-1)) != 0 {
		f |= FlagN
	}
	return f
}

// FlagsAdd：C = 无符号进位，V = 有符号溢出
func FlagsAdd(a, b, r uint64, w uint32) uint32 {
	m := MaskW(w)
	sign := uint64(1) << (w - 1)
	f := nz(r, w)
	ua, ub := a&m, b&m
	if w >= 64 {
		if r < ua {
			f |= FlagC
		}
	} else if ua+ub > m {
		f |= FlagC
	}
	if (^(a ^ b) & (a ^ r) & sign) != 0 {
		f |= FlagV
	}
	return f
}

// FlagsSub：C = 无借位（a >= b），V = 有符号溢出
func FlagsSub(a, b, r uint64, w uint32) uint32 {
	m := MaskW(w)
	sign := uint64(1) << (w - 1)
	f := nz(r, w)
	if a&m >= b&m {
		f |= FlagC
	}
	if ((a ^ b) & (a ^ r) & sign) != 0 {
		f |= FlagV
	}
	return f
}

// FlagsLogic：逻辑运算只影响 N/Z
func FlagsLogic(r uint64, w uint32) uint32 { return nz(r, w) }

// FlagsMul：乘法只影响 N/Z（低位结果）
func FlagsMul(r uint64, w uint32) uint32 { return nz(r, w) }

// FlagsShift：cnt==0 时 C 不变；否则 C = 最后移出的位；V 永远不变
func FlagsShift(r, lastBitOut uint64, w, cnt, oldFlags uint32) uint32 {
	f := nz(r, w) | (oldFlags & FlagV)
	if cnt == 0 {
		f |= oldFlags & FlagC
	} else if lastBitOut&1 != 0 {
		f |= FlagC
	}
	return f
}

// CondHolds 判断条件码是否成立（0..13 为实际条件，14/15 视为 AL）
func CondHolds(cond, f uint32) bool {
	n := f&FlagN != 0
	z := f&FlagZ != 0
	c := f&FlagC != 0
	v := f&FlagV != 0
	switch cond & 15 {
	case 0:
		return z
	case 1:
		return !z
	case 2:
		return c
	case 3:
		return !c
	case 4:
		return n
	case 5:
		return !n
	case 6:
		return v
	case 7:
		return !v
	case 8:
		return c && !z
	case 9:
		return !c || z
	case 10:
		return n == v
	case 11:
		return n != v
	case 12:
		return !z && (n == v)
	case 13:
		return z || (n != v)
	default:
		return true
	}
}

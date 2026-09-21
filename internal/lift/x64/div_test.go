package x64

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// DIV/IDIV 的差分测试：随机（且**构造合法**，即商放得下）的操作数下，
// 用 math/big 独立算出商/余，再与 lift 出来的字节码在参考执行器上跑出的 RDX:RAX 比对。
// 8 位形式走 AH:AL（被除数 = RAX 低 16 位），16/32/64 位走 DX:AX 族。
func TestLiftDivDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(20260203))
	for _, w := range []uint32{8, 16, 32, 64} {
		divCode := liftOneInsn(t, divEncoding(w, false))
		idivCode := liftOneInsn(t, divEncoding(w, true))
		mod := new(big.Int).Lsh(big.NewInt(1), uint(w))
		mask := new(big.Int).Sub(mod, big.NewInt(1))

		// ---- 无符号 DIV：构造 dividend = q*dv + r（r < dv），保证不触发 #DE ----
		for iter := 0; iter < 300; iter++ {
			dv := new(big.Int).Rand(rng, mod)
			if dv.Sign() == 0 {
				dv.SetInt64(1)
			}
			q := new(big.Int).Rand(rng, mod)
			r := new(big.Int).Rand(rng, dv)
			n := new(big.Int).Mul(q, dv)
			n.Add(n, r)
			st := newDivState(w, n, dv)
			if rc, err := st.Run(divCode, 64); err != nil || rc != 0 {
				t.Fatalf("DIV w=%d: 执行失败 rc=%d err=%v", w, rc, err)
			}
			gotQ, gotR := divResult(st, w)
			if gotQ.Cmp(q) != 0 || gotR.Cmp(r) != 0 {
				t.Fatalf("DIV w=%d rng=%d: n=%v dv=%v → q=%v r=%v，期望 q=%v r=%v",
					w, iter, n, dv, gotQ, gotR, q, r)
			}
		}

		// ---- 有符号 IDIV：随机取被除数与除数，商放不下就跳过（拒绝采样）----

		half := new(big.Int).Rsh(mod, 1)
		loLim := new(big.Int).Neg(half)
		hiLim := new(big.Int).Sub(half, big.NewInt(1))
		twoW := new(big.Int).Lsh(big.NewInt(1), uint(2*w))
		for iter := 0; iter < 300; iter++ {
			nRaw := new(big.Int).Rand(rng, twoW)
			n := twosSigned(nRaw, 2*w)
			dvRaw := new(big.Int).Rand(rng, mod)
			dv := twosSigned(dvRaw, w)
			if dv.Sign() == 0 {
				continue
			}
			q, r := new(big.Int), new(big.Int)
			q.QuoRem(n, dv, r)
			if q.Cmp(loLim) < 0 || q.Cmp(hiLim) > 0 {
				continue // 真机上这条会 #DE，跳过
			}
			st := newDivState(w, nRaw, dvRaw)
			if rc, err := st.Run(idivCode, 64); err != nil || rc != 0 {
				t.Fatalf("IDIV w=%d: 执行失败 rc=%d err=%v", w, rc, err)
			}
			gotQ, gotR := divResult(st, w)
			wantQ := new(big.Int).And(q, mask)
			wantR := new(big.Int).And(r, mask)
			if gotQ.Cmp(wantQ) != 0 || gotR.Cmp(wantR) != 0 {
				t.Fatalf("IDIV w=%d rng=%d: n=%v dv=%v → q=%v r=%v，期望 q=%v r=%v",
					w, iter, n, dv, gotQ, gotR, wantQ, wantR)
			}
		}
	}
}

// #DE 兩種：除零、商放不下 —— 都必须 panic，绝不静默给错值。
func TestLiftDivFaults(t *testing.T) {
	for _, w := range []uint32{8, 16, 32, 64} {
		// 除零
		divBC := liftOneInsn(t, divEncoding(w, false))
		st := newDivState(w, big.NewInt(1), big.NewInt(0))
		if !panics(func() { _, _ = st.Run(divBC, 64) }) {
			t.Fatalf("w=%d: 除零应当 panic", w)
		}
		// 商溢出：被除数 = 2^w（放不进 w 位），除数 = 1
		big1 := new(big.Int).Lsh(big.NewInt(1), uint(w))
		st2 := newDivState(w, big1, big.NewInt(1))
		if !panics(func() { _, _ = st2.Run(divBC, 64) }) {
			t.Fatalf("w=%d: 商溢出应当 panic", w)
		}
	}
}

func panics(f func()) (p bool) {
	defer func() {
		if recover() != nil {
			p = true
		}
	}()
	f()
	return false
}

// divEncoding 给出 "div/idiv r/m" + ret 的机器码：rcx 家族（8 位是 CL）。
func divEncoding(w uint32, signed bool) []byte {
	reg := byte(0x06) // /6 = DIV
	if signed {
		reg = 0x07 // /7 = IDIV
	}
	modrm := byte(0xC0) | (reg << 3) | 0x01 // mod=11, rm=001(rcx/cl)
	switch w {
	case 8:
		return []byte{0xF6, modrm, 0xC3}
	case 16:
		return []byte{0x66, 0xF7, modrm, 0xC3}
	case 32:
		return []byte{0xF7, modrm, 0xC3}
	default:
		return []byte{0x48, 0xF7, modrm, 0xC3}
	}
}

// newDivState 按 x86 的隐含寄存器布局摆好被除数：8 位放 RAX 低 16 位，其余放 DX:AX 族。
func newDivState(w uint32, dividend, divisor *big.Int) *vm.RefState {
	st := &vm.RefState{Guest: vm.GuestX86, Mem: map[uint64]byte{}}
	st.Regs[ir.RAX] = 0xDEAD0000_00000000 // 高位哨兵：8/16 位局部写不该动它（32 位会按 x86 零扩展）
	st.Regs[ir.RCX] = divisor.Uint64()
	if w == 8 {
		st.Regs[ir.RAX] = (st.Regs[ir.RAX] &^ 0xFFFF) | (dividend.Uint64() & 0xFFFF)
		st.Regs[ir.RAX] = (0xDEAD0000_00000000) | (dividend.Uint64() & 0xFFFF)
	} else {
		m := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(w)), big.NewInt(1))
		lo := new(big.Int).And(dividend, m)
		hi := new(big.Int).Rsh(dividend, uint(w))
		st.Regs[ir.RAX] = lo.Uint64()
		st.Regs[ir.RDX] = hi.Uint64()
	}
	return st
}

// divResult 取回商/余（8 位在 AH:AL；16 位在 AX/DX 的低 16 位；32/64 位按位宽取）。
func divResult(st *vm.RefState, w uint32) (*big.Int, *big.Int) {
	if w == 8 {
		v := st.Regs[ir.RAX] & 0xFFFF
		return big.NewInt(int64(v & 0xFF)), big.NewInt(int64((v >> 8) & 0xFF))
	}
	if w == 16 {
		return big.NewInt(int64(st.Regs[ir.RAX] & 0xFFFF)), big.NewInt(int64(st.Regs[ir.RDX] & 0xFFFF))
	}
	if w == 32 {
		return big.NewInt(int64(st.Regs[ir.RAX] & 0xFFFFFFFF)), big.NewInt(int64(st.Regs[ir.RDX] & 0xFFFFFFFF))
	}
	return new(big.Int).SetUint64(st.Regs[ir.RAX]), new(big.Int).SetUint64(st.Regs[ir.RDX])
}

// twosSigned 把 width 位的补码值解释成有符号。**不修改入参** ——
// 之前这里就地改了入参，导致后面写进寄存器的"原始位模式"变成了负数的绝对值（测试自己出的错）。
func twosSigned(v *big.Int, width uint32) *big.Int {
	w := new(big.Int).Lsh(big.NewInt(1), uint(width))
	half := new(big.Int).Rsh(w, 1)
	out := new(big.Int).Set(v)
	if out.Cmp(half) >= 0 {
		out.Sub(out, w)
	}
	return out
}

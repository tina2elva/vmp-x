package x64

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// refFlags 用 math/big 独立算出 x86 的 ADC/SBB 结果与标志位（Z/N/C/V），
// 与 VM 逐位比对——公式写错一定会被抓到。
type refOut struct {
	r          *big.Int
	z, n, c, v bool
}

func refAdcSbb(aU, bU *big.Int, cin uint32, w uint32, sub bool) refOut {
	one := big.NewInt(1)
	mod := new(big.Int).Lsh(one, uint(w))
	half := new(big.Int).Lsh(one, uint(w-1))
	// 按 w 位补码解释
	signed := func(x *big.Int) *big.Int {
		v := new(big.Int).Mod(x, mod)
		if v.Cmp(half) >= 0 {
			v.Sub(v, mod)
		}
		return v
	}
	c := big.NewInt(int64(cin))
	var res, exact *big.Int
	var carry bool
	if sub {
		res = new(big.Int).Sub(aU, bU)
		res.Sub(res, c)
		carry = res.Sign() < 0 // 需要借位
		exact = new(big.Int).Sub(signed(aU), signed(bU))
		exact.Sub(exact, c)
	} else {
		res = new(big.Int).Add(aU, bU)
		res.Add(res, c)
		carry = res.Cmp(mod) >= 0 // 无符号溢出 → 进位
		exact = new(big.Int).Add(signed(aU), signed(bU))
		exact.Add(exact, c)
	}
	r := new(big.Int).Mod(res, mod)
	z := r.Sign() == 0
	n := r.Cmp(half) >= 0
	lo := new(big.Int).Neg(half)
	hi := new(big.Int).Sub(half, one)
	v := exact.Cmp(lo) < 0 || exact.Cmp(hi) > 0
	return refOut{r: r, z: z, n: n, c: carry, v: v}
}

func TestLiftAdcSbbDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(20260101))
	widths := []uint32{8, 16, 32, 64}
	for _, w := range widths {
		// 按宽度手写"adc/sbb r/m, r"的寄存器形式（%cl → %al 家族）
		var adc, sbb []byte
		switch w {
		case 8:
			adc, sbb = []byte{0x10, 0xC8}, []byte{0x18, 0xC8} // adc %cl,%al / sbb %cl,%al
		case 16:
			adc, sbb = []byte{0x66, 0x11, 0xC8}, []byte{0x66, 0x19, 0xC8}
		case 32:
			adc, sbb = []byte{0x11, 0xC8}, []byte{0x19, 0xC8}
		default:
			adc, sbb = []byte{0x48, 0x11, 0xC8}, []byte{0x48, 0x19, 0xC8}
		}
		for _, tc := range []struct {
			name string
			code []byte
			sub  bool
		}{{"adc", adc, false}, {"sbb", sbb, true}} {
			bc := liftOneInsn(t, tc.code)
			for iter := 0; iter < 400; iter++ {
				limit := new(big.Int).Lsh(big.NewInt(1), uint(w))
				av := new(big.Int).Rand(rng, limit)
				bv := new(big.Int).Rand(rng, limit)
				cin := uint32(rng.Intn(2))
				a := av.Uint64()
				b := bv.Uint64()
				st := &vm.RefState{Guest: vm.GuestX86, Mem: map[uint64]byte{}}
				st.Regs[ir.RAX] = a
				st.Regs[ir.RCX] = b
				if cin == 1 {
					st.Flags = vm.FlagC
				}
				if rc, err := st.Run(bc, 64); err != nil || rc != 0 {
					t.Fatalf("%s: 执行失败 rc=%d err=%v", tc.name, rc, err)
				}
				got := st.Regs[ir.RAX]
				want := refAdcSbb(av, bv, cin, w, tc.sub)
				// 只比低 w 位（8/16 位形式在 x86 里是部分寄存器写，这里统一按 64 位形式比低 w 位）
				mask := new(big.Int).Sub(limit, big.NewInt(1))
				gm := new(big.Int).And(new(big.Int).SetUint64(got), mask)
				if gm.Cmp(want.r) != 0 {
					t.Fatalf("%s w=%d a=0x%X b=0x%X cin=%d: 结果 0x%X，参考 0x%X",
						tc.name, w, a, b, cin, gm, want.r)
				}
				// 标志位：C/V/N 必须一致（Z 与宽度相关，这里只查 C/V）
				if (st.Flags&vm.FlagC != 0) != want.c {
					t.Fatalf("%s w=%d a=0x%X b=0x%X cin=%d: CF=%v，参考=%v",
						tc.name, w, a, b, cin, st.Flags&vm.FlagC != 0, want.c)
				}
				if (st.Flags&vm.FlagV != 0) != want.v {
					t.Fatalf("%s w=%d a=0x%X b=0x%X cin=%d: OF=%v，参考=%v",
						tc.name, w, a, b, cin, st.Flags&vm.FlagV != 0, want.v)
				}
				if (st.Flags&vm.FlagN != 0) != want.n {
					t.Fatalf("%s w=%d a=0x%X b=0x%X cin=%d: SF=%v，参考=%v",
						tc.name, w, a, b, cin, st.Flags&vm.FlagN != 0, want.n)
				}
			}
		}
	}
}

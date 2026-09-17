package x64

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// MUL 的差分测试：随机操作数下比对 RDX:RAX 与 CF/OF（CF=OF=(高半!=0)），
// 参考实现用 math/big 独立算出 128 位乘积。
func TestLiftMulDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(20260202))
	for _, w := range []uint32{32, 64} {
		var code []byte
		if w == 64 {
			code = []byte{0x48, 0xF7, 0xE1, 0xC3} // mul %rcx ; ret
		} else {
			code = []byte{0xF7, 0xE1, 0xC3} // mul %ecx ; ret
		}
		bc := liftOneInsn(t, code)
		mod := new(big.Int).Lsh(big.NewInt(1), uint(w))
		mask := new(big.Int).Sub(mod, big.NewInt(1))
		for iter := 0; iter < 400; iter++ {
			a := new(big.Int).Rand(rng, mod)
			b := new(big.Int).Rand(rng, mod)
			st := &vm.RefState{Guest: vm.GuestX86, Mem: map[uint64]byte{}}
			st.Regs[ir.RAX] = a.Uint64()
			st.Regs[ir.RCX] = b.Uint64()
			if rc, err := st.Run(bc, 64); err != nil || rc != 0 {
				t.Fatalf("w=%d: 执行失败 rc=%d err=%v", w, rc, err)
			}
			prod := new(big.Int).Mul(a, b)
			wantLo := new(big.Int).And(prod, mask)
			wantHi := new(big.Int).Rsh(prod, uint(w))
			gotLo := new(big.Int).And(new(big.Int).SetUint64(st.Regs[ir.RAX]), mask)
			gotHi := new(big.Int).And(new(big.Int).SetUint64(st.Regs[ir.RDX]), mask)
			if iter == 0 {
				t.Logf("w=%d a=0x%X b=0x%X: VSCR=0x%X RAX=0x%X RDX=0x%X (want hi=0x%X)",
					w, a, b, st.Regs[ir.VMSCR], st.Regs[ir.RAX], st.Regs[ir.RDX], wantHi)
			}
			if gotLo.Cmp(wantLo) != 0 || gotHi.Cmp(wantHi) != 0 {
				t.Fatalf("w=%d a=0x%X b=0x%X: 得到 RDX:RAX=0x%X:0x%X，参考 0x%X:0x%X",
					w, a, b, gotHi, gotLo, wantHi, wantLo)
			}
			wantCF := wantHi.Sign() != 0
			if (st.Flags&vm.FlagC != 0) != wantCF {
				t.Fatalf("w=%d a=0x%X b=0x%X: CF=%v，参考=%v", w, a, b, st.Flags&vm.FlagC != 0, wantCF)
			}
			if (st.Flags&vm.FlagV != 0) != wantCF {
				t.Fatalf("w=%d: OF 应当与 CF 一致", w)
			}
		}
	}
}

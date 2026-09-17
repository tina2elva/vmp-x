package x64

import (
	"math/bits"
	"math/rand"
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// BSF/BSR 差分：结果 = 最低/最高置位位下标；**只有 ZF 被改写**，其它标志位保持；源为 0 时 ZF=1。
func TestLiftBitScanDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(20260214))
	all := vm.FlagZ | vm.FlagN | vm.FlagC | vm.FlagV | vm.FlagP
	type cs struct {
		name string
		code []byte
		high bool
	}
	for _, c := range []cs{
		{"bsf %rcx,%rax", []byte{0x48, 0x0F, 0xBC, 0xC1, 0xC3}, false},
		{"bsr %rcx,%rax", []byte{0x48, 0x0F, 0xBD, 0xC1, 0xC3}, true},
	} {
		bc := liftOneInsn(t, c.code)
		for iter := 0; iter < 400; iter++ {
			v := rng.Uint64()
			if iter%8 == 0 {
				v = 0 // 覆盖源为 0 的边界
			}
			flags := all
			if rng.Intn(2) == 0 {
				flags &^= vm.FlagZ
			}
			st := &vm.RefState{Guest: vm.GuestX86, Mem: map[uint64]byte{}}
			st.Regs[ir.RAX] = 0xAAAAAAAAAAAAAAAA
			st.Regs[ir.RCX] = v
			st.Flags = flags
			if rc, err := st.Run(bc, 64); err != nil || rc != 0 {
				t.Fatalf("%s 执行失败 rc=%d err=%v", c.name, rc, err)
			}
			var want uint64
			if v != 0 {
				if c.high {
					want = uint64(63 - bits.LeadingZeros64(v))
				} else {
					want = uint64(bits.TrailingZeros64(v))
				}
			} else {
				want = 0 // 源为 0 时硬件结果未定义；我们的实现定为 0（目标被写成 0）
			}
			if st.Regs[ir.RAX] != want {
				t.Fatalf("%s v=0x%X: RAX=0x%X 参考=0x%X", c.name, v, st.Regs[ir.RAX], want)
			}
			wantZ := v == 0
			if (st.Flags&vm.FlagZ != 0) != wantZ {
				t.Fatalf("%s v=0x%X: ZF=%v 参考=%v", c.name, v, st.Flags&vm.FlagZ != 0, wantZ)
			}
			if st.Flags&^vm.FlagZ != flags&^vm.FlagZ {
				t.Fatalf("%s v=0x%X: BSF/BSR 改动了 ZF 以外的标志位", c.name, v)
			}
		}
	}
}

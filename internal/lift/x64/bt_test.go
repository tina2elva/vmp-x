package x64

import (
	"math/rand"
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// BT 的差分：位被送进 CF，**其它标志位必须原封不动**（这是 BT 与 SHR 的关键差别）
func TestLiftBtKeepsOtherFlags(t *testing.T) {
	rng := rand.New(rand.NewSource(20260213))
	// bt %rcx,%rax（64 位形式必须带 REX.W）= 48 0F A3 C8 ; ret
	bc := liftOneInsn(t, []byte{0x48, 0x0F, 0xA3, 0xC8, 0xC3})
	allFlags := vm.FlagZ | vm.FlagN | vm.FlagC | vm.FlagV | vm.FlagP
	for iter := 0; iter < 500; iter++ {
		a := rng.Uint64()
		idx := uint64(rng.Intn(64))
		flags := uint32(rng.Intn(2)) * 0 // 先固定"其它标志位"为全 1，便于检查是否被清掉
		flags = allFlags
		if rng.Intn(2) == 0 {
			flags &^= vm.FlagC
		}
		st := &vm.RefState{Guest: vm.GuestX86, Mem: map[uint64]byte{}}
		st.Regs[ir.RAX] = a
		st.Regs[ir.RCX] = idx
		st.Flags = flags
		if rc, err := st.Run(bc, 64); err != nil || rc != 0 {
			t.Fatalf("执行失败 rc=%d err=%v", rc, err)
		}
		want := (a >> (idx & 63)) & 1
		got := st.Flags & vm.FlagC
		if (got != 0) != (want == 1) {
			t.Fatalf("a=0x%X idx=%d: CF=%v，参考=%d", a, idx, got != 0, want)
		}
		// 其它标志位必须保持
		if st.Flags&^vm.FlagC != flags&^vm.FlagC {
			t.Fatalf("a=0x%X idx=%d: BT 改动了 CF 以外的标志位（0x%X → 0x%X）", a, idx, flags, st.Flags)
		}
		// BT 不写目标寄存器
		if st.Regs[ir.RAX] != a {
			t.Fatalf("BT 不该改 %%rax")
		}
	}
}

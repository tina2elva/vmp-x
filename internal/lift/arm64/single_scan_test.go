package arm64

import (
	"encoding/binary"
	"math/rand"
	"testing"

	dec "github.com/vmpx/vmp-x/internal/decode/arm64"
	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// 单条指令扫描：每类指令单独与直接语义比对（比序列更容易定位问题）
func TestArm64LiftSingleScan(t *testing.T) {
	rng := rand.New(rand.NewSource(4242))
	printed := 0
	bad, checked := 0, 0
	for i := 0; i < 40000 && printed < 6; i++ {
		w := genDataInsn(rng)
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, w)
		ins, err := dec.Decode(b, 0x1000)
		if err != nil {
			continue
		}
		var regs [35]uint64
		for k := 0; k < 31; k++ {
			regs[k] = rng.Uint64()
		}
		ref := &refMachine{regs: regs}
		if err := ref.step(&ins); err != nil {
			continue
		}
		fn := &ir.Func{}
		(&Lifter{}).Lift(fn, []dec.Insn{ins})
		if len(fn.Unsupported) > 0 {
			continue
		}
		fn.Insns = append(fn.Insns, ir.Insn{Op: ir.Ret})
		res, err := vm.Generate(fn)
		if err != nil {
			t.Fatalf("codegen: %v", err)
		}
		st := &vm.RefState{Guest: vm.GuestARM64, Mem: map[uint64]byte{}}
		st.Regs = regs
		st.Run(res.Code, 256)
		checked++
		diff := ""
		for k := 0; k < 31; k++ {
			if st.Regs[k] != ref.regs[k] {
				diff = "R" + itoa(k)
				break
			}
		}
		if diff == "" && st.Flags != ref.flags {
			diff = "flags"
		}
		if diff != "" {
			bad++
			printed++
			t.Logf("MISMATCH(%s) 0x%08X class=%v  %s", diff, w, ins.Class, ins.Text())
			t.Logf("    ref flags=0x%X vm flags=0x%X", ref.flags, st.Flags)
			for j := range fn.Insns {
				in := &fn.Insns[j]
				t.Logf("    IR[%d] %v kind=0x%X w=%d dst=%d a=%d b=%d imm=0x%X", j, in.Op, in.Kind, in.Width, in.Dst, in.A, in.B, in.Imm)
			}
			for k := 0; k < 31; k++ {
				if st.Regs[k] != ref.regs[k] {
					t.Logf("    R%d vm=0x%X ref=0x%X", k, st.Regs[k], ref.regs[k])
					break
				}
			}
		}
	}
	t.Logf("单条扫描：校验 %d 条，不一致 %d 条", checked, bad)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

package arm64

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"

	dec "github.com/vmpx/vmp-x/internal/decode/arm64"
	arm64sem "github.com/vmpx/vmp-x/internal/guest/arm64"
	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// MaskW64 按客户机宽度取掩码（32 位读寄存器只取低 32 位）
func MaskW64(w uint32) uint64 {
	if w >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << w) - 1
}
func (m *refMachine) runProgram(insns []dec.Insn, base uint64, maxSteps int) (int, error) {
	idx := map[uint64]int{}
	for i := range insns {
		idx[insns[i].PC] = i
	}
	pc := 0
	for steps := 0; steps < maxSteps; steps++ {
		if pc < 0 || pc >= len(insns) {
			return steps, nil // 走出程序（生成器不会产生这种情况）
		}
		ins := &insns[pc]
		switch ins.Class {
		case dec.ClassBranchReg:
			if ins.Op.String() == "RET" {
				return steps, nil
			}
			return steps, fmt.Errorf("参考执行器不支持 %v", ins.Op)
		case dec.ClassBranchImm:
			tgt, ok := ins.PCRelTarget()
			if !ok {
				return steps, fmt.Errorf("取不到分支目标")
			}
			next, ok := idx[tgt]
			if !ok {
				return steps, fmt.Errorf("分支目标 0x%X 越界", tgt)
			}
			pc = next
			continue
		case dec.ClassBranchCond:
			cond, _ := ins.Cond()
			if arm64sem.CondHolds(cond, m.flags) {
				tgt, _ := ins.PCRelTarget()
				pc = idx[tgt]
			} else {
				pc++
			}
			continue
		case dec.ClassCompareBranch:
			rt := ins.Raw & 31
			w := ir.W32
			if ins.Raw&(1<<31) != 0 {
				w = ir.W64
			}
			v := m.readZR(rt) & MaskW64(uint32(w))
			taken := v == 0 // CBZ/CBNZ **不修改标志位**，只是测试
			if ins.Op.String() == "CBNZ" {
				taken = !taken
			}
			if taken {
				tgt, _ := ins.PCRelTarget()
				pc = idx[tgt]
			} else {
				pc++
			}
			continue
		case dec.ClassTestBranch:
			rt := ins.Raw & 31
			w := ir.W32
			bit := (ins.Raw >> 19) & 31
			if ins.Raw&(1<<31) != 0 {
				bit |= 32
				w = ir.W64
			}
			v := m.readZR(rt) & MaskW64(uint32(w))
			taken := v&(uint64(1)<<bit) == 0 // TBZ/TBNZ 同样不改标志位
			if ins.Op.String() == "TBNZ" {
				taken = !taken
			}
			if taken {
				tgt, _ := ins.PCRelTarget()
				pc = idx[tgt]
			} else {
				pc++
			}
			continue
		}
		if err := m.step(ins); err != nil {
			return steps, err
		}
		pc++
	}
	return maxSteps, fmt.Errorf("超过步数上限")
}

// 生成"数据指令 + 前向分支 + RET"的程序
func genControlProgram(rng *rand.Rand, n int) []uint32 {
	words := make([]uint32, 0, n)
	// 先占位，保证每条都能取到 PC；最后一条固定 RET
	for i := 0; i < n-1; i++ {
		if rng.Intn(3) == 0 {
			// 分支：目标在本程序内。**允许向后跳**以覆盖循环；向后跳时只生成条件分支
			// （无条件 B 向后就是死循环，交给参考执行器的步数上限也没意义）。
			var tgt uint32
			backward := i > 0 && rng.Intn(3) == 0
			if backward {
				tgt = uint32(rng.Intn(i)) // 0..i-1，绝不等于 i
			} else {
				tgt = uint32(i + 1 + rng.Intn(n-1-i))
			}
			delta := int32(tgt) - int32(i)
			kinds := 4
			if backward {
				kinds = 3 // 跳过无条件 B
			}
			switch rng.Intn(kinds) {
			case 0: // B
				words = append(words, 0x14000000|(uint32(delta)&0x03FFFFFF))
			case 1: // B.cond（14 个真实条件）——向后时它就是循环的回边
				cond := uint32(rng.Intn(14))
				words = append(words, 0x54000000|((uint32(delta)&0x1FFFF)<<5)|cond)
			case 2: // CBZ/CBNZ
				op := uint32(rng.Intn(2)) << 24
				sfBit := uint32(rng.Intn(2)) << 31
				rt := uint32(rng.Intn(32))
				words = append(words, 0x34000000|sfBit|op|((uint32(delta)&0x1FFFF)<<5)|rt)
			default: // TBZ/TBNZ
				op := uint32(rng.Intn(2)) << 24
				sfBit := uint32(rng.Intn(2)) << 31
				b40 := uint32(rng.Intn(32))
				rt := uint32(rng.Intn(32))
				words = append(words, 0x36000000|sfBit|op|(b40<<19)|((uint32(delta)&0x3FFF)<<5)|rt)
			}
			continue
		}
		words = append(words, genDataInsn(rng))
	}
	words = append(words, 0xD65F03C0) // RET
	return words
}

func TestArm64LiftControlFlowDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(20240616))
	const iterations = 20000
	const base = 0x1000
	checked, bad := 0, 0
	var skipDecode, skipRef, skipLift, skipLimit int
	for it := 0; it < iterations; it++ {
		n := 4 + rng.Intn(9)
		words := genControlProgram(rng, n)
		var code []byte
		for _, w := range words {
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, w)
			code = append(code, b...)
		}
		insns, err := dec.DecodeRange(code, base, 0)
		if err != nil {
			skipDecode++
			continue
		}
		var regs [35]uint64
		for i := 0; i < 31; i++ {
			regs[i] = rng.Uint64()
		}
		ref := &refMachine{regs: regs}
		if _, err := ref.runProgram(insns, base, 512); err != nil {
			if err.Error() == "超过步数上限" {
				skipLimit++
			} else {
				skipRef++
			}
			continue
		}
		// lift 路径
		fn := &ir.Func{}
		(&Lifter{ImageBase: base, ImageSize: 0x10000}).Lift(fn, insns)
		if len(fn.Unsupported) > 0 {
			skipLift++
			continue
		}
		// RET 已经在程序末尾里（lifter 会生成 Ret）
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
			if bad <= 6 {
				var txt []string
				for i := range insns {
					txt = append(txt, insns[i].Text())
				}
				t.Errorf("用例 %d %v: %s", it, txt, diff)
			}
			continue
		}
		checked++
	}
	t.Logf("ARM64 控制流差分：校验 %d 组，不一致 %d 组；跳过：解码失败 %d、参考不支持 %d、lifter 拒绝 %d、超过步数 %d",
		checked, bad, skipDecode, skipRef, skipLift, skipLimit)
	if bad != 0 {
		t.Fatalf("不一致 %d 组", bad)
	}
}

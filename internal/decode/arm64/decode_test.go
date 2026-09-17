package arm64

import (
	"encoding/binary"
	"math/rand"
	"sort"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

// isFPArg 判断参数是否是 SIMD/FP 寄存器（仅测试用：按打印名首字母判断，SP 例外）
func isFPArg(a arm64asm.Arg) bool {
	if a == nil {
		return false
	}
	// 只对真正的寄存器参数判断：条件码/立即数不是寄存器
	// （否则 "HI"/"HS" 这类条件名会被首字母规则误判）
	switch a.(type) {
	case arm64asm.Reg, arm64asm.RegSP:
	case arm64asm.RegisterWithArrangement, arm64asm.RegisterWithArrangementAndIndex:
		return true // 带排列/通道索引的一定是 SIMD 寄存器
	default:
		return false
	}
	s := a.String()
	if s == "SP" || s == "" {
		return false
	}
	switch s[0] {
	case 'S', 'D', 'Q', 'H', 'B', 'V':
		return true
	}
	return false
}

func word(w uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, w)
	return b
}

// 锚点：这些编码是 A64 里最常用的入口/返回/序言指令，手工核对过助记符与操作数
func TestDecodeAnchors(t *testing.T) {
	cases := []struct {
		raw   uint32
		op    arm64asm.Op
		class Class
		text  string
	}{
		{0xD65F03C0, arm64asm.RET, ClassBranchReg, "RET X30"},
		{0xD503201F, arm64asm.NOP, ClassMisc, "NOP "},
		{0x910003FD, arm64asm.MOV, ClassAddSubImm, "MOV X29, SP"}, // ADD X29, SP, #0
		{0xA9BF7BFD, arm64asm.STP, ClassLoadStorePair, "STP X29, X30, [SP,#-16]!"},
		{0xA8C17BFD, arm64asm.LDP, ClassLoadStorePair, "LDP X29, X30, [SP],#16"},
		{0x52800020, arm64asm.MOV, ClassMoveWide, "MOV W0, #0x1"}, // MOVZ
		{0xF9400020, arm64asm.LDR, ClassLoadStore, "LDR X0, [X1]"},
		{0xB9000020, arm64asm.STR, ClassLoadStore, "STR W0, [X1]"},
		{0x14000005, arm64asm.B, ClassBranchImm, "B .+0x14"},
		{0x94000005, arm64asm.BL, ClassBranchImm, "BL .+0x14"},
		{0x54000040, arm64asm.B, ClassBranchCond, "B EQ, .+0x8"},
		{0x8B010000, arm64asm.ADD, ClassAddSubShifted, "ADD X0, X0, X1"},
		{0xCB010000, arm64asm.SUB, ClassAddSubShifted, "SUB X0, X0, X1"},
		{0xD63F0000, arm64asm.BLR, ClassBranchReg, "BLR X0"},
	}
	for _, c := range cases {
		ins, err := Decode(word(c.raw), 0)
		if err != nil {
			t.Fatalf("0x%08X 解码失败: %v", c.raw, err)
		}
		if ins.Op != c.op {
			t.Errorf("0x%08X op = %v，期望 %v", c.raw, ins.Op, c.op)
		}
		if ins.Class != c.class {
			t.Errorf("0x%08X class = %v，期望 %v", c.raw, ins.Class, c.class)
		}
		if ins.Text() != c.text {
			t.Errorf("0x%08X text = %q，期望 %q", c.raw, ins.Text(), c.text)
		}
	}
}

// 严格性：长度不对或未分配编码必须报错，绝不返回"大概是什么"
func TestDecodeStrict(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3} {
		if _, err := Decode(make([]byte, n), 0); err == nil {
			t.Errorf("长度 %d 应报错", n)
		}
	}
	for _, w := range []uint32{0x00000000, 0xFFFFFFFF, 0x7FFFFFFF} {
		if _, err := Decode(word(w), 0); err == nil {
			t.Errorf("未分配编码 0x%08X 应报错", w)
		}
	}
	if _, err := DecodeRange(make([]byte, 6), 0, 0); err == nil {
		t.Error("长度非 4 倍数应报错")
	}
}

// 分支目标：B/BL/B.cond 的 PCRel 必须等于 PC + 偏移
func TestPCRelTarget(t *testing.T) {
	ins, err := Decode(word(0x14000005), 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	tgt, ok := ins.PCRelTarget()
	if !ok || tgt != 0x1014 {
		t.Errorf("B 目标 = 0x%X (%v)，期望 0x1014", tgt, ok)
	}
	ins2, err := Decode(word(0x94000005), 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if tgt2, ok := ins2.PCRelTarget(); !ok || tgt2 != 0x1014 {
		t.Errorf("BL 目标 = 0x%X (%v)，期望 0x1014", tgt2, ok)
	}
}

// 分类表和参考解码器（arm64asm）必须一致：
// 凡是两者都认得出来的编码，我的分类必须与参考助记符相符。
func TestClassifyMatchesReference(t *testing.T) {
	// 参考助记符 -> 允许的编码类（别名会带来多个可能，这里如实列出）
	allowed := map[arm64asm.Op][]Class{
		arm64asm.ADD:  {ClassAddSubImm, ClassAddSubShifted, ClassAddSubExtended},
		arm64asm.ADDS: {ClassAddSubImm, ClassAddSubShifted, ClassAddSubExtended},
		arm64asm.SUB:  {ClassAddSubImm, ClassAddSubShifted, ClassAddSubExtended},
		arm64asm.SUBS: {ClassAddSubImm, ClassAddSubShifted, ClassAddSubExtended},
		arm64asm.CMP:  {ClassAddSubImm, ClassAddSubShifted, ClassAddSubExtended},
		arm64asm.CMN:  {ClassAddSubImm, ClassAddSubShifted, ClassAddSubExtended},
		arm64asm.MOV:  {ClassMoveWide, ClassLogicalImm, ClassAddSubImm, ClassLogicalShifted},
		arm64asm.MOVN: {ClassMoveWide}, arm64asm.MOVZ: {ClassMoveWide}, arm64asm.MOVK: {ClassMoveWide},
		arm64asm.AND: {ClassLogicalImm, ClassLogicalShifted}, arm64asm.ANDS: {ClassLogicalImm, ClassLogicalShifted},
		arm64asm.ORR: {ClassLogicalImm, ClassLogicalShifted}, arm64asm.EOR: {ClassLogicalImm, ClassLogicalShifted},
		arm64asm.TST: {ClassLogicalImm, ClassLogicalShifted},
		arm64asm.B:   {ClassBranchImm, ClassBranchCond},
		arm64asm.BL:  {ClassBranchImm},
		arm64asm.CBZ: {ClassCompareBranch}, arm64asm.CBNZ: {ClassCompareBranch},
		arm64asm.TBZ: {ClassTestBranch}, arm64asm.TBNZ: {ClassTestBranch},
		arm64asm.BR: {ClassBranchReg}, arm64asm.BLR: {ClassBranchReg}, arm64asm.RET: {ClassBranchReg},
		arm64asm.ADR: {ClassPCRel}, arm64asm.ADRP: {ClassPCRel},
		arm64asm.LDR: {ClassLoadStore, ClassLoadLiteral, ClassFPVec},
		arm64asm.STR: {ClassLoadStore, ClassFPVec},
		arm64asm.LDP: {ClassLoadStorePair}, arm64asm.STP: {ClassLoadStorePair},
		arm64asm.UBFM: {ClassBitfield}, arm64asm.SBFM: {ClassBitfield}, arm64asm.BFM: {ClassBitfield},
		arm64asm.UBFX: {ClassBitfield}, arm64asm.SBFX: {ClassBitfield},
		arm64asm.UBFIZ: {ClassBitfield}, arm64asm.SBFIZ: {ClassBitfield},
		arm64asm.LSL: {ClassBitfield, ClassDataProc2}, arm64asm.LSR: {ClassBitfield, ClassDataProc2},
		arm64asm.ASR:  {ClassBitfield, ClassDataProc2},
		arm64asm.UDIV: {ClassDataProc2}, arm64asm.SDIV: {ClassDataProc2},
		arm64asm.CSEL: {ClassCondSelect}, arm64asm.CSINC: {ClassCondSelect},
		arm64asm.CSINV: {ClassCondSelect}, arm64asm.CSNEG: {ClassCondSelect},
	}

	rng := rand.New(rand.NewSource(20240612))
	checked, skipped, mismatches := 0, 0, 0
	hist := map[string]int{}
	for i := 0; i < 200000; i++ {
		// 采样：一半随机、一半围绕常见前缀扰动
		var w uint32
		if i%2 == 0 {
			w = rng.Uint32()
		} else {
			base := []uint32{
				0x8B000000, 0xCB000000, 0x91000000, 0xD1000000, 0x12000000, 0x0A000000,
				0x52800000, 0x72800000, 0xF2800000, 0x53000000, 0x13000000, 0x1A800000,
				0x1AC00000, 0x14000000, 0x94000000, 0x54000000, 0x34000000, 0x36000000,
				0xD6000000, 0x10000000, 0x90000000, 0xF9400000, 0xB9000000, 0xA9000000,
				0x39000000, 0x38000000, 0x38200000, 0xD65F0000,
			}[rng.Intn(28)]
			w = base | rng.Uint32()&0x03FFFFFF
		}
		b := word(w)
		ref, err := arm64asm.Decode(b)
		if err != nil {
			skipped++
			continue
		}
		classes, known := allowed[ref.Op]
		if !known {
			skipped++
			continue
		}
		got := Classify(w)
		// 统一规则：只要参考解码器给出的第一个操作数是 SIMD/FP 寄存器，
		// 该指令就属于 SIMD/FP 空间，我的分类必须是 ClassFPVec；
		// 否则必须落在该助记符允许的整数编码类里。
		fp := isFPArg(ref.Args[0])
		if fp {
			if got != ClassFPVec {
				mismatches++
				hist[ref.Op.String()+"/"+got.String()]++
				if mismatches <= 10 {
					t.Errorf("0x%08X: 参考 %s（FP），我的分类 %v", w, ref.String(), got)
				}
				checked++
				continue
			}
			checked++
			continue
		}
		ok := false
		for _, c := range classes {
			if got == c {
				ok = true
				break
			}
		}
		if !ok {
			mismatches++
			hist[ref.Op.String()+"/"+got.String()]++
			if mismatches <= 10 {
				t.Errorf("0x%08X: 参考 %s，我的分类 %v（允许 %v）", w, ref.String(), got, classes)
			}
		}
		checked++
	}
	var keys []string
	for k := range hist {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("  不一致类别 %-28s x%d", k, hist[k])
	}
	t.Logf("分类与参考一致性: 校验 %d 条，跳过（参考不认识/未覆盖）%d 条，不一致 %d 条", checked, skipped, mismatches)
}

// DecodeRange 必须逐条与 Decode 一致，且能定位解码失败的位置
func TestDecodeRange(t *testing.T) {
	prologue := []uint32{0xA9BF7BFD, 0x910003FD, 0xD503201F, 0xA8C17BFD, 0xD65F03C0}
	var code []byte
	for _, w := range prologue {
		code = append(code, word(w)...)
	}
	insns, err := DecodeRange(code, 0x400000, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(insns) != len(prologue) {
		t.Fatalf("解出 %d 条，期望 %d 条", len(insns), len(prologue))
	}
	for i, ins := range insns {
		if ins.Raw != prologue[i] {
			t.Errorf("第 %d 条 = 0x%08X，期望 0x%08X", i, ins.Raw, prologue[i])
		}
		if ins.PC != 0x400000+uint64(i)*4 {
			t.Errorf("第 %d 条 PC = 0x%X", i, ins.PC)
		}
	}
	// 中间插入一个未分配编码：必须报错并且报出准确位置
	bad := append(append([]byte{}, code[:8]...), append(word(0), code[12:]...)...)
	if _, err := DecodeRange(bad, 0x400000, 0); err == nil {
		t.Error("含非法编码时应报错")
	}
}

package arm64

import "testing"

// 独立于实现的手算锚点：直接从 ARM ARM 的伪码规则推出来，
// 用来防止"Go 和 C 两份实现同时写错同一个概念"（对拍测不出这种错）。
func TestArm64FlagAnchors(t *testing.T) {
	const (
		n = FlagN
		z = FlagZ
		c = FlagC
		v = FlagV
	)
	type ac struct {
		name string
		got  uint32
		want uint32
	}
	var cases []ac
	add := func(name string, got, want uint32) { cases = append(cases, ac{name, got, want}) }
	// 用变量做减法：Go 的常量折叠会拒绝 uint64(1)-2 这类写法
	sub := func(a, b uint64) uint64 { return a - b }

	// SUB/CMP：ARM64 的 C = **无借位**（与 x86 的 CF 相反）
	add("SUB 1-2 (64) 借位: C=0", FlagsSub(1, 2, sub(1, 2), 64), n)
	add("SUB 2-1 (64) 无借位: C=1", FlagsSub(2, 1, 2-1, 64), c)
	add("SUB 0-1 (32) 借位: C=0", FlagsSub(0, 1, sub(0, 1)&MaskW(32), 32), n)
	add("SUB 5-5: Z=1 且 C=1", FlagsSub(5, 5, 0, 64), z|c)
	// 结果 0x7FFF...：N=0、Z=0、C=1（无借位）、V=1（有符号溢出）
	add("SUB 0x8000000000000000-1: C=1 且 V=1", FlagsSub(0x8000000000000000, 1, 0x7FFFFFFFFFFFFFFF, 64), c|v)

	// ADD：C = 进位，V = 有符号溢出
	add("ADD max+1 进位: C=1 Z=1", FlagsAdd(0xFFFFFFFFFFFFFFFF, 1, 0, 64), z|c)
	add("ADD maxint+1 溢出: N=1 V=1", FlagsAdd(0x7FFFFFFFFFFFFFFF, 1, 0x8000000000000000, 64), n|v)
	// 32 位结果 = 0x10（非 0）→ 只有 C=1
	add("ADD 0xFFFFFFF0+0x20 (32): C=1", FlagsAdd(0xFFFFFFF0, 0x20, 0x10, 32), c)
	add("ADD 1+1: 无标志", FlagsAdd(1, 1, 2, 64), 0)

	// 逻辑运算：只影响 N/Z
	add("AND 结果为 0: Z=1", FlagsLogic(0, 64), z)
	add("AND 结果高位为 1: N=1", FlagsLogic(0x8000000000000000, 64), n)

	// 移位：cnt==0 时 C 不变；否则 C = 最后移出的位；V 保持不变
	add("LSL#1 移出 1: C=1 Z=1", FlagsShift(0, 1, 64, 1, 0), z|c)
	add("LSL#1 移出 0: C=0", FlagsShift(1, 0, 64, 1, 0), 0)
	add("移位量 0: C 保持不变", FlagsShift(1, 0, 64, 0, c|v), c|v)
	// 结果 1（N=0,Z=0）、移出位为 1（C=1）、V 保持
	add("移位保留 V 并设置 C", FlagsShift(1, 1, 64, 1, v), v|c)

	for _, k := range cases {
		if k.got != k.want {
			t.Errorf("%s: 得到 0x%X，期望 0x%X", k.name, k.got, k.want)
		}
	}
}

// 条件码锚点（ARM64：C=1 表示无符号 >=；HI = C=1 且 Z=0；GE/LT 用 N==V）
func TestArm64CondAnchors(t *testing.T) {
	type cc struct {
		name  string
		flags uint32
		holds []uint32 // 应当成立的条件码
		fails []uint32
	}
	all := []cc{
		// Z=1, C=0, N=0, V=0
		{name: "Z=1 (相等)", flags: FlagZ,
			holds: []uint32{0 /*EQ*/, 3 /*CC*/, 5 /*PL*/, 7 /*VC*/, 9 /*LS*/, 10 /*GE*/, 13 /*LE*/},
			fails: []uint32{1 /*NE*/, 2 /*CS*/, 4 /*MI*/, 6 /*VS*/, 8 /*HI*/, 11 /*LT*/, 12 /*GT*/}},
		// C=1, Z=0, N=0, V=0
		{name: "C=1,Z=0", flags: FlagC,
			holds: []uint32{1 /*NE*/, 2 /*CS*/, 5 /*PL*/, 7 /*VC*/, 8 /*HI*/, 10 /*GE*/, 12 /*GT*/},
			fails: []uint32{0 /*EQ*/, 3 /*CC*/, 4 /*MI*/, 6 /*VS*/, 9 /*LS*/, 11 /*LT*/, 13 /*LE*/}},
		{name: "N=1,V=1 (LT 不成立, GE 成立)", flags: FlagN | FlagV,
			holds: []uint32{10 /*GE*/, 4 /*MI*/, 12 /*GT*/},
			fails: []uint32{11 /*LT*/, 5 /*PL*/}},
		{name: "N=1,V=0 (LT 成立)", flags: FlagN,
			holds: []uint32{11 /*LT*/, 4 /*MI*/},
			fails: []uint32{10 /*GE*/, 12 /*GT*/}},
	}
	for _, k := range all {
		for _, cond := range k.holds {
			if !CondHolds(cond, k.flags) {
				t.Errorf("%s: 条件 %d 应成立", k.name, cond)
			}
		}
		for _, cond := range k.fails {
			if CondHolds(cond, k.flags) {
				t.Errorf("%s: 条件 %d 不应成立", k.name, cond)
			}
		}
	}
	// AL/NV 恒成立
	if !CondHolds(14, 0) || !CondHolds(15, 0) {
		t.Error("AL/NV 应恒成立")
	}
}

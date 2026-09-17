package vm

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// 单一来源校验：Go 的操作码表必须与 C 头文件 stub/win/x64/vm_opcode_values.h 完全一致
// （名字与默认编码都要对上，否则 vmpbuild 生成的随机映射会与 Go 侧的解释错位）。
func TestOpcodeTableMatchesC(t *testing.T) {
	p := filepath.FromSlash("../../stub/win/x64/vm_opcode_values.h")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skip("缺少 C 头文件:", p)
	}
	re := regexp.MustCompile("(?m)^#define\\s+(VM_OP_[A-Z0-9_]+)\\s+0x([0-9A-Fa-f]+)\\s*$")
	got := map[string]byte{}
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		v, err := strconv.ParseUint(m[2], 16, 8)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", m[1], err)
		}
		name := m[1][len("VM_"):] // VM_OP_X -> OP_X
		got[name] = byte(v)
	}
	if len(got) != len(OpcodeNames) {
		t.Fatalf("C 头文件有 %d 条，Go 表有 %d 条", len(got), len(OpcodeNames))
	}
	for _, e := range OpcodeNames {
		v, ok := got[e.Name]
		if !ok {
			t.Errorf("C 头文件缺少 %s", e.Name)
			continue
		}
		if v != e.Val {
			t.Errorf("%s: C=0x%02X Go=0x%02X", e.Name, v, e.Val)
		}
	}
	t.Logf("Go/C 操作码表一致，共 %d 条", len(OpcodeNames))
}

// Remap 必须只改操作码字节、不改操作数；用参考 VM 跑一遍比对结果。
func TestRemapRoundTrip(t *testing.T) {
	// 一段小程序：R0 = 5 ; R1 = 7 ; R0 = R0 + R1 ; CMP R0, 12 ; JEQ -> RET ; R0 = 0 ; RET
	var code []byte
	code = append(code, OpMovRI, 64, 0)
	code = append(code, u64le(5)...)
	code = append(code, OpMovRI, 64, 1)
	code = append(code, u64le(7)...)
	code = append(code, OpAluRR, byte(KAdd), 64, 0, 0, 1)
	code = append(code, OpCmpRI, byte(KCmp), 64, 0)

	code = append(code, u32le(12)...)
	code = append(code, OpJcc, 4) // x86 条件码 E=4，目标在下面回填
	code = append(code, u32le(0)...)
	jccAt := len(code) - 4
	code = append(code, OpMovRI, 64, 2)
	code = append(code, u64le(0)...)
	end := len(code)
	code = append(code, OpRet)
	copy(code[jccAt:], u32le(uint32(end)))

	run := func(c []byte, m *OpcodeMap) (uint32, [2]uint64) {
		st := &RefState{Map: m, Mem: map[uint64]byte{}}
		rc, err := st.Run(c, 64)
		if err != nil || rc != 0 {
			t.Fatalf("执行失败 rc=%d err=%v", rc, err)
		}
		return st.Flags, [2]uint64{st.Regs[0], st.Regs[2]}
	}
	flags0, regs0 := run(code, nil)

	// 造一个随机映射（模拟 vmpbuild 的行为：23 个互不相同的编码）
	byName := map[string]byte{}
	next := byte(1)
	for _, e := range OpcodeNames {
		byName[e.Name] = next
		next += 7 // 保证互不相同
	}
	m, err := NewOpcodeMap(byName)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := Remap(code, m)
	if err != nil {
		t.Fatal(err)
	}
	if string(mapped) == string(code) {
		t.Fatal("Remap 没有改变任何字节（映射是恒等？）")
	}
	flags1, regs1 := run(mapped, m)
	if flags0 != flags1 || regs0 != regs1 {
		t.Errorf("重映射后结果不同：flags %#x/%#x regs %v/%v", flags0, flags1, regs0, regs1)
	}
	// 恒等映射必须是原样返回
	if same, err := Remap(code, DefaultOpcodeMap()); err != nil || string(same) != string(code) {
		t.Errorf("恒等映射不应改动字节码: err=%v", err)
	}
}

func u64le(v uint64) []byte {
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
	return b
}

func u32le(v uint32) []byte {
	b := make([]byte, 4)
	for i := 0; i < 4; i++ {
		b[i] = byte(v >> (8 * i))
	}
	return b
}

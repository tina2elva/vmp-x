package vm

import "fmt"

// VM 操作码的"逻辑值"表（默认编码）。
//
// 单一来源纪律：这份表、stub/win/x64/vm_opcode_values.h、以及 vmpbuild 生成映射时用的表
// 必须完全一致——TestOpcodeTableMatchesC 会解析 C 头文件来校验。
//
// M2 起 vmpbuild 会为**每个 blob** 生成一套随机编码（见 OpcodeMap），
// 解释器用编译期常量分发，所以随机化不带来运行时开销。
var OpcodeNames = []struct {
	Name string
	Val  byte
}{
	{"OP_HALT", 0x00}, {"OP_NOP", 0x01}, {"OP_RET", 0x02},
	{"OP_MOV_RR", 0x10}, {"OP_MOV_RI", 0x11}, {"OP_MOV_RI32", 0x12}, {"OP_LEA", 0x13},
	{"OP_ALU_RR", 0x20}, {"OP_ALU_RI", 0x21}, {"OP_ALU_U", 0x22},
	{"OP_CMP_RR", 0x23}, {"OP_CMP_RI", 0x24},
	{"OP_EXT", 0x30},
	{"OP_LOAD", 0x40}, {"OP_STORE", 0x41}, {"OP_ATOMIC", 0x42}, {"OP_FP", 0x43},
	{"OP_PUSH_R", 0x50}, {"OP_PUSH_I", 0x51}, {"OP_POP_R", 0x52},
	{"OP_JCC", 0x60}, {"OP_JMP", 0x61}, {"OP_JBZ", 0x62}, {"OP_JBNZ", 0x63},
	{"OP_CALLN", 0x70}, {"OP_CALLR", 0x71},
}

// OpcodeMap 是本 blob 的"逻辑值 ↔ 编码值"双向表
type OpcodeMap struct {
	Enc      [256]byte
	Dec      [256]byte
	valid    [256]bool
	Identity bool
}

// DefaultOpcodeMap 恒等映射（默认编码）
func DefaultOpcodeMap() *OpcodeMap {
	m := &OpcodeMap{Identity: true}
	for _, e := range OpcodeNames {
		m.Enc[e.Val] = e.Val
		m.Dec[e.Val] = e.Val
		m.valid[e.Val] = true
	}
	return m
}

// NewOpcodeMap 用 "名字 -> 编码" 表构造（名字形如 OP_ALU_RR）
func NewOpcodeMap(byName map[string]byte) (*OpcodeMap, error) {
	m := &OpcodeMap{}
	seen := map[byte]string{}
	for _, e := range OpcodeNames {
		v, ok := byName[e.Name]
		if !ok {
			// 兼容 manifest 里去掉 OP_ 前缀的写法
			v, ok = byName[e.Name[3:]]
		}
		if !ok {
			return nil, fmt.Errorf("opcodeMap 缺少 %s", e.Name)
		}
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("opcodeMap 里 %s 与 %s 编码相同 (0x%02X)", e.Name, prev, v)
		}
		seen[v] = e.Name
		m.Enc[e.Val] = v
		m.Dec[v] = e.Val
		m.valid[v] = true
		if v != e.Val {
			m.Identity = false
		}
	}
	return m, nil
}

// Decode 把字节码里的操作码翻译回逻辑值
func (m *OpcodeMap) Decode(b byte) (byte, bool) {
	if m == nil {
		return b, true
	}
	if !m.valid[b] {
		return 0, false
	}
	return m.Dec[b], true
}

// Encode 把逻辑操作码翻译成实际编码
func (m *OpcodeMap) Encode(logical byte) byte {
	if m == nil {
		return logical
	}
	return m.Enc[logical]
}

// Remap 按指令长度表遍历字节码，把每条指令的**操作码字节**换成实际编码。
// 只改操作码字节，不动操作数——字节码布局由 InsnSize 决定。
func Remap(code []byte, m *OpcodeMap) ([]byte, error) {
	if m == nil || m.Identity {
		return code, nil
	}
	out := make([]byte, len(code))
	copy(out, code)
	// 输入是 codegen 产出的**逻辑**操作码：先按逻辑值算长度，再翻译成实际编码。
	known := map[byte]bool{}
	for _, e := range OpcodeNames {
		known[e.Val] = true
	}
	pc := 0
	for pc < len(out) {
		logical := out[pc]
		if !known[logical] {
			return nil, fmt.Errorf("未知操作码 0x%02X @+0x%X（codegen 产出的应当是逻辑操作码）", logical, pc)
		}
		out[pc] = m.Encode(logical)
		sz := InsnSize(logical)
		if sz <= 0 || pc+sz > len(out) {
			return nil, fmt.Errorf("指令长度异常（op=0x%02X size=%d）@+0x%X", logical, sz, pc)
		}
		pc += sz
	}
	return out, nil
}

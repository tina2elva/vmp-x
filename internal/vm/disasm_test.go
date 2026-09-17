package vm

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

const nl = string(rune(10)) // 换行：刻意不用转义字面量，避免多层转义出错
const bs = string(rune(92)) // 反斜杠

// 交叉校验：Go 侧 opTable 的“操作码值 → 长度”必须与 C 侧 vm_insn_size 完全一致，
// 且 vm_opcodes.h 里的数值必须与 Go 常量一一对应。
// 这类漂移在“双份手写表”的项目里是常见事故来源，因此用测试钉住。
func TestInsnSizeMatchesCInterpreter(t *testing.T) {
	src, err := os.ReadFile("../../stub/win/x64/vm_interp.c")
	if err != nil {
		t.Skip("找不到 C 解释器源码:", err)
	}
	lines := strings.Split(string(src), nl)

	// 注意：C 文件里先有前向声明，要取带 "{" 的定义
	start := -1
	for i, l := range lines {
		if strings.Contains(l, "u32 vm_insn_size(u8 op)") && strings.HasSuffix(strings.TrimSpace(l), "{") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("无法在 C 源码中定位 vm_insn_size 的定义")
	}

	// 整行扫描（同一行可能有多个 case，甚至 case 与 return 同行）
	cSizes := map[string]int{}
	var pending []string
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		search := 0
		for {
			j := strings.Index(l[search:], "case OP_")
			if j < 0 {
				break
			}
			j += search
			rest := l[j+len("case "):]
			k := strings.Index(rest, ":")
			if k < 0 {
				break
			}
			pending = append(pending, strings.TrimSpace(rest[:k]))
			search = j + len("case OP_")
		}
		if r := strings.Index(l, "return "); r >= 0 {
			rest := l[r+len("return "):]
			if k := strings.Index(rest, ";"); k >= 0 {
				if n, err := strconv.Atoi(strings.TrimSpace(rest[:k])); err == nil {
					for _, name := range pending {
						cSizes[name] = n
					}
					pending = nil
				}
			}
		}
		if strings.TrimSpace(l) == "}" && i > start+2 {
			break
		}
	}
	if len(cSizes) < 20 {
		t.Fatalf("从 C 侧只解析出 %d 条指令长度", len(cSizes))
	}

	// vm_opcodes.h 里 OP_* 的数值（处理续行）
	// 操作码的**数值**现在在 vm_opcode_values.h（vm_opcodes.h 只把它们绑成枚举名）
	hdr, err := os.ReadFile("../../stub/win/x64/vm_opcode_values.h")
	if err != nil {
		t.Fatal(err)
	}
	cont := bs + nl
	flat := strings.ReplaceAll(string(hdr), cont, " ")
	cValues := map[string]byte{}
	for _, l := range strings.Split(flat, nl) {
		l = strings.TrimSpace(l)
		// 支持两种写法：#define OP_X 0xNN 与 enum 中的 OP_X = 0xNN,
		switch {
		case strings.HasPrefix(l, "#define VM_OP_"):
			f := strings.Fields(l)
			if len(f) >= 3 {
				if v, err := strconv.ParseUint(f[2], 0, 8); err == nil {
					cValues[strings.TrimPrefix(f[1], "VM_")] = byte(v)
				}
			}
		case strings.HasPrefix(l, "#define OP_"):
			f := strings.Fields(l)
			if len(f) >= 3 {
				if v, err := strconv.ParseUint(f[2], 0, 8); err == nil {
					cValues[f[1]] = byte(v)
				}
			}
		case strings.HasPrefix(l, "OP_") && strings.Contains(l, "= 0x"):
			if i := strings.Index(l, "/*"); i >= 0 { // 去掉行尾注释
				l = l[:i]
			}
			f := strings.Fields(l)
			if len(f) >= 3 {
				val := strings.TrimSuffix(strings.TrimSuffix(f[2], ","), ";")
				if v, err := strconv.ParseUint(val, 0, 8); err == nil {
					cValues[strings.TrimSuffix(f[0], ",")] = byte(v)
				}
			}
		}
	}
	if len(cValues) < 20 {
		t.Fatalf("从 vm_opcodes.h 只解析出 %d 个操作码", len(cValues))
	}

	// Go 侧常量：OpXxx byte = 0xNN
	opSrc, err := os.ReadFile("codegen.go")
	if err != nil {
		t.Fatal(err)
	}
	goByValue := map[byte]string{}
	for _, l := range strings.Split(string(opSrc), nl) {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "Op") || !strings.Contains(l, "byte = 0x") {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		if v, err := strconv.ParseUint(f[3], 0, 8); err == nil {
			goByValue[byte(v)] = f[0]
		}
	}

	checked := 0
	for cname, csize := range cSizes {
		v, ok := cValues[cname]
		if !ok {
			t.Errorf("C 侧 %s 在 vm_opcodes.h 里没有定义", cname)
			continue
		}
		gname, ok := goByValue[v]
		if !ok {
			t.Errorf("C 侧 %s=0x%02X 在 Go 侧没有同值常量", cname, v)
			continue
		}
		if got := InsnSize(v); got != csize {
			t.Errorf("%s/%s (0x%02X): Go 长度 %d != C 长度 %d", cname, gname, v, got, csize)
		}
		checked++
	}
	t.Logf("Go/C 指令长度表一致，共校验 %d 条", checked)
}

func TestDisasmAllTerminates(t *testing.T) {
	code := []byte{
		OpLea, 64, 0, 0xFF, 1, 8, 0, 0, 0, 0,
		OpAluRR, 1, 64, 0, 0, 1,
		OpAluRI, 0, 64, 0, 0, 0x2a, 0, 0, 0,
		OpAluRI, 4, 8, 0, 0, 0xFF, 0, 0, 0,
		OpRet,
	}
	lines := DisasmAll(code)
	if len(lines) != 5 {
		t.Fatalf("期望 5 条指令，得到 %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[4], "RET") {
		t.Errorf("最后一条应当是 RET: %v", lines)
	}
}

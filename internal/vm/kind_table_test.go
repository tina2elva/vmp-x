package vm

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
)

// C 头文件里的 K_* 必须与 Go 侧（IR 的 Kind 与参考实现的 K*）逐一对上。
//
// 由来：我加 kind 时在列表中间插入，导致 BT/BSF/BSR 取值整体错位、两个已有单测立刻红灯。
// 这种靠顺序维持的对应关系必须有守卫（与操作码表的交叉校验测试同理）。
func TestKindTableMatchesC(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "stub", "win", "x64", "vm_opcodes.h"))
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	cvals := map[string]uint8{}
	for _, line := range strings.Split(string(data), "\n") {
		// 一行里可能声明多个（K_ADC = 0x0B, K_SBB = 0x0C,），所以按逗号切开逐个看
		for _, part := range strings.Split(line, ",") {
			// 先砍掉行尾注释（K_LZCNT = 0x12, /* … */ K_MULHIS = 0x13 这种排布会把它带进来）
			if i := strings.Index(part, "/*"); i >= 0 {
				part = part[:i]
			}
			part = strings.TrimSpace(part)
			if i := strings.Index(part, "K_"); i > 0 {
				part = part[i:]
			}
			eq := strings.Index(part, "=")
			if eq < 0 || !strings.HasPrefix(part, "K_") {
				continue
			}
			name := strings.TrimSpace(part[:eq])
			val := strings.TrimSpace(part[eq+1:])
			if len(val) < 3 || val[0] != '0' || (val[1] != 'x' && val[1] != 'X') {
				continue
			}
			n, perr := strconv.ParseUint(val[2:], 16, 8)
			if perr != nil {
				continue
			}
			cvals[name] = uint8(n)
		}
	}
	if len(cvals) == 0 {
		t.Fatal("没有从 C 头文件里解析到任何显式 K_* 常量")
	}
	checks := []struct {
		cname string
		irv   ir.Kind
		refv  uint32
	}{
		{"K_ADC", ir.Adc, KAdc},
		{"K_SBB", ir.Sbb, KSbb},
		{"K_MULHI", ir.MulHi, KMulHi},
		{"K_BT", ir.Bt, KBt},
		{"K_BSF", ir.Bsf, KBsf},
		{"K_BSR", ir.Bsr, KBsr},
		{"K_TZCNT", ir.Tzcnt, KTzcnt},
		{"K_LZCNT", ir.Lzcnt, KLzcnt},
		{"K_MULHIS", ir.MulHiS, KMulHiS},
	}
	for _, c := range checks {
		cv, ok := cvals[c.cname]
		if !ok {
			t.Errorf("C 头文件里没有显式值 %s", c.cname)
			continue
		}
		if uint8(c.irv) != cv {
			t.Errorf("%s: C=%d，IR Kind=%d —— 必须一致", c.cname, cv, uint8(c.irv))
		}
		if uint8(c.refv) != cv {
			t.Errorf("%s: C=%d，参考实现 K*=%d —— 必须一致", c.cname, cv, c.refv)
		}
	}
}

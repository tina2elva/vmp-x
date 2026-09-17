package arm64

import (
	"encoding/binary"
	"math/rand"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

// 从参考解码器打印的文本里取出逻辑立即数（形如 "AND X0, X1, #0xff" / "#0x1010..."）
func refImm(text string) (uint64, bool) {
	i := strings.LastIndex(text, "#")
	if i < 0 {
		return 0, false
	}
	s := strings.TrimSpace(text[i+1:])
	// 去掉可能的移位后缀（本测试只采样纯立即数形式）
	if j := strings.IndexAny(s, " ,"); j >= 0 {
		s = s[:j]
	}
	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func TestDecodeBitMasksAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(4711))
	checked, skipped, bad, reserved := 0, 0, 0, 0
	for i := 0; i < 60000; i++ {
		// 生成逻辑立即数形式的编码：AND/ORR/EOR/ANDS (immediate)
		var w uint32
		switch i % 2 {
		case 0:
			w = 0x12000000 | rng.Uint32()&0x1FFFFFE0
		default:
			w = 0x92000000 | rng.Uint32()&0x1FFFFFE0
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, w)
		ref, err := arm64asm.Decode(b)
		if err != nil {
			skipped++
			continue
		}
		// 只测真正的逻辑立即数：Rn=31 的形式会被打印成 MOV/MVN 别名，
		// 而那些可能来自 MOVZ/MOVN（移动立即数），不是位掩码。
		if (w>>5)&31 == 31 {
			skipped++
			continue
		}
		switch ref.Op {
		case arm64asm.AND, arm64asm.ORR, arm64asm.EOR, arm64asm.ANDS, arm64asm.TST, arm64asm.BIC, arm64asm.ORN, arm64asm.EON:
		default:
			skipped++
			continue
		}
		want, ok := refImm(ref.String())
		if !ok {
			skipped++
			continue
		}
		is64 := w&(1<<31) != 0
		n := (w >> 22) & 1
		immr := (w >> 16) & 0x3F
		imms := (w >> 10) & 0x3F
		// 架构规定：逻辑立即数里 S 全 1 是**保留**编码（会生成无用的全 1 掩码）→ UNDEFINED。
		// 参考解码器对此偏宽松、仍会打印；这类用例不计入比对（我的实现按架构拒绝）。
		field := (n << 6) | ((^imms) & 0x3F)
		length := 0
		for i := 31; i >= 0; i-- {
			if field&(1<<uint(i)) != 0 {
				length = i
				break
			}
		}
		if length >= 1 {
			lvl := (uint32(1) << uint(length)) - 1
			if imms&lvl == lvl {
				reserved++
				continue
			}
		}
		got, err := decodeBitMasks(n, immr, imms, is64)
		if err != nil {
			bad++
			if bad <= 5 {
				t.Errorf("0x%08X (%s): 我的解码失败: %v", w, ref.String(), err)
			}
			continue
		}
		// 32 位形式：参考打印的是 32 位值
		if !is64 {
			got &= 0xFFFFFFFF
		}
		if got != want {
			bad++
			if bad <= 5 {
				t.Errorf("0x%08X (%s): 我得到 0x%X，参考 0x%X", w, ref.String(), got, want)
			}
		}
		checked++
	}
	t.Logf("位掩码立即数解码与参考一致: 校验 %d 条，跳过 %d 条（其中架构保留编码 %d 条），不一致 %d 条",
		checked, skipped, reserved, bad)
	if bad != 0 {
		t.Fatalf("不一致 %d 条", bad)
	}
}

// 锚点：指令字与期望值都取自参考解码器的输出（不是我自己推的编码）
func TestDecodeBitMasksAnchors(t *testing.T) {
	cases := []struct {
		name string
		word uint32
		is64 bool
		want uint64
	}{
		// arm64asm: AND W0, W12, #0xff8001ff （跨 32 位边界旋转的连续 1）
		{"AND W0, W12, #0xff8001ff", 0x12294580, false, 0xFF8001FF},
		// arm64asm: AND W0, W27, #0x44444444
		// 手推：N=0, imms=0b111000, immr=0b110010 → len=2 → levels=3、esize=4；
		// S = imms&3 = 0、R = immr&3 = 2 → welem=Ones(1) → ror(0b1,2,4)=0b0100 → 重复得 0x44444444
		{"AND W0, W27, #0x44444444", 0x1232E360, false, 0x44444444},
	}
	for _, c := range cases {
		n := (c.word >> 22) & 1
		immr := (c.word >> 16) & 0x3F
		imms := (c.word >> 10) & 0x3F
		got, err := decodeBitMasks(n, immr, imms, c.is64)
		if err != nil {
			t.Errorf("%s: 解码失败 %v", c.name, err)
			continue
		}
		if !c.is64 {
			got &= 0xFFFFFFFF
		}
		if got != c.want {
			t.Errorf("%s: 得到 0x%X，期望 0x%X", c.name, got, c.want)
		}
	}
}

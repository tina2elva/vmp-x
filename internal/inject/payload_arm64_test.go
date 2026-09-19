package inject

import (
	"testing"

	arm64dec "github.com/vmpx/vmp-x/internal/decode/arm64"
)

// AArch64 版的入口解密蹦床没有真机可跑，所以用**仓库自带的 AArch64 解码器**逐条核对编码：
// 助记符、ADRP/BL/B 的 PC 相对目标、ADD/CBZ 的立即数。编码写错在这里就会被抓住。
func TestARM64UnpackTrampoline(t *testing.T) {
	const hookRVA = uint32(0x40001000)
	const tableRVA = uint32(0x40003AE0) // 与 hook 不同页，顺便验证 adrp 的页内偏移拆分
	const unpackRVA = uint32(0x40005200)
	const nextRVA = uint32(0x40001800)

	code := buildImgHookARM64(hookRVA, tableRVA, unpackRVA, nextRVA)
	if len(code) != 48 {
		t.Fatalf("长度 = %d 字节，期望 48（12 条指令）", len(code))
	}
	insns, err := arm64dec.DecodeRange(code, uint64(hookRVA), 0)
	if err != nil && len(insns) == 0 {
		t.Fatalf("解码失败: %v", err)
	}
	if len(insns) != 12 {
		t.Fatalf("解出 %d 条指令，期望 12", len(insns))
	}
	want := []string{"MOV", "MOV", "MOV", "ADRP", "ADD", "BL", "CBZ", "BRK", "MOV", "MOV", "MOV", "B"}
	for i, w := range want {
		if got := insns[i].Op.String(); got != w {
			t.Fatalf("第 %d 条是 %s，期望 %s（%s）", i, got, w, insns[i].Text())
		}
	}
	// adrp 的目标必须是表的整页地址
	if tgt, ok := insns[3].PCRelTarget(); !ok || uint32(tgt) != tableRVA&^0xFFF {
		t.Fatalf("adrp 目标 = 0x%X(ok=%v)，期望 0x%X", tgt, ok, tableRVA&^0xFFF)
	}
	// add 的立即数必须是表地址的低 12 位
	if !hasImm(insns[4], int64(tableRVA&0xFFF)) {
		t.Fatalf("add 里找不到立即数 0x%X：%s", tableRVA&0xFFF, insns[4].Text())
	}
	if tgt, ok := insns[5].PCRelTarget(); !ok || uint32(tgt) != unpackRVA {
		t.Fatalf("bl 目标 = 0x%X(ok=%v)，期望 0x%X", tgt, ok, unpackRVA)
	}
	if !hasImm(insns[6], 8) {
		t.Fatalf("cbz 的偏移不是 +8：%s", insns[6].Text())
	}
	if tgt, ok := insns[11].PCRelTarget(); !ok || uint32(tgt) != nextRVA {
		t.Fatalf("b 目标 = 0x%X(ok=%v)，期望 0x%X", tgt, ok, nextRVA)
	}
}

// hasImm：立即数在 Args 里的位置随指令形态不同，这里扫一遍（够用且不脆）。
func hasImm(in arm64dec.Insn, want int64) bool {
	for i := 0; i < len(in.Args); i++ {
		if v, ok := in.Imm(i); ok && v == want {
			return true
		}
	}
	return false
}

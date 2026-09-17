package x64

import (
	"encoding/binary"
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
)

// buildSwitchImage 合成一个 switch 的跳转表形态（函数体与表分开：真实二进制里表在 .rdata）：
//
//	+0x00 cmp  %rcx,3           48 83 F9 03
//	+0x04 ja   default          77 1F
//	+0x06 jmp  *table(%rip)     FF 24 25 <disp32>
//	+0x0D case0: mov $10,%rax ; ret
//	+0x15 case1: mov $20,%rax ; ret
//	+0x1D case2: mov $30,%rax ; ret
//	+0x25 default: mov $99,%rax ; ret
//	+0x100 表（3 个 8 字节绝对地址）
func buildSwitchImage(base uint64, withGuard bool) (body []byte, full []byte) {
	var c []byte
	if withGuard {
		c = append(c, 0x48, 0x83, 0xF9, 0x03) // cmp %rcx,3
		c = append(c, 0x73, 0x1F)             // jae default(0x25)（3 项：0..2）
	}
	at := uint64(len(c))
	disp := int32((base + 0x100) - (base + at + 7))
	// ModRM=24(/4 → JMP r/m64)，SIB=CD：scale=8、index=rcx、base=RIP
	c = append(c, 0xFF, 0x24, 0xCD)
	d4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(d4, uint32(disp))
	c = append(c, d4...)
	mov := func(v uint32) {
		c = append(c, 0x48, 0xC7, 0xC0)
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, v)
		c = append(c, b...)
		c = append(c, 0xC3)
	}
	mov(10)
	mov(20)
	mov(30)
	mov(99)
	body = append([]byte(nil), c...)
	for len(c) < 0x100 {
		c = append(c, 0x90)
	}
	for _, off := range []uint64{0x0D, 0x15, 0x1D} {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, base+off)
		c = append(c, b...)
	}
	return body, c
}

func TestLiftJumpTable(t *testing.T) {
	const base = 0x1000
	body, full := buildSwitchImage(base, true)
	l := NewLifter(base)
	l.SetImageReader(func(rva uint32, n int) []byte {
		off := int(rva)
		if off < 0 || off+n > len(full) {
			return nil
		}
		return full[off : off+n]
	})
	fn, err := l.LiftFunc("sw", body, 0)
	if err != nil {
		for _, u := range fn.Unsupported {
			t.Logf("拒绝: %s", u)
		}
		t.Fatalf("跳转表未翻译: %v", err)
	}
	cmpCount, jccCount := 0, 0
	for _, in := range fn.Insns {
		if in.Op == ir.CmpRI {
			cmpCount++
		}
		if in.Op == ir.Jcc {
			jccCount++
		}
	}
	// 3 组"cmp idx,i ; je case_i"来自合成分支；再加上源码里的 cmp/jae 各一条
	if cmpCount != 4 || jccCount != 4 {
		t.Fatalf("比较链不对：cmp=%d jcc=%d（期望 4/4 = 3 组合成 + 源码的 cmp/jae）", cmpCount, jccCount)
	}
}

// 没有守卫（cmp+ja）时必须拒绝，而不是猜
func TestLiftJumpTableRequiresGuard(t *testing.T) {
	const base = 0x1000
	body, full := buildSwitchImage(base, false)
	l := NewLifter(base)
	l.SetImageReader(func(rva uint32, n int) []byte {
		off := int(rva)
		if off < 0 || off+n > len(full) {
			return nil
		}
		return full[off : off+n]
	})
	fn, err := l.LiftFunc("sw", body, 0)
	if err == nil {
		t.Fatal("没有边界检查的跳转表应当被拒绝")
	}
	if fn == nil || len(fn.Unsupported) == 0 {
		t.Fatal("拒绝原因应当被记录")
	}
}

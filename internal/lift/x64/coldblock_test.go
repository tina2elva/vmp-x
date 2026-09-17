package x64

import (
	"encoding/binary"
	"testing"

	"github.com/vmpx/vmp-x/internal/ir"
)

// 冷块（孤岛）支持：函数主体的某个分支目标落在**函数范围之外**，
// 但它是同一镜像里可识别的代码（以 RET/JMP 结束）——应当被当成孤岛一起翻译。
func TestLiftColdBlockIsland(t *testing.T) {
	const (
		imageVA = 0x1000 // 镜像基址
		bodyVA  = 0x2000 // 函数主体 VA
		coldVA  = 0x3000 // 冷块 VA（远在函数之外）
	)
	imgSize := int(coldVA-imageVA) + 0x100
	img := make([]byte, imgSize)
	put := func(va uint64, b []byte) {
		off := int(va - imageVA)
		copy(img[off:], b)
	}

	// 主体：test %rcx,%rcx ; je cold ; mov $1,%eax ; ret
	body := []byte{
		0x48, 0x85, 0xC9, // +0x00 test %rcx,%rcx
		0x0F, 0x84, 0, 0, 0, 0, // +0x03 je rel32（PC 从 +0x0A 算起）
		0xB8, 0x01, 0x00, 0x00, 0x00, // +0x09 mov $1,%eax
		0xC3, // +0x0E ret
	}
	// je rel32 位于 +0x03，长 6 字节 → 位移从下一条指令（+0x09）算起
	rel := int32(int64(coldVA) - int64(bodyVA+9))
	binary.LittleEndian.PutUint32(body[5:], uint32(rel))
	put(bodyVA, body)

	// 冷块：mov $2,%eax ; ret
	put(coldVA, []byte{0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3})

	l := NewLifter(imageVA)
	l.SetImageReader(func(rva uint32, n int) []byte {
		off := int(rva) // rva 是相对 ImageBase 的
		if off < 0 || off+n > len(img) {
			return nil
		}
		return img[off : off+n]
	})
	// 先直接验一下孤岛提取本身
	if ic, ok := l.readIsland(uint32(coldVA-imageVA), 256); !ok {
		t.Fatalf("readIsland 没读出冷块（rva=0x%X）", coldVA-imageVA)
	} else {
		t.Logf("readIsland 读出 %d 字节: % X", len(ic), ic)
	}
	fn, err := l.LiftFunc("cold", body, uint32(bodyVA-imageVA))
	for _, d := range l.Debug {
		t.Logf("debug: %s", d)
	}
	if err != nil {
		t.Fatalf("冷块没被翻译: %v", err)
	}
	movs := 0
	for _, in := range fn.Insns {
		if in.Op == ir.MovRI {
			movs++
		}
	}
	if movs < 2 {
		t.Fatalf("冷块的 IR 没有被追加进来（MovRI=%d）", movs)
	}
	for _, in := range fn.Insns {
		if (in.Op == ir.Jcc || in.Op == ir.Jmp) && (in.Target < 0 || in.Target >= len(fn.Insns)) {
			t.Fatalf("分支目标没有解析: %+v", in)
		}
	}
}

// 目标落在镜像之外（读不到代码）时必须**明确拒绝**，而不是当成冷块硬塞
func TestLiftColdBlockRejectsBadTarget(t *testing.T) {
	const (
		imageVA = 0x1000
		bodyVA  = 0x2000
	)
	img := make([]byte, 0x1000)
	body := []byte{
		0x48, 0x85, 0xC9, // test
		0x0F, 0x84, 0, 0, 0, 0, // je rel32
		0xB8, 0x01, 0x00, 0x00, 0x00, // mov $1,%eax
		0xC3, // ret
	}
	binary.LittleEndian.PutUint32(body[5:], uint32(int32(0x40000))) // 远到镜像之外
	copy(img[bodyVA-imageVA:], body)
	l := NewLifter(imageVA)
	l.SetImageReader(func(rva uint32, n int) []byte {
		if int(rva)+n > len(img) {
			return nil
		}
		return img[rva : int(rva)+n]
	})
	if _, err := l.LiftFunc("bad", body, uint32(bodyVA-imageVA)); err == nil {
		t.Fatal("读不到目标代码时应当拒绝")
	}
}

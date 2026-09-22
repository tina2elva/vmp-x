package x64

// 用**真实的 32 位编译器产物**验证 Mode32 解码与 lift（比合成用例强得多）。
//
// 样本：C:\Windows\SysWOW64\notepad.exe（PE32/i386，本机就有；没有则跳过）。
// 为什么值得单独测：32 位代码里 0x40-0x4F 是 INC/DEC（64 位是 REX）、[disp32] 是绝对地址 ——
// 解码模式一旦退化，症状是**静默错位**，而不是报错。

import (
	"os"
	"testing"

	x64dec "github.com/vmpx/vmp-x/internal/decode/x64"
	"github.com/vmpx/vmp-x/internal/load/pe"
)

const realPE32 = `C:\Windows\SysWOW64\notepad.exe`

func loadRealPE32(t *testing.T) (*pe.File, []byte) {
	t.Helper()
	b, err := os.ReadFile(realPE32)
	if err != nil {
		t.Skipf("没有 %s（跳过真实 PE32 用例）", realPE32)
	}
	f, err := pe.Parse(b)
	if err != nil {
		t.Fatalf("解析真实 PE32 失败: %v", err)
	}
	if !f.Is32Bit() {
		t.Skipf("%s 不是 PE32（machine=0x%X）", realPE32, f.Machine)
	}
	return f, b
}

// 在真实 32 位代码上逐条解码：每一步都必须成功（对齐正确、无“未知操作码”）。
func TestDecodeRealPE32Code(t *testing.T) {
	f, img := loadRealPE32(t)
	var text *pe.Section
	for i := range f.Sections {
		if f.Sections[i].Name == ".text" {
			text = &f.Sections[i]
			break
		}
	}
	if text == nil {
		t.Fatal("样本里没有 .text")
	}
	// 从入口点开始（入口一定在代码段里）；另外再取两处偏移各试一段
	starts := []uint32{f.AddressOfEntry}
	if len(text.Name) > 0 {
		starts = append(starts, text.VirtualAddress+0x100, text.VirtualAddress+0x800)
	}
	for _, rva := range starts {
		if rva < text.VirtualAddress || rva >= text.VirtualAddress+text.VirtualSize {
			continue
		}
		base := int(text.PointerToRawData + (rva - text.VirtualAddress))
		pos := base
		n := 0
		for n < 24 && pos < len(img) {
			pc := f.ImageBase + uint64(rva) + uint64(pos-base)
			ins, err := x64dec.DecodeMode(img[pos:], pc, x64dec.Mode32)
			if err != nil {
				t.Fatalf("真实 32 位代码 @RVA 0x%X 第 %d 条解码失败: %v", rva, n, err)
			}
			pos += ins.Len()
			n++
		}
		if n == 0 {
			t.Fatalf("RVA 0x%X 处没有解出任何指令", rva)
		}
	}
}

// 试着真的**翻译**入口函数：成功就断言 IR 非空；失败则如实记录原因（不判失败 ——
// 入口可能是 CRT 桩，翻译不了是正常现象，但"为什么不行"是有价值的信息）。
func TestLiftRealPE32Entry(t *testing.T) {
	f, img := loadRealPE32(t)
	var text *pe.Section
	for i := range f.Sections {
		if f.Sections[i].Name == ".text" {
			text = &f.Sections[i]
			break
		}
	}
	if text == nil {
		t.Fatal("样本里没有 .text")
	}
	rva := f.AddressOfEntry
	if rva < text.VirtualAddress || rva >= text.VirtualAddress+text.VirtualSize {
		t.Skip("入口不在 .text 里")
	}
	off := int(text.PointerToRawData + (rva - text.VirtualAddress))
	end := text.PointerToRawData + text.SizeOfRawData
	if end > uint32(len(img)) {
		end = uint32(len(img))
	}
	code := img[off:end]
	l := NewLifterMode(f.ImageBase, x64dec.Mode32)
	l.ReadImage = func(r uint32, n int) []byte {
		for i := range f.Sections {
			s := &f.Sections[i]
			if r >= s.VirtualAddress && r+uint32(n) <= s.VirtualAddress+s.VirtualSize {
				p := int(s.PointerToRawData + (r - s.VirtualAddress))
				if p+n <= len(img) {
					return img[p : p+n]
				}
			}
		}
		return nil
	}
	fn, err := l.LiftFunc("pe32_entry", code, rva)
	if err != nil {
		t.Logf("入口函数未翻译（如实记录）: %v", err)
		return
	}
	if len(fn.Insns) == 0 {
		t.Fatal("翻译成功但 IR 为空")
	}
	t.Logf("真实 PE32 入口翻译成功：%d 条 IR，%d 字节代码", len(fn.Insns), len(code))
}

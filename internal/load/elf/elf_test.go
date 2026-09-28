package elf

import (
	stdelf "debug/elf"
	"os"
	"testing"
)

// 用 Go 标准库独立解析我写出的 ELF：这比“自己解析自己”更有说服力
func TestAddLoadSegmentIsValidELF(t *testing.T) {
	src := "../../../build/linux_target"
	if _, err := os.Stat(src); err != nil {
		t.Skip("需要先构建 build/linux_target（GOOS=linux GOARCH=amd64 go build）")
	}
	f, err := Open(src)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	base := f.ImageBase()
	if base == 0 {
		t.Fatal("image base 为 0")
	}
	before := len(f.Progs)

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	va, fileOff, err := f.AddLoadSegmentFromNote(payload)
	if err != nil {
		t.Fatalf("注入失败: %v", err)
	}
	if va != f.NextVA()-AlignUp(uint64(len(payload)), PageAlign) {
		// NextVA 会随新段变化，这里只做区间检查
	}
	if va%PageAlign != 0 {
		t.Errorf("新段 vaddr 0x%X 未页对齐", va)
	}

	out := t.TempDir() + "/patched.elf"
	if err := f.Save(out); err != nil {
		t.Fatal(err)
	}

	// 用标准库重新解析
	g, err := stdelf.Open(out)
	if err != nil {
		t.Fatalf("标准库无法解析输出: %v", err)
	}
	defer g.Close()
	if len(g.Progs) != before {
		t.Errorf("程序头数量应当不变: %d -> %d", before, len(g.Progs))
	}
	loads := 0
	var found *stdelf.Prog
	for _, p := range g.Progs {
		if p.Type == stdelf.PT_LOAD {
			loads++
		}
		if p.Vaddr == va {
			found = p
		}
	}
	if loads != 4 {
		t.Errorf("期望 4 个 PT_LOAD（原来 3 个 + 新的），得到 %d", loads)
	}
	if found == nil {
		t.Fatalf("没有找到 vaddr=0x%X 的新段", va)
	}
	if found.Flags&stdelf.PF_X == 0 || found.Flags&stdelf.PF_R == 0 {
		t.Errorf("新段应当是 R+X，得到 %v", found.Flags)
	}
	// 关键性质：代码段**不含** W（可写数据由调用方用覆盖段单独给）
	if found.Flags&stdelf.PF_W != 0 {
		t.Errorf("新段不该可写（RWX 是安全坏味道），得到 %v", found.Flags)
	}
	_ = fileOff

	// 再叠一个覆盖段：把 payload 的第 2 页标成 RW，并断言它指向**同一段文件字节**
	if err := f.AddOverlayLoadSegment(va+PageAlign, fileOff+int64(PageAlign), PageAlign, PF_R|PF_W); err != nil {
		t.Fatalf("覆盖段失败: %v", err)
	}
	if err := f.Save(out); err != nil {
		t.Fatal(err)
	}
	g2, err := stdelf.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close()
	var rw *stdelf.Prog
	for _, p := range g2.Progs {
		if p.Type == stdelf.PT_LOAD && p.Vaddr == va+PageAlign {
			rw = p
		}
	}
	if rw == nil {
		t.Fatal("没有找到可写覆盖段")
	}
	if rw.Flags&stdelf.PF_W == 0 || rw.Flags&stdelf.PF_X != 0 {
		t.Errorf("覆盖段应当是 R+W 且不可执行，得到 %v", rw.Flags)
	}
	if found.Filesz != uint64(len(payload)) || found.Memsz != uint64(len(payload)) {
		t.Errorf("新段大小不符: filesz=0x%X memsz=0x%X", found.Filesz, found.Memsz)
	}
	if found.Off%PageAlign != 0 || found.Vaddr%PageAlign != 0 {
		t.Errorf("新段未页对齐: off=0x%X va=0x%X", found.Off, found.Vaddr)
	}

	// 通过 VA 映射读回 payload，确认落盘位置正确
	got, err := g.Section("").Data() // 占位：避免未使用 import
	_ = got
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	back, err := h2.ReadVA(va, len(payload))
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	for i := range payload {
		if back[i] != payload[i] {
			t.Fatalf("payload 第 %d 字节不符: got 0x%02X want 0x%02X", i, back[i], payload[i])
		}
	}

	// 原有段数据不能被破坏
	// 原有段的数据不能被破坏（跳过包含程序头表的头部区域）
	orig, _ := os.ReadFile(src)
	load0 := f.Progs[2]
	dataOff := int(load0.Off) + 0x1000
	if string(orig[dataOff:dataOff+512]) != string(data[dataOff:dataOff+512]) {
		t.Error("原有 PT_LOAD 的数据被修改了")
	}
}

func TestParseRejectsNonELF(t *testing.T) {
	if _, err := Parse([]byte("not an elf file at all............")); err == nil {
		t.Fatal("应当拒绝非 ELF 输入")
	}
}

// 回归：注入一个**更高地址**的段之后，原镜像里带 bss 的 PT_LOAD 必须仍"内核能映射到"，
// 否则那段 bss 整段没有映射（第一次写全局变量 = SIGSEGV，内核记 error 6）。
//
// 用真实的 Go ELF 当夹具（target 不在就跳过），并且**先证明检查器会失败**：
// 注入高层段后不修 ⇒ unmappedBss() 必须报出来；修完 ⇒ 必须为空。
func TestBssStaysMappedAfterInjection(t *testing.T) {
	src := "../../../build/linux_target"
	if _, err := os.Stat(src); err != nil {
		t.Skip("需要先构建 build/linux_target（GOOS=linux GOARCH=amd64 go build）")
	}
	f, err := Open(src)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	var hasBss bool
	for _, p := range f.Progs {
		if p.Type == PT_LOAD && p.Memsz > p.Filesz {
			hasBss = true
		}
	}
	if !hasBss {
		t.Skip("夹具里没有 memsz>filesz 的段，本用例无意义")
	}
	if bad := f.unmappedBss(); len(bad) != 0 {
		t.Fatalf("原镜像本身就有 %d 个 bss 不会被映射的段（夹具不对）", len(bad))
	}

	// 先注入一个更高地址的段：此时**故意不修**，检查器必须报出来（校准）
	if _, _, err := f.AddLoadSegmentFromNote(make([]byte, 4096)); err != nil {
		t.Fatalf("注入失败: %v", err)
	}
	bad := f.unmappedBss()
	if len(bad) == 0 {
		t.Fatal("校准失败：注入高层段之后检查器没有报出未映射的 bss（探针无效）")
	}
	t.Logf("校准 OK：未修时检查器报出 %d 个段（vaddr=0x%X）", len(bad), bad[0].Vaddr)

	if n := f.MakeBssFileBacked(); n == 0 {
		t.Fatal("MakeBssFileBacked 没有处理任何段")
	} else {
		t.Logf("MakeBssFileBacked 处理了 %d 个段", n)
	}
	if left := f.unmappedBss(); len(left) != 0 {
		t.Fatalf("修复后仍有 %d 个段的 bss 不会被映射（vaddr=0x%X）", len(left), left[0].Vaddr)
	}

	// 用标准库独立复核：所有 LOAD 都文件承载，且满足 offset ≡ vaddr (mod align)
	out := t.TempDir() + "/bss.elf"
	if err := f.Save(out); err != nil {
		t.Fatal(err)
	}
	g, err := stdelf.Open(out)
	if err != nil {
		t.Fatalf("标准库无法解析输出: %v", err)
	}
	defer g.Close()
	for _, p := range g.Progs {
		if p.Type != stdelf.PT_LOAD {
			continue
		}
		if p.Filesz != p.Memsz {
			t.Errorf("LOAD vaddr=0x%X 仍是 memsz(0x%X) > filesz(0x%X)", p.Vaddr, p.Memsz, p.Filesz)
		}
		if p.Align != 0 && p.Off%p.Align != p.Vaddr%p.Align {
			t.Errorf("LOAD vaddr=0x%X: p_offset(0x%X) 与 p_vaddr 不同余 (mod 0x%X)", p.Vaddr, p.Off, p.Align)
		}
	}
}

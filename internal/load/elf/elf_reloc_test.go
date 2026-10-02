package elf

import (
	"encoding/binary"
	"os"
	"testing"
)

// synthPIE 造一个最小的 ET_DYN(PIE)：一个覆盖全文件的 PT_LOAD + 一个 PT_DYNAMIC，
// 动态表里给出 DT_RELA/DT_RELASZ/DT_RELAENT，重定位表里放 2 条 R_X86_64_RELATIVE
// 和 1 条非相对重定位。槽位值按**链接期形式**写（= r_addend），与实测的 Go PIE 一致。
//
// 为什么不用现成的产物当夹具：负载测试跑在没有交叉工具链的机器上（go test 是独立可验的），
// 这条用例必须**无条件**跑起来；真实产物那条见 TestRelativeRelocsRealPIE。
func synthPIE(t *testing.T) []byte {
	const loadVA = uint64(0x400000)
	const dynOff = uint64(0x1000)
	const relaOff = uint64(0x2000)
	const slotVA = uint64(0x401500)
	data := make([]byte, 0x3000)

	copy(data[0:], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(data[16:], ET_DYN)
	binary.LittleEndian.PutUint16(data[18:], EM_X86_64)
	binary.LittleEndian.PutUint64(data[24:], loadVA+0x800) // e_entry
	binary.LittleEndian.PutUint64(data[32:], 64)           // e_phoff
	binary.LittleEndian.PutUint16(data[52:], EhdrSize)
	binary.LittleEndian.PutUint16(data[54:], PhdrSize)
	binary.LittleEndian.PutUint16(data[56:], 2)

	putPhdr := func(i int, typ, flags uint32, off, va, filesz, memsz uint64) {
		o := 64 + i*PhdrSize
		binary.LittleEndian.PutUint32(data[o:], typ)
		binary.LittleEndian.PutUint32(data[o+4:], flags)
		binary.LittleEndian.PutUint64(data[o+8:], off)
		binary.LittleEndian.PutUint64(data[o+16:], va)
		binary.LittleEndian.PutUint64(data[o+24:], va)
		binary.LittleEndian.PutUint64(data[o+32:], filesz)
		binary.LittleEndian.PutUint64(data[o+40:], memsz)
		binary.LittleEndian.PutUint64(data[o+48:], PageAlign)
	}
	putPhdr(0, PT_LOAD, PF_R, 0, loadVA, uint64(len(data)), uint64(len(data)))
	putPhdr(1, PT_DYNAMIC, PF_R, dynOff, loadVA+dynOff, 0x80, 0x80)

	putDyn := func(i int, tag, val uint64) {
		o := int(dynOff) + i*16
		binary.LittleEndian.PutUint64(data[o:], tag)
		binary.LittleEndian.PutUint64(data[o+8:], val)
	}
	putDyn(0, DT_RELA, loadVA+relaOff)
	putDyn(1, DT_RELASZ, 3*RelaEntrySize)
	putDyn(2, DT_RELAENT, RelaEntrySize)
	putDyn(3, DT_NULL, 0)

	putRela := func(i int, off uint64, typ uint32, addend uint64) {
		o := int(relaOff) + i*RelaEntrySize
		binary.LittleEndian.PutUint64(data[o:], off)
		binary.LittleEndian.PutUint64(data[o+8:], uint64(typ)) // sym=0
		binary.LittleEndian.PutUint64(data[o+16:], addend)
	}
	putRela(0, slotVA, R_X86_64_RELATIVE, slotVA)
	putRela(1, slotVA+8, R_X86_64_RELATIVE, slotVA+0x100)
	putRela(2, slotVA+0x40, 7 /* R_X86_64_JUMP_SLOT */, 0)

	// 槽位值 = 链接期形式（= r_addend），和实测的真实 PIE 一致
	binary.LittleEndian.PutUint64(data[slotVA-loadVA:], slotVA)
	binary.LittleEndian.PutUint64(data[slotVA-loadVA+8:], slotVA+0x100)
	return data
}

func TestDynRelocsSynthetic(t *testing.T) {
	f, err := Parse(synthPIE(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	all, err := f.DynRelocs()
	if err != nil {
		t.Fatalf("DynRelocs: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("动态重定位条数 = %d，期望 3", len(all))
	}
	if all[0].Offset != 0x401500 || all[0].Type != R_X86_64_RELATIVE || all[0].Addend != 0x401500 {
		t.Errorf("第 0 条解析错: %+v", all[0])
	}
	if all[2].Type != 7 || all[2].Addend != 0 {
		t.Errorf("第 2 条（非相对）解析错: %+v", all[2])
	}

	rel, err := f.RelativeRelocs()
	if err != nil {
		t.Fatalf("RelativeRelocs: %v", err)
	}
	if len(rel) != 2 {
		t.Fatalf("相对重定位条数 = %d，期望 2（非相对的要被丢掉）", len(rel))
	}
	if in := RelocsInVA(rel, 0x401000, 0x401500); len(in) != 0 {
		t.Errorf("[0x401000,0x401500) 里不该有条目，得到 %d 条", len(in))
	}
	if in := RelocsInVA(rel, 0x401500, 0x401508); len(in) != 1 {
		t.Errorf("[0x401500,0x401508) 里应当只有 1 条，得到 %d 条", len(in))
	}
	v, err := f.SlotValue(0x401500)
	if err != nil || v != 0x401500 {
		t.Errorf("SlotValue = 0x%X (err=%v)，期望 0x401500", v, err)
	}
}

// 校准：槽位被"预重定位过"（值已经加过基址）时，NormalizeRelocSlots 必须先减回链接期形式。
// 这是"先减"那一步的可失败校准 —— 用合成 PIE 自己构造缺陷，不依赖外部产物。
func TestNormalizeRelocSlotsCalibration(t *testing.T) {
	f, err := Parse(synthPIE(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	rel, err := f.RelativeRelocs()
	if err != nil {
		t.Fatalf("RelativeRelocs: %v", err)
	}
	// 未构造缺陷时必须是 no-op（真实 RELA 目标就是这样）
	if n, err := f.NormalizeRelocSlots(rel); err != nil || n != 0 {
		t.Fatalf("干净输入应改写 0 个槽位，得到 %d (err=%v)", n, err)
	}
	// 构造缺陷：把槽位改成"已经加过首选基址"的值
	badOff, err := f.VAtoOffset(rel[0].Offset)
	if err != nil {
		t.Fatal(err)
	}
	bad := uint64(rel[0].Addend) + f.ImageBase()
	binary.LittleEndian.PutUint64(f.Data[badOff:], bad)
	if v, _ := f.SlotValue(rel[0].Offset); v == uint64(rel[0].Addend) {
		t.Fatal("校准失败：缺陷没有真的写进去")
	}
	n, err := f.NormalizeRelocSlots(rel)
	if err != nil {
		t.Fatalf("NormalizeRelocSlots: %v", err)
	}
	if n != 1 {
		t.Errorf("应当恰好改写 1 个槽位，得到 %d", n)
	}
	if v, _ := f.SlotValue(rel[0].Offset); v != uint64(rel[0].Addend) {
		t.Errorf("槽位没有减回链接期形式: 0x%X，期望 0x%X", v, rel[0].Addend)
	}
}

// fail-closed：动态表声明了重定位但表地址/尺寸是坏的，必须报错而不是当成"没有重定位"。
func TestDynRelocsFailsClosed(t *testing.T) {
	d := synthPIE(t)
	// DT_RELASZ（动态表第 1 项的 d_val，位于 0x1000+16+8）改成超出文件
	binary.LittleEndian.PutUint64(d[0x1018:], 0x7FFFFFFF)
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := f.DynRelocs(); err == nil {
		t.Fatal("越界的重定位表必须报错（静默当成没有 = 运行期把密文解成垃圾）")
	}
	if _, err := f.RelativeRelocs(); err == nil {
		t.Fatal("RelativeRelocs 也必须把错误透出去")
	}
	// DT_RELAENT 尺寸不对：同样必须报错
	d2 := synthPIE(t)
	binary.LittleEndian.PutUint64(d2[0x1028:], 32) // DT_RELAENT 的 d_val
	f2, err := Parse(d2)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := f2.DynRelocs(); err == nil {
		t.Fatal("DT_RELAENT=32 必须报错")
	}
}

// 真实产物上的独立复核（夹具不在就跳过）：ET_DYN 的 Go PIE 有一大把 R_X86_64_RELATIVE，
// 且**每个槽位都已经是链接期形式** —— 这正是打包端"先减"步骤在真实目标上是 no-op 的依据。
func TestRelativeRelocsRealPIE(t *testing.T) {
	for _, src := range []string{"../../../build/pie_target", "../../../build/elf_target_pie"} {
		if _, err := os.Stat(src); err != nil {
			continue
		}
		f, err := Open(src)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", src, err)
		}
		if f.EType != ET_DYN {
			t.Fatalf("%s 不是 ET_DYN（e_type=%d）", src, f.EType)
		}
		rel, err := f.RelativeRelocs()
		if err != nil {
			t.Fatalf("%s: RelativeRelocs: %v", src, err)
		}
		if len(rel) == 0 {
			t.Fatalf("%s：PIE 应当有相对重定位，得到 0 条（探针无效）", src)
		}
		for _, r := range rel {
			o, err := f.VAtoOffset(r.Offset)
			if err != nil {
				t.Fatalf("%s: r_offset 0x%X 不在任何 PT_LOAD 里: %v", src, r.Offset, err)
			}
			if got := binary.LittleEndian.Uint64(f.Data[o:]); got != uint64(r.Addend) {
				t.Fatalf("%s: r_offset 0x%X 槽位 0x%X != addend 0x%X（不是链接期形式）",
					src, r.Offset, got, r.Addend)
			}
		}
		t.Logf("%s: %d 条相对重定位，槽位全部是链接期形式", src, len(rel))
		return
	}
	t.Skip("需要 build/pie_target（GOOS=linux GOARCH=amd64 go build -buildmode=pie）")
}

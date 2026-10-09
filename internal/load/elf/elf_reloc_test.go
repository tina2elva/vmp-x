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

// synthRelocs 造一个最小的 ET_DYN，可以带 DT_JMPREL（PLT/IFUNC 表）与 DT_RELR（压缩相对重定位）。
// 这两张表在 #597 复评（F4）之前**根本没被读**：守卫 2 因此对它们空转。用例里断言"读到了"
// 就是那条可失败校准 —— 旧实现下这些条目一条都不会出现。
func synthRelocs(t *testing.T, withJmp, withRelr bool) []byte {
	const loadVA = uint64(0x400000)
	const dynOff = uint64(0x1000)
	const relaOff = uint64(0x2000)
	const jmpRelOff = uint64(0x2100)
	const relrOff = uint64(0x2200)
	const slotVA = uint64(0x401500)
	data := make([]byte, 0x3000)

	copy(data[0:], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(data[16:], ET_DYN)
	binary.LittleEndian.PutUint16(data[18:], EM_X86_64)
	binary.LittleEndian.PutUint64(data[24:], loadVA+0x800)
	binary.LittleEndian.PutUint64(data[32:], 64)
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
	putPhdr(1, PT_DYNAMIC, PF_R, dynOff, loadVA+dynOff, 0x100, 0x100)

	i := 0
	putDyn := func(tag, val uint64) {
		o := int(dynOff) + i*16
		binary.LittleEndian.PutUint64(data[o:], tag)
		binary.LittleEndian.PutUint64(data[o+8:], val)
		i++
	}
	putRela := func(off uint64, dst uint64, typ uint32, addend uint64) {
		o := int(off)
		binary.LittleEndian.PutUint64(data[o:], dst)
		binary.LittleEndian.PutUint64(data[o+8:], uint64(typ))
		binary.LittleEndian.PutUint64(data[o+16:], addend)
	}
	putDyn(DT_RELA, loadVA+relaOff)
	putDyn(DT_RELASZ, RelaEntrySize)
	putDyn(DT_RELAENT, RelaEntrySize)
	putRela(relaOff, slotVA, R_X86_64_RELATIVE, slotVA)
	if withJmp {
		// 两条 PLT 条目：JUMP_SLOT（目标在可写段）与 IRELATIVE（r_offset 指向 **可执行段里的 PLT 桩**，
		// 也就是打包端的加密范围 —— 这正是"漏读 DT_JMPREL ⇒ 守卫空转"的真实形态）。
		putDyn(DT_JMPREL, loadVA+jmpRelOff)
		putDyn(DT_PLTRELSZ, 2*RelaEntrySize)
		putDyn(DT_PLTREL, DT_RELA)
		putRela(jmpRelOff, 0x402000, 7 /* R_X86_64_JUMP_SLOT */, 0)
		putRela(jmpRelOff+RelaEntrySize, 0x401000, 37 /* R_X86_64_IRELATIVE */, 0x401200)
	}
	if withRelr {
		putDyn(DT_RELR, loadVA+relrOff)
		putDyn(DT_RELRSZ, 2*8)
		putDyn(DT_RELRENT, 8)
		binary.LittleEndian.PutUint64(data[int(relrOff):], 0x401600) // base
		// bitmap：第 1 位与第 3 位置位 ⇒ 0x401608 与 0x401618
		binary.LittleEndian.PutUint64(data[int(relrOff)+8:], (1<<1|1<<3)<<1|1)
	}
	putDyn(DT_NULL, 0)
	return data
}

// DT_JMPREL 必须被读到（含 IRELATIVE —— 它的 r_offset 落在可执行段 = 打包端的加密范围）；
// DT_RELR 则**故意不解析**：它是隐式 addend 表，打包端改为"带 DT_RELR 就拒绝打包"（见 HasRELR）。
// 这条用例是那条策略的可失败校准：若 DynRelocs 又把 RELR 条目塞回来（或 HasRELR 失灵），它会红。
func TestDynRelocsCoversPltAndDetectsRelr(t *testing.T) {
	f, err := Parse(synthRelocs(t, true, true))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	all, err := f.DynRelocs()
	if err != nil {
		t.Fatalf("DynRelocs: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("动态重定位条数 = %d，期望 3（1 DT_RELA + 2 DT_JMPREL；DT_RELR 不入列）", len(all))
	}
	if all[1].Offset != 0x402000 || all[1].Type != 7 {
		t.Errorf("DT_JMPREL 第 0 条解析错: %+v", all[1])
	}
	if all[2].Offset != 0x401000 || all[2].Type != 37 {
		t.Errorf("DT_JMPREL 第 1 条（IRELATIVE）解析错: %+v", all[2])
	}
	// RELR 条目描述的那些槽位**不**该出现在结果里（我们不再解码 RELR）
	if in := RelocsInVA(all, 0x401600, 0x401700); len(in) != 0 {
		t.Errorf("DT_RELR 的槽位不该被解出来（本包不做 RELR 解码），得到 %+v", in)
	}
	// IRELATIVE 落在可执行段 [0x401000,0x401200) 里 ⇒ 打包端的加密范围守卫必须看得见它
	if in := RelocsInVA(all, 0x401000, 0x401200); len(in) != 1 || in[0].Type != 37 {
		t.Errorf("加密范围内应当看得见 IRELATIVE，得到 %+v", in)
	}
	rel, err := f.RelativeRelocs()
	if err != nil {
		t.Fatalf("RelativeRelocs: %v", err)
	}
	if len(rel) != 1 {
		t.Errorf("相对重定位条数 = %d，期望 1（只有 DT_RELA 那条）", len(rel))
	}
	// 带 DT_RELR 与不带 DT_RELR 的目标必须被分开认出来（打包端据此拒绝）
	has, err := f.HasRELR()
	if err != nil {
		t.Fatalf("HasRELR: %v", err)
	}
	if !has {
		t.Error("带 DT_RELR 的目标必须被 HasRELR 认出来（否则打包端会放行不可还原的产物）")
	}
	f2, err := Parse(synthRelocs(t, true, false))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	has2, err := f2.HasRELR()
	if err != nil {
		t.Fatalf("HasRELR: %v", err)
	}
	if has2 {
		t.Error("没有 DT_RELR 的目标不该被认成带 RELR")
	}
}

// 隐式 addend（DT_REL 语义）的条目：ImplicitAddend 必须为真、加数不读、且**不进 RelativeRelocs**
// （否则调用方拿它去跑 NormalizeRelocSlots 会把真实槽位清零 —— #597 复评 R3）。
func TestDynRelocsImplicitAddendNotNormalizable(t *testing.T) {
	d := synthRelocs(t, false, false)
	// 把动态表改成 REL 语义：DT_RELA→DT_REL、DT_RELASZ→DT_RELSZ、DT_RELAENT→DT_RELENT(16)
	binary.LittleEndian.PutUint64(d[0x1000+0:], DT_REL)
	binary.LittleEndian.PutUint64(d[0x1000+16:], DT_RELSZ)
	binary.LittleEndian.PutUint64(d[0x1000+24:], RelEntrySize)
	binary.LittleEndian.PutUint64(d[0x1000+32:], DT_RELENT)
	binary.LittleEndian.PutUint64(d[0x1000+40:], RelEntrySize)
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	all, err := f.DynRelocs()
	if err != nil {
		t.Fatalf("DynRelocs: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("DT_REL 表条数 = %d，期望 1（16 字节条目）", len(all))
	}
	if !all[0].ImplicitAddend {
		t.Errorf("DT_REL 语义的条目必须标成 ImplicitAddend: %+v", all[0])
	}
	if all[0].Addend != 0 {
		t.Errorf("隐式 addend 的条目不该读到 r_addend: %+v", all[0])
	}
	rel, err := f.RelativeRelocs()
	if err != nil {
		t.Fatalf("RelativeRelocs: %v", err)
	}
	if len(rel) != 0 {
		t.Errorf("隐式 addend 的条目必须被 RelativeRelocs 过滤掉（否则会清零真实槽位），得到 %+v", rel)
	}
}

// fail-closed：DT_JMPREL/DT_RELR 声明了表但地址/尺寸/语义坏掉时必须报错，不许当成"没有"。
func TestDynRelocsPltRelrFailsClosed(t *testing.T) {
	d := synthRelocs(t, true, false)
	binary.LittleEndian.PutUint64(d[0x1000+3*16+8:], 0) // DT_JMPREL 的 d_ptr 清零
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := f.DynRelocs(); err == nil {
		t.Fatal("DT_JMPREL 有 size 但地址为 0 必须报错")
	}
	// DT_PLTREL 是无意义的值
	d2 := synthRelocs(t, true, false)
	binary.LittleEndian.PutUint64(d2[0x1000+5*16+8:], 99) // DT_PLTREL 的 d_val
	f2, err := Parse(d2)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := f2.DynRelocs(); err == nil {
		t.Fatal("DT_PLTREL=99 必须报错（不能猜语义）")
	}
	// DT_RELR 的 d_ptr 为 0 但 DT_RELRSZ 非 0：仍然必须认成"带 RELR"（fail-closed，不许当成没有，
	// 否则打包端会放行一个它无法还原的产物）
	d3 := synthRelocs(t, false, true)
	binary.LittleEndian.PutUint64(d3[0x1000+3*16+8:], 0) // DT_RELR 的 d_ptr 清零（DT_RELRSZ 仍非 0）
	f3, err := Parse(d3)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	has, herr := f3.HasRELR()
	if herr != nil {
		t.Fatalf("HasRELR: %v", herr)
	}
	if !has {
		t.Fatal("DT_RELR 的 d_ptr 为 0 但 DT_RELRSZ 非 0 时也必须认成带 RELR（不能当成没有）")
	}
	// 读不出动态表时必须报错（不允许"读不到就当没有"）
	d4 := synthRelocs(t, false, true)
	binary.LittleEndian.PutUint64(d4[64+56+32:], 0x7FFFFFFF) // PT_DYNAMIC 的 p_filesz
	f4, err := Parse(d4)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, herr := f4.HasRELR(); herr == nil {
		t.Fatal("PT_DYNAMIC 越界时 HasRELR 必须报错（不能当成没有 DT_RELR）")
	}
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

// ---- RELR（DT_RELR 压缩相对重定位）----
//
// 这些用例是"契约测试先行"的第一块：运行期应用器还没实现（打包端目前仍然拒绝带 DT_RELR 的目标），
// 但**解码语义必须先钉死** —— 它是打包端判断"这些槽位能不能进加密范围"的唯一依据。

// synthRelr 造一个只带 DT_RELR 的最小 ET_DYN：entries 就是 .relr.dyn 里的原始条目。
// PT_LOAD 覆盖 [loadVA, loadVA+0x3000)，因此条目解出的槽位必须落在这个区间内。
func synthRelr(t *testing.T, loadVA uint64, entries []uint64) []byte {
	t.Helper()
	const dynOff = uint64(0x1000)
	const relrOff = uint64(0x2000)
	const fileSize = uint64(0x3000)
	data := make([]byte, fileSize)

	copy(data[0:], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(data[16:], ET_DYN)
	binary.LittleEndian.PutUint16(data[18:], EM_X86_64)
	binary.LittleEndian.PutUint64(data[32:], 64)
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
	putPhdr(0, PT_LOAD, PF_R|PF_W, 0, loadVA, fileSize, fileSize)
	putPhdr(1, PT_DYNAMIC, PF_R, dynOff, loadVA+dynOff, 0x100, 0x100)

	i := 0
	putDyn := func(tag, val uint64) {
		o := int(dynOff) + i*16
		binary.LittleEndian.PutUint64(data[o:], tag)
		binary.LittleEndian.PutUint64(data[o+8:], val)
		i++
	}
	putDyn(DT_RELR, loadVA+relrOff)
	putDyn(DT_RELRSZ, uint64(len(entries))*RelrEntrySize)
	putDyn(DT_RELRENT, RelrEntrySize)
	putDyn(DT_NULL, 0)
	for k, e := range entries {
		binary.LittleEndian.PutUint64(data[int(relrOff)+k*RelrEntrySize:], e)
	}
	return data
}

// relrSlots 解码并返回槽位地址；顺带断言每一条都标着隐式 addend（否则它会被喂进
// NormalizeRelocSlots 并**清零真实槽位** —— 那正是 #597 复评 R3 抓到的缺陷形态）。
func relrSlots(t *testing.T, data []byte) []uint64 {
	t.Helper()
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	rs, err := f.RelrRelocs()
	if err != nil {
		t.Fatalf("RelrRelocs: %v", err)
	}
	out := make([]uint64, 0, len(rs))
	for _, r := range rs {
		if !r.ImplicitAddend {
			t.Fatalf("RELR 条目必须标成隐式 addend（槽位 0x%X）", r.Offset)
		}
		out = append(out, r.Offset)
	}
	return out
}

// TestRelrGoldenVectorAgainstReadelf 是本条最要紧的一条：**向量来自真实产物**
// （Ubuntu binutils 2.46 链接的 PIE，readelf -rW 的输出）：
//
//	Relocation section '.relr.dyn' ... contains 3 entries which relocate 3 locations:
//	0000:  0000000000003d78  0000000000003d78  __frame_dummy_init_array_entry
//	0001:  0000000000000003  0000000000003d80  __do_global_dtors_aux_fini_array_entry
//	0002:  0000000000080001  0000000000004008  __dso_handle
//
// 条目 [0x3d78, 0x3, 0x80001] ⇒ 槽位 {0x3d78, 0x3d80, 0x4008}。三处旧缺陷任何一个回来这里就红：
// 缺 base += 63*8 ⇒ 第三个槽位错；首个 bitmap 的 base 不是 addr+8 ⇒ 第二个槽位错；
// 丢掉裸地址条目 ⇒ 少第一条。tools/e2e_elf_image.sh 里还有一条同算法的 readelf 对账（CI 侧）。
func TestRelrGoldenVectorAgainstReadelf(t *testing.T) {
	const loadVA = 0x3000 // 覆盖 0x3000..0x6000，容得下这三个槽位
	got := relrSlots(t, synthRelr(t, loadVA, []uint64{0x3d78, 0x3, 0x80001}))
	want := []uint64{0x3d78, 0x3d80, 0x4008}
	if len(got) != len(want) {
		t.Fatalf("解出 %d 个槽位 %v，期望 %d 个 %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 个槽位 = 0x%X，期望 0x%X（整组：%v）", i, got[i], want[i], got)
		}
	}
}

// TestRelrBitmapWindows：位图窗口的算术 —— 一条地址条目 + 两个位图。第二个位图必须从
// **第一个窗口推进 63*8 之后**开始（这正是旧解码器漏掉的那一步）。
func TestRelrBitmapWindows(t *testing.T) {
	const loadVA = uint64(0x400000)
	addr := loadVA + 0x1000
	// bit0 是"这是位图"的标志位，数据位从 bit1 开始；slot = base + (bit-1)*8
	d1 := (uint64(1)<<1 | uint64(1)<<3) | 1
	d2 := (uint64(1) << 1) | (uint64(1) << 63) | 1
	got := relrSlots(t, synthRelr(t, loadVA, []uint64{addr, d1, d2}))
	base2 := addr + 8 + 63*8 // 第一个位图窗口之后
	want := []uint64{
		addr,             // 地址条目本身
		addr + 8,         // bit1：base + 0
		addr + 8 + 2*8,   // bit3：base + (3-1)*8
		base2,            // 第二个窗口的 bit1
		base2 + (63-1)*8, // 第二个窗口的 bit63
	}
	if len(got) != len(want) {
		t.Fatalf("解出 %d 个槽位 %v，期望 %d 个 %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 个槽位 = 0x%X，期望 0x%X（整组：%v）", i, got[i], want[i], got)
		}
	}
}

// TestRelrRelocsFailsClosed：解码器坏了/表坏了必须**报错**，绝不能返回半张表
// （少一条就可能让打包端放行一个运行期还原不了的槽位）。改坏任一处 ⇒ 用例红。
func TestRelrRelocsFailsClosed(t *testing.T) {
	const loadVA = uint64(0x400000)
	relrENT := 0x1000 + 2*16 + 8 // 动态表里 DT_RELRENT 的值
	relrSZ := 0x1000 + 1*16 + 8  // DT_RELRSZ 的值

	t.Run("DT_RELRENT 不是 8", func(t *testing.T) {
		d := synthRelr(t, loadVA, []uint64{loadVA + 0x1000})
		binary.LittleEndian.PutUint64(d[relrENT:], 16)
		f, err := Parse(d)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if _, rerr := f.RelrRelocs(); rerr == nil {
			t.Fatal("DT_RELRENT=16 时必须报错")
		}
	})

	t.Run("DT_RELRSZ 不是 8 的整数倍", func(t *testing.T) {
		d := synthRelr(t, loadVA, []uint64{loadVA + 0x1000})
		binary.LittleEndian.PutUint64(d[relrSZ:], 12)
		f, err := Parse(d)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if _, rerr := f.RelrRelocs(); rerr == nil {
			t.Fatal("DT_RELRSZ=12 时必须报错")
		}
	})

	t.Run("槽位落在 PT_LOAD 之外", func(t *testing.T) {
		// 0x900000 是个合法地址但不在镜像里 —— 解码失步时正是这个形态。
		d := synthRelr(t, loadVA, []uint64{0x900000})
		f, err := Parse(d)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if _, rerr := f.RelrRelocs(); rerr == nil {
			t.Fatal("槽位不在任何 PT_LOAD 内时必须报错")
		}
	})

	t.Run("有 RELRSZ 没有 RELR 地址", func(t *testing.T) {
		d := synthRelr(t, loadVA, []uint64{loadVA + 0x1000})
		relrADDR := 0x1000 + 0*16 + 8 // DT_RELR 的值
		binary.LittleEndian.PutUint64(d[relrADDR:], 0)
		f, err := Parse(d)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if _, rerr := f.RelrRelocs(); rerr == nil {
			t.Fatal("DT_RELRSZ 非 0 但 DT_RELR=0 时必须报错")
		}
	})

	t.Run("DT_RELRENT=0 按 8 处理（规格默认）", func(t *testing.T) {
		d := synthRelr(t, loadVA, []uint64{loadVA + 0x1000})
		binary.LittleEndian.PutUint64(d[relrENT:], 0)
		if got := relrSlots(t, d); len(got) != 1 || got[0] != loadVA+0x1000 {
			t.Fatalf("DT_RELRENT=0 时应按 8 处理，解出 %v", got)
		}
	})
}

// TestRelrRelocsStayOutOfRelativeRelocs：RELR 的条目**不能**混进 RelativeRelocs ——
// 那条路会把 Addend（隐式 addend 恒为 0）**写回槽位**，等于把真实槽位清零（#597 复评 R3）。
// 这条同时钉住管线的另一半：打包端守卫 2 仍然按"隐式 addend"拒绝显式表里的这类条目，
// 而 RELR 走的是 RelrRelocs 这条独立的路。
func TestRelrRelocsStayOutOfRelativeRelocs(t *testing.T) {
	const loadVA = uint64(0x400000)
	d := synthRelr(t, loadVA, []uint64{loadVA + 0x1000, (uint64(1)<<1 | uint64(1)<<2) | 1})
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	relr, err := f.RelrRelocs()
	if err != nil {
		t.Fatalf("RelrRelocs: %v", err)
	}
	if len(relr) != 3 {
		t.Fatalf("期望 3 条 RELR 槽位（1 地址 + 2 位图），得到 %d", len(relr))
	}
	all, err := f.DynRelocs()
	if err != nil {
		t.Fatalf("DynRelocs: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("DynRelocs 不应返回 RELR 条目（策略未变），得到 %+v", all)
	}
	rel, err := f.RelativeRelocs()
	if err != nil {
		t.Fatalf("RelativeRelocs: %v", err)
	}
	if len(rel) != 0 {
		t.Fatalf("RELR 条目绝不能出现在 RelativeRelocs 里（会被 NormalizeRelocSlots 清零），得到 %+v", rel)
	}
}

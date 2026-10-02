package inject

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/vmpx/vmp-x/internal/vm"
)

// 这段测试**钉死**重定位应用表的形状（偏移/字段/掩码）与报告里那几个字段的名字。
// 为什么必须有它：这张表是"打包端 ↔ 运行期应用器"的跨进程契约，注释写得再清楚，
// 运行期（stub/win/x64/vm_interp.c 的 Linux 区）也只能按字节对齐去读；形状一改而没人
// 发现，现象是"运行期按错误偏移读出垃圾 delta ⇒ 全量 trap"。改这张表就必须改这个测试。

func relocTestPayload(t *testing.T, relocs []ImgReloc, secs []ImgSection) (*Payload, uint32, []byte) {
	t.Helper()
	stub := make([]byte, 64)
	copy(stub, "VMPTEST-STUB")
	const baseRVA = uint32(0x1E6000)
	code := []byte{vm.OpMovRI32, 0, 0x2a, 0, 0, 0, vm.OpRet}
	pl, err := BuildPayload(Options{
		Stub:        stub,
		StubEntry:   8,
		Funcs:       []FuncSpec{{Name: "f", RVA: 0x1000, Code: code}},
		ImgSections: secs,
		ImgRelocs:   relocs,
		PrefBase:    0x400000,
	}, baseRVA)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	return pl, baseRVA, pl.Data
}

func TestRelocTableShape(t *testing.T) {
	const (
		secRVA = uint32(0x1000)
		secSz  = uint32(0x100)
	)
	relocs := []ImgReloc{
		{RVA: 0x1010, Type: 8},    // R_X86_64_RELATIVE
		{RVA: 0x10F0, Type: 8},    // 末尾槽位（rva+8 == 范围末）
		{RVA: 0x1020, Type: 1027}, // aarch64 的类型号也照样记录（运行期按类型号 fail-closed）
	}
	secs := []ImgSection{{RVA: secRVA, Size: secSz, Flags: 1}}
	pl, baseRVA, data := relocTestPayload(t, relocs, secs)
	if pl.ImgRelocTableRVA == 0 {
		t.Fatal("有重定位时必须在 payload 里生成应用表（ImgRelocTableRVA=0）")
	}
	if want := RelocTableHeaderSize + len(relocs)*RelocEntrySize; pl.ImgRelocLen != want {
		t.Fatalf("表长 = %d，期望 %d（表头 %d + %d 条 × %d）",
			pl.ImgRelocLen, want, RelocTableHeaderSize, len(relocs), RelocEntrySize)
	}
	off := int(pl.ImgRelocTableRVA - baseRVA)
	tbl := append([]byte(nil), data[off:off+pl.ImgRelocLen]...)
	if le32(tbl, 0) != RelocTableMagic {
		t.Fatalf("magic = 0x%X，期望 0x%X（VMPR）", le32(tbl, 0), RelocTableMagic)
	}
	// 表头 [4,28) 与 m_reloc[0:24] 异或、每条 8 字节与 m_reloc[24:32] 异或（没有主密钥时用全零 master）
	mr := FieldMask(make([]byte, 32), FieldMaskDomainReloc, 0)
	XorMask(tbl, 4, 24, mr[0:24])
	for i := range relocs {
		XorMask(tbl, RelocTableHeaderSize+i*RelocEntrySize, RelocEntrySize, mr[24:32])
	}
	if got := le32(tbl, 4); got != uint32(len(relocs)) {
		t.Errorf("+4 count = %d，期望 %d", got, len(relocs))
	}
	if got := le32(tbl, 8); got != pl.ImgRelocTableRVA {
		t.Errorf("+8 selfRVA = 0x%X，期望 0x%X（运行期 base = 表地址 − selfRVA）", got, pl.ImgRelocTableRVA)
	}
	if got := le32(tbl, 12); got != RelocTableFlagDelta {
		t.Errorf("+12 flags = 0x%X，期望 0x%X", got, RelocTableFlagDelta)
	}
	if got := binary.LittleEndian.Uint64(tbl[16:]); got != 0x400000 {
		t.Errorf("+16 prefBase = 0x%X，期望 0x400000（delta = 基址 − prefBase）", got)
	}
	if got := le32(tbl, 24); got != RelocEntrySize {
		t.Errorf("+24 entrySize = %d，期望 %d", got, RelocEntrySize)
	}
	for i, r := range relocs {
		o := RelocTableHeaderSize + i*RelocEntrySize
		if got := le32(tbl, o); got != r.RVA {
			t.Errorf("条目 %d 的 rva = 0x%X，期望 0x%X", i, got, r.RVA)
		}
		if got := le32(tbl, o+4); got != r.Type {
			t.Errorf("条目 %d 的 type = %d，期望 %d", i, got, r.Type)
		}
	}
}

func TestRelocTableAbsentWithoutRelocs(t *testing.T) {
	pl, _, _ := relocTestPayload(t, nil, []ImgSection{{RVA: 0x1000, Size: 0x100, Flags: 1}})
	if pl.ImgRelocTableRVA != 0 || pl.ImgRelocLen != 0 {
		t.Fatalf("没有重定位时不该生成应用表：RVA=0x%X len=%d", pl.ImgRelocTableRVA, pl.ImgRelocLen)
	}
}

// fail-closed：表里只允许出现"落在被加密范围内的槽位"。范围外的槽位会让运行期去加减一个
// 从来没被加密过的地址（静默错值），必须在打包期就拒绝。
func TestRelocOutsideEncryptedRangeRejected(t *testing.T) {
	stub := make([]byte, 64)
	code := []byte{vm.OpMovRI32, 0, 0x2a, 0, 0, 0, vm.OpRet}
	_, err := BuildPayload(Options{
		Stub: stub, StubEntry: 8,
		Funcs:       []FuncSpec{{Name: "f", RVA: 0x1000, Code: code}},
		ImgSections: []ImgSection{{RVA: 0x1000, Size: 0x100, Flags: 1}},
		ImgRelocs:   []ImgReloc{{RVA: 0x2000, Type: 8}}, // 在所有加密范围之外
		PrefBase:    0x400000,
	}, 0x1E6000)
	if err == nil {
		t.Fatal("范围外的重定位槽位必须报错（fail-closed）")
	}
	// 半个槽位跨出范围末（rva+8 > 末）也要拒绝
	_, err = BuildPayload(Options{
		Stub: stub, StubEntry: 8,
		Funcs:       []FuncSpec{{Name: "f", RVA: 0x1000, Code: code}},
		ImgSections: []ImgSection{{RVA: 0x1000, Size: 0x100, Flags: 1}},
		ImgRelocs:   []ImgReloc{{RVA: 0x10FC, Type: 8}},
		PrefBase:    0x400000,
	}, 0x1E6000)
	if err == nil {
		t.Fatal("跨出范围末的槽位必须报错")
	}
}

// 报告（JSON）的形状也是契约：运行期应用器/门禁脚本按这些字段名取数。
func TestReportShapeRelocFields(t *testing.T) {
	res := Result{
		SectionRVA:       0x1000,
		SectionSize:      0x200,
		ImgSections:      []ImgSection{{RVA: 0x1000, Size: 0x100, Flags: 1}},
		ImgRelocTableRVA: 0x1E7000,
		ImgRelocLen:      RelocTableHeaderSize + 2*RelocEntrySize,
		ImgRelocCount:    2,
		ImgPrefBase:      0x400000,
		ImgEType:         3,
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"imgSections", "imgRelocTableRVA", "imgRelocLen", "imgRelocCount", "imgPrefBase", "imgEType"} {
		if _, ok := got[k]; !ok {
			t.Errorf("报告里缺字段 %q", k)
		}
	}
	sec := got["imgSections"].([]any)[0].(map[string]any)
	for _, k := range []string{"rva", "size", "flags"} {
		if _, ok := sec[k]; !ok {
			t.Errorf("imgSections 条目里缺字段 %q", k)
		}
	}
	rb, err := json.Marshal(ImgReloc{RVA: 0x1010, Type: 8})
	if err != nil {
		t.Fatal(err)
	}
	var rl map[string]any
	if err := json.Unmarshal(rb, &rl); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"rva", "type"} {
		if _, ok := rl[k]; !ok {
			t.Errorf("ImgReloc 里缺字段 %q", k)
		}
	}
}

func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

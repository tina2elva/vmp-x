package inject

import (
	"encoding/binary"
	"os"
	"testing"

	elfload "github.com/vmpx/vmp-x/internal/load/elf"
	"github.com/vmpx/vmp-x/internal/vm"
)

// 结构化验证 ELF 注入：重新从磁盘解析产物，逐字节核对
// 入口补丁、thunk、描述符、字节码落点是否正确。
func TestApplyELFStructural(t *testing.T) {
	src := "../../build/linux_target"
	if _, err := os.Stat(src); err != nil {
		t.Skip("需要先构建 build/linux_target")
	}
	f, err := elfload.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	imageBase := f.ImageBase()

	// 假的 stub：只要 > StubEntry 即可（本测试不执行它）
	stub := make([]byte, 64)
	copy(stub, "VMPTEST-STUB")
	const stubEntry = 8

	code1 := []byte{vm.OpMovRI32, 0, 0x2a, 0, 0, 0, vm.OpRet}
	code2 := []byte{vm.OpMovRI32, 1, 0x07, 0, 0, 0, vm.OpRet}
	specs := []FuncSpec{
		{Name: "main.checkKey", RVA: 0x91AA0, Code: code1},
		{Name: "main.sumTo", RVA: 0x91AC0, Code: code2},
	}

	res, err := ApplyELF(f, Options{SectionName: ".vmp", Stub: stub, StubEntry: stubEntry, Funcs: specs})
	if err != nil {
		t.Fatalf("ApplyELF: %v", err)
	}
	out := t.TempDir() + "/patched"
	if err := f.Save(out); err != nil {
		t.Fatal(err)
	}

	// 独立重新解析产物
	g, err := elfload.Open(out)
	if err != nil {
		t.Fatalf("重新解析失败: %v", err)
	}
	if g.ImageBase() != imageBase {
		t.Errorf("镜像基址变了: 0x%X -> 0x%X", imageBase, g.ImageBase())
	}

	rd32 := func(va uint64) uint32 {
		b, err := g.ReadVA(va, 4)
		if err != nil {
			t.Fatalf("读 0x%X 失败: %v", va, err)
		}
		return binary.LittleEndian.Uint32(b)
	}
	rdBytes := func(va uint64, n int) []byte {
		b, err := g.ReadVA(va, n)
		if err != nil {
			t.Fatalf("读 0x%X 失败: %v", va, err)
		}
		return b
	}

	for i, p := range res.Placements {
		funcVA := imageBase + uint64(p.FuncRVA)

		// 1. 入口补丁：E9 rel32 → thunk
		patched := rdBytes(funcVA, 5)
		if string(patched) != string(p.EntryPatch) {
			t.Errorf("%s 入口补丁不符: got % X want % X", p.Name, patched, p.EntryPatch)
		}
		if patched[0] != 0xE9 {
			t.Fatalf("%s 入口不是 jmp", p.Name)
		}
		target := funcVA + 5 + uint64(int32(binary.LittleEndian.Uint32(patched[1:])))
		if target != imageBase+uint64(p.ThunkRVA) {
			t.Errorf("%s jmp 目标 0x%X != thunk 0x%X", p.Name, target, imageBase+uint64(p.ThunkRVA))
		}

		// 2. thunk：call vm_entry（5 字节）；描述符必须紧跟其前 16 字节
		th := rdBytes(imageBase+uint64(p.ThunkRVA), 5)
		if th[0] != 0xE8 {
			t.Errorf("%s thunk 字节不符: % X", p.Name, th)
		}
		callTarget := imageBase + uint64(p.ThunkRVA) + 5 + uint64(int64(int32(binary.LittleEndian.Uint32(th[1:5]))))
		if callTarget != imageBase+uint64(res.StubEntryRVA) {
			t.Errorf("%s thunk 的 call 指向 0x%X，应为 vm_entry 0x%X", p.Name, callTarget, imageBase+uint64(res.StubEntryRVA))
		}
		if p.ThunkRVA != p.DescRVA+64 { // VM_DESC_SIZE：描述符现在含 AEAD 的 nonce/tag
			t.Errorf("%s thunk(0x%X) 不在描述符(0x%X) 之后 64 字节处", p.Name, p.ThunkRVA, p.DescRVA)
		}

		// 3. 描述符
		descVA := imageBase + uint64(p.DescRVA)
		magic := rd32(descVA)
		if magic != descMagic {
			t.Errorf("%s 描述符 magic=0x%X", p.Name, magic)
		}
		self := rd32(descVA + 4)
		if self != p.DescRVA {
			t.Errorf("%s selfRVA=0x%X want 0x%X（模块基址 = 描述符地址 - selfRVA）", p.Name, self, p.DescRVA)
		}
		codeRel := rd32(descVA + 8)
		if codeRel != p.CodeRVA-p.DescRVA {
			t.Errorf("%s codeRVA=0x%X want 0x%X", p.Name, codeRel, p.CodeRVA-p.DescRVA)
		}
		codeLen := rd32(descVA + 12)
		want := specs[i].Code
		if int(codeLen) != len(want) {
			t.Errorf("%s codeLen=%d want %d", p.Name, codeLen, len(want))
		}

		// 4. 字节码内容 + 能被自己的反汇编器完整解码
		bc := rdBytes(imageBase+uint64(p.CodeRVA), len(want))
		if string(bc) != string(want) {
			t.Errorf("%s 字节码不符", p.Name)
		}
		pc := 0
		for pc < len(bc) {
			n := vm.InsnSize(bc[pc])
			if n == 0 {
				t.Fatalf("%s 字节码在 +0x%X 处无法解码", p.Name, pc)
			}
			pc += n
		}
		if bc[len(bc)-1] != vm.OpRet {
			t.Errorf("%s 字节码未以 RET 结束", p.Name)
		}
	}

	// 新段必须是 R+X 且包含 payload
	var found bool
	for _, p := range g.Progs {
		if p.Type == elfload.PT_LOAD && p.Vaddr == imageBase+uint64(res.SectionRVA) {
			found = true
			if p.Flags&elfload.PF_X == 0 || p.Flags&elfload.PF_R == 0 {
				t.Errorf("新段应为 R+X，实际 flags=%d", p.Flags)
			}
			if int(p.Filesz) != res.SectionSize {
				t.Errorf("新段大小 %d != %d", p.Filesz, res.SectionSize)
			}
		}
	}
	if !found {
		t.Error("没有找到注入的新 PT_LOAD")
	}
}

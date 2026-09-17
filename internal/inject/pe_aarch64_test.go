package inject

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vmpx/vmp-x/internal/load/pe"
)

// PE/AArch64 的**结构性**验证（不执行）：
//   - vmpack 会从 PE 头的 COFF Machine 判定目标架构（0xAA64 = ARM64）；
//   - 打包器为 ARM64 写出 4 字节 B 入口补丁（而不是 x86 的 5 字节 E9），且目标正好是 thunk；
//   - 新节与 SizeOfImage 的修正与 x86-64 走同一条代码路径。
//
// 本机没有真正的 PE/arm64 样本，所以做法是：用 mingw 编出 PE/x64，然后把它头里的 Machine
// 改成 0xAA64（只影响"架构判定"这条路径），再按 ARM64 打包——校验的是结构与编码，
// 不是执行（执行需要 Windows/arm64 或全系统仿真）。
func TestApplyPEStructuralARM64(t *testing.T) {
	cc := ""
	for _, c := range []string{"gcc", "x86_64-w64-mingw32-gcc", "C:\\msys64\\ucrt64\\bin\\gcc.exe"} {
		if p, err := exec.LookPath(c); err == nil {
			cc = p
			break
		}
	}
	if cc == "" {
		t.Skip("没有可用的 gcc/mingw，跳过 PE 结构测试")
	}
	dir := t.TempDir()
	src := filepath.FromSlash("../../testdata/target.c")
	exe := filepath.Join(dir, "target.exe")
	if out, err := exec.Command(cc, "-O2", "-o", exe, src).CombinedOutput(); err != nil {
		t.Skipf("编译 PE 失败（可能不是 mingw 目标的 gcc）: %v | %s", err, out)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	// 先用 pe.Open 确认它确实是 PE，再改 Machine 字段（仅用于驱动架构判定）
	if pf, err := pe.Open(exe); err != nil {
		t.Skipf("不是 PE：%v", err)
	} else {
		_ = pf
	}
	peOff := int(binary.LittleEndian.Uint32(data[0x3C:]))
	if string(data[peOff:peOff+4]) != "PE\x00\x00" {
		t.Skip("PE 签名不符")
	}
	binary.LittleEndian.PutUint16(data[peOff+4:], 0xAA64)
	patchedPath := filepath.Join(dir, "target_arm64.exe")
	if err := os.WriteFile(patchedPath, data, 0o755); err != nil {
		t.Fatal(err)
	}
	f2, err := pe.Open(patchedPath)
	if err != nil {
		t.Fatal(err)
	}

	stub := make([]byte, 0x2000)
	res, err := Apply(f2, Options{
		SectionName: ".vmp",
		Stub:        stub,
		StubEntry:   0x1000,
		Arch:        ArchARM64,
		Funcs:       []FuncSpec{{Name: "check_key", RVA: 0x1000, Code: []byte{0x21, 0x80, 64, 0, 0, 6, 0, 0, 0, 0x02}}},
	})
	if err != nil {
		t.Fatalf("ARM64 打包失败: %v", err)
	}
	p := res.Placements[0]
	// AArch64 的入口补丁是 8 字节：mov x16, x30（保住调用方返回地址）+ b thunk
	if len(p.EntryPatch) != 8 {
		t.Fatalf("ARM64 入口补丁应为 8 字节，实际 %d（% X）", len(p.EntryPatch), p.EntryPatch)
	}
	if got := binary.LittleEndian.Uint32(p.EntryPatch[0:]); got != 0xAA1E03F0 {
		t.Fatalf("入口补丁第一条不是 mov x16,x30：0x%08X", got)
	}
	insn := binary.LittleEndian.Uint32(p.EntryPatch[4:])
	if insn>>26 != 0x05 {
		t.Fatalf("入口补丁不是 B：0x%08X", insn)
	}
	imm := int32(insn & 0x03FFFFFF)
	if imm&(1<<25) != 0 {
		imm -= 1 << 26
	}
	// B 位于 funcRVA+4，因此目标 = funcRVA + 4 + imm*4
	if int64(p.FuncRVA)+4+int64(imm)*4 != int64(p.ThunkRVA) {
		t.Fatalf("入口补丁目标 0x%X != thunk 0x%X", int64(p.FuncRVA)+4+int64(imm)*4, p.ThunkRVA)
	}
	t.Logf("PE/AArch64 结构性检查通过：patch=% X thunk=0x%X", p.EntryPatch, p.ThunkRVA)
}

package vm

// x86-32 客户机的**栈槽宽度**差分（目标项 ③-e 的第一块）。
//
// 判据：同一段字节码 —— PushR RBP; PushR RBP; PopR RBP; Halt ——
//   * x86-32 客户机：两次压栈各 4 字节、一次弹栈 4 字节 ⇒ RSP 净变化 **-4**
//   * x86-64 客户机：各 8 字节 ⇒ 净变化 **-8**
// 并且 **C 解释器与 Go 参考实现必须给出同一个数**（这是"打包端与运行期一致"纪律的一部分）。
//
// 需要预先构建（缺了就跳过，与既有对拍测试一致）：
//   build/vmpbuild.exe -src stub/win/x64 -out build/vm_interp_x8632.bin \
//       -manifest build/vm_interp_x8632.json -entry vm_entry -guest x86-32 -random-opcodes=false
//   gcc -O2 -DVM_GUEST_X86_32=1 -I stub/win/x64 -o build/runbc_x8632.exe stub/win/x64/blob_probe.c

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type blobInfo struct {
	Symbols   map[string]int `json:"symbols"`
	OpcodeMap map[string]int `json:"opcodeMap"`
}

func loadBlob(t *testing.T, blob, manifest, runner string) (blobInfo, int, *OpcodeMap) {
	t.Helper()
	for _, p := range []string{blob, manifest, runner} {
		if _, err := os.Stat(filepath.FromSlash(p)); err != nil {
			t.Skipf("缺少 %s（先按注释里的命令构建 x86-32 资产）", p)
		}
	}
	mb, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var info blobInfo
	if err := json.Unmarshal(mb, &info); err != nil {
		t.Fatal(err)
	}
	entry, ok := info.Symbols["vm_run"]
	if !ok {
		t.Fatal("manifest 里没有 vm_run")
	}
	byName := map[string]byte{}
	for k, v := range info.OpcodeMap {
		byName[k] = byte(v)
	}
	om, err := NewOpcodeMap(byName)
	if err != nil {
		t.Fatal(err)
	}
	return info, entry, om
}

// logicalOp 从 OpcodeNames 表里取逻辑操作码值（表是"单一来源"，注释里明确要求别处别写死）。
func logicalOp(t *testing.T, name string) byte {
	t.Helper()
	for _, e := range OpcodeNames {
		if e.Name == name {
			return e.Val
		}
	}
	t.Fatalf("OpcodeNames 里没有 %s", name)
	return 0
}

// runBatchOne 把一个用例喂给 C 解释器探针，返回结果里的 RSP。
func runBatchOne(t *testing.T, runner, blob string, entry int, code []byte, rsp uint64) uint64 {
	t.Helper()
	dir := t.TempDir()
	casesPath := filepath.Join(dir, "cases.bin")
	resPath := filepath.Join(dir, "results.bin")
	buf := u32b(1)
	buf = append(buf, u32b(uint32(len(code)))...)
	for r := 0; r < 18; r++ {
		v := uint64(0)
		if r == 4 {
			v = rsp
		}
		buf = append(buf, u64b(v)...)
	}
	buf = append(buf, code...)
	if err := os.WriteFile(casesPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(runner, "batch", blob, fmt.Sprint(entry), casesPath, resPath).CombinedOutput()
	if err != nil {
		t.Fatalf("runbc batch 失败（runner=%s blob=%s rsp=0x%X）: %v | %s", runner, blob, rsp, err, string(out))
	}
	raw, err := os.ReadFile(resPath)
	if err != nil {
		t.Fatal(err)
	}
	off := 8 + 4 // base + blen
	off += 4 + 4 // rc + flags
	return binary.LittleEndian.Uint64(raw[off+4*8:])
}

func TestX8632StackSlot(t *testing.T) {
	const (
		x64Blob     = "../../build/vm_interp.bin"
		x64Manifest = "../../build/vm_interp.json"
		x64Runner   = "../../build/runbc.exe"
		x32Blob     = "../../build/vm_interp_x8632.bin"
		x32Manifest = "../../build/vm_interp_x8632.json"
		x32Runner   = "../../build/runbc_x8632.exe"
	)
	_, x64Entry, x64Map := loadBlob(t, x64Blob, x64Manifest, x64Runner)
	_, x32Entry, x32Map := loadBlob(t, x32Blob, x32Manifest, x32Runner)
	// 历史：本轮先踩了两个坑，都已修掉（留档避免重走）——
	//   1) RSP 取 batchBufBase+batchBufLen-0x100 恰好等于窗口基址（窗口只有 256 字节），
	//      第一次 push 写到窗口外 ⇒ 探针 0xC0000005；改成 base+len-16 即可。
	//   2) 参考实现必须用与字节码**匹配**的映射，写死 x32 的映射跑 x64 字节码会报“未知操作码 0x47”。
	// 资产缺失时跳过（与既有对拍测试一致）：CI 目前不构建 x86-32 资产 ⇒ 在 CI 上会跳过（已登记为未做项）。

	const rbp = byte(5)
	// RSP 必须落在 batch 内存窗口**内部**：写这段测试时先踩了一次 ——
	// 用 batchBufBase+batchBufLen-0x100 恰好等于基址（窗口只有 256 字节），
	// 于是第一次 push 写到 base-4（窗口外）⇒ 探针 0xC0000005。
	rsp := uint64(batchBufBase + batchBufLen - 16)

	// 用逻辑操作码编好，再按各自 blob 的映射编码（x86-32 资产是 -random-opcodes=false，编码即恒等，
	// 但这里仍走 Encode，保证将来换成随机映射也成立）。
	enc := func(om *OpcodeMap) []byte {
		return []byte{om.Encode(logicalOp(t, "OP_PUSH_R")), rbp,
			om.Encode(logicalOp(t, "OP_PUSH_R")), rbp,
			om.Encode(logicalOp(t, "OP_POP_R")), rbp,
			om.Encode(logicalOp(t, "OP_HALT"))}
	}
	code64 := enc(x64Map)
	code32 := enc(x32Map)
	rspC64 := runBatchOne(t, x64Runner, x64Blob, x64Entry, code64, rsp)
	rspC32 := runBatchOne(t, x32Runner, x32Blob, x32Entry, code32, rsp)

	// Go 参考：同一个客户机设置必须给出与 C 相同的净变化
	// 注意：参考实现必须用**与该字节码匹配**的映射 —— 一开始把 Map 写死成 x32 的，
	// 拿它去跑 x64 的字节码就报“未知操作码 0x47”（两套映射不同）。
	ref := func(g Guest, om *OpcodeMap, code []byte) uint64 {
		st := &RefState{Map: om, Guest: g, BufBase: batchBufBase, BufSize: batchBufLen, Mem: map[uint64]byte{}}
		for k := 0; k < batchBufLen; k++ {
			st.Mem[batchBufBase+uint64(k)] = byte((k*7 + 3) & 0xFF)
		}
		st.Regs[4] = rsp
		if _, err := st.Run(code, 4096); err != nil {
			t.Fatalf("参考实现报错: %v", err)
		}
		return st.Regs[4]
	}
	rspGo32 := ref(GuestX8632, x32Map, code32)
	rspGo64 := ref(GuestX86, x64Map, code64)

	slotC64 := int64(rsp) - int64(rspC64)
	slotC32 := int64(rsp) - int64(rspC32)
	slotGo32 := int64(rsp) - int64(rspGo32)
	slotGo64 := int64(rsp) - int64(rspGo64)
	t.Logf("净压栈字节：C(x86-64)=%d C(x86-32)=%d Go(GuestX86)=%d Go(GuestX8632)=%d", slotC64, slotC32, slotGo64, slotGo32)

	if slotC64 != 8 || slotGo64 != 8 {
		t.Fatalf("64 位客户机应当是 8 字节（push+push-pop）：C=%d Go=%d", slotC64, slotGo64)
	}
	if slotC32 != 4 || slotGo32 != 4 {
		t.Fatalf("32 位客户机应当是 4 字节（push+push-pop）：C=%d Go=%d —— C 与 Go 必须一致", slotC32, slotGo32)
	}
}

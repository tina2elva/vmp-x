package vm

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const (
	batchBufBase = 0x10000000
	batchBufLen  = 256
)

type confCase struct {
	name string
	code []byte
	regs [18]uint64
}

func u32b(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
func u64b(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// 生成“一致性对拍”用例：每条指令都用若干边界值跑一遍
func genCases() []confCase {
	var cases []confCase
	edgeVals := []uint64{
		0, 1, 2, 7, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF,
		0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
		0xFFFFFFFFFFFFFFFF, 0x123456789ABCDEF0,
	}
	pairs := [][2]uint64{}
	for i := 0; i < len(edgeVals); i++ {
		for j := 0; j < len(edgeVals); j++ {
			if (i*len(edgeVals)+j)%7 != 0 {
				continue // 抽样，避免用例爆炸
			}
			pairs = append(pairs, [2]uint64{edgeVals[i], edgeVals[j]})
		}
	}

	kinds := []uint32{KAdd, KSub, KAnd, KOr, KXor, KMul, KShl, KShr, KSar, KRol, KRor}
	widths := []uint32{8, 16, 32, 64}

	// 1) 二元 ALU（寄存器形式）
	for _, k := range kinds {
		for _, w := range widths {
			for _, p := range pairs {
				code := cat([]byte{OpAluRR, byte(k), byte(w), 0, 1, 2}, []byte{OpRet})
				var regs [18]uint64
				regs[1], regs[2] = p[0], p[1]
				cases = append(cases, confCase{
					name: fmt.Sprintf("ALU kind=%d w=%d a=0x%X b=0x%X", k, w, p[0], p[1]),
					code: code, regs: regs,
				})
			}
		}
	}

	// 2) 一元 ALU
	for _, k := range []uint32{KUNeg, KUNot, KUInc, KUDec} {
		for _, w := range widths {
			for _, v := range edgeVals {
				code := cat([]byte{OpAluU, byte(k), byte(w), 0, 1}, []byte{OpRet})
				var regs [18]uint64
				regs[1] = v
				cases = append(cases, confCase{name: fmt.Sprintf("UN kind=%d w=%d v=0x%X", k, w, v), code: code, regs: regs})
			}
		}
	}

	// 3) 比较 + 全部 16 个条件码：R3 = 条件成立 ? 1 : 0
	for _, ck := range []uint32{KCmp, KTest} {
		for _, w := range widths {
			for _, p := range pairs {
				for cond := 0; cond < 16; cond++ {
					// CmpRR ; Jcc cond -> L1 ; MovRI32 R3,0 ; Ret ; L1: MovRI32 R3,1 ; Ret
					code := []byte{OpCmpRR, byte(ck), byte(w), 1, 2}
					code = append(code, OpJcc, byte(cond))
					jccAt := len(code)
					code = append(code, 0, 0, 0, 0)
					code = append(code, OpMovRI32, 3)
					code = append(code, u32b(0)...)
					code = append(code, OpRet)
					l1 := len(code)
					code = append(code, OpMovRI32, 3)
					code = append(code, u32b(1)...)
					code = append(code, OpRet)
					binary.LittleEndian.PutUint32(code[jccAt:], uint32(l1))
					var regs [18]uint64
					regs[1], regs[2] = p[0], p[1]
					cases = append(cases, confCase{
						name: fmt.Sprintf("CMP kind=%d w=%d cond=%d a=0x%X b=0x%X", ck, w, cond, p[0], p[1]),
						code: code, regs: regs,
					})
				}
			}
		}
	}

	// 4) MOV 各宽度（含 8/16 位局部写）
	for _, w := range widths {
		for _, v := range edgeVals {
			code := cat([]byte{OpMovRI, byte(w), 0}, u64b(v), []byte{OpRet})
			var regs [18]uint64
			regs[0] = 0xAAAAAAAA55555555
			cases = append(cases, confCase{name: fmt.Sprintf("MOV_RI w=%d v=0x%X", w, v), code: code, regs: regs})
		}
	}
	for _, w := range widths {
		code := cat([]byte{OpMovRR, byte(w), 0, 1}, []byte{OpRet})
		var regs [18]uint64
		regs[0], regs[1] = 0x0123456789ABCDEF, 0xFEDCBA9876543210
		cases = append(cases, confCase{name: fmt.Sprintf("MOV_RR w=%d", w), code: code, regs: regs})
	}
	// MOV32 零扩展
	cases = append(cases, confCase{
		name: "MOV_RI32", code: cat([]byte{OpMovRI32, 0}, u32b(0xFFFFFFFF), []byte{OpRet}),
		regs: [18]uint64{0xDEADBEEF00000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	})

	// 5) 扩展 zx/sx
	for _, sx := range []uint32{0, 1} {
		for _, sw := range []uint32{8, 16, 32} {
			for _, v := range []uint64{0x80, 0xFF, 0x8000, 0xFFFF, 0x80000000, 0xFFFFFFFF, 0x7F} {
				code := cat([]byte{OpExt, byte(sx), byte(sw), 0, 1}, []byte{OpRet})
				var regs [18]uint64
				regs[1] = v
				cases = append(cases, confCase{name: fmt.Sprintf("EXT sx=%d sw=%d v=0x%X", sx, sw, v), code: code, regs: regs})
			}
		}
	}

	// 6) LEA（base+index*scale+disp，全部落在内存窗口内）
	for _, scale := range []uint32{1, 2, 4, 8} {
		for _, disp := range []int32{0, 8, 64, 128} {
			code := cat([]byte{OpLea, 64, 0, 15, 14, byte(scale)}, u32b(uint32(disp)), []byte{OpRet})
			var regs [18]uint64
			regs[15] = batchBufBase
			regs[14] = 3
			cases = append(cases, confCase{name: fmt.Sprintf("LEA scale=%d disp=%d", scale, disp), code: code, regs: regs})
		}
	}

	// 7) LOAD/STORE 各宽度与符号扩展（窗口内的 base+index*scale+disp）
	for _, w := range []uint32{8, 16, 32, 64} {
		for _, sx := range []uint32{0, 1} {
			code := cat([]byte{OpLoad, byte(sx), byte(w), 0, 15, 14, 1}, u32b(16), []byte{OpRet})
			var regs [18]uint64
			regs[15], regs[14] = batchBufBase, 8
			cases = append(cases, confCase{name: fmt.Sprintf("LOAD w=%d sx=%d", w, sx), code: code, regs: regs})
		}
	}
	for _, w := range []uint32{8, 16, 32, 64} {
		// [op][width][base][index][scale][disp32][src]
		code := cat([]byte{OpStore, byte(w), 15, 14, 2}, u32b(24), []byte{3}, []byte{OpRet})
		var regs [18]uint64
		regs[15], regs[14] = batchBufBase, 4
		regs[3] = 0x0123456789ABCDEF
		cases = append(cases, confCase{name: fmt.Sprintf("STORE w=%d", w), code: code, regs: regs})
	}

	return cases
}

type batchResult struct {
	rc    uint32
	flags uint32
	regs  [18]uint64
	mem   []byte
}

func TestConformanceAgainstCInterpreter(t *testing.T) {
	blob := filepath.FromSlash("../../build/vm_interp.bin")
	runner := filepath.FromSlash("../../build/runbc.exe")
	// 该 runner 是**预编译**的：源码比它新就说明它是旧的，必须重建，否则会拿到误导性的结果
	if rs, err := os.Stat(runner); err == nil {
		for _, s := range []string{"../../stub/win/x64/blob_probe.c", "../../stub/win/x64/vm_abi.h", "../../stub/win/x64/vm_types.h"} {
			if ss, err2 := os.Stat(filepath.FromSlash(s)); err2 == nil && ss.ModTime().After(rs.ModTime()) {
				t.Fatalf("%s 比 %s 旧，请先重建：gcc -O2 -I stub/win/x64 -o build/runbc.exe stub/win/x64/blob_probe.c", runner, s)
			}
		}
	}
	manifest := filepath.FromSlash("../../build/vm_interp.json")
	for _, p := range []string{blob, runner, manifest} {
		if _, err := os.Stat(p); err != nil {
			t.Skip("缺少构建产物，跳过 C 对拍:", p)
		}
	}
	mb, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var man struct {
		Symbols   map[string]int `json:"symbols"`
		OpcodeMap map[string]int `json:"opcodeMap"`
	}
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatal(err)
	}
	entry, ok := man.Symbols["vm_run"]
	if !ok {
		t.Fatal("manifest 里没有 vm_run")
	}
	// blob 可能是用**构建期随机操作码**编出来的：读它的映射，用例先翻译成实际编码，
	// 参考 VM 也带同一份映射运行——这样对拍同时验证了随机映射本身。
	var oMap *OpcodeMap
	if len(man.OpcodeMap) > 0 {
		byName := map[string]byte{}
		for k, v := range man.OpcodeMap {
			byName[k] = byte(v)
		}
		oMap, err = NewOpcodeMap(byName)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("blob 使用构建期随机操作码映射（%d 条）", len(byName))
	}

	cases := genCases()
	if len(cases) == 0 {
		t.Fatal("没有生成任何用例")
	}

	// 写 cases 文件
	dir := t.TempDir()
	casesPath := filepath.Join(dir, "cases.bin")
	resPath := filepath.Join(dir, "results.bin")
	var buf []byte
	buf = append(buf, u32b(uint32(len(cases)))...)
	for i := range cases {
		c := &cases[i]
		if mapped, merr := Remap(c.code, oMap); merr == nil {
			c.code = mapped
		} else {
			t.Fatalf("Remap 失败: %v", merr)
		}
		buf = append(buf, u32b(uint32(len(c.code)))...)
		for r := 0; r < 18; r++ {
			buf = append(buf, u64b(c.regs[r])...)
		}
		buf = append(buf, c.code...)
	}
	if err := os.WriteFile(casesPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(runner, "batch", blob, fmt.Sprint(entry), casesPath, resPath).CombinedOutput()
	if err != nil {
		t.Fatalf("runbc batch 失败: %v | %s", err, string(out))
	}

	raw, err := os.ReadFile(resPath)
	if err != nil {
		t.Fatal(err)
	}
	off := 0
	base := binary.LittleEndian.Uint64(raw[off:])
	off += 8
	blen := binary.LittleEndian.Uint32(raw[off:])
	off += 4
	if base != batchBufBase || blen != batchBufLen {
		t.Fatalf("C 侧内存窗口不符: base=0x%X len=%d", base, blen)
	}

	results := make([]batchResult, len(cases))
	for i := range cases {
		var r batchResult
		r.rc = binary.LittleEndian.Uint32(raw[off:])
		off += 4
		r.flags = binary.LittleEndian.Uint32(raw[off:])
		off += 4
		for k := 0; k < 18; k++ {
			r.regs[k] = binary.LittleEndian.Uint64(raw[off:])
			off += 8
		}
		r.mem = raw[off : off+batchBufLen]
		off += batchBufLen
		results[i] = r
	}

	// 与 Go 参考实现对拍
	mismatches := 0
	for i := range cases {
		c := &cases[i]
		st := &RefState{Map: oMap, BufBase: batchBufBase, BufSize: batchBufLen, Mem: map[uint64]byte{}}
		for k := 0; k < batchBufLen; k++ {
			st.Mem[batchBufBase+uint64(k)] = byte((k*7 + 3) & 0xFF)
		}
		// RefState.Regs 覆盖两种客户机（35 槽），x86-64 只用前 18 个
		for k := 0; k < 18; k++ {
			st.Regs[k] = c.regs[k]
		}
		rc, rerr := st.Run(c.code, 4096)
		if rerr != nil {
			t.Errorf("[%s] 参考实现报错: %v", c.name, rerr)
			mismatches++
			continue
		}
		got := results[i]
		if uint32(rc) != got.rc {
			t.Errorf("[%s] rc: go=%d c=%d", c.name, rc, got.rc)
			mismatches++
			continue
		}
		if st.Flags != got.flags {
			t.Errorf("[%s] flags: go=0x%X c=0x%X", c.name, st.Flags, got.flags)
			mismatches++
		}
		for k := 0; k < 18; k++ {
			if st.Regs[k] != got.regs[k] {
				t.Errorf("[%s] R%d: go=0x%X c=0x%X", c.name, k, st.Regs[k], got.regs[k])
				mismatches++
			}
		}
		for k := 0; k < batchBufLen; k++ {
			if st.Mem[batchBufBase+uint64(k)] != got.mem[k] {
				t.Errorf("[%s] mem[%d]: go=0x%02X c=0x%02X", c.name, k,
					st.Mem[batchBufBase+uint64(k)], got.mem[k])
				mismatches++
				break
			}
		}
		if mismatches > 20 {
			t.Fatalf("不一致过多，提前终止（已到 %d）", mismatches)
		}
	}
	t.Logf("Go 参考实现与 C 解释器对拍完成: %d 个用例，%d 处不一致", len(cases), mismatches)
}

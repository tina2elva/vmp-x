package vm

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	batchBufBase = 0x10000000
	batchBufLen  = 256
)

type confCase struct {
	name string
	code []byte
	// raw 是**重映射之前**的字节码（默认操作码表）。带随机操作码的 blob 会把 code 换成实际编码，
	// 于是 DisasmAll(code) 会印出一堆 UNKNOWN —— 定位失败用例时要用 raw 才看得懂。
	raw  []byte
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

	// 8) **随机指令序列**（固定 seed ⇒ 可复现）。固定集合只覆盖"单条指令 × 边界值"，
	//    而解释器的坑大多在**序列**里（上一条改写寄存器/标志后，下一条读到）——#599 的静默错值
	//    就是循环体里多条指令的组合。随机程序由 C 解释器与 Go 参考 VM 各自跑一遍，逐位对拍。
	cases = append(cases, genRandomCases(1, randProgramCount)...)
	return cases
}

// randProgramCount 是随机程序条数。数量取"够密但不拖慢门禁"：每条 6~20 条指令，
// 批量对拍一次跑完（现有的固定用例本来就是几千条）。
const randProgramCount = 400

// genRandomCases 生成随机字节码程序。seed 固定 ⇒ 每次跑的是**同一批**程序（失败可复现）；
// 换 seed 就能扩展覆盖面（将来想 nightly 跑更多，直接调这个函数即可）。
func genRandomCases(seed int64, n int) []confCase {
	rng := rand.New(rand.NewSource(seed))
	var cases []confCase
	for i := 0; i < n; i++ {
		code, regs, hasLoop := randProgram(rng)
		if hasLoop {
			randCasesWithLoop++
		}
		cases = append(cases, confCase{
			name: fmt.Sprintf("rnd#%d(seed=%d)", i, seed),
			code: code,
			regs: regs,
		})
	}
	return cases
}

// randDivInsns 由 emitRandInsn 填：生成的 DIV/IDIV 指令条数。
// 与 randCasesWithLoop 同理 —— 防的是"这一类指令其实一条都没生成"的**空转**
// （#604.2 的教训：断言必须能区分"真的验了"和"什么都没验"）。
var randDivInsns int

// randCasesWithLoop 由 genRandomCases 填：含**真循环**（往回跳）的程序条数。
// 测试里断言它占相当比例 —— 防的是"循环生成悄悄失效、用例其实全是直行代码"这种**空转**
// （#604.2 的教训：断言必须能区分"真的验了"和"什么都没验"）。
var randCasesWithLoop int

// randImm 偏置到"边界值 + 随机值"：边界值让进位/借位/符号边界更常被踩到，随机值补覆盖面。
func randImm(rng *rand.Rand) uint64 {
	edge := []uint64{0, 1, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFFFFFF, 0x80000000,
		0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF}
	if rng.Intn(3) == 0 {
		return edge[rng.Intn(len(edge))]
	}
	return rng.Uint64()
}

// randProgram 造一个随机程序：以 RET 结尾；所有分支的目标都回填到**末尾的 RET**
// （于是控制流永远在程序内、且必然终止）；内存访问一律 base=r15(=batchBufBase)、无 index、
// disp 落在批量对拍的 256 字节窗口内。故意不用 PUSH/POP/CALL/DIV/FP ——
// 它们要么依赖批量 runner 没设的栈，要么会 trap 改变 rc 语义，不适合放进这条随机对拍。
func randProgram(rng *rand.Rand) ([]byte, [18]uint64, bool) {
	const base = 15 // 与 genCases 里 LOAD/STORE 用的基址寄存器一致
	// 循环计数器专用寄存器：**故意不在 work 里** ⇒ 循环体碰不到它 ⇒ 计数器严格递减 ⇒ 必然终止。
	const counter = 6
	// 故意**不含 RSP(4)**：程序里写客户机栈指针会让解释器走硬门（#606.3 实测：一条 MOV16 RSP, RAX
	// 就让批量对拍以 0xC000001D 崩掉；#607/#608 已定性为有意的 fail-closed 守卫）。这条随机对拍
	// 验的是**指令语义**，不是"能不能乱改栈指针"。
	work := []byte{0, 1, 2, 3, 5}

	var buf []byte
	var patches []int

	// 约一半的程序带一个**真循环**（往回跳）—— #599 那类"大行程循环静默错值"就藏在循环里。
	// 行程数受 Go 参考 VM 的 maxSteps（本测试传 4096）约束，所以按循环体长度反算上限并留足余量。
	hasLoop := false
	if rng.Intn(2) == 0 {
		hasLoop = true
		body := 2 + rng.Intn(7)
		trips := []int{1, 2, 3, 5, 8, 13, 21, 50, 120}[rng.Intn(9)]
		if cap := 2000 / (body + 2); cap > 0 && trips > cap {
			trips = cap
		}
		if trips < 1 {
			trips = 1
		}
		buf = append(buf, OpMovRI, 64, counter)
		buf = append(buf, u64b(uint64(trips))...)
		header := len(buf)
		for i := 0; i < body; i++ {
			emitRandInsn(rng, &buf, &patches, work, base)
		}
		// 尾部：counter -= 1; jne header（SUB 紧挨 JCC ⇒ 条件只取决于这次 SUB）
		buf = append(buf, OpAluRI, byte(KSub), 64, counter, counter)
		buf = append(buf, u32b(1)...)
		buf = append(buf, OpJcc, 5 /* x86 条件码 NE = 5 */, 0, 0, 0, 0)
		binary.LittleEndian.PutUint32(buf[len(buf)-4:], uint32(header))
	}

	n := 6 + rng.Intn(15)
	for i := 0; i < n; i++ {
		emitRandInsn(rng, &buf, &patches, work, base)
	}
	end := uint32(len(buf))
	buf = append(buf, OpRet)
	for _, p := range patches {
		binary.LittleEndian.PutUint32(buf[p:], end)
	}

	var regs [18]uint64
	for k := 0; k < 18; k++ {
		regs[k] = randImm(rng)
	}
	regs[base] = batchBufBase
	return buf, regs, hasLoop
}

// emitRandInsn 追加一条随机指令。循环体与主体**共用**这一个生成器（这样"循环里能出现什么"
// 与"主体里能出现什么"永远一致，不会两条路各漂各的）。分支的目标先占位（0 占位），
// 由 randProgram 在末尾统一回填到 RET —— 于是控制流永远留在程序内、且必然终止。
func emitRandInsn(rng *rand.Rand, buf *[]byte, patches *[]int, work []byte, base byte) {
	kinds := []byte{KAdd, KSub, KAnd, KOr, KXor, KMul, KShl, KShr, KSar, KRol, KRor, KAdc, KSbb}
	unary := []byte{KUNeg, KUNot, KUInc, KUDec}
	widths := []uint32{8, 16, 32, 64}
	scales := []byte{1, 2, 4, 8}
	d := work[rng.Intn(len(work))]
	a := work[rng.Intn(len(work))]
	b := work[rng.Intn(len(work))]
	w := widths[rng.Intn(len(widths))]
	switch rng.Intn(13) {
	case 0:
		*buf = append(*buf, OpMovRR, byte(w), d, a)
	case 1:
		*buf = append(*buf, OpMovRI, byte(w), d)
		*buf = append(*buf, u64b(randImm(rng))...)
	case 2:
		*buf = append(*buf, OpMovRI32, d)
		*buf = append(*buf, u32b(uint32(randImm(rng)))...)
	case 3:
		*buf = append(*buf, OpAluRR, kinds[rng.Intn(len(kinds))], byte(w), d, a, b)
	case 4:
		*buf = append(*buf, OpAluRI, kinds[rng.Intn(len(kinds))], byte(w), d, a)
		*buf = append(*buf, u32b(uint32(randImm(rng)))...)
	case 5:
		*buf = append(*buf, OpAluU, unary[rng.Intn(len(unary))], byte(w), d, a)
	case 6:
		*buf = append(*buf, OpCmpRR, byte(KCmp), byte(w), a, b)
	case 7:
		*buf = append(*buf, OpCmpRI, byte(KCmp), byte(w), a)
		*buf = append(*buf, u32b(uint32(randImm(rng)))...)
	case 8: // LEA：窗口内的 base+disp
		*buf = append(*buf, OpLea, byte(w), d, base, 0xFF, scales[rng.Intn(len(scales))])
		*buf = append(*buf, u32b(uint32(rng.Intn(200)))...)
	case 9: // LOAD：disp+w 必须落在 256 字节窗口内
		kind := byte(rng.Intn(2))
		*buf = append(*buf, OpLoad, kind, byte(w), d, base, 0xFF, 0)
		*buf = append(*buf, u32b(uint32(rng.Intn(257-int(w))))...)
	case 10: // STORE
		*buf = append(*buf, OpStore, byte(w), base, 0xFF, 0)
		*buf = append(*buf, u32b(uint32(rng.Intn(257-int(w))))...)
		*buf = append(*buf, a)
	case 11: // 分支：目标先占位，最后统一回填到末尾的 RET
		if rng.Intn(2) == 0 {
			*buf = append(*buf, OpJcc, byte(rng.Intn(16)))
			*patches = append(*patches, len(*buf))
			*buf = append(*buf, 0, 0, 0, 0)
		} else {
			*buf = append(*buf, OpJmp)
			*patches = append(*patches, len(*buf))
			*buf = append(*buf, 0, 0, 0, 0)
		}
	case 12: // DIV/IDIV —— **只生成不会 trap 的输入**
		// 除零 / 商放不下会让解释器走硬门（ud2），而批量对拍里**一条 trap 就整个进程挂掉**
		// ⇒ 随机程序里只喂安全输入：RDX=0（被除数高半）、RAX=小正数、除数寄存器=非零常数，
		// 于是商必然放得下（三种宽度都成立）。
		// 两个被约束的寄存器不能当除数：RAX(0) 是被除数低半、RDX(2) 是高半 ⇒ 除数只从 {1,3,5} 里挑。
		divRegs := []byte{1, 3, 5}
		dv := divRegs[rng.Intn(len(divRegs))]
		kind := byte(KDivU)
		if rng.Intn(2) == 0 {
			kind = KDivS
		}
		*buf = append(*buf, OpMovRI, 64, 2) // RDX = 0
		*buf = append(*buf, u64b(0)...)
		*buf = append(*buf, OpMovRI, 64, 0) // RAX = 小正数（0..64）
		*buf = append(*buf, u64b(uint64(rng.Intn(65)))...)
		*buf = append(*buf, OpMovRI, byte(w), dv) // 除数 = 非零常数（2..255，任意宽度下都非零）
		*buf = append(*buf, u64b(uint64(2+rng.Intn(254)))...)
		*buf = append(*buf, OpAluU, kind, byte(w), 0, dv) // dst 不用：商→RAX、余→RDX
		randDivInsns++
	}
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
	// 防空转：随机程序里必须真的有相当比例带**循环**（往回跳），否则"循环覆盖"是假的。
	if randCasesWithLoop < randProgramCount/4 {
		t.Fatalf("随机程序里带循环的只有 %d/%d 条 —— 循环生成八成失效了（这条用例的卖点就是循环覆盖）",
			randCasesWithLoop, randProgramCount)
	}
	t.Logf("随机程序 %d 条：带真循环（往回跳）的 %d 条、DIV/IDIV 指令 %d 条", randProgramCount, randCasesWithLoop, randDivInsns)
	if randDivInsns == 0 {
		t.Fatal("随机程序里一条 DIV/IDIV 都没有 —— 除法覆盖是假的")
	}

	// 写 cases 文件
	dir := t.TempDir()
	casesPath := filepath.Join(dir, "cases.bin")
	resPath := filepath.Join(dir, "results.bin")
	var buf []byte
	buf = append(buf, u32b(uint32(len(cases)))...)
	for i := range cases {
		c := &cases[i]
		c.raw = append([]byte(nil), c.code...)
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
		// 批量跑挂了（解释器走硬门 trap ⇒ ud2 / 崩溃）：用**二分**把"是哪一条"定位出来 ——
		// 随机程序几百条，只报一句"batch 失败"等于没报。
		// 注意**不能**用单条模式定位：那个入口要的是 .vmb 容器格式，不是裸字节码（本轮踩过）。
		runPrefix := func(n int) error {
			var b []byte
			b = append(b, u32b(uint32(n))...)
			for i := 0; i < n; i++ {
				c := &cases[i]
				b = append(b, u32b(uint32(len(c.code)))...)
				for r := 0; r < 18; r++ {
					b = append(b, u64b(c.regs[r])...)
				}
				b = append(b, c.code...)
			}
			if werr := os.WriteFile(casesPath, b, 0o644); werr != nil {
				t.Fatal(werr)
			}
			_, e2 := exec.Command(runner, "batch", blob, fmt.Sprint(entry), casesPath, resPath).CombinedOutput()
			return e2
		}
		lo, hi := 1, len(cases)
		for lo < hi {
			mid := (lo + hi) / 2
			if runPrefix(mid) != nil {
				hi = mid
			} else {
				lo = mid + 1
			}
		}
		c := &cases[lo-1]
		t.Fatalf("批量对拍失败（%v | %s）\n二分定位到第 %d 条 [%s]；它的原始字节码反汇编:\n%s",
			err, string(out), lo-1, c.name, strings.Join(DisasmAll(c.raw), "\n"))
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

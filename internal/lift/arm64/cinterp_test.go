package arm64

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	dec "github.com/vmpx/vmp-x/internal/decode/arm64"
	"github.com/vmpx/vmp-x/internal/ir"
	"github.com/vmpx/vmp-x/internal/vm"
)

// ARM64 客户机语义的**成规模**差分：AArch64 指令 -> lift -> 字节码，
// 分别交给 (a) Go 参考 VM（GuestARM64）和 (b) C 解释器（-DVM_GUEST_ARM64，35 槽位）执行，比对寄存器与标志位。
//
// 这是"ARM64 宿主 blob 之前必须先过的一关"：客户机语义（C=无借位、移位 C/V 规则、
// N/Z 位序与 x86 不同）如果写错，端到端只会静默算错。
func TestArm64GuestInCInterpreter(t *testing.T) {
	harness := "../../../build/runbc_a64g.exe"
	blob := "../../../build/vm_interp_a64g.bin"
	manifestPath := "../../../build/vm_interp_a64g.json"
	for _, p := range []string{harness, blob, manifestPath} {
		if _, err := os.Stat(filepath.FromSlash(p)); err != nil {
			t.Skipf("缺少 %s（先构建 -guest arm64 的 blob 与 runbc_a64g.exe）", p)
		}
	}
	var man struct {
		Symbols  map[string]int `json:"symbols"`
		Guest    string         `json:"guest"`
		RegCount int            `json:"regCount"`
	}
	mb, err := os.ReadFile(filepath.FromSlash(manifestPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatal(err)
	}
	// 守卫：harness 与 blob 必须用同一套 ctx 布局（35 槽）。
	if man.RegCount != 35 || man.Guest != "arm64" {
		t.Fatalf("需要 arm64 且 regCount=35 的 blob，实际 guest=%q regCount=%d（harness 要用 -DVM_GUEST_ARM64=1 -DVM_REG_COUNT=35）",
			man.Guest, man.RegCount)
	}

	rng := rand.New(rand.NewSource(20260916))
	const iterations = 20000
	const seqLen = 5
	const regCount = 35

	type caseT struct {
		code []byte
		regs [35]uint64
		ref  [35]uint64
		rfl  uint32
		src  []string
		ir   []string
	}
	var cases []caseT
	var skipDecode, skipRef, skipLift int
	for it := 0; it < iterations && len(cases) < 2000; it++ {
		var words []uint32
		if rng.Intn(3) == 0 {
			// 控制流程序（含向后分支 = 循环）：真实目标的求和循环走的就是这条路径
			words = genControlProgram(rng, seqLen+1)
		} else {
			words = make([]uint32, seqLen)
			for i := range words {
				words[i] = genDataInsn(rng)
			}
		}
		var code []byte
		for _, w := range words {
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, w)
			code = append(code, b...)
		}
		insns, err := dec.DecodeRange(code, 0x1000, 0)
		if err != nil {
			skipDecode++
			continue
		}
		var regs [35]uint64
		for i := 0; i < 31; i++ {
			regs[i] = rng.Uint64()
		}
		regs[31] = 0x1A000 // SP：数据类指令一般不动，给个合法值
		ref := &refMachine{regs: regs}
		refOK := true
		for i := range insns {
			if err := ref.step(&insns[i]); err != nil {
				refOK = false
				break
			}
		}
		if !refOK {
			skipRef++
			continue
		}
		fn := &ir.Func{}
		(&Lifter{ImageBase: 0}).Lift(fn, insns)
		if len(fn.Unsupported) > 0 {
			skipLift++
			continue
		}
		fn.Insns = append(fn.Insns, ir.Insn{Op: ir.Ret})
		res, err := vm.Generate(fn)
		if err != nil {
			t.Fatalf("codegen 失败: %v", err)
		}
		var srcs []string
		for i := range insns {
			srcs = append(srcs, insns[i].Text())
		}
		var irs []string
		for i := range fn.Insns {
			in := &fn.Insns[i]
			irs = append(irs, fmt.Sprintf("IR %v kind=0x%X w=%d dst=%d a=%d b=%d imm=0x%X", in.Op, in.Kind, in.Width, in.Dst, in.A, in.B, in.Imm))
		}
		cases = append(cases, caseT{code: res.Code, regs: regs, ref: ref.regs, rfl: ref.flags, src: srcs, ir: irs})
	}
	if len(cases) == 0 {
		t.Fatalf("没有可用用例（解码失败 %d / 参考拒绝 %d / lifter 拒绝 %d）", skipDecode, skipRef, skipLift)
	}

	// 组批处理输入
	var buf []byte
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(cases)))
	for _, c := range cases {
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(c.code)))
		for r := 0; r < regCount; r++ {
			buf = binary.LittleEndian.AppendUint64(buf, c.regs[r])
		}
		buf = append(buf, c.code...)
	}
	dir := t.TempDir()
	cf, rf := filepath.Join(dir, "cases.bin"), filepath.Join(dir, "res.bin")
	if err := os.WriteFile(cf, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.FromSlash(harness), "batch",
		filepath.FromSlash(blob), fmt.Sprint(man.Symbols["vm_run"]), cf, rf).CombinedOutput()
	if err != nil {
		t.Fatalf("runbc 失败（含 120s 超时）: %v | %s", err, out)
	}
	raw, err := os.ReadFile(rf)
	if err != nil {
		t.Fatal(err)
	}

	// 结果：[base:8][blen:4] + 每用例 [rc:4][flags:4][regs:35*8][buf:VM_BATCH_BUFLEN]
	const header = 12
	const perCaseFixed = 4 + 4 + 8*regCount
	batchBufLen := 256 // VM_BATCH_BUFLEN（见 blob_probe.c）
	off := header
	bad, execFail := 0, 0
	for i, c := range cases {
		rc := binary.LittleEndian.Uint32(raw[off:])
		cflags := binary.LittleEndian.Uint32(raw[off+4:])
		cregs := raw[off+8 : off+8+8*regCount]
		if rc != 0 {
			execFail++
			if execFail <= 3 {
				t.Logf("用例 %d: C 解释器执行失败 rc=%d", i, rc)
			}
			off += perCaseFixed + batchBufLen
			continue
		}
		diff := ""
		for r := 0; r < 31; r++ {
			got := binary.LittleEndian.Uint64(cregs[8*r:])
			if got != c.ref[r] {
				diff = fmt.Sprintf("R%d: c=0x%X ref=0x%X", r, got, c.ref[r])
				break
			}
		}
		if diff == "" && cflags != c.rfl {
			diff = fmt.Sprintf("flags: c=0x%X ref=0x%X", cflags, c.rfl)
		}
		if diff != "" {
			bad++
			if bad <= 2 {
				t.Logf("用例 %d: %s", i, diff)
				t.Logf("   初始 R0=0x%X R1=0x%X", c.regs[0], c.regs[1])
				for _, s := range c.src {
					t.Logf("   src %s", s)
				}
				for _, s := range c.ir {
					t.Logf("   %s", s)
				}
			}
		}
		off += perCaseFixed + batchBufLen
	}
	fmt.Printf("ARM64 客户机（C 解释器 vs Go 参考）：校验 %d 组，不一致 %d，执行失败 %d；"+
		"跳过：解码失败 %d、参考拒绝 %d、lifter 拒绝 %d\n", len(cases), bad, execFail, skipDecode, skipRef, skipLift)
	if bad > 0 || execFail > 0 {
		t.Fatalf("不一致 %d 组，执行失败 %d", bad, execFail)
	}
}

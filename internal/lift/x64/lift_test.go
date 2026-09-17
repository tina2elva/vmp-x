package x64

import (
	"encoding/hex"
	"strconv"
	"testing"

	"golang.org/x/arch/x86/x86asm"

	x64dec "github.com/vmpx/vmp-x/internal/decode/x64"
	"github.com/vmpx/vmp-x/internal/ir"
)

// 自校验：确认 x86asm 的寄存器编号区间假设仍然成立。
// 若上游改了常量顺序，这个测试会失败，而不是悄悄生成错误字节码。
func TestRegInfoMapping(t *testing.T) {
	cases := []struct {
		r    x86asm.Reg
		want ir.Reg
		w    ir.Width
	}{
		{x86asm.RAX, ir.RAX, ir.W64},
		{x86asm.R15, ir.R15, ir.W64},
		{x86asm.EAX, ir.RAX, ir.W32},
		{x86asm.R15L, ir.R15, ir.W32},
		{x86asm.AX, ir.RAX, ir.W16},
		{x86asm.R15W, ir.R15, ir.W16},
		{x86asm.AL, ir.RAX, ir.W8},
		{x86asm.SPB, ir.RSP, ir.W8},
		{x86asm.DIB, ir.RDI, ir.W8},
		{x86asm.R15B, ir.R15, ir.W8},
		{x86asm.ECX, ir.RCX, ir.W32},
		{x86asm.EDX, ir.RDX, ir.W32},
	}
	for _, c := range cases {
		got, w, ok := regInfo(c.r)
		if !ok {
			t.Errorf("%v: 映射失败", c.r)
			continue
		}
		if got != c.want || w != c.w {
			t.Errorf("%v: got (%d,%d) want (%d,%d)", c.r, got, w, c.want, c.w)
		}
	}
	for _, r := range []x86asm.Reg{x86asm.AH, x86asm.CH, x86asm.DH, x86asm.BH} {
		if _, _, ok := regInfo(r); ok {
			t.Errorf("%v: 高字节寄存器不应被支持", r)
		}
	}
}

// check_key 的真实机器码（取自 testdata/hello.exe，RVA 0x1450）：
//
//	48 8d 04 cd 00 00 00 00   lea rax,[rcx*8]
//	48 29 c8                  sub rax,rcx
//	48 83 c0 2a               add rax,0x2a
//	34 ff                     xor al,0xff
//	c3                        ret
const checkKeyHex = "488d04cd00000000" + "4829c8" + "4883c02a" + "34ff" + "c3"

func TestLiftCheckKey(t *testing.T) {
	code, err := hex.DecodeString(checkKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLifter(0x140000000)
	f, err := l.LiftFunc("check_key", code, 0x1450)
	if err != nil {
		t.Fatalf("lift 失败: %v | %s", err, joinUnsupported(f))
	}
	if len(f.Insns) != 5 {
		t.Fatalf("IR 指令数 = %d, want 5 | %s", len(f.Insns), dump(f))
	}
	want := []ir.Insn{
		{Op: ir.Lea, Width: ir.W64, Dst: ir.RAX, Base: ir.NoReg, Index: ir.RCX, Scale: 8, Disp: 0},
		{Op: ir.AluRR, Kind: uint8(ir.Sub), Width: ir.W64, Dst: ir.RAX, A: ir.RAX, B: ir.RCX},
		{Op: ir.AluRI, Kind: uint8(ir.Add), Width: ir.W64, Dst: ir.RAX, A: ir.RAX, Imm: 0x2a},
		{Op: ir.AluRI, Kind: uint8(ir.Xor), Width: ir.W8, Dst: ir.RAX, A: ir.RAX, Imm: 0xff},
		{Op: ir.Ret},
	}
	for i, w := range want {
		g := f.Insns[i]
		if g.Op != w.Op || g.Width != w.Width || g.Dst != w.Dst || g.A != w.A || g.B != w.B ||
			g.Kind != w.Kind || g.Base != w.Base || g.Index != w.Index || g.Scale != w.Scale ||
			g.Disp != w.Disp || g.Imm != w.Imm || g.Cond != w.Cond {
			t.Errorf("IR[%d] 不一致 | got: %+v | want: %+v", i, g, w)
		}
	}
}

// sum_to 的真实机器码（RVA 0x1470，长 0x45 字节），含两个基本块与尾部 nop 填充
const sumToHex = "4189c8" + "85c9" + "7e39" + "31d2" + "4183e001" + "8d4901" + "b801000000" +
	"7419" + "b802000000" + "ba01000000" + "39c8" + "7416" +
	"66662e0f1f840000000000" + "8d544201" + "83c002" + "39c8" + "75f5" + "89d0" + "c3" +
	"6690" + "31d2" + "89d0" + "c3"

func TestLiftSumTo(t *testing.T) {
	code, err := hex.DecodeString(sumToHex)
	if err != nil {
		t.Fatal(err)
	}
	if insns, derr := x64dec.DecodeRange(code, 0x140001470, 0); derr == nil {
		for _, in := range insns {
			t.Logf("+0x%02X len=%d  %s", in.PC-0x140001470, in.Len(), in.Text())
		}
	} else {
		t.Logf("decode 失败: %v", derr)
	}
	l := NewLifter(0x140000000)
	f, err := l.LiftFunc("sum_to", code, 0x1470)
	if err != nil {
		t.Fatalf("lift 失败: %v | %s", err, joinUnsupported(f))
	}
	for i, in := range f.Insns {
		if in.Op == ir.Jcc || in.Op == ir.Jmp {
			if in.Target < 0 || in.Target >= len(f.Insns) {
				t.Errorf("IR[%d] 分支目标越界: %d", i, in.Target)
			}
		}
	}
	t.Logf("sum_to: %d 条 IR 指令", len(f.Insns))
}

// 带栈帧的函数：函数自己帧内的访问（eff < 0）不做修正
func TestLiftFramedOwnFrame(t *testing.T) {
	// sub rsp,0x28 ; mov [rsp+0x20],rcx ; mov rax,[rsp+0x20] ; add rsp,0x28 ; ret
	code, err := hex.DecodeString("4883ec28" + "48894c2420" + "488b442420" + "4883c428" + "c3")
	if err != nil {
		t.Fatal(err)
	}
	l := NewLifter(0x140000000)
	l.SetFrameSkew(8608)
	f, err := l.LiftFunc("framed", code, 0x1000)
	if err != nil {
		t.Fatalf("带栈帧的函数应当可翻译: %v | %s", err, joinUnsupported(f))
	}
	var store, load *ir.Insn
	for i := range f.Insns {
		switch f.Insns[i].Op {
		case ir.Store:
			store = &f.Insns[i]
		case ir.Load:
			load = &f.Insns[i]
		}
	}
	if store == nil || load == nil {
		t.Fatalf("应当生成 Store/Load: %s", dump(f))
	}
	// eff = 0x20 - 0x28 = -8 < 0 → 属于函数自己的帧，不修正
	if store.Disp != 0x20 || load.Disp != 0x20 {
		t.Errorf("函数自身帧的偏移不应被修正: store=%d load=%d", store.Disp, load.Disp)
	}
}

// 读取调用方栈帧（eff >= 0）必须补上 FRAME_SKEW
func TestLiftCallerFrameGetsSkew(t *testing.T) {
	// mov rax,[rsp+0x28] ; ret —— 进入时 RSP+0x28 是调用方压的第 5 个参数
	code, err := hex.DecodeString("488b442428" + "c3")
	if err != nil {
		t.Fatal(err)
	}
	const skew = 8608
	l := NewLifter(0x140000000)
	l.SetFrameSkew(skew)
	f, err := l.LiftFunc("stack_arg", code, 0x1000)
	if err != nil {
		t.Fatalf("应当可翻译: %v", err)
	}
	if f.Insns[0].Op != ir.Load {
		t.Fatalf("期望 Load，得到 %v", f.Insns[0].Op)
	}
	if want := int32(0x28 + skew); f.Insns[0].Disp != want {
		t.Errorf("调用方栈帧访问偏移应为 0x28+FRAME_SKEW=0x%X，得到 0x%X", want, f.Insns[0].Disp)
	}
	l2 := NewLifter(0x140000000)
	f2, err := l2.LiftFunc("stack_arg", code, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if f2.Insns[0].Disp != 0x28 {
		t.Errorf("未启用 FRAME_SKEW 时不应修正，得到 0x%X", f2.Insns[0].Disp)
	}
}

// 把调用方栈地址取到别的寄存器属于“无法跟踪的逃逸”，必须拒绝
func TestLiftRejectsStackAddressEscape(t *testing.T) {
	// lea rax,[rsp+0x8] ; ret
	code, err := hex.DecodeString("488d442408" + "c3")
	if err != nil {
		t.Fatal(err)
	}
	l := NewLifter(0x140000000)
	l.SetFrameSkew(8608)
	f, err := l.LiftFunc("escape", code, 0x1000)
	if err == nil {
		t.Fatal("栈地址逃逸应当被拒绝")
	}
	if len(f.Unsupported) == 0 {
		t.Fatal("应当给出原因")
	}
	t.Logf("拒绝原因: %s", f.Unsupported[0])
}

func TestLiftRejectsUnsupported(t *testing.T) {
	// 0f 77 = EMMS（MMX 遗留指令，必须被拒绝而不是猜）
	if _, err := NewLifter(0).LiftFunc("bad", []byte{0x0f, 0x77, 0xc3}, 0); err == nil {
		t.Fatal("期望不支持指令报错")
	}
}

func joinUnsupported(f *ir.Func) string {
	if f == nil {
		return ""
	}
	s := ""
	for _, u := range f.Unsupported {
		s += " | " + u
	}
	return s
}

func dump(f *ir.Func) string {
	s := ""
	for i, in := range f.Insns {
		s += " | [" + strconv.Itoa(i) + "] " + in.Op.String()
	}
	return s
}

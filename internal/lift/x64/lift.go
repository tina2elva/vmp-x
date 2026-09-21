// Package x64 把 x86-64 机器码 lift 成线性 IR。
//
// 原则：
//   - 不支持就报错，绝不“猜一个近似实现”。错误信息带偏移与原始指令文本。
//   - 宽度语义严格按 x86-64：32 位运算零扩展、8/16 位局部写。
//   - RIP-relative 一律折算成 "VMBASE + RVA"，因此天然支持 ASLR/重定位。
package x64

import (
	"fmt"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	x64dec "github.com/vmpx/vmp-x/internal/decode/x64"
	"github.com/vmpx/vmp-x/internal/ir"
)

// Lifter 持有模块级信息与“当前函数”的栈跟踪状态
// looksLikeFuncEntry 判断某 RVA 是否"像函数入口"：函数入口前通常是填充（0xCC/0x90/0x00），
// 而"函数中段"前面一定是一条会流进来的指令（非填充）。用于区分真正的尾调用与函数续段。
func (l *Lifter) looksLikeFuncEntry(rva uint32) bool {
	if l.ReadImage == nil {
		return true
	}
	if rva == 0 {
		return true
	}
	n := uint32(8)
	if rva < n {
		n = rva
	}
	b := l.ReadImage(rva-n, int(n))
	if len(b) == 0 {
		return true
	}
	for _, x := range b {
		if x != 0xCC && x != 0x90 && x != 0x00 {
			return false
		}
	}
	return true
}

type Lifter struct {
	ImageBase uint64
	// FrameSkew = 模拟栈比原生栈低多少（来自 vm_abi.h / manifest）。
	// 对“相对进入时 RSP 偏移 >= 0”的访问要补上它，才能读到调用方的栈帧。
	FrameSkew int64

	// 以下为 per-function 状态，在 LiftFunc 中重置
	spDelta int64 // 相对进入时 RSP 的偏移
	spKnown bool
	// spLostBy 记录第一条让 RSP 变得不可跟踪的指令（诊断用：覆盖率工具会按它聚合）
	spLostBy string
	// ReadImage 按 RVA 读镜像字节（跳转表需要）；nil = 不可用
	ReadImage func(rva uint32, n int) []byte
	// prev1/prev2 是最近两条已解码指令（识别"越界跳默认"的边界检查）
	prev1, prev2 *x64dec.Insn
	// recent 是最近若干条已解码指令（跳转表的分裂形态要回看 4~6 条）
	recent []x64dec.Insn
	// Debug 记录孤岛收集过程（诊断用）
	Debug []string
	// XMMAreaRVA 是 blob 里 XMM 寄存器堆（16×16 字节）在**目标镜像 RVA 空间**中的地址；
	// 0 表示不可用（此时所有 SIMD 指令照旧拒绝）。
	XMMAreaRVA uint32
	// ScratchRVA 是 blob 里的 8 字节暂存槽（vm_tmp），SIMD 按位运算借通用寄存器时用它保存旧值。
	// 用它而不是 push/pop：push 会动模拟 RSP，让同一条指令里后面的 [rsp+disp] 操作数算错。
	ScratchRVA uint32
	rbpEff     int64 // rbp 相对进入时 RSP 的偏移（仅当 rbp 直接由 rsp 派生时有效）
	rbpKnown   bool
}

func NewLifter(imageBase uint64) *Lifter { return &Lifter{ImageBase: imageBase} }

// SetScratchArea 告诉 lifter：blob 里那个 8 字节暂存槽（vm_tmp）在目标镜像的哪个 RVA。
func (l *Lifter) SetScratchArea(rva uint32) { l.ScratchRVA = rva }

// SetImageReader 注入"按 RVA 读镜像字节"的能力（跳转表等静态数据需要它）。
// 返回 nil 表示该 RVA 不可读——这时相关指令会被明确拒绝，而不是猜。
func (l *Lifter) SetImageReader(f func(rva uint32, n int) []byte) { l.ReadImage = f }

// SetXMMArea 告诉 lifter：blob 里的 XMM 寄存器堆放在目标镜像的哪个 RVA。
// XMM 是调用者保存寄存器，所以只要有这块私有内存就能承载它们（无需改 ABI/入口）。
func (l *Lifter) SetXMMArea(rva uint32) { l.XMMAreaRVA = rva }

// xmmDisp 返回 XMMn 第 half(0/1) 个 8 字节在镜像里的 RVA
func (l *Lifter) xmmDisp(r x86asm.Reg, half int) (int32, bool) {
	if l.XMMAreaRVA == 0 {
		return 0, false
	}
	n := -1
	if r >= x86asm.X0 && r <= x86asm.X15 {
		n = int(r - x86asm.X0)
	}
	if n < 0 {
		return 0, false
	}
	return int32(l.XMMAreaRVA) + int32(n*16) + int32(half*8), true
}

// SetFrameSkew 设置模拟栈偏移（vmpack 从 manifest 读取后调用）
func (l *Lifter) SetFrameSkew(v int64) { l.FrameSkew = v }

// adjustStackDisp 判断某个“相对栈的偏移”是否需要补 FrameSkew。
// eff 是相对进入时 RSP 的偏移：eff >= 0 表示访问的是调用方的栈帧
// （返回地址、栈上传参、调用方局部），在模拟栈里必须补上差值。
func (l *Lifter) adjustStackDisp(disp int32, eff int64) int32 {
	if eff >= 0 && l.FrameSkew != 0 {
		return disp + int32(l.FrameSkew)
	}
	return disp
}

// LiftFunc 翻译一个函数
// irTargetFixed 是"合成分支"的哨兵：Target 已经是最终的 IR 下标，不需要再由 `offToIR` 换算。
// （SETcc/CMOVcc 用**分支降级**实现，会自己合成前向分支。）
const irTargetFixed = ^uint32(0)

func (l *Lifter) LiftFunc(name string, code []byte, rva uint32) (*ir.Func, error) {
	base := l.ImageBase + uint64(rva)
	f := &ir.Func{Name: name, Addr: base, RVA: rva, Size: len(code)}
	offToIR := map[uint32]int{}

	// 每个函数独立的栈跟踪状态：spDelta 从 0（进入时 RSP）开始
	l.spDelta, l.spKnown, l.spLostBy = 0, true, ""
	l.rbpEff, l.rbpKnown = 0, false

	// ---- 分区域翻译 ----
	// 函数主体是一段连续代码，但编译器会把**冷块**（switch 的默认分支、不常走的分支）
	// 放到很远的地方。所以除了主体之外，还要能按"分支目标"去抓这些冷块，
	// 把它们作为**孤岛**追加到同一个函数的 IR 后面（主体以 RET 结束，顺序执行不会掉进孤岛）。
	type region struct {
		code []byte
		rva  uint32
	}
	const (
		maxIslands     = 16
		maxIslandInsns = 256
	)
	regions := []region{{code: code, rva: rva}}
	// seen 按**镜像 RVA** 记账（不要用函数相对偏移：函数的 RVA 可能恰好等于某个目标偏移，
	// 会造成『这个目标已经处理过』的假象——这个 bug 真的发生过）
	seen := map[uint32]bool{f.RVA: true}
	done := map[uint32]bool{}
	totalInsns, islands := 0, 0

	for {
		// 取一段还没翻译的区域
		cur := -1
		for i := range regions {
			if !done[regions[i].rva] {
				cur = i
				break
			}
		}
		if cur < 0 {
			break
		}
		rg := regions[cur]
		done[rg.rva] = true

		insns, derr := x64dec.DecodeRange(rg.code, l.ImageBase+uint64(rg.rva), 0)
		if derr != nil {
			if rg.rva == rva {
				return nil, derr
			}
			// 孤岛解码失败：当作"这条分支无法翻译"，由下面的目标解析报错
			f.Unsupported = append(f.Unsupported,
				fmt.Sprintf("冷块 +0x%X 解码失败: %v", rg.rva-rva, derr))
			continue
		}
		l.recent = l.recent[:0]

		for idx := range insns {
			ins := insns[idx]
			var p1, p2 *x64dec.Insn
			if idx > 0 {
				p1 = &insns[idx-1]
			}
			if idx > 1 {
				p2 = &insns[idx-2]
			}
			l.prev1, l.prev2 = p1, p2
			off := uint32(ins.PC - f.Addr)
			offToIR[off] = len(f.Insns)
			err := l.liftOne(f, ins, off)
			if err == nil {
				// 栈跟踪必须在指令成功翻译后更新（操作数使用的是指令执行前的 RSP）
				err = l.trackRegs(ins)
			}
			if err != nil {
				f.Unsupported = append(f.Unsupported,
					fmt.Sprintf("+0x%X: %-30s — %v", off, ins.Text(), err))
			}
			l.recent = append(l.recent, ins)
			if len(l.recent) > 12 {
				l.recent = l.recent[len(l.recent)-12:]
			}
		}
		totalInsns += len(insns)

		// 收集"落在已翻译区域之外"的分支目标，尝试抓成孤岛
		for i := range f.Insns {
			in := &f.Insns[i]
			// 只把**条件分支**的目标当冷块：无条件 jmp 大多是尾调用/跳到别处，
			// 把它们的落地代码当成本函数的一部分会拖进无关代码（实测会显著拉低可保护率）。
			if (in.Op != ir.Jcc && in.Op != ir.Jmp) || in.TargetOff == irTargetFixed {
				continue
			}
			if _, ok := offToIR[in.TargetOff]; ok {
				continue
			}
			if seen[f.RVA+in.TargetOff] || islands >= maxIslands || l.ReadImage == nil {
				continue
			}
			// 注意：TargetOff 是**相对函数起点**的偏移，读镜像要用镜像 RVA
			rva := f.RVA + in.TargetOff
			ic, ok := l.readIsland(rva, maxIslandInsns)
			l.Debug = append(l.Debug, fmt.Sprintf("target=+0x%X rva=0x%X read=%v len=%d", in.TargetOff, rva, ok, len(ic)))
			if !ok {
				continue // 留着让后面的目标解析给出明确错误
			}
			seen[rva] = true
			islands++
			regions = append(regions, region{code: ic, rva: rva})
		}
	}

	if len(f.Unsupported) > 0 {
		return f, fmt.Errorf("%d/%d 条指令无法翻译", len(f.Unsupported), totalInsns)
	}

	for i := range f.Insns {
		in := &f.Insns[i]
		if in.Op != ir.Jmp && in.Op != ir.Jcc {
			continue
		}
		if in.TargetOff == irTargetFixed {
			continue // 合成分支：Target 已就绪
		}
		idx, ok := offToIR[in.TargetOff]
		if !ok {
			return f, fmt.Errorf("分支目标 +0x%X 不在函数内、也不是可识别的冷块（来自 +0x%X: %s）",
				in.TargetOff, in.SrcOff, in.Text)
		}
		in.Target = idx
	}
	return f, nil
}

// readIsland 从镜像里读一段"冷块"：逐条解码，遇到 RET 或无条件 JMP 就结束。
// 只用于把分支目标解释成代码——解不出来就返回 false（由调用方报错，不猜）。
func (l *Lifter) readIsland(rva uint32, maxInsns int) ([]byte, bool) {
	if l.ReadImage == nil {
		return nil, false
	}
	// 镜像读取器要求"整段都可读"，冷块靠段尾时 4096 字节会读不到——
	// 所以从大到小试几个长度，取第一个能读到的（冷块本身很短）。
	var buf []byte
	for _, probe := range []int{4096, 1024, 256, 64} {
		if b := l.ReadImage(rva, probe); len(b) > 0 {
			buf = b
			break
		}
	}
	if len(buf) == 0 {
		return nil, false
	}
	base := l.ImageBase + uint64(rva)
	off := 0
	for i := 0; i < maxInsns && off < len(buf); i++ {
		ins, err := x64dec.Decode(buf[off:], base+uint64(off))
		if err != nil || ins.Len() <= 0 {
			return nil, false
		}
		off += ins.Len()
		switch ins.Op() {
		case x86asm.RET, x86asm.JMP:
			return buf[:off], true
		}
	}
	return nil, false
}

func (l *Lifter) emit(f *ir.Func, in ir.Insn) { f.Insns = append(f.Insns, in) }

// ---------------- 寄存器映射 ----------------

// regInfo 把 x86asm 寄存器映射为 (规范编号, 宽度)。
// 数值区间来自 x86asm/inst.go 的常量顺序（见 lift_test.go 的自校验测试）。
func regInfo(r x86asm.Reg) (ir.Reg, ir.Width, bool) {
	v := int(r)
	switch {
	case v >= 1 && v <= 4: // AL..BL
		return ir.Reg(v - 1), ir.W8, true
	case v >= 5 && v <= 8: // AH/CH/DH/BH 高字节寄存器：不支持
		return 0, 0, false
	case v >= 9 && v <= 12: // SPB..DIB
		return ir.Reg(v - 9 + 4), ir.W8, true
	case v >= 13 && v <= 20: // R8B..R15B
		return ir.Reg(v - 13 + 8), ir.W8, true
	case v >= 21 && v <= 28: // AX..DI
		return ir.Reg(v - 21), ir.W16, true
	case v >= 29 && v <= 36: // R8W..R15W
		return ir.Reg(v - 29 + 8), ir.W16, true
	case v >= 37 && v <= 44: // EAX..EDI
		return ir.Reg(v - 37), ir.W32, true
	case v >= 45 && v <= 52: // R8L..R15L
		return ir.Reg(v - 45 + 8), ir.W32, true
	case v >= 53 && v <= 68: // RAX..R15
		return ir.Reg(v - 53), ir.W64, true
	}
	return 0, 0, false
}

func regArg(a x86asm.Arg) (x86asm.Reg, bool) { r, ok := a.(x86asm.Reg); return r, ok }
func memArg(a x86asm.Arg) (x86asm.Mem, bool) { m, ok := a.(x86asm.Mem); return m, ok }
func immArg(a x86asm.Arg) (int64, bool)      { i, ok := a.(x86asm.Imm); return int64(i), ok }
func relArg(a x86asm.Arg) (int64, bool)      { r, ok := a.(x86asm.Rel); return int64(r), ok }

// regArgInfo 一步拿到规范编号与宽度
func regArgInfo(a x86asm.Arg) (ir.Reg, ir.Width, bool) {
	r, ok := regArg(a)
	if !ok {
		return 0, 0, false
	}
	return regInfo(r)
}

// memAddr 解析内存操作数；RIP-relative 折算为 VMBASE+RVA
func (l *Lifter) memAddr(ins x64dec.Insn, m x86asm.Mem) (base, index ir.Reg, scale uint8, disp int32, err error) {
	base, index, scale = ir.NoReg, ir.NoReg, 1
	if ins.Inst.AddrSize != 0 && ins.Inst.AddrSize != 64 {
		return 0, 0, 0, 0, fmt.Errorf("不支持 %d 位地址长度", ins.Inst.AddrSize)
	}
	switch {
	case m.Base == 0:
		// 无基址
	case m.Base == x86asm.RIP:
		target, ok := ins.PCRelTarget()
		if !ok {
			return 0, 0, 0, 0, fmt.Errorf("RIP-relative 但无法解析目标地址")
		}
		if target < l.ImageBase {
			return 0, 0, 0, 0, fmt.Errorf("RIP-relative 目标 0x%X 低于镜像基址 0x%X", target, l.ImageBase)
		}
		base = ir.VMBASE
		disp = int32(target - l.ImageBase)
	default:
		r, w, ok := regInfo(m.Base)
		if !ok || w != ir.W64 {
			return 0, 0, 0, 0, fmt.Errorf("不支持的基址寄存器 %v", m.Base)
		}
		base = r
	}
	if m.Index != 0 {
		r, w, ok := regInfo(m.Index)
		if !ok || w != ir.W64 {
			return 0, 0, 0, 0, fmt.Errorf("不支持的索引寄存器 %v", m.Index)
		}
		if m.Scale != 1 && m.Scale != 2 && m.Scale != 4 && m.Scale != 8 {
			return 0, 0, 0, 0, fmt.Errorf("不支持的 scale %d", m.Scale)
		}
		index = r
		scale = uint8(m.Scale)
	}
	if m.Base != x86asm.RIP {
		disp = int32(m.Disp)
	}
	// 栈相对寻址：模拟栈位于原生栈下方 FrameSkew 处，因此
	// “相对进入时 RSP 偏移 >= 0”的访问（调用方返回地址/传参/局部）必须补上差值，
	// 而函数自己的帧（eff < 0）留在私有区域即可，无需修正。
	if base == ir.RSP {
		if !l.spKnown {
			return 0, 0, 0, 0, fmt.Errorf("RSP 已被不可跟踪的方式修改（%s），无法安全翻译栈访问", l.spLostBy)
		}
		disp = l.adjustStackDisp(disp, int64(disp)+l.spDelta)
	} else if base == ir.RBP && l.rbpKnown {
		disp = l.adjustStackDisp(disp, int64(disp)+l.rbpEff)
	}
	return base, index, scale, disp, nil
}

// opWidth 取运算宽度：优先用目标寄存器宽度，其次用 DataSize
func opWidth(ins x64dec.Insn) ir.Width {
	if _, w, ok := regArgInfo(ins.Inst.Args[0]); ok {
		return w
	}
	switch ins.Inst.DataSize {
	case 8:
		return ir.W8
	case 16:
		return ir.W16
	case 32:
		return ir.W32
	default:
		return ir.W64
	}
}

func memWidth(ins x64dec.Insn) ir.Width {
	if ins.Inst.MemBytes > 0 {
		return ir.Width(ins.Inst.MemBytes * 8)
	}
	return opWidth(ins)
}

// ---------------- 单条指令 ----------------

func (l *Lifter) liftOne(f *ir.Func, ins x64dec.Insn, off uint32) error {
	if ins.Endbr64 || ins.Endbr32 {
		l.emit(f, ir.Insn{Op: ir.Nop, SrcOff: off, Text: ins.Text()})
		return nil
	}
	args := ins.Inst.Args
	op := ins.Op()
	em := func(in ir.Insn) {
		in.SrcOff = off
		in.Text = ins.Text()
		l.emit(f, in)
	}

	// LOCK 前缀（x86 的原子读改写）单独走一条路径：真用宿主硬件的原子指令实现。
	// LOCK 前缀（x86 的原子读改写）。之前数值不符的根因已定位：解释器里为取旧值先做了一次
	// 无条件 exchange，把内存改了两次（CMPXCHG 还会被提前破坏）；现在按 kind 用对应的
	// __atomic_fetch_* / compare_exchange 内建。
	for _, px := range ins.Inst.Prefix {
		if px == x86asm.PrefixLOCK {
			return l.liftLocked(f, ins, off, em)
		}
	}

	switch op {
	case x86asm.NOP:
		em(ir.Insn{Op: ir.Nop})
		return nil

	case x86asm.XCHG:
		a, aw, aok := regArgInfo(args[0])
		b, bw, bok := regArgInfo(args[1])
		if aok && bok {
			if a == b {
				// xchg %ax,%ax 是 GCC/Go 常用的多字节 NOP
				em(ir.Insn{Op: ir.Nop})
				return nil
			}
			// 寄存器对寄存器：用 VMSCR 中转做交换（3 条 MOV，不改标志位）
			w := aw
			if bw < w {
				w = bw
			}
			em(ir.Insn{Op: ir.MovRR, Width: w, Dst: ir.VMSCR, A: a})
			em(ir.Insn{Op: ir.MovRR, Width: w, Dst: a, A: b})
			em(ir.Insn{Op: ir.MovRR, Width: w, Dst: b, A: ir.VMSCR})
			return nil
		}
		// 内存形式 XCHG [mem], reg：隐含 lock 的原子交换（寄存器拿到旧值）。
		swap := func(m x86asm.Mem, r ir.Reg) error {
			base, index, scale, disp, merr := l.memAddr(ins, m)
			if merr != nil {
				return merr
			}
			em(ir.Insn{Op: ir.Atomic, Kind: vmKindXchg, Width: memWidth(ins), Dst: r, A: r,
				Base: base, Index: index, Scale: scale, Disp: disp})
			return nil
		}
		if m, okm := memArg(args[0]); okm {
			r, _, rok := regArgInfo(args[1])
			if !rok {
				return fmt.Errorf("XCHG 内存形式需要寄存器源")
			}
			return swap(m, r)
		}
		if m, okm := memArg(args[1]); okm {
			r, _, rok := regArgInfo(args[0])
			if !rok {
				return fmt.Errorf("XCHG 内存形式需要寄存器源")
			}
			return swap(m, r)
		}
		return fmt.Errorf("只支持寄存器之间的 XCHG 与内存原子 XCHG")

	case x86asm.MOV:
		return l.liftMov(f, ins, off)

	case x86asm.LEA:
		dst, w, ok := regArgInfo(args[0])
		if !ok {
			return fmt.Errorf("LEA 目标必须是寄存器")
		}
		m, ok := memArg(args[1])
		if !ok {
			return fmt.Errorf("LEA 源必须是内存操作数")
		}
		base, index, scale, disp, err := l.memAddr(ins, m)
		if err != nil {
			return err
		}
		em(ir.Insn{Op: ir.Lea, Width: w, Dst: dst, Base: base, Index: index, Scale: scale, Disp: disp})
		return nil

	case x86asm.ADD, x86asm.SUB, x86asm.AND, x86asm.OR, x86asm.XOR,
		x86asm.ADC, x86asm.SBB:
		// ADC/SBB 与 ADD/SUB 的形状完全一样，只是多算一个进位——用新的 kind 交给 VM。
		kind := map[x86asm.Op]ir.Kind{
			x86asm.ADD: ir.Add, x86asm.SUB: ir.Sub, x86asm.AND: ir.And,
			x86asm.OR: ir.Or, x86asm.XOR: ir.Xor,
			x86asm.ADC: ir.Adc, x86asm.SBB: ir.Sbb,
		}[op]
		return l.liftAlu(f, ins, off, kind)

	case x86asm.CMP, x86asm.TEST:
		kind := ir.Cmp
		if op == x86asm.TEST {
			kind = ir.Test
		}
		return l.liftCmp(f, ins, off, kind)

	case x86asm.MUL:
		// MUL r/m：RDX:RAX = RAX * src（无符号），CF=OF=(高半 != 0)
		//   - 高半先算（RAX 还是原值），用新 kind K_MULHI —— 它同时给出正确的 CF/OF；
		//   - 低半用 K_MUL|KeepFlags，避免把上面的标志位覆盖掉；
		//   - 最后把高半搬进 RDX（MovRR 不改标志位）。
		// 8/16 位形式的隐式寄存器是 AX/DX，约定不同，明确拒绝。
		{
			w := opWidth(ins)
			if w != ir.W32 && w != ir.W64 {
				return fmt.Errorf("MUL 只支持 32/64 位形式")
			}
			var src ir.Reg
			if s, _, ok := regArgInfo(args[0]); ok {
				src = s
			} else if m, ok := memArg(args[0]); ok {
				base, index, scale, disp, err := l.memAddr(ins, m)
				if err != nil {
					return err
				}
				mw := memWidth(ins)
				em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: mw, SrcW: mw, Dst: ir.VMSCR,
					Base: base, Index: index, Scale: scale, Disp: disp})
				src = ir.VMSCR
			} else {
				return fmt.Errorf("MUL 的操作数不支持")
			}
			em(ir.Insn{Op: ir.AluRR, Kind: uint8(ir.MulHi), Width: w, Dst: ir.VMSCR, A: ir.RAX, B: src})
			em(ir.Insn{Op: ir.AluRR, Kind: uint8(ir.Mul) | ir.KeepFlags, Width: w, Dst: ir.RAX, A: ir.RAX, B: src})
			em(ir.Insn{Op: ir.MovRR, Width: w, Dst: ir.RDX, A: ir.VMSCR})
			return nil
		}

	case x86asm.BT:
		// BT r/m, r|imm：把第 (index mod width) 位送进 CF，**其它标志位保持不变**。
		// 用新 kind K_BT：解释器只改 CF（这正是 BT 与 SHR 的关键差别——SHR 会顺手改掉 Z/S/V）。
		{
			w := opWidth(ins)
			if w != ir.W32 && w != ir.W64 {
				return fmt.Errorf("BT 只支持 32/64 位形式")
			}
			var val ir.Reg
			if r, _, ok := regArgInfo(args[0]); ok {
				val = r
			} else if m, ok := memArg(args[0]); ok {
				base, index, scale, disp, err := l.memAddr(ins, m)
				if err != nil {
					return err
				}
				mw := memWidth(ins)
				em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: mw, SrcW: mw, Dst: ir.VMSCR,
					Base: base, Index: index, Scale: scale, Disp: disp})
				val = ir.VMSCR
			} else {
				return fmt.Errorf("BT 的操作数不支持")
			}
			if idx, _, ok := regArgInfo(args[1]); ok {
				em(ir.Insn{Op: ir.AluRR, Kind: uint8(ir.Bt), Width: w, Dst: ir.VMSCR, A: val, B: idx})
				return nil
			}
			if imm, ok := immArg(args[1]); ok {
				em(ir.Insn{Op: ir.AluRI, Kind: uint8(ir.Bt), Width: w, Dst: ir.VMSCR, A: val, Imm: uint64(uint32(imm))})
				return nil
			}
			return fmt.Errorf("BT 的位索引操作数不支持")
		}

	case x86asm.BSF, x86asm.BSR, x86asm.TZCNT, x86asm.LZCNT:
		// 位扫描：结果 = 最低/最高置位位的下标；**只改 ZF**（源为 0 → ZF=1，目标保持原值）。
		{
			w := opWidth(ins)
			if w != ir.W16 && w != ir.W32 && w != ir.W64 {
				return fmt.Errorf("BSF/BSR 只支持 16/32/64 位形式")
			}
			dst, _, okd := regArgInfo(args[0])
			if !okd {
				return fmt.Errorf("BSF/BSR 的目标必须是寄存器")
			}
			kind := ir.Bsf
			switch op {
			case x86asm.BSR:
				kind = ir.Bsr
			case x86asm.TZCNT:
				kind = ir.Tzcnt
			case x86asm.LZCNT:
				kind = ir.Lzcnt
			}
			if src, _, oks := regArgInfo(args[1]); oks {
				em(ir.Insn{Op: ir.AluRR, Kind: uint8(kind), Width: w, Dst: dst, A: src, B: src})
				return nil
			}
			if m, okm := memArg(args[1]); okm {
				base, index, scale, disp, merr := l.memAddr(ins, m)
				if merr != nil {
					return merr
				}
				mw := memWidth(ins)
				em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: mw, SrcW: mw, Dst: ir.VMSCR,
					Base: base, Index: index, Scale: scale, Disp: disp})
				em(ir.Insn{Op: ir.AluRR, Kind: uint8(kind), Width: w, Dst: dst, A: ir.VMSCR, B: ir.VMSCR})
				return nil
			}
			return fmt.Errorf("BSF/BSR 的源操作数不支持")
		}

	case x86asm.IMUL:
		return l.liftImul(f, ins, off)

	case x86asm.SHL, x86asm.SHR, x86asm.SAR, x86asm.ROL, x86asm.ROR:
		kind := map[x86asm.Op]ir.Kind{
			x86asm.SHL: ir.Shl, x86asm.SHR: ir.Shr, x86asm.SAR: ir.Sar,
			x86asm.ROL: ir.Rol, x86asm.ROR: ir.Ror,
		}[op]
		return l.liftShift(f, ins, off, kind)

	case x86asm.INC, x86asm.DEC, x86asm.NEG, x86asm.NOT:
		uk := map[x86asm.Op]ir.UnKind{
			x86asm.INC: ir.Inc, x86asm.DEC: ir.Dec, x86asm.NEG: ir.Neg, x86asm.NOT: ir.Not,
		}[op]
		w := opWidth(ins)
		if r, _, ok := regArgInfo(args[0]); ok {
			em(ir.Insn{Op: ir.AluU, Kind: uint8(uk), Width: w, Dst: r, A: r})
			return nil
		}
		if m, ok := memArg(args[0]); ok {
			base, index, scale, disp, err := l.memAddr(ins, m)
			if err != nil {
				return err
			}
			mw := memWidth(ins)
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: mw, SrcW: mw, Dst: ir.VMSCR,
				Base: base, Index: index, Scale: scale, Disp: disp})
			em(ir.Insn{Op: ir.AluU, Kind: uint8(uk), Width: mw, Dst: ir.VMSCR, A: ir.VMSCR})
			em(ir.Insn{Op: ir.Store, Width: mw, Base: base, Index: index, Scale: scale, Disp: disp, A: ir.VMSCR})
			return nil
		}
		return fmt.Errorf("不支持的 INC/DEC/NEG/NOT 操作数")

	case x86asm.MOVZX, x86asm.MOVSX, x86asm.MOVSXD:
		dst, dstW, ok := regArgInfo(args[0])
		if !ok {
			return fmt.Errorf("扩展指令目标必须是寄存器")
		}
		kind := ir.ZeroExt
		if op == x86asm.MOVSX || op == x86asm.MOVSXD {
			kind = ir.SignExt
		}
		if src, srcW, ok := regArgInfo(args[1]); ok {
			em(ir.Insn{Op: ir.Ext, Kind: uint8(kind), SrcW: srcW, Width: dstW, Dst: dst, A: src})
			return nil
		}
		if m, ok := memArg(args[1]); ok {
			base, index, scale, disp, err := l.memAddr(ins, m)
			if err != nil {
				return err
			}
			srcW := memWidth(ins)
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: srcW, SrcW: srcW, Dst: ir.VMSCR,
				Base: base, Index: index, Scale: scale, Disp: disp})
			em(ir.Insn{Op: ir.Ext, Kind: uint8(kind), SrcW: srcW, Width: dstW, Dst: dst, A: ir.VMSCR})
			return nil
		}
		return fmt.Errorf("不支持的扩展源操作数")

	case x86asm.CDQE:
		em(ir.Insn{Op: ir.Ext, Kind: uint8(ir.SignExt), SrcW: ir.W32, Width: ir.W64, Dst: ir.RAX, A: ir.RAX})
		return nil

	// CDQ / CQO：把累加器**符号扩展**到 DX（x86 的"给 IDIV 准备被除数"）。
	//   CDQ: EDX:EAX ← SignExt(EAX)   等价于 EDX = SAR(EAX,31)
	//   CQO: RDX:RAX ← SignExt(RAX)   等价于 RDX = SAR(RAX,63)
	// 两者都**不改标志位** —— 所以带 |KeepFlags（x86 侧本来恒为 0，这里正是它的用武之地）。
	// 注意：CDQE（EAX→RAX）在上面单独一支；Go 的 x86asm 把 CDQ/CQO 与 CDQE 分成不同助记符。
	case x86asm.CDQ:
		em(ir.Insn{Op: ir.AluRI, Kind: uint8(ir.Sar) | ir.KeepFlags, Width: ir.W32,
			Dst: ir.RDX, A: ir.RAX, Imm: 31})
		return nil
	case x86asm.CQO:
		em(ir.Insn{Op: ir.AluRI, Kind: uint8(ir.Sar) | ir.KeepFlags, Width: ir.W64,
			Dst: ir.RDX, A: ir.RAX, Imm: 63})
		return nil

	case x86asm.DIV, x86asm.IDIV:
		return l.liftDiv(f, ins, off)

	case x86asm.PUSH:
		if r, w, ok := regArgInfo(args[0]); ok {
			if w != ir.W64 {
				return fmt.Errorf("只支持 64 位 PUSH 寄存器")
			}
			em(ir.Insn{Op: ir.PushR, Dst: r})
			return nil
		}
		if i, ok := immArg(args[0]); ok {
			em(ir.Insn{Op: ir.PushI, Imm: uint64(i)})
			return nil
		}
		return fmt.Errorf("不支持的 PUSH 操作数")

	case x86asm.POP:
		r, w, ok := regArgInfo(args[0])
		if !ok || w != ir.W64 {
			return fmt.Errorf("只支持 64 位 POP 寄存器")
		}
		em(ir.Insn{Op: ir.PopR, Dst: r})
		return nil

	case x86asm.JMP:
		if rel, ok := relArg(args[0]); ok {
			target := ins.PC + uint64(ins.Len()) + uint64(rel)
			// 目标落在函数外 = **尾调用**：原语义是"跳到那里、然后返回我的调用者"，
			// 等价于 call 目标; ret。VM 里有 CALLN（相对）与 RET，且参数本来就在客户机寄存器里。
			if target < f.Addr || target >= f.Addr+uint64(f.Size) {
				if target < l.ImageBase {
					return fmt.Errorf("尾调用目标 0x%X 低于镜像基址", target)
				}
				// 目标在镜像内、但**不像函数入口**（前面不是填充/对齐字节）⇒ 它其实是本函数的续段：
				// 必须当普通跳转翻译，并交给孤岛机制去解码目标；若翻成原生调用，那段"函数中段"会在
				// **解释器的栈**上跑（客户的帧内保存位全部错位）—— 实测必崩（__pyx_pymod_create 那例）。
				if l.ReadImage != nil && !l.looksLikeFuncEntry(uint32(target-l.ImageBase)) {
					em(ir.Insn{Op: ir.Jmp, TargetOff: uint32(target - f.Addr)})
					return nil
				}
				em(ir.Insn{Op: ir.CallN, Imm: target - l.ImageBase})
				em(ir.Insn{Op: ir.Ret})
				return nil
			}
			em(ir.Insn{Op: ir.Jmp, TargetOff: uint32(target - f.Addr)})
			return nil
		}
		// 跳转表：JMPQ *table(,idx,8)  —— 编译器为 switch 生成的标准形态，
		// 前面必有 "cmp idx, N; ja default"（下面会校验这个守卫，缺一不可）。
		if m, ok := memArg(args[0]); ok {
			return l.liftJumpTable(f, ins, off, m)
		}
		// 分裂形态（gcc/mingw 的 switch）：lea base,[rip+d] ; movsxd reg,[base+idx*4] ; add reg,base ; jmp *reg
		if r, _, ok := regArgInfo(args[0]); ok {
			return l.liftSplitJumpTable(f, ins, off, r)
		}
		return fmt.Errorf("只支持相对 JMP / 跳转表（融合或分裂形态）")

	case x86asm.CALL:
		// 相对 CALL：目标是编译期常量 → CALLN（RVA）
		if rel, ok := relArg(args[0]); ok {
			target := ins.PC + uint64(ins.Len()) + uint64(rel)
			if target < l.ImageBase {
				return fmt.Errorf("调用目标 0x%X 低于镜像基址", target)
			}
			em(ir.Insn{Op: ir.CallN, Imm: target - l.ImageBase})
			return nil
		}
		// 间接 CALL（虚调用/函数指针）：目标运行时才知道 → CALLR
		//   寄存器形式：直接调用该寄存器里的客户机地址；
		//   内存形式  ：先把目标读进 VMSCR，再调用它。
		if src, _, sok := regArgInfo(args[0]); sok {
			em(ir.Insn{Op: ir.CallR, A: src})
			return nil
		}
		if m, mok := memArg(args[0]); mok {
			base, index, scale, disp, merr := l.memAddr(ins, m)
			if merr != nil {
				return merr
			}
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64,
				Dst: ir.VMSCR, Base: base, Index: index, Scale: scale, Disp: disp})
			em(ir.Insn{Op: ir.CallR, A: ir.VMSCR})
			return nil
		}
		return fmt.Errorf("只支持相对 CALL 或间接 CALL r/m")

	case x86asm.RET:
		em(ir.Insn{Op: ir.Ret})
		return nil
	}

	// ---- SIMD 位搬运（MOVUPS/MOVDQU/MOVQ/PXOR 清零等）----
	if handled, serr := l.liftSIMD(f, ins, off); handled {
		return serr
	}

	// ---- SETcc / CMOVcc：用**前向分支**降级（不需要新的 VM 指令）----
	//
	// SETcc r/m8   →  Jcc cond, L_one ; mov dst,0 ; jmp L_end ; L_one: mov dst,1
	// CMOVcc r,r/m →  Jcc !cond, L_end ; mov dst,src
	//
	// 条件码取反就是 XOR 1（x86 编码里 O/No、B/AE、E/NE … 正好是低比特翻转），
	// 与 VM 的 x86 条件求值器（internal/vm/ref.go 的 condHolds）一致。
	if cond, ok := setccCond[op]; ok {
		w := ir.W8
		// 目标：寄存器或内存字节
		if dst, rw, rok := regArgInfo(args[0]); rok {
			w = rw
			base := len(f.Insns)
			em(ir.Insn{Op: ir.Jcc, Cond: cond, Target: base + 3, TargetOff: irTargetFixed})
			em(ir.Insn{Op: ir.MovRI, Width: w, Dst: dst, Imm: 0})
			em(ir.Insn{Op: ir.Jmp, Target: base + 4, TargetOff: irTargetFixed})
			em(ir.Insn{Op: ir.MovRI, Width: w, Dst: dst, Imm: 1})
			return nil
		}
		m, mok := memArg(args[0])
		if !mok {
			return fmt.Errorf("SETcc 目标必须是寄存器或内存")
		}
		b, idx, sc, disp, err := l.memAddr(ins, m)
		if err != nil {
			return err
		}
		base := len(f.Insns)
		em(ir.Insn{Op: ir.Jcc, Cond: cond, Target: base + 4, TargetOff: irTargetFixed})
		em(ir.Insn{Op: ir.MovRI, Width: w, Dst: ir.VMSCR, Imm: 0})
		em(ir.Insn{Op: ir.Store, Width: w, Base: b, Index: idx, Scale: sc, Disp: disp, A: ir.VMSCR})
		em(ir.Insn{Op: ir.Jmp, Target: base + 6, TargetOff: irTargetFixed})
		em(ir.Insn{Op: ir.MovRI, Width: w, Dst: ir.VMSCR, Imm: 1})
		em(ir.Insn{Op: ir.Store, Width: w, Base: b, Index: idx, Scale: sc, Disp: disp, A: ir.VMSCR})
		return nil
	}
	if cond, ok := cmovccCond[op]; ok {
		dst, w, rok := regArgInfo(args[0])
		if !rok {
			return fmt.Errorf("CMOVcc 目标必须是寄存器")
		}
		base := len(f.Insns)
		em(ir.Insn{Op: ir.Jcc, Cond: cond ^ 1, Target: base + 2, TargetOff: irTargetFixed})
		if src, _, sok := regArgInfo(args[1]); sok {
			em(ir.Insn{Op: ir.MovRR, Width: w, Dst: dst, A: src})
			return nil
		}
		m, mok := memArg(args[1])
		if !mok {
			return fmt.Errorf("CMOVcc 源必须是寄存器或内存")
		}
		b, idx, sc, disp, err := l.memAddr(ins, m)
		if err != nil {
			return err
		}
		em(ir.Insn{Op: ir.Load, Width: w, Kind: uint8(ir.ZeroExt), Dst: dst, Base: b, Index: idx, Scale: sc, Disp: disp})
		return nil
	}

	if cond, ok := jccCond[op]; ok {
		rel, ok2 := relArg(args[0])
		if !ok2 {
			return fmt.Errorf("只支持相对 Jcc")
		}
		target := ins.PC + uint64(ins.Len()) + uint64(rel)
		em(ir.Insn{Op: ir.Jcc, Cond: cond, TargetOff: uint32(target - f.Addr)})
		return nil
	}

	return fmt.Errorf("暂不支持该指令")
}

// setccCond / cmovccCond：x86 条件码（与 ir.Cond 的顺序一致，取反 = XOR 1）
var setccCond = map[x86asm.Op]ir.Cond{
	x86asm.SETO: ir.O, x86asm.SETNO: ir.No,
	x86asm.SETB: ir.B, x86asm.SETAE: ir.AE,
	x86asm.SETE: ir.E, x86asm.SETNE: ir.NE,
	x86asm.SETBE: ir.BE, x86asm.SETA: ir.A,
	x86asm.SETS: ir.S, x86asm.SETNS: ir.NS,
	x86asm.SETP: ir.P, x86asm.SETNP: ir.NP,
	x86asm.SETL: ir.L, x86asm.SETGE: ir.GE,
	x86asm.SETLE: ir.LE, x86asm.SETG: ir.G,
}

var cmovccCond = map[x86asm.Op]ir.Cond{
	x86asm.CMOVO: ir.O, x86asm.CMOVNO: ir.No,
	x86asm.CMOVE: ir.E, x86asm.CMOVNE: ir.NE,
	x86asm.CMOVB: ir.B, x86asm.CMOVAE: ir.AE,
	x86asm.CMOVBE: ir.BE, x86asm.CMOVA: ir.A,
	x86asm.CMOVS: ir.S, x86asm.CMOVNS: ir.NS,
	x86asm.CMOVP: ir.P, x86asm.CMOVNP: ir.NP,
	x86asm.CMOVL: ir.L, x86asm.CMOVGE: ir.GE,
	x86asm.CMOVLE: ir.LE, x86asm.CMOVG: ir.G,
}

var jccCond = map[x86asm.Op]ir.Cond{
	x86asm.JO: ir.O, x86asm.JNO: ir.No,
	x86asm.JB: ir.B, x86asm.JAE: ir.AE,
	x86asm.JE: ir.E, x86asm.JNE: ir.NE,
	x86asm.JBE: ir.BE, x86asm.JA: ir.A,
	x86asm.JS: ir.S, x86asm.JNS: ir.NS,
	x86asm.JP: ir.P, x86asm.JNP: ir.NP,
	x86asm.JL: ir.L, x86asm.JGE: ir.GE,
	x86asm.JLE: ir.LE, x86asm.JG: ir.G,
}

// trackRegs 跟踪 RSP/RBP 相对进入时 RSP 的偏移，并检测“栈地址逃逸”。
//
// 规则：
//
//	push/pop          → spDelta ∓ 8
//	add/sub rsp, imm  → spDelta ± imm
//	lea rsp,[rsp+d]   → spDelta += d
//	mov rbp,rsp       → rbp 的等效偏移 = 当前 spDelta
//	lea rbp,[rsp+d]   → rbp 的等效偏移 = spDelta + d
//	其它写 RSP/RBP    → 标记为“不可跟踪”（后续栈访问失败，而不是算错）
//	把 eff >= 0 的栈地址取到别的寄存器 → 不支持（无法跟踪其后续使用）
//
// loseSP 标记 RSP 不可跟踪，并记下**第一条**导致它的指令（后续栈访问会因此被拒）
func (l *Lifter) loseSP(ins x64dec.Insn) {
	if l.spKnown {
		l.spLostBy = strings.TrimSpace(ins.Text())
	}
	l.spKnown = false
}

func (l *Lifter) trackRegs(ins x64dec.Insn) error {
	args := ins.Inst.Args
	clobber := func(r ir.Reg) {
		if r == ir.RSP {
			l.loseSP(ins)
		}
		if r == ir.RBP {
			l.rbpKnown = false
		}
	}
	argReg := func(i int) (ir.Reg, bool) {
		if i >= len(args) {
			return 0, false
		}
		r, _, ok := regArgInfo(args[i])
		return r, ok
	}

	switch ins.Op() {
	case x86asm.PUSH:
		if l.spKnown {
			l.spDelta -= 8
		}
		return nil

	case x86asm.POP:
		if r, ok := argReg(0); ok && r == ir.RSP {
			l.loseSP(ins)
			return nil
		}
		if l.spKnown {
			l.spDelta += 8
		}
		return nil

	case x86asm.CALL:
		// 我们的 CALL 是“净零”语义：不模拟 push 返回地址（被调方 ret 时抵消），
		// 因此调用后 spDelta 不变。
		return nil

	case x86asm.LEA:
		dst, ok := argReg(0)
		if !ok {
			return nil
		}
		m, isM := memArg(args[1])
		if !isM {
			clobber(dst)
			return nil
		}
		var eff int64
		known := false
		switch {
		case m.Base == x86asm.RSP:
			eff, known = l.spDelta+int64(m.Disp), l.spKnown
		case m.Base == x86asm.RBP && l.rbpKnown:
			eff, known = l.rbpEff+int64(m.Disp), true
		default:
			clobber(dst)
			return nil
		}
		if m.Index != 0 {
			// 带索引的栈地址：真实偏移 = 常量部分 + idx*scale，符号取决于运行期 idx，
			// 无法判定要不要补 FrameSkew。落在"调用方帧"那一侧时宁可拒绝，也不猜。
			if known && eff >= 0 && l.FrameSkew != 0 {
				return fmt.Errorf("栈地址（相对进入时 RSP %+d，带索引）被取到 %s，无法判定是否需要 FrameSkew 修正", eff, dst)
			}
			clobber(dst)
			return nil
		}
		switch {
		case dst == ir.RSP:
			if known {
				l.spDelta = eff
			} else {
				l.loseSP(ins)
			}
		case dst == ir.RBP:
			if known {
				l.rbpEff, l.rbpKnown = eff, true
			} else {
				l.rbpKnown = false
			}
		default:
			// 把栈地址取到普通寄存器：**没有索引寄存器时地址是常量偏移**，可以照搬 memAddr 的修正规则
			// （eff >= 0 的访问补 FrameSkew），于是寄存器的值就是宿主侧那个地址，后续 [reg+disp] 也是对的。
			// 带索引的形式（rsp + idx*scale + disp）符号取决于运行期 idx，无法判定是否要补 FrameSkew → 仍保守拒绝。
			if known && eff >= 0 && l.FrameSkew != 0 && m.Index != 0 {
				return fmt.Errorf("栈地址（相对进入时 RSP %+d，带索引）被取到 %s，无法判定是否需要修正", eff, dst)
			}
			clobber(dst)
		}
		return nil

	case x86asm.MOV:
		dst, ok := argReg(0)
		if !ok {
			return nil
		}
		src, srcIsReg := argReg(1)
		if !srcIsReg {
			clobber(dst)
			return nil
		}
		switch {
		case dst == ir.RBP && src == ir.RSP:
			if l.spKnown {
				l.rbpEff, l.rbpKnown = l.spDelta, true
			} else {
				l.rbpKnown = false
			}
		case dst != ir.RSP && src == ir.RSP:
			// mov reg, rsp：放行，寄存器拿到的是模拟栈那一侧的值（= 当前 guest RSP）。
			// 这对"存一下、最后 mov rsp,reg 还原"的用法（greet 就是）是正确的；
			// 但如果该寄存器随后被用来访问**调用方帧**（正偏移），就会差一个 FrameSkew ——
			// 实测 add_dly 的函数体正是这样（崩溃点在 numpy 里，VM 侧一切正常）。
			// 彻底修法是把这类寄存器纳入与 rbpEff 同类的**别名跟踪**，见 docs/STATUS.md。
			clobber(dst)
		default:
			clobber(dst)
		}
		return nil

	case x86asm.ADD, x86asm.SUB:
		// x86asm 不为“寄存器+立即数”单独设操作码，这里按操作数类型区分
		r, ok := argReg(0)
		if !ok {
			return nil
		}
		if r == ir.RSP {
			imm, iok := immArg(args[1])
			if !iok || !l.spKnown {
				l.loseSP(ins)
				return nil
			}
			if ins.Op() == x86asm.ADD {
				l.spDelta += imm
			} else {
				l.spDelta -= imm
			}
			return nil
		}
		clobber(r)
		return nil
	}

	// 只读指令：它们不写操作数，只写标志位，因此**不能**按下面的保守规则当成"改写了 RSP"。
	// Go 的栈增长检查 CMP RSP, [R14+0x10] 正是这种情况：实测一个 Go 二进制里
	// 14651/19506 条被拒指令都由它引起——是误判，不是能力不足。
	switch ins.Op() {
	case x86asm.CMP, x86asm.TEST, x86asm.BT:
		return nil
	}

	// MUL 写 RAX/RDX（隐式），要如实报告（否则可能漏掉对 RSP 的破坏）
	if ins.Op() == x86asm.MUL {
		clobber(ir.RAX)
		clobber(ir.RDX)
		return nil
	}

	// 其它指令：保守处理——第一个操作数是 RSP/RBP 就认为被改写
	if r, ok := argReg(0); ok {
		clobber(r)
	}
	return nil
}

// liftJumpTable 处理编译器为 switch 生成的跳转表：
//
//	cmp  idx, N-1        ; 边界检查（寄存器 + 立即数）
//	ja   default         ; 越界跳默认分支
//	jmpq *table(,idx,8)  ; 表项是指向本函数各 case 的绝对地址
//
// 只有**守卫完整**时才翻译：从表里读出 N 个入口，每一个都必须落在本函数内，
// 否则整条指令拒绝（宁可保护不了，也不能猜错分支）。
func (l *Lifter) liftJumpTable(f *ir.Func, ins x64dec.Insn, off uint32, m x86asm.Mem) error {
	if l.ReadImage == nil {
		return fmt.Errorf("跳转表需要镜像读取能力（ReadImage 未设置）")
	}
	// RIP 基址的两种表示：x86asm 对 MOV 给出 Base=RIP，对 FF /4（JMP）给出 Base=0 + Index≠0。
	// 在 64 位模式下"无基址 + 有下标"的 SIB 只能是 RIP 相对形式，所以两者都接受。
	ripRel := m.Base == x86asm.RIP || (m.Base == 0 && m.Index != 0)
	if !ripRel || m.Index == 0 {
		return fmt.Errorf("跳转表形式只支持 RIP 基址 + 寄存器下标")
	}
	// 表项宽度：8 字节（绝对地址）或 4 字节（相对偏移），都只接受静态表
	entSize := 8
	rel4 := false
	switch m.Scale {
	case 8:
	case 4:
		entSize, rel4 = 4, true
	default:
		return fmt.Errorf("跳转表下标缩放 %d 不支持", m.Scale)
	}
	idxReg, _, ok := regArgInfo(x86asm.Reg(m.Index))
	if !ok {
		return fmt.Errorf("跳转表下标寄存器无法识别")
	}
	// 守卫：上一条是 Jcc（越界跳默认），再上一条是 CMP idx, 立即数
	if l.prev1 == nil || l.prev2 == nil {
		return fmt.Errorf("跳转表缺少前面的边界检查")
	}
	guardOp := l.prev1.Op()
	guardTgt, gok := l.prev1.PCRelTarget()
	if !gok {
		return fmt.Errorf("边界检查的跳转目标取不到")
	}
	var n int
	switch guardOp {
	case x86asm.JA: // idx > K → 越界 ⇒ 合法范围 0..K ⇒ K+1 项
		n = -1
	case x86asm.JAE: // idx >= K → 越界 ⇒ 合法范围 0..K-1 ⇒ K 项
		n = -2
	default:
		return fmt.Errorf("跳转表缺少 'ja/jae default' 形式的边界检查（实际 %v）", guardOp)
	}
	if l.prev2.Op() != x86asm.CMP {
		return fmt.Errorf("边界检查前不是 CMP")
	}
	cmpArgs := l.prev2.Inst.Args
	cr, _, cok := regArgInfo(cmpArgs[0])
	if !cok || cr != idxReg {
		return fmt.Errorf("边界检查比较的不是跳转表下标寄存器")
	}
	k, kok := immArg(cmpArgs[1])
	if !kok || k < 0 || k > 4096 {
		return fmt.Errorf("边界检查的立即数不合理")
	}
	if n == -1 {
		n = int(k) + 1
	} else {
		n = int(k)
	}
	if n <= 0 || n > 1024 {
		return fmt.Errorf("跳转表项数 %d 不合理", n)
	}
	tableVA := ins.PC + uint64(ins.Len()) + uint64(int64(m.Disp))
	if tableVA < l.ImageBase {
		return fmt.Errorf("跳转表地址 0x%X 低于镜像基址", tableVA)
	}
	raw := l.ReadImage(uint32(tableVA-l.ImageBase), n*entSize)
	if len(raw) < n*entSize {
		return fmt.Errorf("读不到跳转表（需要 %d 字节）", n*entSize)
	}
	targets := make([]uint64, n)
	funcStart, funcEnd := f.Addr, f.Addr+uint64(f.Size)
	for i := 0; i < n; i++ {
		var v uint64
		if rel4 {
			// 相对偏移表：目标 = 表基址 + 偏移（gcc 的 -fPIC 风格）
			d := int32(uint32(raw[i*4]) | uint32(raw[i*4+1])<<8 | uint32(raw[i*4+2])<<16 | uint32(raw[i*4+3])<<24)
			v = tableVA + uint64(int64(d))
		} else {
			v = uint64(raw[i*8]) | uint64(raw[i*8+1])<<8 | uint64(raw[i*8+2])<<16 | uint64(raw[i*8+3])<<24 |
				uint64(raw[i*8+4])<<32 | uint64(raw[i*8+5])<<40 | uint64(raw[i*8+6])<<48 | uint64(raw[i*8+7])<<56
		}
		if v < funcStart || v >= funcEnd {
			// 有表项落到函数外：要么这不是跳转表，要么表比守卫说的长 → 拒绝（fail-fast）
			return fmt.Errorf("跳转表第 %d 项 0x%X 不在本函数内", i, v)
		}
		targets[i] = v
	}
	return l.emitJumpTableChain(f, ins, off, idxReg, targets, guardTgt)
}

// emitJumpTableChain 把"表 + 守卫"降级成比较链：cmp idx,i ; je case_i …… 最后跳到默认分支
func (l *Lifter) emitJumpTableChain(f *ir.Func, ins x64dec.Insn, off uint32, idxReg ir.Reg, targets []uint64, defaultTgt uint64) error {
	em := func(in ir.Insn) {
		in.SrcOff = off
		in.Text = ins.Text()
		l.emit(f, in)
	}
	for i := range targets {
		em(ir.Insn{Op: ir.CmpRI, Kind: uint8(ir.Cmp), Width: ir.W64, A: idxReg, Imm: uint64(i)})
		em(ir.Insn{Op: ir.Jcc, Cond: ir.E, TargetOff: uint32(targets[i] - f.Addr)})
	}
	em(ir.Insn{Op: ir.Jmp, TargetOff: uint32(defaultTgt - f.Addr)})
	return nil
}

// liftSplitJumpTable 处理 gcc/Go 实际生成的分裂形态跳转表：
//
//	and    $mask,%ecx              ; 可选
//	cmp    $K,%ecx                 ; 守卫（寄存器 + 立即数）
//	ja/jae default                 ; 越界跳默认
//	lea    table(%rip),%r8         ; 表基址
//	movsxd (%r8,%rcx,4),%rax       ; 读 4 字节**自相对**偏移（clang -fno-pic 会用 8 字节绝对地址）
//	add    %r8,%rax                ; 目标 = 表基址 + 偏移
//	jmp    *%rax
//
// 与融合形态同一套纪律：表项必须全部落在本函数内、必须有守卫，否则整条指令拒绝。
func (l *Lifter) liftSplitJumpTable(f *ir.Func, ins x64dec.Insn, off uint32, jmpReg ir.Reg) error {
	if l.ReadImage == nil {
		return fmt.Errorf("跳转表需要镜像读取能力（ReadImage 未设置）")
	}
	n := len(l.recent)
	if n < 3 {
		return fmt.Errorf("分裂跳转表：前面的指令太少")
	}
	// (1) 前一条是"把表基址加到下标上"：gcc 两种写法都要认——
	//     add jmpReg, base            或     lea (base, jmpReg), jmpReg
	addIns := l.recent[n-1]
	var base ir.Reg
	switch addIns.Op() {
	case x86asm.ADD:
		addDst, _, ok1 := regArgInfo(addIns.Inst.Args[0])
		addSrc, _, ok2 := regArgInfo(addIns.Inst.Args[1])
		if !ok1 || !ok2 || addDst != jmpReg {
			return fmt.Errorf("分裂跳转表：ADD 的目标不是被跳转的寄存器")
		}
		base = addSrc
	default:
		// 实测 gcc 在个别形态下会给 "lea table(%rip),reg ; jmp *reg"（基址装载后直接跳），
		// 那不是跳转表（表项是相对表基址的偏移，必须再有一次加法）。这里如实拒绝。
		return fmt.Errorf("分裂跳转表：前一条不是 ADD 加法（实际 %v）", addIns.Op())
	}
	// (2) 再前一条：movsxd jmpReg, [base + idx*scale]
	mv := l.recent[n-2]
	if mv.Op() != x86asm.MOVSXD && mv.Op() != x86asm.MOVSX {
		return fmt.Errorf("分裂跳转表：读表不是 MOVSXD（实际 %v）", mv.Op())
	}
	mvDst, _, ok3 := regArgInfo(mv.Inst.Args[0])
	if !ok3 || mvDst != jmpReg {
		return fmt.Errorf("分裂跳转表：读表目标不是被跳转的寄存器")
	}
	m, okm := memArg(mv.Inst.Args[1])
	if !okm {
		return fmt.Errorf("分裂跳转表：读表不是内存操作数")
	}
	mBase, _, ok4 := regInfo(m.Base)
	if !ok4 || mBase != base {
		return fmt.Errorf("分裂跳转表：读表基址与 ADD 的不是同一个寄存器")
	}
	idxReg, _, ok5 := regInfo(m.Index)
	if !ok5 {
		return fmt.Errorf("分裂跳转表：读表没有下标寄存器")
	}
	entSize := int(m.Scale)
	if entSize != 4 && entSize != 8 {
		return fmt.Errorf("分裂跳转表：表项宽度 %d 不支持", entSize)
	}
	rel4 := entSize == 4
	// (3) 往前找 lea base, [rip+disp]（表基址）
	tableVA := uint64(0)
	foundTable := false
	for k := n - 3; k >= 0 && k >= n-12; k-- {
		li := l.recent[k]
		if li.Op() != x86asm.LEA {
			continue
		}
		ldst, _, okd := regArgInfo(li.Inst.Args[0])
		if !okd || ldst != base {
			continue
		}
		lm, okl := memArg(li.Inst.Args[1])
		if !okl || lm.Base != x86asm.RIP || lm.Index != 0 {
			continue
		}
		tableVA = li.PC + uint64(li.Len()) + uint64(int64(lm.Disp))
		foundTable = true
		break
	}
	if !foundTable {
		return fmt.Errorf("分裂跳转表：找不到 lea table(%%rip)")
	}
	// (4) 守卫：cmp idx,K 紧跟 ja/jae default
	count, defaultTgt, guardOK := 0, uint64(0), false
	for k := n - 2; k >= 0 && k >= n-12; k-- {
		if l.recent[k].Op() != x86asm.CMP {
			continue
		}
		ca := l.recent[k].Inst.Args
		cr, _, okc := regArgInfo(ca[0])
		if !okc || cr != idxReg {
			continue
		}
		kk, okk := immArg(ca[1])
		if !okk || kk < 0 || kk > 4096 {
			continue
		}
		if k+1 >= n {
			break
		}
		jc := l.recent[k+1]
		switch jc.Op() {
		case x86asm.JA:
			count = int(kk) + 1
		case x86asm.JAE:
			count = int(kk)
		default:
			continue
		}
		tg, okt := jc.PCRelTarget()
		if !okt {
			continue
		}
		defaultTgt, guardOK = tg, true
		break
	}
	if !guardOK {
		return fmt.Errorf("分裂跳转表：找不到 'cmp idx,K ; ja/jae default' 守卫")
	}
	if count <= 0 || count > 1024 {
		return fmt.Errorf("分裂跳转表：项数 %d 不合理", count)
	}
	// (5) 读表并逐一校验
	raw := l.ReadImage(uint32(tableVA-l.ImageBase), count*entSize)
	if len(raw) < count*entSize {
		return fmt.Errorf("分裂跳转表：读不到表（需要 %d 字节）", count*entSize)
	}
	funcStart, funcEnd := f.Addr, f.Addr+uint64(f.Size)
	targets := make([]uint64, count)
	for i := 0; i < count; i++ {
		var v uint64
		if rel4 {
			d := int32(uint32(raw[i*4]) | uint32(raw[i*4+1])<<8 | uint32(raw[i*4+2])<<16 | uint32(raw[i*4+3])<<24)
			v = tableVA + uint64(int64(d))
		} else {
			v = uint64(raw[i*8]) | uint64(raw[i*8+1])<<8 | uint64(raw[i*8+2])<<16 | uint64(raw[i*8+3])<<24 |
				uint64(raw[i*8+4])<<32 | uint64(raw[i*8+5])<<40 | uint64(raw[i*8+6])<<48 | uint64(raw[i*8+7])<<56
		}
		if v < funcStart || v >= funcEnd {
			return fmt.Errorf("分裂跳转表：第 %d 项 0x%X 不在本函数内", i, v)
		}
		targets[i] = v
	}
	return l.emitJumpTableChain(f, ins, off, idxReg, targets, defaultTgt)
}

// liftLocked 处理带 LOCK 前缀的原子读改写。目标是内存操作数，源是寄存器：
//
//	LOCK XADD  [mem], reg   mem ← mem+reg，reg ← 旧值   → KA_ADD + Dst=reg
//	LOCK ADD/SUB/AND/OR/XOR [mem], reg                  → KA_* + Dst=none（寄存器不变）
//	LOCK INC/DEC [mem]                                  → KA_INC/KA_DEC
//	LOCK CMPXCHG [mem], reg                              → KA_CMPXCHG（与 RAX 比较）
//
// 真正的原子性由解释器用 __atomic_*（x86-64 上就是 lock 前缀指令）保证，多线程语义与原生一致。
func (l *Lifter) liftLocked(f *ir.Func, ins x64dec.Insn, off uint32, em func(ir.Insn)) error {
	args := ins.Inst.Args
	if len(args) == 0 {
		return fmt.Errorf("LOCK 指令没有操作数")
	}
	m, isM := memArg(args[0])
	if !isM {
		return fmt.Errorf("LOCK 只支持内存目标（%s）", ins.Text())
	}
	base, index, scale, disp, merr := l.memAddr(ins, m)
	if merr != nil {
		return merr
	}
	w := memWidth(ins)
	// 源寄存器（XADD/ADD/CMPXCHG 等）
	var src ir.Reg = ir.NoReg
	if len(args) > 1 {
		if r, _, ok := regArgInfo(args[1]); ok {
			src = r
		}
	}
	switch ins.Op() {
	case x86asm.XADD:
		if src == ir.NoReg {
			return fmt.Errorf("XADD 需要寄存器源")
		}
		em(ir.Insn{Op: ir.Atomic, Kind: vmKindAdd, Width: w, Dst: src, A: src,
			Base: base, Index: index, Scale: scale, Disp: disp})
		return nil
	case x86asm.ADD, x86asm.SUB, x86asm.AND, x86asm.OR, x86asm.XOR:
		if src == ir.NoReg {
			// 立即数形式（如 lock addq $1, g）：先把立即数放进暂存寄存器
			if imm, okimm := immArg(args[1]); okimm {
				em(ir.Insn{Op: ir.MovRI, Width: w, Dst: ir.VMSCR, Imm: uint64(uint32(imm))})
				src = ir.VMSCR
			} else {
				return fmt.Errorf("LOCK ALU 需要寄存器或立即数源")
			}
		}
		kind := map[x86asm.Op]uint8{
			x86asm.ADD: vmKindAdd, x86asm.SUB: vmKindSub, x86asm.AND: vmKindAnd,
			x86asm.OR: vmKindOr, x86asm.XOR: vmKindXor,
		}[ins.Op()]
		em(ir.Insn{Op: ir.Atomic, Kind: kind, Width: w, Dst: ir.NoReg, A: src,
			Base: base, Index: index, Scale: scale, Disp: disp})
		return nil
	case x86asm.INC, x86asm.DEC:
		var kind uint8 = vmKindInc
		if ins.Op() == x86asm.DEC {
			kind = vmKindDec
		}
		em(ir.Insn{Op: ir.Atomic, Kind: kind, Width: w, Dst: ir.NoReg, A: ir.NoReg,
			Base: base, Index: index, Scale: scale, Disp: disp})
		return nil
	case x86asm.CMPXCHG:
		if src == ir.NoReg {
			return fmt.Errorf("CMPXCHG 需要寄存器源")
		}
		em(ir.Insn{Op: ir.Atomic, Kind: vmKindCmpxchg, Width: w, Dst: ir.NoReg, A: src,
			Base: base, Index: index, Scale: scale, Disp: disp})
		return nil
	}
	return fmt.Errorf("暂不支持该 LOCK 指令（%s）", ins.Text())
}

// 原子子操作编号（与 C 侧 KA_* 一致）
const (
	vmKindXchg = iota
	vmKindAdd
	vmKindSub
	vmKindAnd
	vmKindOr
	vmKindXor
	vmKindInc
	vmKindDec
	vmKindCmpxchg
)

// xmmReg 判断操作数是否是 XMM 寄存器（X0..X15）
func xmmReg(a x86asm.Arg) (x86asm.Reg, bool) {
	r, ok := a.(x86asm.Reg)
	if !ok || r < x86asm.X0 || r > x86asm.X15 {
		return 0, false
	}
	return r, true
}

// liftSIMD 处理只用"位搬运"就能表达的 SIMD 指令（不含浮点运算）：
//
//	MOVUPS/MOVAPS/MOVDQU/MOVDQA  128 位搬运（寄存器↔寄存器、寄存器↔内存）
//	MOVQ/MOVD                    XMM 与通用寄存器/内存之间的搬运（按 x86 语义清零高位）
//	PXOR/XORPS 同寄存器          清零
//
// XMM 寄存器堆放在 blob 的 .bss 里（见 vm_interp.c 的 vm_xmm），用 VMBASE+RVA 寻址，
// 因此**不需要改 ctx ABI，也不需要入口保存/恢复 XMM**（x86-64 里它们是调用者保存的）。
//
// 返回值 handled=true 表示这条指令归本函数管（err 为 nil 即翻译成功）。
func (l *Lifter) liftSIMD(f *ir.Func, ins x64dec.Insn, off uint32) (bool, error) {
	op := ins.Op()
	args := ins.Inst.Args
	em := func(in ir.Insn) { in.SrcOff = off; in.Text = ins.Text(); l.emit(f, in) }
	needXMM := func() error {
		if l.XMMAreaRVA == 0 {
			return fmt.Errorf("SIMD 需要 XMM 寄存器堆（SetXMMArea 未设置）")
		}
		return nil
	}

	switch op {
	case x86asm.MOVUPS, x86asm.MOVAPS, x86asm.MOVDQU, x86asm.MOVDQA, x86asm.MOVUPD, x86asm.MOVAPD:
		if err := needXMM(); err != nil {
			return true, err
		}
		dx, dstIsX := xmmReg(args[0])
		sx, srcIsX := xmmReg(args[1])
		switch {
		case dstIsX && srcIsX:
			for half := 0; half < 2; half++ {
				dd, ok1 := l.xmmDisp(dx, half)
				sd, ok2 := l.xmmDisp(sx, half)
				if !ok1 || !ok2 {
					return true, fmt.Errorf("XMM 槽位不可用")
				}
				em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64,
					Dst: ir.VMSCR, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: sd})
				em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd, A: ir.VMSCR})
			}
			return true, nil
		case dstIsX:
			m, ok := memArg(args[1])
			if !ok {
				return true, fmt.Errorf("SIMD 源操作数不支持")
			}
			base, index, scale, disp, err := l.memAddr(ins, m)
			if err != nil {
				return true, err
			}
			for half := 0; half < 2; half++ {
				dd, ok := l.xmmDisp(dx, half)
				if !ok {
					return true, fmt.Errorf("XMM 槽位不可用")
				}
				em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.VMSCR,
					Base: base, Index: index, Scale: scale, Disp: disp + int32(half*8)})
				em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd, A: ir.VMSCR})
			}
			return true, nil
		case srcIsX:
			m, ok := memArg(args[0])
			if !ok {
				return true, fmt.Errorf("SIMD 目标操作数不支持")
			}
			base, index, scale, disp, err := l.memAddr(ins, m)
			if err != nil {
				return true, err
			}
			for half := 0; half < 2; half++ {
				sd, ok := l.xmmDisp(sx, half)
				if !ok {
					return true, fmt.Errorf("XMM 槽位不可用")
				}
				em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64,
					Dst: ir.VMSCR, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: sd})
				em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: base, Index: index, Scale: scale,
					Disp: disp + int32(half*8), A: ir.VMSCR})
			}
			return true, nil
		}
		return true, fmt.Errorf("SIMD 搬运形式不支持")

	case x86asm.PADDB, x86asm.PADDW, x86asm.PADDD, x86asm.PADDQ,
		x86asm.PSUBB, x86asm.PSUBW, x86asm.PSUBD, x86asm.PSUBQ,
		x86asm.PANDN:
		// 打包（按 lane）算术：逐 lane 用现有 ALU 处理，全部带 |KeepFlags（打包指令不改标志位）。
		// lane 宽度 = 1/2/4/8 字节；R11 依旧通过 blob 暂存槽 vm_tmp 借用（不碰 RSP）。
		if err := needXMM(); err != nil {
			return true, err
		}
		if l.ScratchRVA == 0 {
			return true, fmt.Errorf("打包 SIMD 需要暂存槽（SetScratchArea 未设置）")
		}
		pdx, pokd := xmmReg(args[0])
		if !pokd {
			return true, fmt.Errorf("%v 的目标必须是 XMM", op)
		}
		laneBytes := 4
		switch op {
		case x86asm.PADDB, x86asm.PSUBB:
			laneBytes = 1
		case x86asm.PADDW, x86asm.PSUBW:
			laneBytes = 2
		case x86asm.PADDQ, x86asm.PSUBQ:
			laneBytes = 8
		}
		laneW := ir.Width(laneBytes * 8)
		pkind := ir.Add
		switch op {
		case x86asm.PSUBB, x86asm.PSUBW, x86asm.PSUBD, x86asm.PSUBQ:
			pkind = ir.Sub
		case x86asm.PANDN:
			pkind = ir.And
		}
		// 源地址：XMM 槽位（用 VMBASE）或内存操作数
		var sBase, sIndex ir.Reg = ir.VMBASE, ir.NoReg
		var sScale uint8 = 1
		var sDisp int32
		if psx, poks := xmmReg(args[1]); poks {
			d0, ok := l.xmmDisp(psx, 0)
			if !ok {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			sDisp = d0
		} else if pm, pokm := memArg(args[1]); pokm {
			b2, i2, sc2, d2, merr := l.memAddr(ins, pm)
			if merr != nil {
				return true, merr
			}
			sBase, sIndex, sScale, sDisp = b2, i2, sc2, d2
		} else {
			return true, fmt.Errorf("%v 的源操作数不支持", op)
		}
		em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: int32(l.ScratchRVA), A: ir.R11})
		lanes := 16 / laneBytes
		for lane := 0; lane < lanes; lane++ {
			off := int32(lane * laneBytes)
			dd, ok := l.xmmDisp(pdx, 0)
			if !ok {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: laneW, SrcW: laneW, Dst: ir.R11,
				Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd + off})
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: laneW, SrcW: laneW, Dst: ir.VMSCR,
				Base: sBase, Index: sIndex, Scale: sScale, Disp: sDisp + off})
			if op == x86asm.PANDN {
				em(ir.Insn{Op: ir.AluU, Kind: uint8(ir.Not) | ir.KeepFlags, Width: laneW, Dst: ir.R11, A: ir.R11})
			}
			em(ir.Insn{Op: ir.AluRR, Kind: uint8(pkind) | ir.KeepFlags, Width: laneW, Dst: ir.R11, A: ir.R11, B: ir.VMSCR})
			em(ir.Insn{Op: ir.Store, Width: laneW, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd + off, A: ir.R11})
		}
		em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.R11,
			Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: int32(l.ScratchRVA)})
		return true, nil

	case x86asm.PXOR, x86asm.XORPS, x86asm.PAND, x86asm.POR, x86asm.ANDPS, x86asm.ORPS:
		if err := needXMM(); err != nil {
			return true, err
		}
		dx, okd := xmmReg(args[0])
		sx, oks := xmmReg(args[1])
		// 按位运算：dst = dst OP src，逐 8 字节处理。
		//
		// 难点：ALU 需要**两个寄存器**，而我只有一个暂存 VMSCR。这里借 R11 用，但**不能 push/pop**：
		// push 会改动模拟 RSP，于是同一条指令里后面那些 [rsp+disp] 形式的内存操作数会算错
		// （实测就是这么来的：结果呈现『原生*4+1』的怪规律）。改用 blob 里的专用暂存槽 vm_tmp。
		// 所有 ALU 都带 |KeepFlags —— 按位指令本来就不改标志位，Load/Store 也不碰标志位。
		if l.ScratchRVA == 0 {
			return true, fmt.Errorf("按位 SIMD 需要暂存槽（SetScratchArea 未设置）")
		}
		bitKind := map[x86asm.Op]ir.Kind{
			x86asm.PXOR: ir.Xor, x86asm.XORPS: ir.Xor,
			x86asm.PAND: ir.And, x86asm.ANDPS: ir.And,
			x86asm.POR: ir.Or, x86asm.ORPS: ir.Or,
		}[op]
		save := func() {
			em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: int32(l.ScratchRVA), A: ir.R11})
		}
		restore := func() {
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.R11, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: int32(l.ScratchRVA)})
		}
		if okd && dx != 0 && !oks {
			m, okm := memArg(args[1])
			if !okm {
				return true, fmt.Errorf("%v 的源操作数不支持", op)
			}
			base, index, scale, disp, merr := l.memAddr(ins, m)
			if merr != nil {
				return true, merr
			}
			save()
			for half := 0; half < 2; half++ {
				dd, ok := l.xmmDisp(dx, half)
				if !ok {
					return true, fmt.Errorf("XMM 槽位不可用")
				}
				em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.R11,
					Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd})
				em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.VMSCR,
					Base: base, Index: index, Scale: scale, Disp: disp + int32(half*8)})
				em(ir.Insn{Op: ir.AluRR, Kind: uint8(bitKind) | ir.KeepFlags, Width: ir.W64,
					Dst: ir.R11, A: ir.R11, B: ir.VMSCR})
				em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd, A: ir.R11})
			}
			restore()
			return true, nil
		}
		if okd && oks && dx != sx {
			save()
			for half := 0; half < 2; half++ {
				dd, ok1 := l.xmmDisp(dx, half)
				sd, ok2 := l.xmmDisp(sx, half)
				if !ok1 || !ok2 {
					return true, fmt.Errorf("XMM 槽位不可用")
				}
				em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.R11,
					Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd})
				em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.VMSCR,
					Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: sd})
				em(ir.Insn{Op: ir.AluRR, Kind: uint8(bitKind) | ir.KeepFlags, Width: ir.W64,
					Dst: ir.R11, A: ir.R11, B: ir.VMSCR})
				em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd, A: ir.R11})
			}
			restore()
			return true, nil
		}

		if okd && oks && dx == sx {
			for half := 0; half < 2; half++ {
				dd, ok := l.xmmDisp(dx, half)
				if !ok {
					return true, fmt.Errorf("XMM 槽位不可用")
				}
				em(ir.Insn{Op: ir.MovRI, Width: ir.W64, Dst: ir.VMSCR, Imm: 0})
				em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd, A: ir.VMSCR})
			}
			return true, nil
		}
		return true, fmt.Errorf("%v 只支持同寄存器清零、寄存器/内存按位运算（SIMD 算术不在子集内）", op)

	case x86asm.PUNPCKLQDQ, x86asm.PUNPCKHQDQ, x86asm.MOVDDUP:
		// 64 位半搬移/复制（纯位搬运，不碰标志位、不借通用寄存器）：
		//   PUNPCKLQDQ: dst.hi ← src.lo          （dst.lo 保持）
		//   PUNPCKHQDQ: dst.lo ← src.hi          （dst.hi 保持）
		//   MOVDDUP   : dst.lo ← src.lo ; dst.hi ← src.lo
		if err := needXMM(); err != nil {
			return true, err
		}
		dx, okd := xmmReg(args[0])
		if !okd {
			return true, fmt.Errorf("%v 的目标必须是 XMM", op)
		}
		if sx, oks := xmmReg(args[1]); oks {
			sh := 0
			if op == x86asm.PUNPCKHQDQ {
				sh = 1
			}
			sd, ok := l.xmmDisp(sx, sh)
			if !ok {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.VMSCR,
				Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: sd})
		} else if m, okm := memArg(args[1]); okm {
			base, index, scale, disp, merr := l.memAddr(ins, m)
			if merr != nil {
				return true, merr
			}
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.VMSCR,
				Base: base, Index: index, Scale: scale, Disp: disp})
		} else {
			return true, fmt.Errorf("%v 的源操作数不支持", op)
		}
		var halves []int
		switch op {
		case x86asm.PUNPCKLQDQ:
			halves = []int{1}
		case x86asm.PUNPCKHQDQ:
			halves = []int{0}
		default: // MOVDDUP
			halves = []int{0, 1}
		}
		for _, half := range halves {
			dd, ok := l.xmmDisp(dx, half)
			if !ok {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd, A: ir.VMSCR})
		}
		return true, nil

	case x86asm.PUNPCKLDQ, x86asm.PUNPCKHDQ, x86asm.PSRLDQ, x86asm.PSLLDQ:
		// 需要"先整体读、再整体写"（源与目标重叠），所以借用 blob 里的 16 字节构建缓冲
		// （vm_tmp+8），最后整体拷回目标。全程不碰标志位、不碰 RSP。
		if err := needXMM(); err != nil {
			return true, err
		}
		if l.ScratchRVA == 0 {
			return true, fmt.Errorf("%v 需要暂存槽（SetScratchArea 未设置）", op)
		}
		bdx, bokd := xmmReg(args[0])
		if !bokd {
			return true, fmt.Errorf("%v 的目标必须是 XMM", op)
		}
		dd0, okdd := l.xmmDisp(bdx, 0)
		if !okdd {
			return true, fmt.Errorf("XMM 槽位不可用")
		}
		build := int32(l.ScratchRVA) + 8
		switch op {
		case x86asm.PUNPCKLDQ, x86asm.PUNPCKHDQ:
			// 源：XMM 或内存
			var sBase, sIndex ir.Reg = ir.VMBASE, ir.NoReg
			var sScale uint8 = 1
			var sDisp int32
			if psx, poks := xmmReg(args[1]); poks {
				s0, ok := l.xmmDisp(psx, 0)
				if !ok {
					return true, fmt.Errorf("XMM 槽位不可用")
				}
				sDisp = s0
			} else if pm, pokm := memArg(args[1]); pokm {
				b2, i2, sc2, d2, merr := l.memAddr(ins, pm)
				if merr != nil {
					return true, merr
				}
				sBase, sIndex, sScale, sDisp = b2, i2, sc2, d2
			} else {
				return true, fmt.Errorf("%v 的源操作数不支持", op)
			}
			// 结果 dword 顺序：[dst.d0, src.d0, dst.d1, src.d1]（高版用 d2/d3）
			base := 0
			if op == x86asm.PUNPCKHDQ {
				base = 2
			}
			em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: int32(l.ScratchRVA), A: ir.R11})
			for i := 0; i < 4; i++ {
				fromDst := i%2 == 0
				lane := base + i/2
				if fromDst {
					em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W32, SrcW: ir.W32, Dst: ir.VMSCR,
						Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd0 + int32(lane*4)})
				} else {
					em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W32, SrcW: ir.W32, Dst: ir.VMSCR,
						Base: sBase, Index: sIndex, Scale: sScale, Disp: sDisp + int32(lane*4)})
				}
				em(ir.Insn{Op: ir.Store, Width: ir.W32, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: build + int32(i*4), A: ir.VMSCR})
			}
		case x86asm.PSRLDQ, x86asm.PSLLDQ:
			imm, okimm := immArg(args[1])
			if !okimm || imm < 0 || imm > 255 {
				return true, fmt.Errorf("%v 需要 imm8", op)
			}
			n := int(imm)
			em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: int32(l.ScratchRVA), A: ir.R11})
			for i := 0; i < 16; i++ {
				var srcIdx int
				if op == x86asm.PSRLDQ {
					srcIdx = i + n // 右移：低位 ← 高位
				} else {
					srcIdx = i - n // 左移：高位 ← 低位
				}
				if srcIdx >= 0 && srcIdx < 16 {
					em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W8, SrcW: ir.W8, Dst: ir.VMSCR,
						Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd0 + int32(srcIdx)})
				} else {
					em(ir.Insn{Op: ir.MovRI, Width: ir.W64, Dst: ir.VMSCR, Imm: 0})
				}
				em(ir.Insn{Op: ir.Store, Width: ir.W8, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: build + int32(i), A: ir.VMSCR})
			}
		}
		// 把构建好的 16 字节拷回目标
		for half := 0; half < 2; half++ {
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.VMSCR,
				Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: build + int32(half*8)})
			em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd0 + int32(half*8), A: ir.VMSCR})
		}
		em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.R11,
			Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: int32(l.ScratchRVA)})
		return true, nil

	case x86asm.ADDSD, x86asm.SUBSD, x86asm.MULSD, x86asm.DIVSD,
		x86asm.CVTSI2SD, x86asm.CVTTSD2SI, x86asm.UCOMISD, x86asm.COMISD,
		x86asm.CVTDQ2PD:
		// 第 71 轮查明："加了浮点代码就连别的函数都错"是 gcc **-O2 对解释器整体编译错**（疑似既有 UB
		// 被浮点代码改变了优化决策）。把浮点实现拆成独立函数也无效，改用 -O1 编译解释器后一切正常。
		// 详见 STATUS 第 71 轮；性能代价 ~1.3-1.7×，已记录在案。

		// 注：COMISD 与 UCOMISD 的标志位结果完全相同，差别只在 QNaN 时是否置 FP 异常标志位——
		// 本 VM 不建模 FP 异常，所以按同一种处理。
		// 浮点标量运算：目标/第一操作数在 XMM 槽位里，内存操作数先搬到暂存槽（vm_tmp+8）。
		// 解释器用它自己的 FPU 算（原生 double），所以语义与硬件一致。
		if err := needXMM(); err != nil {
			return true, err
		}
		if l.ScratchRVA == 0 {
			return true, fmt.Errorf("浮点运算需要暂存槽（SetScratchArea 未设置）")
		}
		scratch := int32(l.ScratchRVA) + 8
		valOff := func(arg x86asm.Arg, need64 bool) (int32, error) {
			if sx, oks := xmmReg(arg); oks {
				sd, ok := l.xmmDisp(sx, 0)
				if !ok {
					return 0, fmt.Errorf("XMM 槽位不可用")
				}
				return sd, nil
			}
			if m, okm := memArg(arg); okm {
				base, index, scale, disp, merr := l.memAddr(ins, m)
				if merr != nil {
					return 0, merr
				}
				if need64 {
					em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.VMSCR,
						Base: base, Index: index, Scale: scale, Disp: disp})
					em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: scratch, A: ir.VMSCR})
				} else {
					em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W32, SrcW: ir.W32, Dst: ir.VMSCR,
						Base: base, Index: index, Scale: scale, Disp: disp})
					em(ir.Insn{Op: ir.Store, Width: ir.W32, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: scratch, A: ir.VMSCR})
				}
				return scratch, nil
			}
			return 0, fmt.Errorf("浮点操作数不支持")
		}
		switch op {
		case x86asm.ADDSD, x86asm.SUBSD, x86asm.MULSD, x86asm.DIVSD:
			dx, okd := xmmReg(args[0])
			if !okd {
				return true, fmt.Errorf("%v 的目标必须是 XMM", op)
			}
			dd, ok := l.xmmDisp(dx, 0)
			if !ok {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			so, serr := valOff(args[1], true)
			if serr != nil {
				return true, serr
			}
			kind := map[x86asm.Op]uint8{
				x86asm.ADDSD: 0 /* KF_ADD */, x86asm.SUBSD: 1, /* KF_SUB */
				x86asm.MULSD: 2 /* KF_MUL */, x86asm.DIVSD: 3, /* KF_DIV */
			}[op]
			em(ir.Insn{Op: ir.Fp, Kind: kind, Width: ir.W64, Disp: dd, Imm: uint64(uint32(dd)), Imm2: uint64(uint32(so))})
			return true, nil
		case x86asm.CVTSI2SD:
			// 源是整数寄存器/内存：先按宽度符号扩展到暂存槽，再转成 double
			dx, okd := xmmReg(args[0])
			if !okd {
				return true, fmt.Errorf("CVTSI2SD 的目标必须是 XMM")
			}
			dd, ok := l.xmmDisp(dx, 0)
			if !ok {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			src64 := opWidth(ins) == ir.W64
			if src, _, oks := regArgInfo(args[1]); oks {
				if src64 {
					em(ir.Insn{Op: ir.MovRR, Width: ir.W64, Dst: ir.VMSCR, A: src})
				} else {
					em(ir.Insn{Op: ir.MovRR, Width: ir.W32, Dst: ir.VMSCR, A: src})
					em(ir.Insn{Op: ir.Ext, Kind: uint8(ir.SignExt), Width: ir.W64, SrcW: ir.W32, Dst: ir.VMSCR, A: ir.VMSCR})
				}
				em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: scratch, A: ir.VMSCR})
			} else if m, okm := memArg(args[1]); okm {
				base, index, scale, disp, merr := l.memAddr(ins, m)
				if merr != nil {
					return true, merr
				}
				mw := memWidth(ins)
				// 32 位源走「零扩展载入 + 显式符号扩展」两步 —— 与上面寄存器路径同形。
				// 原来直接用 Load{SignExt, W64, SrcW=mw}，实测 32 位形式会读成 8 字节（cvt32 得到 ~2^53）。
				if mw == ir.W32 {
					em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W32, SrcW: ir.W32, Dst: ir.VMSCR,
						Base: base, Index: index, Scale: scale, Disp: disp})
					em(ir.Insn{Op: ir.Ext, Kind: uint8(ir.SignExt), Width: ir.W64, SrcW: ir.W32, Dst: ir.VMSCR, A: ir.VMSCR})
				} else {
					em(ir.Insn{Op: ir.Load, Kind: uint8(ir.SignExt), Width: ir.W64, SrcW: mw, Dst: ir.VMSCR,
						Base: base, Index: index, Scale: scale, Disp: disp})
				}
				em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: scratch, A: ir.VMSCR})
			} else {
				return true, fmt.Errorf("CVTSI2SD 的源操作数不支持")
			}
			em(ir.Insn{Op: ir.Fp, Kind: 7 /* KF_CVTSI2F */, Width: ir.W64, Disp: dd,
				Imm: uint64(uint32(scratch)), Imm2: 0})
			return true, nil
		case x86asm.CVTDQ2PD:
			// CVTDQ2PD dst, src：把 src 低 64 位（两个 int32）各自转成 double，写满 dst 的 128 位。
			// 源可以是 XMM（直接用它的槽位）或内存（先搬到暂存槽：vm_tmp+8，和别的内存操作数一致）。
			cdx, okc := xmmReg(args[0])
			if !okc {
				return true, fmt.Errorf("CVTDQ2PD 的目标必须是 XMM")
			}
			cdd, okcd := l.xmmDisp(cdx, 0)
			if !okcd {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			var csrc int32
			if sx, oks := xmmReg(args[1]); oks {
				sd, ok2 := l.xmmDisp(sx, 0)
				if !ok2 {
					return true, fmt.Errorf("XMM 槽位不可用")
				}
				csrc = sd
			} else if m, okm := memArg(args[1]); okm {
				base, index, scale, disp, merr := l.memAddr(ins, m)
				if merr != nil {
					return true, merr
				}
				em(ir.Insn{Op: ir.Load, Width: ir.W64, SrcW: ir.W64, Dst: ir.VMSCR,
					Base: base, Index: index, Scale: scale, Disp: disp})
				em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1,
					Disp: scratch, A: ir.VMSCR})
				csrc = scratch
			} else {
				return true, fmt.Errorf("CVTDQ2PD 的源操作数不支持")
			}
			em(ir.Insn{Op: ir.Fp, Kind: 10 /* KF_CVTDQ2PD */, Width: ir.W64, Disp: cdd,
				Imm: uint64(uint32(csrc)), Imm2: 0})
			return true, nil
		case x86asm.CVTTSD2SI:
			dst, _, okd := regArgInfo(args[0])
			if !okd {
				return true, fmt.Errorf("CVTTSD2SI 的目标必须是寄存器")
			}
			sd, serr := valOff(args[1], true)
			if serr != nil {
				return true, serr
			}
			em(ir.Insn{Op: ir.Fp, Kind: 8 /* KF_CVTTF2SI */, Width: ir.W64, Disp: scratch,
				Imm: uint64(uint32(sd)), Imm2: 0})
			w := opWidth(ins)
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: w, SrcW: w, Dst: dst,
				Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: scratch})
			return true, nil
		default: // UCOMISD
			ax, oka := xmmReg(args[0])
			if !oka {
				return true, fmt.Errorf("UCOMISD 的第一操作数必须是 XMM")
			}
			ao, ok1 := l.xmmDisp(ax, 0)
			if !ok1 {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			bo, serr := valOff(args[1], true)
			if serr != nil {
				return true, serr
			}
			em(ir.Insn{Op: ir.Fp, Kind: 9 /* KF_UCOMI */, Width: ir.W64, Disp: int32(scratch),
				Imm: uint64(uint32(ao)), Imm2: uint64(uint32(bo))})
			return true, nil
		}

	case x86asm.MOVSD_XMM, x86asm.MOVSS:
		// 标量搬移（只搬位，不做浮点运算）：
		//   寄存器-寄存器：只覆盖目标的低 8/4 字节，**高位保持**
		//   内存 → 寄存器：低 8/4 字节来自内存，**其余位清零**（硬件行为）
		//   寄存器 → 内存：只写低 8/4 字节
		if err := needXMM(); err != nil {
			return true, err
		}
		scalar := 8
		if op == x86asm.MOVSS {
			scalar = 4
		}
		sw := ir.W64
		if scalar == 4 {
			sw = ir.W32
		}
		mdx, dstIsX := xmmReg(args[0])
		if dstIsX {
			dd, ok := l.xmmDisp(mdx, 0)
			if !ok {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			if msx, srcIsX := xmmReg(args[1]); srcIsX {
				sd, ok2 := l.xmmDisp(msx, 0)
				if !ok2 {
					return true, fmt.Errorf("XMM 槽位不可用")
				}
				em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: sw, SrcW: sw, Dst: ir.VMSCR,
					Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: sd})
				em(ir.Insn{Op: ir.Store, Width: sw, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd, A: ir.VMSCR})
				return true, nil
			}
			if mm, okm := memArg(args[1]); okm {
				base, index, scale, disp, merr := l.memAddr(ins, mm)
				if merr != nil {
					return true, merr
				}
				em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: sw, SrcW: sw, Dst: ir.VMSCR,
					Base: base, Index: index, Scale: scale, Disp: disp})
				em(ir.Insn{Op: ir.Store, Width: sw, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd, A: ir.VMSCR})
				// 其余位清零：4 字节形式清 12 字节，8 字节形式清 8 字节
				em(ir.Insn{Op: ir.MovRI, Width: ir.W64, Dst: ir.VMSCR, Imm: 0})
				em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd + 8, A: ir.VMSCR})
				if scalar == 4 {
					em(ir.Insn{Op: ir.Store, Width: ir.W32, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd + 4, A: ir.VMSCR})
				}
				return true, nil
			}
			return true, fmt.Errorf("%v 的源操作数不支持", op)
		}
		if msx, srcIsX := xmmReg(args[1]); srcIsX {
			mm, okm := memArg(args[0])
			if !okm {
				return true, fmt.Errorf("%v 的目标操作数不支持", op)
			}
			sd, ok := l.xmmDisp(msx, 0)
			if !ok {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			base, index, scale, disp, merr := l.memAddr(ins, mm)
			if merr != nil {
				return true, merr
			}
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: sw, SrcW: sw, Dst: ir.VMSCR,
				Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: sd})
			em(ir.Insn{Op: ir.Store, Width: sw, Base: base, Index: index, Scale: scale, Disp: disp, A: ir.VMSCR})
			return true, nil
		}
		return true, fmt.Errorf("%v 的形式不支持", op)

	case x86asm.MOVHLPS, x86asm.MOVLHPS:
		// 64 位"半搬移"：MOVHLPS dst.lo = src.hi（dst.hi 保持）；MOVLHPS dst.hi = src.lo（dst.lo 保持）。
		// 纯位搬运，不碰标志位、不借用任何通用寄存器（所以与 RSP 无关，是安全的）。
		if err := needXMM(); err != nil {
			return true, err
		}
		mx, okm := xmmReg(args[0])
		nx, okn := xmmReg(args[1])
		if !okm || !okn {
			return true, fmt.Errorf("%v 需要两个 XMM 寄存器", op)
		}
		dstHalf, srcHalf := 0, 1
		if op == x86asm.MOVLHPS {
			dstHalf, srcHalf = 1, 0
		}
		dd, ok1 := l.xmmDisp(mx, dstHalf)
		sd, ok2 := l.xmmDisp(nx, srcHalf)
		if !ok1 || !ok2 {
			return true, fmt.Errorf("XMM 槽位不可用")
		}
		em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: ir.W64, SrcW: ir.W64, Dst: ir.VMSCR,
			Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: sd})
		em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: dd, A: ir.VMSCR})
		return true, nil

	case x86asm.MOVQ, x86asm.MOVD:
		if err := needXMM(); err != nil {
			return true, err
		}
		nb := 8
		if op == x86asm.MOVD {
			nb = 4
		}
		// 注意：IR 的 Width 是**位宽**（8/16/32/64），不是字节数。
		wbits := ir.W64
		if nb == 4 {
			wbits = ir.W32
		}
		dx, dstIsX := xmmReg(args[0])
		sx, srcIsX := xmmReg(args[1])
		dg, _, dstIsG := regArgInfo(args[0])
		sg, _, srcIsG := regArgInfo(args[1])
		switch {
		case dstIsX && srcIsG: // XMM ← 通用寄存器：写低 nb 字节，其余清零
			d0, ok := l.xmmDisp(dx, 0)
			if !ok {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			em(ir.Insn{Op: ir.Store, Width: wbits, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: d0, A: sg})
			em(ir.Insn{Op: ir.MovRI, Width: ir.W64, Dst: ir.VMSCR, Imm: 0})
			em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: d0 + 8, A: ir.VMSCR})
			if nb == 4 {
				em(ir.Insn{Op: ir.Store, Width: ir.W32, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: d0 + 4, A: ir.VMSCR})
			}
			return true, nil
		case srcIsX && dstIsG: // 通用寄存器 ← XMM 低 nb 字节
			s0, ok := l.xmmDisp(sx, 0)
			if !ok {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: wbits, SrcW: wbits,
				Dst: dg, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: s0})
			return true, nil
		case dstIsX: // XMM ← 内存：读 nb 字节并清零其余
			m, ok := memArg(args[1])
			if !ok {
				return true, fmt.Errorf("SIMD 源操作数不支持")
			}
			base, index, scale, disp, err := l.memAddr(ins, m)
			if err != nil {
				return true, err
			}
			d0, ok := l.xmmDisp(dx, 0)
			if !ok {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: wbits, SrcW: wbits,
				Dst: ir.VMSCR, Base: base, Index: index, Scale: scale, Disp: disp})
			em(ir.Insn{Op: ir.Store, Width: wbits, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: d0, A: ir.VMSCR})
			em(ir.Insn{Op: ir.MovRI, Width: ir.W64, Dst: ir.VMSCR, Imm: 0})
			em(ir.Insn{Op: ir.Store, Width: ir.W64, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: d0 + 8, A: ir.VMSCR})
			if nb == 4 {
				em(ir.Insn{Op: ir.Store, Width: ir.W32, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: d0 + 4, A: ir.VMSCR})
			}
			return true, nil
		case srcIsX: // 内存 ← XMM 低 nb 字节
			m, ok := memArg(args[0])
			if !ok {
				return true, fmt.Errorf("SIMD 目标操作数不支持")
			}
			base, index, scale, disp, err := l.memAddr(ins, m)
			if err != nil {
				return true, err
			}
			s0, ok := l.xmmDisp(sx, 0)
			if !ok {
				return true, fmt.Errorf("XMM 槽位不可用")
			}
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: wbits, SrcW: wbits,
				Dst: ir.VMSCR, Base: ir.VMBASE, Index: ir.NoReg, Scale: 1, Disp: s0})
			em(ir.Insn{Op: ir.Store, Width: wbits, Base: base, Index: index, Scale: scale, Disp: disp, A: ir.VMSCR})
			return true, nil
		}
		return true, fmt.Errorf("MOVQ/MOVD 形式不支持")
	}
	return false, nil
}

func (l *Lifter) liftMov(f *ir.Func, ins x64dec.Insn, off uint32) error {
	args := ins.Inst.Args
	dst, dstW, dstIsReg := regArgInfo(args[0])
	src, srcW, srcIsReg := regArgInfo(args[1])
	mem, isM := memArg(args[0])
	srcMem, isSrcM := memArg(args[1])
	imm, isI := immArg(args[1])
	em := func(in ir.Insn) { in.SrcOff = off; in.Text = ins.Text(); l.emit(f, in) }

	switch {
	case dstIsReg && srcIsReg:
		em(ir.Insn{Op: ir.MovRR, Width: dstW, Dst: dst, A: src})
		return nil
	case dstIsReg && isI:
		em(ir.Insn{Op: ir.MovRI, Width: dstW, Dst: dst, Imm: uint64(imm)})
		return nil
	case dstIsReg && isSrcM:
		base, index, scale, disp, err := l.memAddr(ins, srcMem)
		if err != nil {
			return err
		}
		em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: dstW, SrcW: dstW, Dst: dst,
			Base: base, Index: index, Scale: scale, Disp: disp})
		return nil
	case isM && srcIsReg:
		base, index, scale, disp, err := l.memAddr(ins, mem)
		if err != nil {
			return err
		}
		em(ir.Insn{Op: ir.Store, Width: srcW, Base: base, Index: index, Scale: scale, Disp: disp, A: src})
		return nil
	case isM && isI:
		base, index, scale, disp, err := l.memAddr(ins, mem)
		if err != nil {
			return err
		}
		w := memWidth(ins)
		em(ir.Insn{Op: ir.MovRI, Width: w, Dst: ir.VMSCR, Imm: uint64(imm)})
		em(ir.Insn{Op: ir.Store, Width: w, Base: base, Index: index, Scale: scale, Disp: disp, A: ir.VMSCR})
		return nil
	}
	return fmt.Errorf("不支持的 MOV 形式")
}

func (l *Lifter) liftAlu(f *ir.Func, ins x64dec.Insn, off uint32, kind ir.Kind) error {
	args := ins.Inst.Args
	w := opWidth(ins)
	dst, _, dstIsReg := regArgInfo(args[0])
	mem, isM := memArg(args[0])
	src, _, srcIsReg := regArgInfo(args[1])
	imm, isI := immArg(args[1])
	em := func(in ir.Insn) { in.SrcOff = off; in.Text = ins.Text(); l.emit(f, in) }

	switch {
	case dstIsReg && srcIsReg:
		em(ir.Insn{Op: ir.AluRR, Kind: uint8(kind), Width: w, Dst: dst, A: dst, B: src})
		return nil
	case dstIsReg && isI:
		em(ir.Insn{Op: ir.AluRI, Kind: uint8(kind), Width: w, Dst: dst, A: dst, Imm: uint64(uint32(imm))})
		return nil
	case dstIsReg && !srcIsReg:
		m, ok := memArg(args[1])
		if !ok {
			return fmt.Errorf("不支持的 ALU 源操作数")
		}
		base, index, scale, disp, err := l.memAddr(ins, m)
		if err != nil {
			return err
		}
		sw := memWidth(ins)
		em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: sw, SrcW: sw, Dst: ir.VMSCR,
			Base: base, Index: index, Scale: scale, Disp: disp})
		em(ir.Insn{Op: ir.AluRR, Kind: uint8(kind), Width: w, Dst: dst, A: dst, B: ir.VMSCR})
		return nil
	case isM:
		base, index, scale, disp, err := l.memAddr(ins, mem)
		if err != nil {
			return err
		}
		mw := memWidth(ins)
		em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: mw, SrcW: mw, Dst: ir.VMSCR,
			Base: base, Index: index, Scale: scale, Disp: disp})
		if srcIsReg {
			em(ir.Insn{Op: ir.AluRR, Kind: uint8(kind), Width: mw, Dst: ir.VMSCR, A: ir.VMSCR, B: src})
		} else if isI {
			em(ir.Insn{Op: ir.AluRI, Kind: uint8(kind), Width: mw, Dst: ir.VMSCR, A: ir.VMSCR, Imm: uint64(uint32(imm))})
		} else {
			return fmt.Errorf("不支持的 ALU 源操作数")
		}
		em(ir.Insn{Op: ir.Store, Width: mw, Base: base, Index: index, Scale: scale, Disp: disp, A: ir.VMSCR})
		return nil
	}
	return fmt.Errorf("不支持的 ALU 形式")
}

func (l *Lifter) liftCmp(f *ir.Func, ins x64dec.Insn, off uint32, kind ir.CmpKind) error {
	args := ins.Inst.Args
	w := opWidth(ins)
	a, _, aIsReg := regArgInfo(args[0])
	src, _, srcIsReg := regArgInfo(args[1])
	imm, isI := immArg(args[1])
	em := func(in ir.Insn) { in.SrcOff = off; in.Text = ins.Text(); l.emit(f, in) }

	switch {
	case aIsReg && srcIsReg:
		em(ir.Insn{Op: ir.CmpRR, Kind: uint8(kind), Width: w, A: a, B: src})
		return nil
	case aIsReg && isI:
		em(ir.Insn{Op: ir.CmpRI, Kind: uint8(kind), Width: w, A: a, Imm: uint64(uint32(imm))})
		return nil
	case aIsReg:
		m, ok := memArg(args[1])
		if !ok {
			return fmt.Errorf("不支持的 CMP 源操作数")
		}
		base, index, scale, disp, err := l.memAddr(ins, m)
		if err != nil {
			return err
		}
		sw := memWidth(ins)
		em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: sw, SrcW: sw, Dst: ir.VMSCR,
			Base: base, Index: index, Scale: scale, Disp: disp})
		em(ir.Insn{Op: ir.CmpRR, Kind: uint8(kind), Width: w, A: a, B: ir.VMSCR})
		return nil
	}
	if m, ok := memArg(args[0]); ok {
		base, index, scale, disp, err := l.memAddr(ins, m)
		if err != nil {
			return err
		}
		mw := memWidth(ins)
		em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: mw, SrcW: mw, Dst: ir.VMSCR,
			Base: base, Index: index, Scale: scale, Disp: disp})
		switch {
		case srcIsReg:
			em(ir.Insn{Op: ir.CmpRR, Kind: uint8(kind), Width: mw, A: ir.VMSCR, B: src})
		case isI:
			em(ir.Insn{Op: ir.CmpRI, Kind: uint8(kind), Width: mw, A: ir.VMSCR, Imm: uint64(uint32(imm))})
		default:
			return fmt.Errorf("不支持的 CMP 源操作数")
		}
		return nil
	}
	return fmt.Errorf("不支持的 CMP/TEST 形式")
}

// liftDiv 处理单操作数 DIV/IDIV（F7 /6、F7 /7；8 位是 F6 /6、/7）：
//
//	DIV : (DX:AX) / src → 商 AX、余 DX（无符号）
//	IDIV: 同上（有符号）
//
// 被除数与两个输出都是**隐含寄存器**，所以复用 ir.AluU 的编码：A = 除数、Dst 不用。
// 真正的语义（含除零/商溢出的处理）在解释器 vm_interp.c 的 OP_ALU_U 分支里。
func (l *Lifter) liftDiv(f *ir.Func, ins x64dec.Insn, off uint32) error {
	args := ins.Inst.Args
	em := func(in ir.Insn) { in.SrcOff = off; in.Text = ins.Text(); l.emit(f, in) }
	w := opWidth(ins)

	// 单操作数形式：x86asm 把隐含的 RAX/RDX 也放进 Args，判据同样是 args[1] == nil。
	if len(args) < 2 || args[1] != nil {
		return fmt.Errorf("DIV/IDIV 只支持单操作数形式")
	}
	kind := ir.DivU
	if ins.Inst.Op == x86asm.IDIV {
		kind = ir.DivS
	}
	var src ir.Reg
	if r, _, ok := regArgInfo(args[0]); ok {
		src = r
	} else if m, okm := memArg(args[0]); okm {
		base, index, scale, disp, merr := l.memAddr(ins, m)
		if merr != nil {
			return merr
		}
		mw := memWidth(ins)
		em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: mw, SrcW: mw, Dst: ir.VMSCR,
			Base: base, Index: index, Scale: scale, Disp: disp})
		src = ir.VMSCR
	} else {
		return fmt.Errorf("DIV/IDIV 的操作数不支持")
	}
	em(ir.Insn{Op: ir.AluU, Kind: uint8(kind), Width: w, Dst: ir.RAX, A: src})
	return nil
}

func (l *Lifter) liftImul(f *ir.Func, ins x64dec.Insn, off uint32) error {
	args := ins.Inst.Args
	em := func(in ir.Insn) { in.SrcOff = off; in.Text = ins.Text(); l.emit(f, in) }
	w := opWidth(ins)

	// 单操作数形式：IMUL r/m → RDX:RAX = RAX × src（**有符号**）
	//   高半用新 kind K_MULHIS（它同时给出正确的 CF/OF），低半带 |KeepFlags。
	//   注意：x86asm 把隐含的 RAX/RDX 也算进 Args（len==4），判据是 args[1] == nil。
	if len(args) >= 2 && args[1] == nil {
		if w != ir.W32 && w != ir.W64 {
			return fmt.Errorf("单操作数 IMUL 只支持 32/64 位形式")
		}
		var src ir.Reg
		if r, _, ok := regArgInfo(args[0]); ok {
			src = r
		} else if m, okm := memArg(args[0]); okm {
			base, index, scale, disp, merr := l.memAddr(ins, m)
			if merr != nil {
				return merr
			}
			mw := memWidth(ins)
			em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: mw, SrcW: mw, Dst: ir.VMSCR,
				Base: base, Index: index, Scale: scale, Disp: disp})
			src = ir.VMSCR
		} else {
			return fmt.Errorf("IMUL 的操作数不支持")
		}
		em(ir.Insn{Op: ir.AluRR, Kind: uint8(ir.MulHiS), Width: w, Dst: ir.VMSCR, A: ir.RAX, B: src})
		em(ir.Insn{Op: ir.AluRR, Kind: uint8(ir.Mul) | ir.KeepFlags, Width: w, Dst: ir.RAX, A: ir.RAX, B: src})
		em(ir.Insn{Op: ir.MovRR, Width: w, Dst: ir.RDX, A: ir.VMSCR})
		return nil
	}

	dst, _, ok := regArgInfo(args[0])
	if !ok {
		return fmt.Errorf("IMUL 目标必须是寄存器")
	}

	if src, _, srcIsReg := regArgInfo(args[1]); srcIsReg {
		if len(args) >= 3 {
			if imm, isI := immArg(args[2]); isI {
				em(ir.Insn{Op: ir.AluRI, Kind: uint8(ir.Mul), Width: w, Dst: dst, A: src, Imm: uint64(uint32(imm))})
				return nil
			}
		}
		em(ir.Insn{Op: ir.AluRR, Kind: uint8(ir.Mul), Width: w, Dst: dst, A: dst, B: src})
		return nil
	}
	if m, isM := memArg(args[1]); isM {
		base, index, scale, disp, err := l.memAddr(ins, m)
		if err != nil {
			return err
		}
		mw := memWidth(ins)
		em(ir.Insn{Op: ir.Load, Kind: uint8(ir.ZeroExt), Width: mw, SrcW: mw, Dst: ir.VMSCR,
			Base: base, Index: index, Scale: scale, Disp: disp})
		// 三操作数形式 IMUL r, m, imm 表示 dst = m 乘 imm。
		// 这里原来漏了两件事：1) 丢掉立即数（退化成 dst = dst 乘 m，拿旧值当被乘数）；
		// 2) 用了内存宽度而不是目的宽度。/Od 下 MSVC 大量生成这种带内存源与立即数的 imul，
		// 于是算出静默错值（实测 a + b*2 + c*3 + d*4 得到 27 而不是 30）。
		if len(args) >= 3 {
			if imm, isI := immArg(args[2]); isI {
				em(ir.Insn{Op: ir.AluRI, Kind: uint8(ir.Mul), Width: w, Dst: dst, A: ir.VMSCR,
					Imm: uint64(uint32(imm))})
				return nil
			}
		}
		// 两操作数形式 IMUL r, m 表示 dst = dst 乘 m
		em(ir.Insn{Op: ir.AluRR, Kind: uint8(ir.Mul), Width: w, Dst: dst, A: dst, B: ir.VMSCR})
		return nil
	}
	return fmt.Errorf("不支持的 IMUL 形式")
}

func (l *Lifter) liftShift(f *ir.Func, ins x64dec.Insn, off uint32, kind ir.Kind) error {
	args := ins.Inst.Args
	dst, _, ok := regArgInfo(args[0])
	if !ok {
		return fmt.Errorf("移位目标必须是寄存器")
	}
	w := opWidth(ins)
	em := func(in ir.Insn) { in.SrcOff = off; in.Text = ins.Text(); l.emit(f, in) }

	if imm, isI := immArg(args[1]); isI {
		em(ir.Insn{Op: ir.AluRI, Kind: uint8(kind), Width: w, Dst: dst, A: dst, Imm: uint64(uint32(imm))})
		return nil
	}
	if r, _, isReg := regArgInfo(args[1]); isReg {
		if r != ir.RCX {
			return fmt.Errorf("只支持以 CL/RCX 作为移位计数")
		}
		em(ir.Insn{Op: ir.AluRR, Kind: uint8(kind), Width: w, Dst: dst, A: dst, B: ir.RCX})
		return nil
	}
	return fmt.Errorf("不支持的移位计数操作数")
}

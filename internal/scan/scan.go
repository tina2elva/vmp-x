// Package scan 负责在 PE 中定位函数并确定其精确边界。
//
// 边界判定策略（fail-fast）：
//  1. 起点用符号地址；
//  2. 终点取同节内下一个更大的符号地址（没有则到节尾）；
//  3. 从尾部回退跳过填充（NOP/int3/全零/同寄存器 XCHG）；
//  4. 要求最后一条“真实”指令是 RET，否则拒绝翻译。
package scan

import (
	dbgpe "debug/pe"
	"encoding/binary"
	"fmt"
	"sort"

	"golang.org/x/arch/x86/x86asm"

	x64dec "github.com/vmpx/vmp-x/internal/decode/x64"
	"github.com/vmpx/vmp-x/internal/load/pe"
)

// Found 一个已定位的函数
type Found struct {
	Name     string
	RVA      uint32
	End      uint32
	Code     []byte
	InstrNum int
}

// FindFunction 按符号名定位函数；path 用于读取 COFF 符号表
func findFunctionRaw(path string, f *pe.File, name string) (*Found, error) {
	df, err := dbgpe.Open(path)
	if err != nil {
		return nil, err
	}
	defer df.Close()

	var target *dbgpe.Symbol
	/* i386 的 COFF 符号带**前导下划线**（`int vm32_sum10()` → 符号 `_vm32_sum10`），
	 * 而调用方给的是源码里的名字 ⇒ 两种写法都要试。
	 * （同一个坑先前在 cmd/vmpbuild 读 COFF 时踩过，见 STATUS #441/#453。） */
	alt := "_" + name
	for _, s := range df.Symbols {
		if (s.Name == name || s.Name == alt) && s.SectionNumber > 0 {
			target = s
			break
		}
	}
	if target == nil {
		// 没有 COFF 符号表是**常态**：wheel 装出来的 .pyd、strip 过的 DLL 都这样。
		// 退回两条正统来源：导出表定位（例如 PyInit_xxx）、.pdata 给精确边界，
		// 再退到「同节内下一个导出」或节尾。
		// 优先级：MAP（构建时产物，名字最全）→ 导出表（运行期可见的那个）→ 报错。
		rva, ok := mapRVA(name)
		if !ok {
			rva, ok = exportRVA(df, name)
		}
		// 增量链接（ILT）会把函数符号指向一条 5 字节 `jmp rel32` 桩，真正的函数体在目标处；
		// 翻译桩没有意义（后面是 int3 填充），所以先跟到目标 RVA。
		rva = followThunk(f, rva)
		if !ok {
			return nil, fmt.Errorf("找不到符号 %q（该 PE 有 %d 个符号；MAP 与导出表里都没有这个名字，可用 -map 指定 MAP）", name, len(df.Symbols))
		}
		// 边界取「所有可用上界里最小的那个」：
		//   · .pdata 里同起点的那条（精确）；
		//   · 否则 .pdata 里下一个函数的起点（叶子函数常常没有自己的条目）；
		//   · 再否则下一个导出；最后才退到节尾。
		// 边界候选全部列出，然后**从小到大试**，取第一个"末尾确实是 RET/JMP"的。
		// 只取最小上界会出问题：.pdata/下一个符号给的 end 可能落在函数中间（实测 greet 与
		// add_dly 的函数体就是这样），于是"最后一个真实指令"是普通指令而被保守拒绝。
		// 反过来，"宁可选大"也不行——那会把下一个函数的代码吞进来。
		var cands []uint32
		add := func(v uint32) {
			if v > rva {
				cands = append(cands, v)
			}
		}
		if e, ok := mapNextBegin(rva); ok {
			add(e)
		}
		if _, e, ok2 := pdataEnd(df, rva); ok2 {
			add(e)
		}
		if e2, ok3 := pdataNextBegin(df, rva); ok3 {
			add(e2)
		}
		if e3, ok4 := nextExportEnd(df, rva); ok4 {
			add(e3)
		}
		if si, ok5 := sectionOfRVA(f, rva); ok5 {
			add(sectionEndOf(f, si))
		}
		if len(cands) == 0 {
			return nil, fmt.Errorf("导出 %q（RVA 0x%X）找不到可用边界", name, rva)
		}
		sort.Slice(cands, func(i, j int) bool { return cands[i] < cands[j] })
		var terr error
		for _, end := range cands {
			code, cerr := readCode(f, rva, end)
			if cerr != nil {
				terr = cerr
				continue
			}
			var trimmed []byte
			var n int
			if f.Machine == peMachineARM64 {
				trimmed, n, terr = trimTrailingPaddingARM64(rva, code)
			} else {
				trimmed, n, terr = TrimTrailingPadding(f.ImageBase, rva, code)
			}
			if terr != nil {
				continue
			}
			return &Found{Name: name, RVA: rva, End: rva + uint32(len(trimmed)), Code: trimmed, InstrNum: n}, nil
		}
		if terr == nil {
			terr = fmt.Errorf("函数 %q（RVA 0x%X）的候选边界里没有以 RET/JMP 收尾的", name, rva)
		}
		return nil, terr
	}
	secIdx := int(target.SectionNumber) - 1
	if secIdx < 0 || secIdx >= len(f.Sections) {
		return nil, fmt.Errorf("符号 %q 的节号 %d 越界", name, target.SectionNumber)
	}
	sec := f.Sections[secIdx]
	secEnd := sec.VirtualAddress + sec.VirtualSize
	if sec.VirtualSize == 0 {
		secEnd = sec.VirtualAddress + sec.SizeOfRawData
	}

	// COFF 符号值的“基准”没有统一约定：mingw + Go debug/pe 给出的是**节内偏移**
	// （例如真实 RVA 0x24F0 的符号其 Value 是 0x14F0），但也可能是 RVA 或 VA。
	// 与其猜，不如**逐个约定试一遍并用“能否解码成整段且以 RET 结束”来定夺**；
	// 全都不成立就报错并列出候选，绝不悄悄用错地址。
	type conv int
	const (
		convSectionRel conv = iota
		convRVA
		convVA
	)
	convert := func(v uint32, c conv) (uint32, bool) {
		switch c {
		case convSectionRel:
			r := sec.VirtualAddress + v
			if v < sec.SizeOfRawData && r < secEnd {
				return r, true
			}
		case convRVA:
			if v >= sec.VirtualAddress && v < secEnd {
				return v, true
			}
		case convVA:
			if uint64(v) >= f.ImageBase {
				r := uint32(uint64(v) - f.ImageBase)
				if r >= sec.VirtualAddress && r < secEnd {
					return r, true
				}
			}
		}
		return 0, false
	}

	// 同节内的候选边界（只要函数符号）
	boundaries := func(c conv) []uint32 {
		var out []uint32
		for _, s := range df.Symbols {
			if s.SectionNumber != target.SectionNumber {
				continue
			}
			// mingw 的符号表里还散落着 .text 之类的节符号（type=0），把它们当边界会截断函数。
			// 函数类型的约定有两种：mingw 放低位 0x20，lld-link 放高位 0x2000 —— 都接受。
			if s.Type&0x20 == 0 && s.Type&0x2000 == 0 {
				continue
			}
			if v, ok := convert(uint32(s.Value), c); ok {
				out = append(out, v)
			}
		}
		return out
	}

	var lastErr error
	for _, c := range []conv{convSectionRel, convRVA, convVA} {
		rva, ok := convert(uint32(target.Value), c)
		if !ok {
			continue
		}
		var end uint32
		for _, v := range boundaries(c) {
			if v > rva && (end == 0 || v < end) {
				end = v
			}
		}
		if end == 0 || end > secEnd {
			end = secEnd
		}
		if end <= rva {
			continue
		}
		lo := rva - sec.VirtualAddress
		hi := end - sec.VirtualAddress
		if int(sec.PointerToRawData+hi) > len(f.Data) {
			continue
		}
		raw := make([]byte, hi-lo)
		copy(raw, f.Data[sec.PointerToRawData+lo:sec.PointerToRawData+hi])
		var trimmed []byte
		var n int
		var terr error
		if f.Machine == peMachineARM64 {
			trimmed, n, terr = trimTrailingPaddingARM64(rva, raw)
		} else {
			trimmed, n, terr = TrimTrailingPadding(f.ImageBase, rva, raw)
		}
		if terr != nil {
			lastErr = terr
			continue
		}
		return &Found{Name: name, RVA: rva, End: rva + uint32(len(trimmed)), Code: trimmed, InstrNum: n}, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("无法用任何符号基准约定确定 %s 的边界（最后一次错误: %v）", name, lastErr)
	}
	return nil, fmt.Errorf("符号 %q 的值 0x%X 无法映射到节 %s (0x%X-0x%X) 内", name, target.Value, sec.Name, sec.VirtualAddress, secEnd)
}

// peMachineARM64 是 COFF 的 ARM64 Machine（0xAA64）。
const peMachineARM64 = 0xAA64

// trimTrailingPaddingARM64：AArch64 的尾部裁剪。
// 这里不能借用 x86 的解码器（那正是 Windows/arm64 打包时卡住的地方：
// arm64 的机器码用 x64dec 一条都解不出来，于是"无法用任何符号基准约定确定"）。
// 做法足够保守：从尾部跳过 0 填充，要求最后一条真实指令是 ret / br x30，否则报错。
func trimTrailingPaddingARM64(rva uint32, code []byte) ([]byte, int, error) {
	const (
		retX30 = 0xD65F03C0 // ret
		brX30  = 0xD61F03C0 // br x30
	)
	if len(code) < 4 {
		return nil, 0, fmt.Errorf("0x%X 处没有可解码的指令", rva)
	}
	n := len(code) &^ 3
	for n >= 4 {
		w := binary.LittleEndian.Uint32(code[n-4:])
		if w == 0 { // 尾部填充
			n -= 4
			continue
		}
		if w == retX30 || w == brX30 {
			return code[:n], n / 4, nil
		}
		return nil, 0, fmt.Errorf("0x%X 处最后一条指令不是 ret/br x30（0x%08X）", rva+uint32(n-4), w)
	}
	return nil, 0, fmt.Errorf("0x%X 处的代码全是填充", rva)
}

// TrimTrailingPadding 解码并在尾部裁掉填充，要求最后一条真实指令是 RET
func TrimTrailingPadding(imageBase uint64, rva uint32, code []byte) ([]byte, int, error) {
	base := imageBase + uint64(rva)
	var insns []x64dec.Insn
	off := 0
	for off < len(code) {
		ins, err := x64dec.Decode(code[off:], base+uint64(off))
		if err != nil {
			break
		}
		insns = append(insns, ins)
		off += ins.Len()
	}
	if len(insns) == 0 {
		return nil, 0, fmt.Errorf("无法解码任何指令")
	}
	i := len(insns) - 1
	for i >= 0 && IsPadding(insns[i]) {
		i--
	}
	if i < 0 {
		return nil, 0, fmt.Errorf("整段都是填充字节")
	}
	last := insns[i]
	// 末尾允许 RET，或**直接无条件跳转**（尾调用 / 跳到别处 —— 增量链接与 thunk 都这么收尾）。
	// 跳转的具体语义交给 lifter 判定：目标在函数外时会被抬成 CALLN + RET。
	// `jmp [rip+disp]`（导入桩）仍然保守拒绝，避免把"跳到导入表"当成函数体。
	okTail := last.Op() == x86asm.RET
	if !okTail && last.Op() == x86asm.JMP && len(last.Inst.Args) > 0 {
		if _, isRel := last.Inst.Args[0].(x86asm.Rel); isRel {
			okTail = true
		}
	}
	if !okTail {
		return nil, 0, fmt.Errorf("函数末尾不是 RET/JMP（+0x%X 是 %s）", last.PC-base, last.Text())
	}
	end := int(last.PC-base) + last.Len()
	return code[:end], i + 1, nil
}

// IsPadding 判断是否为对齐填充
func IsPadding(ins x64dec.Insn) bool {
	if ins.Op() == x86asm.NOP {
		return true
	}
	if len(ins.Raw) > 0 && ins.Raw[0] == 0xCC {
		return true
	}
	allZero := true
	for _, b := range ins.Raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return true
	}
	if ins.Op() == x86asm.XCHG {
		a, ok1 := ins.Inst.Args[0].(x86asm.Reg)
		b, ok2 := ins.Inst.Args[1].(x86asm.Reg)
		return ok1 && ok2 && a == b
	}
	return false
}

// ---- 供「没有符号表」那条通路使用的三个小助手（用我们的 PE 加载器读字节）----

// sectionOfRVA 返回包含该 RVA 的节下标。
func sectionOfRVA(f *pe.File, rva uint32) (int, bool) {
	for i := range f.Sections {
		s := &f.Sections[i]
		end := s.VirtualAddress + s.VirtualSize
		if s.VirtualSize == 0 {
			end = s.VirtualAddress + s.SizeOfRawData
		}
		if rva >= s.VirtualAddress && rva < end {
			return i, true
		}
	}
	return 0, false
}

// sectionEndOf 返回该节的结束 RVA。
func sectionEndOf(f *pe.File, i int) uint32 {
	s := &f.Sections[i]
	if s.VirtualSize == 0 {
		return s.VirtualAddress + s.SizeOfRawData
	}
	return s.VirtualAddress + s.VirtualSize
}

// readCode 按 RVA 区间取代码字节（走节表的 PointerToRawData）。
func readCode(f *pe.File, rva, end uint32) ([]byte, error) {
	for i := range f.Sections {
		s := &f.Sections[i]
		secEnd := s.VirtualAddress + s.VirtualSize
		if s.VirtualSize == 0 {
			secEnd = s.VirtualAddress + s.SizeOfRawData
		}
		if rva >= s.VirtualAddress && rva < secEnd {
			lo := rva - s.VirtualAddress
			hi := end - s.VirtualAddress
			if int(s.PointerToRawData+hi) > len(f.Data) {
				return nil, fmt.Errorf("函数 0x%X..0x%X 越过文件末尾", rva, end)
			}
			b := make([]byte, hi-lo)
			copy(b, f.Data[s.PointerToRawData+lo:s.PointerToRawData+hi])
			return b, nil
		}
	}
	return nil, fmt.Errorf("RVA 0x%X 不在任何节内", rva)
}

// FindFunction：定位函数并做一层"桩解析"——有些函数的符号指向一个 5 字节的 `jmp rel32`（增量链接的 ILT 桩），
// 真正的函数体在跳转目标处。翻译桩本身没有意义（后面是 int3 填充），所以跟到目标：
// 用**目标的 RVA** 去翻译并打补丁 —— 桩保持原样，它自然会把控制流带进我们的补丁。
func FindFunction(path string, f *pe.File, name string) (*Found, error) {
	found, err := findFunctionRaw(path, f, name)
	if err != nil {
		return nil, err
	}
	return resolveLeadingThunk(f, path, found)
}

// resolveLeadingThunk 跟随开头的直接跳转桩（最多 4 跳，防环）。
func resolveLeadingThunk(f *pe.File, path string, found *Found) (*Found, error) {
	df, err := dbgpe.Open(path)
	if err != nil {
		return nil, err
	}
	defer df.Close()
	for hop := 0; hop < 4; hop++ {
		c := found.Code
		if len(c) < 5 {
			return found, nil
		}
		if c[0] == 0xFF && len(c) >= 6 && c[1] == 0x25 {
			return nil, fmt.Errorf("%s 是导入桩（jmp [rip+disp]），不是本模块的函数", found.Name)
		}
		if c[0] != 0xE9 {
			return found, nil
		}
		rel := int32(binary.LittleEndian.Uint32(c[1:5]))
		target := uint32(int64(found.RVA) + 5 + int64(rel))
		if target == 0 || target == found.RVA {
			return found, nil
		}
		end := uint32(0)
		take := func(v uint32) {
			if v > target && (end == 0 || v < end) {
				end = v
			}
		}
		if _, e, ok := pdataEnd(df, target); ok {
			take(e)
		}
		if e, ok := pdataNextBegin(df, target); ok {
			take(e)
		}
		if e, ok := nextExportEnd(df, target); ok {
			take(e)
		}
		if si, ok := sectionOfRVA(f, target); ok {
			take(sectionEndOf(f, si))
		}
		if end <= target {
			return nil, fmt.Errorf("%s 的 jmp 桩目标 0x%X 找不到可用边界", found.Name, target)
		}
		code, cerr := readCode(f, target, end)
		if cerr != nil {
			return nil, cerr
		}
		var trimmed []byte
		var n int
		var terr error
		if f.Machine == peMachineARM64 {
			trimmed, n, terr = trimTrailingPaddingARM64(target, code)
		} else {
			trimmed, n, terr = TrimTrailingPadding(f.ImageBase, target, code)
		}
		if terr != nil {
			return nil, terr
		}
		found = &Found{Name: found.Name, RVA: target, End: target + uint32(len(trimmed)), Code: trimmed, InstrNum: n}
	}
	return found, nil
}

// followThunk 跟随开头的直接跳转桩（最多 4 跳，防环）。只跟 `jmp rel32`；
// `jmp [rip+disp]`（导入桩）不跟随——那种不是本模块的函数。
func followThunk(f *pe.File, rva uint32) uint32 {
	for hop := 0; hop < 4; hop++ {
		b, err := readCode(f, rva, rva+5)
		if err != nil || len(b) < 5 || b[0] != 0xE9 {
			return rva
		}
		rel := int32(binary.LittleEndian.Uint32(b[1:5]))
		target := uint32(int64(rva) + 5 + int64(rel))
		if target == 0 || target == rva {
			return rva
		}
		rva = target
	}
	return rva
}

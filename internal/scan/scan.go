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
func FindFunction(path string, f *pe.File, name string) (*Found, error) {
	df, err := dbgpe.Open(path)
	if err != nil {
		return nil, err
	}
	defer df.Close()

	var target *dbgpe.Symbol
	for _, s := range df.Symbols {
		if s.Name == name && s.SectionNumber > 0 {
			target = s
			break
		}
	}
	if target == nil {
		// 没有 COFF 符号表是**常态**：wheel 装出来的 .pyd、strip 过的 DLL 都这样。
		// 退回两条正统来源：导出表定位（例如 PyInit_xxx）、.pdata 给精确边界，
		// 再退到「同节内下一个导出」或节尾。
		rva, ok := exportRVA(f, name)
		if !ok {
			return nil, fmt.Errorf("找不到符号 %q（该 PE 有 %d 个符号，导出表里也没有这个名字）", name, len(df.Symbols))
		}
		end := uint32(0)
		if _, e, ok2 := pdataEnd(f, rva); ok2 {
			end = e
		} else if e2, ok3 := nextExportEnd(f, rva); ok3 {
			end = e2
		} else if si, ok4 := sectionOfRVA(f, rva); ok4 {
			end = sectionEndOf(f, si)
		}
		if end <= rva {
			return nil, fmt.Errorf("导出 %q（RVA 0x%X）找不到可用边界", name, rva)
		}
		code, cerr := readCode(f, rva, end)
		if cerr != nil {
			return nil, cerr
		}
		var trimmed []byte
		var n int
		var terr error
		if f.Machine == peMachineARM64 {
			trimmed, n, terr = trimTrailingPaddingARM64(rva, code)
		} else {
			trimmed, n, terr = TrimTrailingPadding(f.ImageBase, rva, code)
		}
		if terr != nil {
			return nil, terr
		}
		return &Found{Name: name, RVA: rva, End: rva + uint32(len(trimmed)), Code: trimmed, InstrNum: n}, nil
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
	if last.Op() != x86asm.RET {
		return nil, 0, fmt.Errorf("函数末尾不是 RET（+0x%X 是 %s）", last.PC-base, last.Text())
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

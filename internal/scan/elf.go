package scan

import (
	"debug/elf"
	"fmt"
)

// FindFunctionELF 按符号名在 ELF 中定位函数。
// ELF 符号通常带 Size，边界比 PE 可靠；Size 为 0 时退回“下一个符号 + 去填充”。
func FindFunctionELF(path string, imageBase uint64, name string) (*Found, error) {
	df, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer df.Close()

	// 优先静态符号表；被 strip 的库通常只剩 .dynsym（动态符号表），两者都试。
	var syms []elf.Symbol
	if st, err := df.Symbols(); err == nil {
		syms = append(syms, st...)
	}
	if ds, err := df.DynamicSymbols(); err == nil {
		syms = append(syms, ds...)
	}
	if len(syms) == 0 {
		return nil, fmt.Errorf("既没有 .symtab 也没有 .dynsym，无法定位函数")
	}
	var target *elf.Symbol
	var targetIdx = -1
	for i := range syms {
		s := &syms[i]
		if s.Name == name && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
			target, targetIdx = s, i
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("在 .symtab/.dynsym 共 %d 个符号里找不到函数 %q", len(syms), name)
	}
	_ = targetIdx
	if target.Value < imageBase {
		return nil, fmt.Errorf("符号 %q 地址 0x%X 低于镜像基址 0x%X", name, target.Value, imageBase)
	}
	rva := uint32(target.Value - imageBase)

	if target.Size > 0 {
		code, err := readVA(df, target.Value, int(target.Size))
		if err != nil {
			return nil, err
		}
		// 去掉尾部对齐填充（函数之间常有 nop）。**必须按架构选裁剪器**：
		// 原先一律用 x86-64 的那个，在 arm64 上会把随机字节当成 RET/JMP 解码成功，
		// 裁出 29 这种非 4 倍数长度（aarch64 lifter 随即报“代码长度不是 4 的倍数”）。
		var trimmed []byte
		var n int
		var terr error
		minLen := 5
		if df.FileHeader.Machine == elf.EM_AARCH64 {
			trimmed, n, terr = trimTrailingPaddingARM64(rva, code)
			minLen = 4
		} else {
			trimmed, n, terr = TrimTrailingPadding(imageBase, rva, code)
		}
		if terr == nil && len(trimmed) >= minLen {
			return &Found{Name: name, RVA: rva, End: rva + uint32(len(trimmed)), Code: trimmed, InstrNum: n}, nil
		}
		return &Found{Name: name, RVA: rva, End: rva + uint32(len(code)), Code: code}, nil
	}

	end := uint64(0)
	for i := range syms {
		s := &syms[i]
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Value <= target.Value {
			continue
		}
		if end == 0 || s.Value < end {
			end = s.Value
		}
	}
	if end == 0 || end <= target.Value {
		return nil, fmt.Errorf("符号 %q 没有尺寸信息，也无法推断终点", name)
	}
	raw, err := readVA(df, target.Value, int(end-target.Value))
	if err != nil {
		return nil, err
	}
	trimmed, n, err := TrimTrailingPadding(imageBase, rva, raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &Found{Name: name, RVA: rva, End: rva + uint32(len(trimmed)), Code: trimmed, InstrNum: n}, nil
}

// readVA 通过 PT_LOAD 映射读取虚拟地址处的内容
func readVA(f *elf.File, va uint64, n int) ([]byte, error) {
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if va >= p.Vaddr && va+uint64(n) <= p.Vaddr+p.Filesz {
			buf := make([]byte, n)
			if _, err := p.ReadAt(buf, int64(va-p.Vaddr)); err != nil {
				return nil, err
			}
			return buf, nil
		}
	}
	return nil, fmt.Errorf("VA 0x%X (+%d) 不在任何 PT_LOAD 中", va, n)
}

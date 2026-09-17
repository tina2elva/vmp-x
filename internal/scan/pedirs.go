package scan

// PE 目录解析：给「没有 COFF 符号表」的真实二进制用。
//
// 典型场景就是 wheel 安装的 .pyd：文件是标准 DLL，但符号表被 strip 掉了，
// scan 原来只认 COFF 符号，于是报「找不到符号 X（该 PE 有 0 个符号）」。
// 这里补两条正统来源：
//   · 导出表（IMAGE_DIRECTORY_ENTRY_EXPORT）—— 能定位被导出的函数，例如 PyInit_xxx；
//   · 异常目录（IMAGE_DIRECTORY_ENTRY_EXCEPTION，即 .pdata 的 RUNTIME_FUNCTION）——
//     x64 上给的是每个函数的**精确起止 RVA**，比「下一个符号」可靠得多。

import (
	"encoding/binary"
	"fmt"

	"github.com/vmpx/vmp-x/internal/load/pe"
)

// peDataDir 读 PE 可选头里的第 idx 个数据目录（返回 RVA 与大小）。
func peDataDir(f *pe.File, idx int) (uint32, uint32, bool) {
	d := f.Data
	if len(d) < 0x40 {
		return 0, 0, false
	}
	peOff := int(binary.LittleEndian.Uint32(d[0x3C:]))
	if peOff+24 > len(d) || string(d[peOff:peOff+4]) != "PE\x00\x00" {
		return 0, 0, false
	}
	optOff := peOff + 24
	if optOff+2 > len(d) {
		return 0, 0, false
	}
	ddOff := optOff + 112 // PE32+：DataDirectory 在可选头 +112；PE32 是 +96
	if binary.LittleEndian.Uint16(d[optOff:]) == 0x10b {
		ddOff = optOff + 96
	}
	if ddOff+8*idx+8 > len(d) {
		return 0, 0, false
	}
	rva := binary.LittleEndian.Uint32(d[ddOff+8*idx:])
	size := binary.LittleEndian.Uint32(d[ddOff+8*idx+4:])
	if rva == 0 {
		return 0, 0, false
	}
	return rva, size, true
}

// exportRVA 在导出表里按名字找函数 RVA。
func exportRVA(f *pe.File, name string) (uint32, bool) {
	dirRVA, _, ok := peDataDir(f, 0)
	if !ok {
		return 0, false
	}
	off, err := f.RVAtoOffset(dirRVA)
	if err != nil || off+40 > len(f.Data) {
		return 0, false
	}
	d := f.Data
	nFuncs := binary.LittleEndian.Uint32(d[off+0x18:])
	nNames := binary.LittleEndian.Uint32(d[off+0x1C:])
	funcsOff, e1 := f.RVAtoOffset(binary.LittleEndian.Uint32(d[off+0x20:]))
	namesOff, e2 := f.RVAtoOffset(binary.LittleEndian.Uint32(d[off+0x24:]))
	ordsOff, e3 := f.RVAtoOffset(binary.LittleEndian.Uint32(d[off+0x28:]))
	if e1 != nil || e2 != nil || e3 != nil {
		return 0, false
	}
	for i := uint32(0); i < nNames; i++ {
		if namesOff+int(4*i)+4 > len(d) || ordsOff+int(2*i)+2 > len(d) {
			return 0, false
		}
		so, err := f.RVAtoOffset(binary.LittleEndian.Uint32(d[namesOff+int(4*i):]))
		if err != nil || so >= len(d) {
			continue
		}
		end := so
		for end < len(d) && d[end] != 0 {
			end++
		}
		if string(d[so:end]) != name {
			continue
		}
		ord := uint32(binary.LittleEndian.Uint16(d[ordsOff+int(2*i):]))
		if ord >= nFuncs || funcsOff+int(4*ord)+4 > len(d) {
			return 0, false
		}
		return binary.LittleEndian.Uint32(d[funcsOff+int(4*ord):]), true
	}
	return 0, false
}

// pdataEnd 用 .pdata 的 RUNTIME_FUNCTION 找函数精确起止（x64 的异常目录）。
func pdataEnd(f *pe.File, rva uint32) (uint32, uint32, bool) {
	dirRVA, dirSize, ok := peDataDir(f, 3)
	if !ok || dirSize < 12 {
		return 0, 0, false
	}
	off, err := f.RVAtoOffset(dirRVA)
	if err != nil {
		return 0, 0, false
	}
	for i := uint32(0); i+12 <= dirSize; i += 12 {
		if off+int(i)+12 > len(f.Data) {
			break
		}
		beg := binary.LittleEndian.Uint32(f.Data[off+int(i):])
		end := binary.LittleEndian.Uint32(f.Data[off+int(i)+4:])
		if beg == rva && end > beg {
			return beg, end, true
		}
	}
	return 0, 0, false
}

// nextExportEnd：没有 .pdata 时的退路 —— 用同节内下一个更大的导出 RVA 当边界。
func nextExportEnd(f *pe.File, rva uint32) (uint32, bool) {
	dirRVA, _, ok := peDataDir(f, 0)
	if !ok {
		return 0, false
	}
	off, err := f.RVAtoOffset(dirRVA)
	if err != nil || off+40 > len(f.Data) {
		return 0, false
	}
	d := f.Data
	nFuncs := binary.LittleEndian.Uint32(d[off+0x18:])
	funcsOff, err := f.RVAtoOffset(binary.LittleEndian.Uint32(d[off+0x20:]))
	if err != nil {
		return 0, false
	}
	best := uint32(0)
	for i := uint32(0); i < nFuncs; i++ {
		if funcsOff+int(4*i)+4 > len(d) {
			break
		}
		v := binary.LittleEndian.Uint32(d[funcsOff+int(4*i):])
		if v > rva && (best == 0 || v < best) {
			best = v
		}
	}
	if best == 0 {
		return 0, false
	}
	return best, true
}

// readCode 按 RVA 区间从文件里取代码字节（走节的 PointerToRawData）。
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

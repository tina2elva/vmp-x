package scan

// PE 目录解析：给「没有 COFF 符号表」的真实二进制用。
//
// 典型场景就是 wheel 装出来的 .pyd：文件是标准 DLL，但符号表被 strip 掉了。
// scan 原来只认 COFF 符号，于是报「找不到符号 X（该 PE 有 0 个符号）」。
// 这里补两条正统来源：
//   - 导出表（IMAGE_DIRECTORY_ENTRY_EXPORT）：定位被导出的函数，例如 PyInit_xxx；
//   - 异常目录（IMAGE_DIRECTORY_ENTRY_EXCEPTION，即 .pdata 的 RUNTIME_FUNCTION）：
//     x64 上给出每个函数的精确起止 RVA，比「下一个符号」可靠得多。
//
// 数据目录一律交给 debug/pe 解析：我自己按可选头偏移算过一次、算错 4 字节，
// 现象是所有字段整体错位，很难查。
import (
	"encoding/binary"

	dbgpe "debug/pe"
)

// peDataDir 取第 idx 个数据目录（RVA 与大小）。
func peDataDir(df *dbgpe.File, idx int) (uint32, uint32, bool) {
	switch oh := df.OptionalHeader.(type) {
	case *dbgpe.OptionalHeader64:
		if idx < len(oh.DataDirectory) && oh.DataDirectory[idx].VirtualAddress != 0 {
			return oh.DataDirectory[idx].VirtualAddress, oh.DataDirectory[idx].Size, true
		}
	case *dbgpe.OptionalHeader32:
		if idx < len(oh.DataDirectory) && oh.DataDirectory[idx].VirtualAddress != 0 {
			return oh.DataDirectory[idx].VirtualAddress, oh.DataDirectory[idx].Size, true
		}
	}
	return 0, 0, false
}

// secFor 找到包含 rva 的节，返回节数据与节内偏移。
func secFor(df *dbgpe.File, rva uint32) ([]byte, int, bool) {
	for _, s := range df.Sections {
		end := s.VirtualAddress + s.VirtualSize
		if s.VirtualSize == 0 {
			end = s.VirtualAddress + s.Size
		}
		if rva >= s.VirtualAddress && rva < end {
			b, err := s.Data()
			if err != nil {
				return nil, 0, false
			}
			return b, int(rva - s.VirtualAddress), true
		}
	}
	return nil, 0, false
}

// u32at 读节内偏移处的 32 位小端值。
func u32at(sec []byte, off int) (uint32, bool) {
	if off < 0 || off+4 > len(sec) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(sec[off:]), true
}

// exportRVA 在导出表里按名字找函数 RVA。
// IMAGE_EXPORT_DIRECTORY：+0x0C Name、+0x10 Base、+0x14 NumberOfFunctions、
// +0x18 NumberOfNames、+0x1C AddressOfFunctions、+0x20 AddressOfNames、+0x24 AddressOfNameOrdinals。
// （最初写成 +0x18 起，整体多 4 字节 —— 实测这个 .pyd 的目录原始字节才发现。）
func exportRVA(df *dbgpe.File, name string) (uint32, bool) {
	dirRVA, _, ok := peDataDir(df, 0)
	if !ok {
		return 0, false
	}
	sec, off, ok := secFor(df, dirRVA)
	if !ok || off+40 > len(sec) {
		return 0, false
	}
	nFuncs, _ := u32at(sec, off+0x14)
	nNames, _ := u32at(sec, off+0x18)
	funcsRVA, _ := u32at(sec, off+0x1C)
	namesRVA, _ := u32at(sec, off+0x20)
	ordsRVA, _ := u32at(sec, off+0x24)
	for i := uint32(0); i < nNames; i++ {
		nsec, no, ok := secFor(df, namesRVA+4*i)
		if !ok {
			return 0, false
		}
		nr, ok := u32at(nsec, no)
		if !ok {
			return 0, false
		}
		ssec, so, ok := secFor(df, nr)
		if !ok || so >= len(ssec) {
			continue
		}
		end := so
		for end < len(ssec) && ssec[end] != 0 {
			end++
		}
		if string(ssec[so:end]) != name {
			continue
		}
		osec, oo, ok := secFor(df, ordsRVA+2*i)
		if !ok || oo+2 > len(osec) {
			return 0, false
		}
		ord := uint32(binary.LittleEndian.Uint16(osec[oo:]))
		if ord >= nFuncs {
			return 0, false
		}
		fsec, fo, ok := secFor(df, funcsRVA+4*ord)
		if !ok {
			return 0, false
		}
		return u32at(fsec, fo)
	}
	return 0, false
}

// pdataEnd 用 .pdata 的 RUNTIME_FUNCTION 找函数精确起止（x64 异常目录）。
func pdataEnd(df *dbgpe.File, rva uint32) (uint32, uint32, bool) {
	dirRVA, dirSize, ok := peDataDir(df, 3)
	if !ok || dirSize < 12 {
		return 0, 0, false
	}
	sec, off, ok := secFor(df, dirRVA)
	if !ok {
		return 0, 0, false
	}
	for i := uint32(0); i+12 <= dirSize; i += 12 {
		beg, ok1 := u32at(sec, off+int(i))
		end, ok2 := u32at(sec, off+int(i)+4)
		if !ok1 || !ok2 {
			break
		}
		if beg == rva && end > beg {
			return beg, end, true
		}
	}
	return 0, 0, false
}

// nextExportEnd：没有 .pdata 时的退路 —— 同节内下一个更大的导出 RVA。
func nextExportEnd(df *dbgpe.File, rva uint32) (uint32, bool) {
	dirRVA, _, ok := peDataDir(df, 0)
	if !ok {
		return 0, false
	}
	sec, off, ok := secFor(df, dirRVA)
	if !ok || off+40 > len(sec) {
		return 0, false
	}
	nFuncs, _ := u32at(sec, off+0x14)
	funcsRVA, _ := u32at(sec, off+0x1C)
	best := uint32(0)
	for i := uint32(0); i < nFuncs; i++ {
		fsec, fo, ok := secFor(df, funcsRVA+4*i)
		if !ok {
			break
		}
		v, ok := u32at(fsec, fo)
		if !ok {
			break
		}
		if v > rva && (best == 0 || v < best) {
			best = v
		}
	}
	if best == 0 {
		return 0, false
	}
	return best, true
}

// pdataNextBegin 返回 .pdata 里比 rva 大的最近一个函数起点，用作上界。
// 有些函数（叶子函数）没有自己的 RUNTIME_FUNCTION，但下一个函数的起点依然可用。
func pdataNextBegin(df *dbgpe.File, rva uint32) (uint32, bool) {
	dirRVA, dirSize, ok := peDataDir(df, 3)
	if !ok || dirSize < 12 {
		return 0, false
	}
	sec, off, ok := secFor(df, dirRVA)
	if !ok {
		return 0, false
	}
	best := uint32(0)
	for i := uint32(0); i+12 <= dirSize; i += 12 {
		beg, ok1 := u32at(sec, off+int(i))
		if !ok1 {
			break
		}
		if beg > rva && (best == 0 || beg < best) {
			best = beg
		}
	}
	if best == 0 {
		return 0, false
	}
	return best, true
}

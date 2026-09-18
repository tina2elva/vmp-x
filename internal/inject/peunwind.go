package inject

// .pdata（异常目录）处理：把被保护函数的 RUNTIME_FUNCTION 删掉，并清掉它指向的 UNWIND_INFO。
//
// 为什么必须做（来自对打包产物的静态分析报告）：
//   · 被入口补丁吃掉的 5 字节，可以从函数尾声（保存寄存器的镜像）与 .pdata 的 UNWIND_INFO
//     （prolog_size + 保存了哪些寄存器/栈槽）精确推回来，补上就 100% 还原原生代码；
//   · 这条 unwind 记录同时也是「这个函数被特殊处理过」的路标 —— 正常函数不会只有一个入口 jmp。
//
// 做法：把 begin 命中被保护 RVA 的条目整体前移删掉（Windows 是按序线性查找的，
// 只置零会让查找提前结束），同步把数据目录的 Size 减 12，并把那条 UNWIND_INFO 清零。
import (
	"encoding/binary"
	"fmt"

	"github.com/vmpx/vmp-x/internal/load/pe"
)

const (
	dirEntryException = 3 // IMAGE_DIRECTORY_ENTRY_EXCEPTION（x64 上就是 .pdata）
	runtimeFuncSize   = 12
)

// dirEntryOff 返回第 idx 个数据目录项在文件里的偏移（可直接改写它的 RVA/Size）。
func dirEntryOff(f *pe.File, idx int) (int, bool) {
	d := f.Data
	if len(d) < 0x40 {
		return 0, false
	}
	peOff := int(binary.LittleEndian.Uint32(d[0x3C:]))
	if peOff+24 > len(d) || d[peOff] != 'P' || d[peOff+1] != 'E' {
		return 0, false
	}
	optOff := peOff + 24
	if optOff+2 > len(d) {
		return 0, false
	}
	ddOff := optOff + 112 // PE32+；PE32 是 +96
	if binary.LittleEndian.Uint16(d[optOff:]) == 0x10b {
		ddOff = optOff + 96
	}
	off := ddOff + 8*idx
	if off+8 > len(d) {
		return 0, false
	}
	return off, true
}

// neutralizeUnwind 删除 .pdata 里 begin 命中 rvas 的条目，并清零对应 UNWIND_INFO。
// 返回删除的条目数；没有 .pdata 或没命中时返回 0，不报错。
func neutralizeUnwind(f *pe.File, rvas []uint32) (int, error) {
	if len(rvas) == 0 {
		return 0, nil
	}
	want := map[uint32]bool{}
	for _, r := range rvas {
		want[r] = true
	}
	dirOff, ok := dirEntryOff(f, dirEntryException)
	if !ok {
		return 0, nil
	}
	dirRVA := binary.LittleEndian.Uint32(f.Data[dirOff:])
	dirSize := binary.LittleEndian.Uint32(f.Data[dirOff+4:])
	if dirRVA == 0 || dirSize < runtimeFuncSize {
		return 0, nil
	}
	base, err := f.RVAtoOffset(dirRVA)
	if err != nil {
		return 0, fmt.Errorf("异常目录 RVA 0x%X 不可映射: %w", dirRVA, err)
	}
	n := int(dirSize / runtimeFuncSize)
	if base+n*runtimeFuncSize > len(f.Data) {
		n = (len(f.Data) - base) / runtimeFuncSize
	}
	// 先清零要删的条目对应的 UNWIND_INFO（压实之前读，位置还准）
	for i := 0; i < n; i++ {
		off := base + i*runtimeFuncSize
		beg := binary.LittleEndian.Uint32(f.Data[off:])
		if !want[beg] {
			continue
		}
		uw := binary.LittleEndian.Uint32(f.Data[off+8:])
		if uw == 0 {
			continue
		}
		uo, err := f.RVAtoOffset(uw)
		if err != nil || uo+4 > len(f.Data) {
			continue
		}
		codes := int(f.Data[uo+2])
		sz := 4 + codes*2
		if f.Data[uo]&0x4 != 0 { // UNW_FLAG_CHAININFO：尾部还有一个 RUNTIME_FUNCTION
			sz += 12
		}
		if uo+sz > len(f.Data) {
			sz = len(f.Data) - uo
		}
		for k := 0; k < sz; k++ {
			f.Data[uo+k] = 0
		}
	}
	// 再压实：保留的条目依次前移
	kept := 0
	for i := 0; i < n; i++ {
		src := base + i*runtimeFuncSize
		beg := binary.LittleEndian.Uint32(f.Data[src:])
		if want[beg] {
			continue
		}
		if kept != i {
			copy(f.Data[base+kept*runtimeFuncSize:base+(kept+1)*runtimeFuncSize], f.Data[src:src+runtimeFuncSize])
		}
		kept++
	}
	removed := n - kept
	for k := 0; k < removed*runtimeFuncSize; k++ { // 尾部清零
		f.Data[base+kept*runtimeFuncSize+k] = 0
	}
	binary.LittleEndian.PutUint32(f.Data[dirOff+4:], uint32(kept*runtimeFuncSize))
	return removed, nil
}

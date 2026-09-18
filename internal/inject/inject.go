package inject

import (
	"fmt"

	"github.com/vmpx/vmp-x/internal/load/pe"
)

// Apply 把 payload 注入 PE：追加一个 RX 节，并把被保护函数入口改写成 jmp thunk。
// f 会被就地修改。
func Apply(f *pe.File, opt Options) (*Result, error) {
	base := f.NextRVA()
	pl, err := BuildPayload(opt, base)
	if err != nil {
		return nil, err
	}

	// 逐个写入入口补丁（先打补丁再追加节，互不影响）
	for _, p := range pl.Placements {
		off, err := f.RVAtoOffset(p.FuncRVA)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.Name, err)
		}
		if off+len(p.EntryPatch) > len(f.Data) {
			return nil, fmt.Errorf("%s 入口补丁越界", p.Name)
		}
		copy(f.Data[off:off+len(p.EntryPatch)], p.EntryPatch)
	}

	// 入口补丁打完后，把被保护函数的 .pdata 记录删掉（并清掉对应 UNWIND_INFO）：
	// 否则分析者既能据此定位"哪个函数被特殊处理过"，也能从 prologue 描述把被覆盖的字节推回来。
	var patched []uint32
	for _, p := range pl.Placements {
		patched = append(patched, p.FuncRVA)
	}
	if removed, err := neutralizeUnwind(f, patched); err != nil {
		return nil, fmt.Errorf("清理 .pdata 失败: %w", err)
	} else if removed > 0 && opt.Verbose {
		fmt.Printf("[*] 已从 .pdata 删除 %d 条 RUNTIME_FUNCTION\n", removed)
	}

	// payload 布局：[blob(含 .bss)] [描述符/thunk/字节码槽]。.bss 在 blob **中部**，
	// 所以按"可写区间"切成三段、按顺序追加，RVA 必须与 blob 里的偏移一致：
	//   .vmp  : [0, bssOff)                 → R+X（代码/只读数据）
	//   .vmpb : [bssOff, bssOff+bssSize)    → R+W（.bss：解释器的明文解密缓存）
	//   .vmpc : [bssOff+bssSize, end)       → R+X（描述符/thunk/字节码）
	bssOff, bssSize := pl.BSSOff, pl.BSSSize
	if bssOff < 0 || bssSize < 0 || bssOff+bssSize > len(pl.Data) {
		bssOff, bssSize = len(pl.Data), 0 // 没有可写区间：单段搞定
	}
	sec, err := f.AddSection(opt.SectionName, pl.Data[:bssOff], pe.ScnCntCode|pe.ScnMemExecute|pe.ScnMemRead)
	if err != nil {
		return nil, err
	}
	if sec.VirtualAddress != base {
		return nil, fmt.Errorf("节 RVA 与预估不一致（预估 0x%X，实际 0x%X）", base, sec.VirtualAddress)
	}
	if bssSize > 0 {
		rwSec, err := f.AddSection(opt.SectionName+"b", pl.Data[bssOff:bssOff+bssSize], pe.ScnCntInitData|pe.ScnMemRead|pe.ScnMemWrite)
		if err != nil {
			return nil, err
		}
		if want := base + uint32(bssOff); rwSec.VirtualAddress != want {
			return nil, fmt.Errorf("可写段 RVA 与 blob 布局不一致（期望 0x%X，实际 0x%X）", want, rwSec.VirtualAddress)
		}
		if rest := pl.Data[bssOff+bssSize:]; len(rest) > 0 {
			cxSec, err := f.AddSection(opt.SectionName+"c", rest, pe.ScnCntCode|pe.ScnMemExecute|pe.ScnMemRead)
			if err != nil {
				return nil, err
			}
			if want := base + uint32(bssOff+bssSize); cxSec.VirtualAddress != want {
				return nil, fmt.Errorf("第二代码段 RVA 与 blob 布局不一致（期望 0x%X，实际 0x%X）", want, cxSec.VirtualAddress)
			}
		}
	}

	return &Result{
		SectionRVA:   sec.VirtualAddress,
		SectionSize:  bssOff, // 第一段（R+X）的长度；后面还有可能的 RW/RX 段
		StubEntryRVA: sec.VirtualAddress + uint32(opt.StubEntry),
		Placements:   pl.Placements,
	}, nil
}

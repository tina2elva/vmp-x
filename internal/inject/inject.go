package inject

import (
	"fmt"

	"github.com/vmpx/vmp-x/internal/load/pe"
)

// wipeSeed 由「构建密钥 + 函数 RVA + payload 基址」派生抹除填充的种子：
// 每次构建、每个函数都不同，产物之间无法用固定填充模式互相定位。
func wipeSeed(key [8]byte, funcRVA, baseRVA uint32) uint64 {
	s := uint64(baseRVA)<<32 | uint64(funcRVA)
	for _, b := range key {
		s = s*6364136223846793005 + uint64(b) + 1442695040888963407
	}
	return s
}

// wipeResidue 把 data[off:off+n] 填成 seed 派生的伪随机字节。
//
// 目的不是"加密"而是**抹除**：入口补丁只覆盖前 5/8 字节，函数其余部分原本是原样保留的
// 原生指令 —— 拿到同源的另一份构建（或 PDB/符号表）就能按 RVA 差分把函数体拼回来，
// "还原"的代价只是改回入口那几字节。抹掉之后，产物里不再有任何属于该函数的原生指令，
// 还原要么得反编译 VM 字节码，要么得把同源版本重新链接进来。
//
// 用伪随机而非 0x00/0xCC 固定填充：固定填充本身就是"这段被处理过"的静态特征。
func wipeResidue(data []byte, off, n int, seed uint64) {
	if off < 0 || n <= 0 || off+n > len(data) {
		return
	}
	s := seed
	for i := off; i < off+n; i++ {
		s += 0x9E3779B97F4A7C15
		z := s
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		data[i] = byte(z ^ (z >> 31))
	}
}

// wipeNative 抹除所有被保护函数的原生机器码（保留入口跳板本身）。
// 返回抹除的总字节数。patchLen 是入口补丁长度（x86-64 5 / arm64 8）。
func wipeNative(data []byte, key [8]byte, baseRVA uint32, pl *Payload, patchLen int, rvaToOff func(uint32) (int, error)) (int, error) {
	total := 0
	for i := range pl.Placements {
		p := &pl.Placements[i]
		if p.NativeSize <= patchLen {
			continue
		}
		n := p.NativeSize - patchLen
		off, err := rvaToOff(p.FuncRVA + uint32(patchLen))
		if err != nil {
			return total, fmt.Errorf("%s: 抹除原生码时定位失败: %w", p.Name, err)
		}
		if off < 0 || off+n > len(data) {
			return total, fmt.Errorf("%s 抹除区间越界（off=0x%X n=%d len=%d）", p.Name, off, n, len(data))
		}
		wipeResidue(data, off, n, wipeSeed(key, p.FuncRVA, baseRVA))
		p.WipedBytes = n
		total += n
	}
	return total, nil
}

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

	// (d) 抹除原生机器码：入口补丁只覆盖前 5 字节，函数其余部分原样留在镜像里，
	// 于是"还原"退化成"把入口几字节改回去"。这里把补丁之后的整段函数体填成伪随机字节。
	if opt.Wipe {
		_, patchLen, aerr := opt.Arch.info()
		if aerr != nil {
			return nil, aerr
		}
		wiped, err := wipeNative(f.Data, opt.PatchKey, base, pl, patchLen, func(rva uint32) (int, error) {
			return f.RVAtoOffset(rva)
		})
		if err != nil {
			return nil, err
		}
		if opt.Verbose && wiped > 0 {
			fmt.Printf("[*] 已抹除 %d 字节原生机器码（入口跳板保留）\n", wiped)
		}
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
	nameB := opt.SectionNameB
	if nameB == "" {
		nameB = opt.SectionName + "b"
	}
	nameC := opt.SectionNameC
	if nameC == "" {
		nameC = opt.SectionName + "c"
	}
	sec, err := f.AddSection(opt.SectionName, pl.Data[:bssOff], pe.ScnCntCode|pe.ScnMemExecute|pe.ScnMemRead)
	if err != nil {
		return nil, err
	}
	if sec.VirtualAddress != base {
		return nil, fmt.Errorf("节 RVA 与预估不一致（预估 0x%X，实际 0x%X）", base, sec.VirtualAddress)
	}
	if bssSize > 0 {
		rwSec, err := f.AddSection(nameB, pl.Data[bssOff:bssOff+bssSize], pe.ScnCntInitData|pe.ScnMemRead|pe.ScnMemWrite)
		if err != nil {
			return nil, err
		}
		if want := base + uint32(bssOff); rwSec.VirtualAddress != want {
			return nil, fmt.Errorf("可写段 RVA 与 blob 布局不一致（期望 0x%X，实际 0x%X）", want, rwSec.VirtualAddress)
		}
		if rest := pl.Data[bssOff+bssSize:]; len(rest) > 0 {
			cxSec, err := f.AddSection(nameC, rest, pe.ScnCntCode|pe.ScnMemExecute|pe.ScnMemRead)
			if err != nil {
				return nil, err
			}
			if want := base + uint32(bssOff+bssSize); cxSec.VirtualAddress != want {
				return nil, fmt.Errorf("第二代码段 RVA 与 blob 布局不一致（期望 0x%X，实际 0x%X）", want, cxSec.VirtualAddress)
			}
		}
	}

	// (c) 加载期校验：把入口点改到 payload 里的校验蹦床（它验完再跳回原入口）。
	// 只有加载期能拦住"把补丁字节回填成原生代码"那种绕过 —— 那时 VM 根本不会被执行。
	// 入口点优先给"原镜像自解密蹦床"（它接着跳补丁校验蹦床，再到原始入口）。
	switch {
	case pl.ImgHookRVA != 0:
		if err := SetEntryRVA(f, pl.ImgHookRVA); err != nil {
			return nil, fmt.Errorf("改写 PE 入口点失败: %w", err)
		}
	case pl.EntryHookRVA != 0:
		if err := SetEntryRVA(f, pl.EntryHookRVA); err != nil {
			return nil, fmt.Errorf("改写 PE 入口点失败: %w", err)
		}
	}

	return &Result{SectionNames: []string{opt.SectionName, nameB, nameC},
		SectionRVA:     sec.VirtualAddress,
		SectionSize:    bssOff, // 第一段（R+X）的长度；后面还有可能的 RW/RX 段
		StubEntryRVA:   sec.VirtualAddress + uint32(opt.StubEntry),
		Placements:     pl.Placements,
		ImgTableRVA:    pl.ImgTableRVA,
		ImgTableLen:    pl.ImgTableLen,
		ImgTlsArrayRVA: pl.ImgTlsArrayRVA,
		LoadCfgRVA:     pl.LoadCfgRVA,
		TlsDirRVA:      pl.TlsDirRVA,
	}, nil
}

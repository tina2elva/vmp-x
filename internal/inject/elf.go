package inject

import (
	"fmt"

	"github.com/vmpx/vmp-x/internal/load/elf"
)

// ApplyELF 把 payload 注入 ELF（Linux/amd64）：
// 复用第一个 PT_NOTE 槽位改写成指向 payload 的 PT_LOAD(RX)，
// 并把被保护函数入口改写成 jmp thunk。f 会被就地修改。
//
// 注意：这里不新增节头（section header）。内核加载只看程序头，
// 因此不影响执行；若希望 readelf -S 也可读，再补节头。
func ApplyELF(f *elf.File, opt Options) (*Result, error) {
	// warnRWX 记录是否因为无法分段而退回可写代码段（供报告/CI 断言用）
	warnRWX := false
	_ = warnRWX
	imageBase := f.ImageBase()
	if imageBase == 0 {
		return nil, fmt.Errorf("无法确定镜像基址")
	}
	baseVA := f.NextVA()
	if baseVA < imageBase || baseVA-imageBase > 0xFFFFFFFF {
		return nil, fmt.Errorf("新段地址 0x%X 超出 32 位表示范围", baseVA)
	}
	baseRVA := uint32(baseVA - imageBase)

	pl, err := BuildPayload(opt, baseRVA)
	if err != nil {
		return nil, err
	}

	for _, p := range pl.Placements {
		va := imageBase + uint64(p.FuncRVA)
		if err := f.WriteVA(va, p.EntryPatch); err != nil {
			return nil, fmt.Errorf("%s: %w", p.Name, err)
		}
	}

	// (d) 抹除原生机器码（与 PE 侧同义）：入口补丁之外的原生函数体不再留在镜像里，
	// 否则同源的另一份构建就能按 RVA 差分把函数体拼回来。
	if opt.Wipe {
		_, patchLen, aerr := opt.Arch.info()
		if aerr != nil {
			return nil, aerr
		}
		for i := range pl.Placements {
			p := &pl.Placements[i]
			if p.NativeSize <= patchLen {
				continue
			}
			n := p.NativeSize - patchLen
			buf := make([]byte, n)
			wipeResidue(buf, 0, n, wipeSeed(opt.PatchKey, p.FuncRVA, baseRVA))
			if err := f.WriteVA(imageBase+uint64(p.FuncRVA)+uint64(patchLen), buf); err != nil {
				return nil, fmt.Errorf("%s: 抹除原生机器码失败: %w", p.Name, err)
			}
			p.WipedBytes = n
		}
	}

	// (c) 入口点：**优先给"原镜像自解密蹦床"**（它接着跳校验蹦床，再到原始入口点）；
	// 没做整体加密时才是校验蹦床。这条与 PE 侧同义 —— PE 那边早就这么分流了，ELF 这边漏了：
	// 结果是加密后的 ELF 从校验蹦床直接开跑，.text 还是密文 → 进程起手就死，
	// 连失败 trace 都打不出来（CI run #292 的现场就是"packed 一个字都没输出"）。
	// 内部校验路径本身不依赖"运行期读目标字节"（那个做法在 ELF 上会出问题，见 STATUS 第 392 条）。
	switch {
	case pl.ImgHookRVA != 0:
		if err := f.SetEntry(imageBase + uint64(pl.ImgHookRVA)); err != nil {
			return nil, fmt.Errorf("改写 ELF 入口点失败: %w", err)
		}
	case pl.EntryHookRVA != 0:
		if err := f.SetEntry(imageBase + uint64(pl.EntryHookRVA)); err != nil {
			return nil, fmt.Errorf("改写 ELF 入口点失败: %w", err)
		}
	}

	newVA, payloadOff, err := f.AddLoadSegmentFromNote(pl.Data)
	if err != nil {
		return nil, err
	}
	if newVA != baseVA {
		return nil, fmt.Errorf("新段 VA 与预估不一致（预估 0x%X，实际 0x%X）", baseVA, newVA)
	}

	// blob 里的 .bss（解释器的明文解密缓存）需要写权限，但代码段不该可写（RWX 是安全坏味道）。
	// 做法：上面的段是 R+X，再用一个**重叠的** PT_LOAD 把 .bss 那一截覆盖成 R+W。
	// 因为 blob 构建时已把 .bss 起止都对齐到 0x1000，所以两段的页不会交错。
	if pl.BSSSize > 0 {
		if err := f.AddOverlayLoadSegment(baseVA+uint64(pl.BSSOff), payloadOff+int64(pl.BSSOff),
			uint64(pl.BSSSize), elf.PF_R|elf.PF_W); err != nil {
			// 没有空槽位可复用（例如动态链接的 ELF 里 PT_PHDR 不能丢）：
			// 退回"整段 RWX"并**明确告警**，而不是悄悄接受一个可写的代码段。
			if !f.SetLoadSegmentFlags(newVA, elf.PF_R|elf.PF_X|elf.PF_W) {
				return nil, fmt.Errorf("添加可写覆盖段失败且无法退回: %w", err)
			}
			fmt.Printf("[warn] 无法为该 ELF 分段（%v）：payload 段退回 RWX（代码页可写）\n", err)
			warnRWX = true
		}
	}

	// 顺序修正（很关键）：内核按程序头表顺序依次 mmap 各 PT_LOAD，**重叠区间上后面的覆盖前面的**。
	// 可写覆盖段必须排在 payload 段之后，否则 .bss 会被随后的 RX 映射盖回去 ——
	// 解释器写解密缓存就 SIGSEGV（SEGV_ACCERR，Linux 实测；PE 侧按节合并、写标志生效，不暴露此问题）。
	// 实测：payload 复用 PT_NOTE（索引 1），覆盖段落到更低的索引 0（可丢弃的 PT_PHDR），
	// 于是 payload 后映射、把 RW 盖掉。
	if pi, oi := payloadPhdrIndex(f, newVA), payloadPhdrIndex(f, baseVA+uint64(pl.BSSOff)); pi >= 0 && oi >= 0 && oi < pi {
		f.SwapPhdrs(oi, pi)
	}

	return &Result{
		SectionRVA:   baseRVA,
		SectionSize:  len(pl.Data),
		StubEntryRVA: baseRVA + uint32(opt.StubEntry),
		Placements:   pl.Placements,
		ImgTableRVA:  pl.ImgTableRVA,
		ImgTableLen:  pl.ImgTableLen,
	}, nil
}

// payloadPhdrIndex 按 VA 找出某个 PT_LOAD 在程序头表里的索引（找不到返回 -1）。
func payloadPhdrIndex(f *elf.File, va uint64) int {
	for i, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Vaddr == va {
			return i
		}
	}
	return -1
}

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

	return &Result{
		SectionRVA:   baseRVA,
		SectionSize:  len(pl.Data),
		StubEntryRVA: baseRVA + uint32(opt.StubEntry),
		Placements:   pl.Placements,
	}, nil
}

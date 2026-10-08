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
	// payloadWX 记录本次是否**退回**了"载荷里存在可写+可执行段"的形状（②窗口+尾部合并成
	// 一段 RWX，或 ③整段 RWX）。它落进报告（Result.PayloadWXFallback），门禁据此断言
	// "报告说的形状"与"产物程序头里的形状"一致 —— 例如可复用槽位足够的目标不得走回退。
	payloadWX := false
	imageBase := f.ImageBase()
	// ET_DYN(PIE) 的首选基址**可以就是 0**（gcc 默认布局：第一个 PT_LOAD 的 p_vaddr = 0，
	// 内核把它映射到 load_bias）。此时 RVA == VA，本函数里所有 "imageBase + RVA" 的算术照样成立，
	// 运行期也照旧用 "解密表地址 − selfRVA" 反推基址。只有 ET_EXEC 的基址为 0 才是解析失败。
	if imageBase == 0 && f.EType != elf.ET_DYN {
		return nil, fmt.Errorf("无法确定镜像基址")
	}
	baseVA := f.NextVA()
	if baseVA < imageBase || baseVA-imageBase > 0xFFFFFFFF {
		return nil, fmt.Errorf("新段地址 0x%X 超出 32 位表示范围", baseVA)
	}
	baseRVA := uint32(baseVA - imageBase)

	// 链接期（首选）基址要写进重定位应用表：运行期 delta = 运行期基址 − 首选基址。
	// 注意与 opt.ImageBase（写进解密表头、运行期用来**强制**基址）不同：ELF 侧那里传 0
	// （PIE 必然被搬走，不能强制）；这里必须是真实的链接期基址。
	opt.PrefBase = imageBase

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

	// 关键前置步骤：把"带 .bss 的 PT_LOAD"改成文件承载，**然后**才允许在更高地址加段。
	// 原因（实测）：Linux 内核只把 [PAGEALIGN(max(vaddr+filesz)), PAGEALIGN(max(vaddr+memsz)))
	// 这一段映射成 bss；我们的载荷段在更高地址 ⇒ 原 RW 段的 .bss 会整段没有映射 ⇒
	// 程序第一次写全局变量就 SIGSEGV（内核 "segfault at <bss> ... error 6"；Go 目标的
	// runtime.g0 就在里面）。老内核一路如此（WSL 6.6 实测），新内核改成逐段映射所以 CI 是绿的
	// —— 也就是说**生产上大量老内核都会踩**，必须在打包端修。详见 MakeBssFileBacked 的注释。
	if n := f.MakeBssFileBacked(); n > 0 {
		fmt.Printf("[*] ELF：%d 个带 .bss 的段改成文件承载（否则高层载荷段会让内核漏映射这段 bss）\n", n)
	}

	// ---- 载荷分段（M5 的核心，见 STATUS #597）----
	//
	// 首选形状：RX 前缀 [0, bssOff) + RW 窗口 [bssOff, bssOff+bssSize) + R+X 尾部
	// […, len(Data))。三者 VA 相邻、**不重叠** ⇒ 不存在任何"非可写 LOAD 盖住可写窗口"的形状。
	//
	// 为什么必须不重叠：glibc 只在 DT_TEXTREL 路径按 PT_LOAD 重设回原保护。老形状是
	// "整段 RX + 重叠的 RW 覆盖段"，它靠"后映射者胜"才拿到可写；一旦 glibc 按 RX 段把页
	// 重设成只读（#597 的 textrel 实测），解释器第一次写自己的解密缓存就 SIGSEGV。
	// 回退形状（下面梯子的 ②③）都让那一整段**可写** —— 整段可写对这种重设同样免疫 ——
	// 但**绝不**退回那个重叠形状（上一轮的洞正是在这里）。
	//
	// 槽位账：前缀 + 窗口 = 2 个；若载荷在窗口之后还有字节（尾部，装着**可执行蹦床**：
	// 两段版把尾部并进 RW 段时 normal/textrel 两个产物都立刻 SIGSEGV）则要 3 个。
	// 槽位不足时按下面的梯子降级（每降一级都会打醒目告警，并写进报告）。
	spare := f.SparePhdrSlots()
	segments := 1
	tailSize := 0
	// 窗口必须整帧落在页上：内核只按页 mmap/mprotect，窗口若从页中间开始，那页的前半截
	// 仍被 RX 前缀段覆盖 —— glibc 按前缀段把该页设成只读时，窗口的前几个字节就跟着变只读
	// （实测：这是同一个 SIGSEGV，只是窗口小了一半）。blob 构建把 .bss 起止都对齐到 0x1000，
	// 所以真实产物永远满足；这里留一条守卫，不满足就整段 RWX（而不是假装分得很干净）。
	pageOK := pl.BSSOff%elf.PageAlign == 0 && pl.BSSSize%elf.PageAlign == 0
	if pl.BSSSize > 0 && pl.BSSOff > 0 && pl.BSSOff < len(pl.Data) && pageOK {
		if end := pl.BSSOff + pl.BSSSize; end > len(pl.Data) {
			segments = 1 // 窗口越出载荷（不该发生）：退回单段
		} else {
			segments = 2
			if tailSize = len(pl.Data) - end; tailSize > 0 {
				segments = 3
			}
		}
	} else if pl.BSSSize > 0 && !pageOK {
		fmt.Printf("[warn] 载荷的可写窗口未按页对齐（bssOff=0x%X bssSize=0x%X）：无法切成独立段 ⇒ 整段 RWX\n",
			pl.BSSOff, pl.BSSSize)
	}
	// 分段方案的选择（**这条梯子就是"绝不再产生重叠形状"的保证**）：
	//   ① spare >= segments         ：两段/三段**相邻**拆分（代码页保持只读，最好）；
	//   ② spare == 2 且有窗口+尾部   ：两段拆分，窗口与尾部合并成**一段 RWX**
	//      （窗口与尾部同权限时直接切一刀是对的：W 与 R+X 各自都在，而且仍与别的段不重叠）；
	//   ③ 其它（只剩 1 个槽）        ：整段 RWX。
	// ②/③ 都是"整个那段可写"，所以对 glibc 的 TEXTREL 保护重设免疫；它们都不产生重叠段。
	split := segments >= 2 && spare >= segments
	// ②：窗口自带可执行尾部（tailSize 紧跟在窗口之后、同一段里）—— 只有恰好 2 个槽时用。
	splitRWXWindow := !split && segments == 3 && spare == 2

	var newVA uint64
	var payloadOff int64
	if !split && !splitRWXWindow {
		// 单段（无可写窗口，或槽位不够）：**整段**映射。有窗口时给 RWX —— 整段可写 ⇒ 无重叠形状。
		wholeFlags := uint32(elf.PF_R | elf.PF_X)
		if pl.BSSSize > 0 {
			wholeFlags |= elf.PF_W
		}
		newVA, payloadOff, err = f.AddLoadSegmentFromNote(pl.Data)
		if err != nil {
			return nil, err
		}
		if newVA != baseVA {
			return nil, fmt.Errorf("新段 VA 与预估不一致（预估 0x%X，实际 0x%X）", baseVA, newVA)
		}
		if !f.SetLoadSegmentFlags(newVA, wholeFlags) {
			return nil, fmt.Errorf("无法设置载荷段权限（VA 0x%X 不在程序头表里）", newVA)
		}
		if pl.BSSSize > 0 {
			fmt.Printf("[warn] 无法为该 ELF 分段（可复用程序头槽位 %d 个，需要 %d 个）：payload 段**整段退回 RWX**（代码页可写）；"+
				"整段可写 ⇒ 对 glibc 的 TEXTREL 保护重设免疫，且不产生任何重叠段\n", spare, segments)
			payloadWX = true
		}
	} else {
		// 前缀：只映射 [0, bssOff)，段本身仍是 RX 且**止于 bssOff**。
		newVA, payloadOff, err = f.AddLoadSegmentFromNoteSized(pl.Data, pl.BSSOff)
		if err != nil {
			return nil, err
		}
		if newVA != baseVA {
			return nil, fmt.Errorf("新段 VA 与预估不一致（预估 0x%X，实际 0x%X）", baseVA, newVA)
		}
		// 窗口与尾部都指向**已经追加进文件**的那份载荷字节（不新增文件内容）。
		//
		// 这里**不依赖程序头表顺序**：三段按页互不相交，所以内核先映射谁都不影响结果
		// （实测产物里窗口段甚至排在载荷前缀段**之前**：PH[0]=RWX 窗口+尾部、PH[1]=RX 前缀）。
		// 老形状才依赖"后映射者胜"—— 那正是 #597 的脆弱点：glibc 在 DT_TEXTREL 路径按
		// PT_LOAD 重设保护时不管映射顺序，RX 段盖住窗口页就把窗口设成了只读。
		winSize := uint64(pl.BSSSize)
		winFlags := uint32(elf.PF_R | elf.PF_W)
		if splitRWXWindow {
			// ②：只多一个槽 —— 窗口与紧随其后的尾部合成**一段 RWX**（[bssOff, len(Data))）。
			// 这一段自己可写，所以不存在"非可写段盖住窗口"；它仍然与别的段不重叠。
			winSize += uint64(tailSize)
			winFlags |= elf.PF_X
		}
		if err := f.AddOverlayLoadSegment(newVA+uint64(pl.BSSOff), payloadOff+int64(pl.BSSOff),
			winSize, winFlags); err != nil {
			return nil, fmt.Errorf("添加可写窗口段失败（已按槽位数预算过分段）: %w", err)
		}
		if tailSize > 0 && !splitRWXWindow {
			if err := f.AddOverlayLoadSegment(newVA+uint64(pl.BSSOff+pl.BSSSize),
				payloadOff+int64(pl.BSSOff+pl.BSSSize), uint64(tailSize), elf.PF_R|elf.PF_X); err != nil {
				return nil, fmt.Errorf("添加载荷尾部段失败（已按槽位数预算过分段）: %w", err)
			}
		}
		if splitRWXWindow {
			// ②：只有 2 个槽 —— 代码页仍是只读，但**窗口与尾部的这一段**是 RWX（可写）。
			// 醒目告警的原因与 ③ 一样：这一段整段可写，是回退而不是首选形状。
			fmt.Printf("[warn] 可复用程序头槽位只有 %d 个（三段需要 %d 个）：退而求其次 —— RX 前缀 [0, 0x%X) 保持只读，"+
				"但窗口+尾部合成**一段 RWX** [0x%X, 0x%X)（该段可写，代码页中只有这一截可写；两段相邻不重叠，"+
				"整段可写 ⇒ 对 glibc 的 TEXTREL 保护重设免疫）\n",
				spare, segments, pl.BSSOff, pl.BSSOff, pl.BSSOff+pl.BSSSize+tailSize)
			payloadWX = true
		} else if tailSize > 0 {
			fmt.Printf("[*] ELF 载荷分段：RX 前缀 [0, 0x%X) + RW 窗口 [0x%X, 0x%X) + R+X 尾部 0x%X 字节"+
				"（三段相邻不重叠；可复用槽位 %d，用 %d）\n", pl.BSSOff, pl.BSSOff, pl.BSSOff+pl.BSSSize, tailSize, spare, segments)
		} else {
			fmt.Printf("[*] ELF 载荷分段：RX 前缀 [0, 0x%X) + RW 窗口 [0x%X, 0x%X)"+
				"（两段相邻不重叠；可复用槽位 %d，用 %d）\n", pl.BSSOff, pl.BSSOff, pl.BSSOff+pl.BSSSize, spare, segments)
		}
	}

	// 重定位应用表（运行期应用器的契约，见 RelocTableHeaderSize）连同"到底加密了哪些范围"
	// 一起落进报告：布局门禁据此核对"范围里没有没被记录的重定位"。
	return &Result{
		SectionRVA:       baseRVA,
		SectionSize:      len(pl.Data),
		StubEntryRVA:     baseRVA + uint32(opt.StubEntry),
		Placements:       pl.Placements,
		ImgTableRVA:      pl.ImgTableRVA,
		ImgTableLen:      pl.ImgTableLen,
		ImgSections:      opt.ImgSections,
		ImgRelocTableRVA: pl.ImgRelocTableRVA,
		ImgRelocLen:      pl.ImgRelocLen,
		ImgRelocCount:    len(opt.ImgRelocs),
		ImgPrefBase:      imageBase,
		ImgEType:         f.EType,
		// "载荷里存在可写+可执行段"这个事实必须随产物一起落进报告：门禁拿它与程序头对账，
		// 于是"报告说拆开了、产物却有一个 RWX 载荷段"（或反过来）会当场红，而不是靠人眼看日志。
		PayloadWXFallback: payloadWX,
	}, nil
}

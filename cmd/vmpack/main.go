// vmpack - 把 ELF/PE 中的指定函数保护起来（x86-64 整数子集 + VM 解释器注入）
//
// 用法:
//
//	vmpack -exe in.bin -func name [-func name2] -out out.bin
//	       [-blob build/vm_interp.bin] [-manifest build/vm_interp.json] [-report out.json]
//
// 目前支持：Windows/amd64 PE、Linux/amd64 ELF。（arm64 后端见 docs/DESIGN.md §8b）
package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	arm64dec "github.com/vmpx/vmp-x/internal/decode/arm64"
	"github.com/vmpx/vmp-x/internal/inject"
	"github.com/vmpx/vmp-x/internal/ir"
	arm64lift "github.com/vmpx/vmp-x/internal/lift/arm64"
	"github.com/vmpx/vmp-x/internal/lift/x64"
	elfload "github.com/vmpx/vmp-x/internal/load/elf"
	"github.com/vmpx/vmp-x/internal/load/pe"
	"github.com/vmpx/vmp-x/internal/scan"
	"github.com/vmpx/vmp-x/internal/vm"
	"golang.org/x/crypto/chacha20poly1305"
)

type stubManifest struct {
	EntryOff  int    `json:"entryOff"`
	BSSOff    int    `json:"bssOff"`
	BSSSize   int    `json:"bssSize"`
	Key       string `json:"key"`
	BlobSize  int    `json:"blobSize"`
	FrameSkew int    `json:"frameSkew"`
	// DescMagic：blob 期望的描述符魔数（release 构建每次不同，见 vmpbuild -release）。
	DescMagic uint32         `json:"descMagic"`
	Symbols   map[string]int `json:"symbols"`
	OpcodeMap map[string]int `json:"opcodeMap"` // 本 blob 的操作码编码（M2 起每 blob 随机）
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	exe := flag.String("exe", "", "输入文件（PE 或 ELF）")
	out := flag.String("out", "", "输出文件（默认 <输入>.vmp）")
	blobPath := flag.String("blob", "build/vm_interp.bin", "解释器 blob 路径")
	manPath := flag.String("manifest", "build/vm_interp.json", "blob manifest 路径")
	noEncrypt := flag.Bool("no-encrypt", false, "不加密字节码（调试用；默认加密）")
	wipe := flag.Bool("wipe", true, "抹除被保护函数的原生机器码（默认开；-wipe=false 保留旧行为，仅供对照实验）")
	noEncImage := flag.Bool("no-enc-image", false, "关闭原镜像整体加密（默认对 x86-64 EXE 开启）")
	encImageSections := flag.String("enc-image-sections", "", "只整体加密这些节（逗号分隔；留空=默认 .text,.rdata,.data）")
	noEncImageDLL := flag.Bool("no-enc-image-dll", false, "对 DLL 关闭原镜像整体加密（默认对 DLL 也开）")
	noEncImageELF := flag.Bool("no-enc-image-elf", false, "对 ET_EXEC 的 ELF 关闭原镜像整体加密（默认开；探针已改为合成补丁字节，不再依赖明文）")
	dumpBytecode := flag.String("dumpbytecode", "", "把每个函数的**明文**字节码转储到该目录（诊断用）")
	mapPath := flag.String("map", "", "MSVC MAP 文件：目标没有 COFF 符号表时用它按名字定位函数")
	reportPath := flag.String("report", "", "注入报告 JSON 路径（可选）")
	section := flag.String("section", "", "注入节名（仅 PE；留空则每次构建随机生成三个互不相关的名字）")
	verbose := flag.Bool("v", false, "打印 IR 详情")
	keepSelfChecksFlag = flag.Bool("keep-selfchecks", false, "保留运行期自校验调用（默认丢弃；仅用于对照实验）")
	var funcs multiFlag
	flag.Var(&funcs, "func", "要保护的函数名（可重复）")
	flag.Parse()
	wipeEnabled = *wipe
	encImageEnabled = !*noEncImage
	encImageDLLEnabled = !*noEncImageDLL
	encImageELFEnabled = !*noEncImageELF
	encImageSectionList = *encImageSections

	if *exe == "" || len(funcs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: vmpack -exe in.bin -func name [-func name2] [-out out.bin]")
		os.Exit(2)
	}
	outPath := *out
	if outPath == "" {
		outPath = *exe + ".vmp"
	}

	// 1. 解释器 blob + manifest
	stub, err := os.ReadFile(*blobPath)
	must(err)
	var man stubManifest
	mb, err := os.ReadFile(*manPath)
	must(err)
	must(json.Unmarshal(mb, &man))
	entryOff, ok := man.Symbols["vm_entry"]
	if !ok {
		fatalf("%s 里没有 vm_entry 符号；请用 -entry vm_entry 构建 blob", *manPath)
	}
	fmt.Printf("[*] 解释器: %s (%d 字节), vm_entry @ +0x%X, FRAME_SKEW=%d, 可写区 [0x%X,+0x%X)",
		*blobPath, len(stub), entryOff, man.FrameSkew, man.BSSOff, man.BSSSize)
	fmt.Println()

	var opcodeMap *vm.OpcodeMap
	if len(man.OpcodeMap) > 0 {
		byName := map[string]byte{}
		for k, v := range man.OpcodeMap {
			byName[k] = byte(v)
		}
		opcodeMap, err = vm.NewOpcodeMap(byName)
		must(err)
		nonIdent := !opcodeMap.Identity
		fmt.Printf("[*] 操作码映射: %d 条%s", len(byName), map[bool]string{true: "（构建期随机）", false: "（默认编码）"}[nonIdent])
		fmt.Println()
	}

	// 字节码加密（M2.2）：用 blob 的主密钥逐函数密封。密钥来自 manifest（vmpbuild 生成）。
	dumpSeq := 0
	var patchKey [8]byte
	var enc inject.EncryptFunc
	if !*noEncrypt && man.Key != "" {
		key, err := hex.DecodeString(man.Key)
		must(err)
		if len(key) != 32 {
			fatalf("manifest 里的 key 长度不对（%d 字节）", len(key))
		}
		aead, err := chacha20poly1305.New(key)
		must(err)
		imgAEAD = aead
		enc = func(plain []byte, aad []byte) ([]byte, [12]byte, [16]byte, error) {
			var nonce [12]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return nil, nonce, [16]byte{}, err
			}
			if *dumpBytecode != "" {
				// 诊断用：把**明文**字节码单独存一份。payload 里放的是密文，				// 从 payload 直接读出来的字节不是指令流（我曾因此得出过错误结论）。
				_ = os.MkdirAll(*dumpBytecode, 0o755)
				name := fmt.Sprintf("%s/bytecode_%02d.bin", *dumpBytecode, dumpSeq)
				dumpSeq++
				_ = os.WriteFile(name, plain, 0o644)
			}
			sealed := aead.Seal(nil, nonce[:], plain, aad)
			var tag [16]byte
			copy(tag[:], sealed[len(sealed)-16:])
			return sealed[:len(sealed)-16], nonce, tag, nil
		}
		copy(patchKey[:], key[:8])
		fmt.Printf("[*] 字节码加密: ChaCha20-Poly1305（%d 字节密钥，来自 blob manifest）", len(key))
		fmt.Println()
	}

	head, err := os.ReadFile(*exe)
	must(err)
	isELF := len(head) >= 4 && head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F'
	isPE := len(head) >= 2 && head[0] == 'M' && head[1] == 'Z'
	if !isELF && !isPE {
		fatalf("无法识别的文件格式（既不是 PE 也不是 ELF）：%s", *exe)
	}

	// 目标架构：ELF 的 e_machine（0x3E=x86-64，0xB7=AArch64）；PE 目前只支持 x86-64
	arch := inject.ArchX64
	switch {
	case isELF:
		if len(head) < 20 {
			fatalf("ELF 头部过短")
		}
		switch binary.LittleEndian.Uint16(head[18:]) {
		case 0xB7:
			arch = inject.ArchARM64
		case 0x3E:
			arch = inject.ArchX64
		default:
			fatalf("不支持的 ELF 机器类型 0x%X", binary.LittleEndian.Uint16(head[18:]))
		}
	case isPE:
		// PE：e_lfanew(0x3C) → "PE\0\0" → COFF Machine（+4）
		if len(head) < 0x40 {
			fatalf("PE 头部过短")
		}
		peOff := int(binary.LittleEndian.Uint32(head[0x3C:]))
		if peOff+6 > len(head) || string(head[peOff:peOff+4]) != "PE\x00\x00" {
			fatalf("PE 头签名不对")
		}
		switch binary.LittleEndian.Uint16(head[peOff+4:]) {
		case 0xAA64:
			arch = inject.ArchARM64
		case 0x8664:
			arch = inject.ArchX64
		default:
			fatalf("不支持的 PE 机器类型 0x%X", binary.LittleEndian.Uint16(head[peOff+4:]))
		}
	}
	fmt.Printf("[*] 目标架构: %s", arch)
	fmt.Println()

	if *mapPath != "" {
		if err := scan.LoadMapFile(*mapPath); err != nil {
			fatalf("读 MAP 失败: %v", err)
		}
		fmt.Println("[*] 已载入 MAP：按名字定位函数")
	}

	scratchOff, hasCache := man.Symbols["vm_bc_cache"]
	scratchEnd, hasLock := man.Symbols["vm_bc_lock"]
	scratchLen := 0
	if hasCache && hasLock && scratchEnd > scratchOff {
		scratchLen = scratchEnd - scratchOff
	}
	var res *inject.Result
	if isELF {
		verifyFnELF, hasVerifyELF := man.Symbols["vm_verify_table"]
		if !hasVerifyELF {
			verifyFnELF = -1
		}
		res = packELF(*exe, outPath, stub, entryOff, man.FrameSkew, man.DescMagic, patchKey, verifyFnELF, man.Symbols["vm_unpack_image"], scratchOff, scratchLen, man.BSSOff, man.BSSSize, man.Symbols["vm_xmm"], man.Symbols["vm_tmp"], funcs, opcodeMap, enc, arch, *verbose, *reportPath)
	} else {
		scratchOff, hasCache := man.Symbols["vm_bc_cache"]
		scratchEnd, hasLock := man.Symbols["vm_bc_lock"]
		scratchLen := 0
		if hasCache && hasLock && scratchEnd > scratchOff {
			scratchLen = scratchEnd - scratchOff
		}
		verifyFn, hasVerify := man.Symbols["vm_verify_table"]
		if !hasVerify {
			verifyFn = -1
		}
		*section = sectionNamesFor(*section)
		bytecodeLimitFlag = bytecodeLimit(man.Symbols, stub)
		res = packPE(*exe, outPath, stub, entryOff, man.FrameSkew, man.DescMagic, patchKey, verifyFn, man.Symbols["vm_unpack_image"], scratchOff, scratchLen, man.BSSOff, man.BSSSize, man.Symbols["vm_xmm"], man.Symbols["vm_tmp"], funcs, opcodeMap, enc, arch, *verbose, *section, *reportPath)
	}

	for _, p := range res.Placements {
		fmt.Printf("    %-16s desc=0x%-7X thunk=0x%-7X code=0x%-7X patch=[%s]",
			p.Name, p.DescRVA, p.ThunkRVA, p.CodeRVA, p.EntryPatchHex)
		fmt.Println()
	}
	fmt.Printf("[+] 输出: %s (%d 字节)", outPath, sizeOf(outPath))
	fmt.Println()
	if *reportPath != "" {
		must(inject.WriteReport(*reportPath, res))
		fmt.Printf("[+] 报告: %s", *reportPath)
		fmt.Println()
	}
	_ = vm.OpHalt
}

func sizeOf(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}

// liftIface 抽象 lifter：x86-64 与 AArch64 各有一套 API（后者要先解码再 Lift），
// 这里只要求"给我一个函数名和它的字节，返回 IR"。
type liftIface interface {
	LiftFunc(name string, code []byte, rva uint32) (*ir.Func, error)
}

// a64Adapter 让 AArch64 lifter 满足 liftIface。
// AArch64 是定长 4 字节指令：先整体解码（decode/arm64），再交给 lifter.Lift。
type a64Adapter struct{ l *arm64lift.Lifter }

func (a a64Adapter) LiftFunc(name string, code []byte, rva uint32) (*ir.Func, error) {
	insns, err := arm64dec.DecodeRange(code, uint64(rva), 0)
	if err != nil && len(insns) == 0 {
		return nil, err
	}
	fn := &ir.Func{Name: name, RVA: rva, Size: len(code)}
	a.l.Lift(fn, insns)
	// 关键：不能吞掉 Unsupported。之前这里直接 return fn,nil，于是 arm64 上
	// "lifter 不认识某条指令"会被静默丢掉（sum_to 的 cmp 就是这样消失的，
	// 结果循环永远不退出）。x86 侧是会报错的，这里必须一致 —— fail-fast。
	if len(fn.Unsupported) > 0 {
		return fn, fmt.Errorf("ARM64 有 %d 条指令无法翻译：%v", len(fn.Unsupported), fn.Unsupported[0])
	}
	return fn, nil
}

// liftAll 对所有目标函数做 lift + codegen（与容器/架构无关）
func liftAll(lifter liftIface, names []string, find func(string) (*scan.Found, error), opcodeMap *vm.OpcodeMap, verbose bool, bytesAt func(rva uint32, n int) ([]byte, bool), keepSelfChecks bool) ([]inject.FuncSpec, error) {
	var specs []inject.FuncSpec
	seen := map[uint32]string{}
	for _, name := range names {
		found, err := find(name)
		if err != nil {
			return nil, err
		}
		// 去重：桩解析之后，"包装函数"和它跳转到的函数体会落在同一个 RVA 上。
		// 同一个 RVA 放两份 = 后者覆盖前者的补丁字节，加载期校验表就必然对不上（实测：DLL 初始化例程失败）。
		if prev, dup := seen[found.RVA]; dup {
			fmt.Printf("    %s: RVA=0x%X 与 %s 相同（桩/别名），跳过重复放置", name, found.RVA, prev)
			fmt.Println()
			continue
		}
		seen[found.RVA] = name
		irFunc, err := lifter.LiftFunc(name, found.Code, found.RVA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s: %v", name, err)
			fmt.Fprintln(os.Stderr)
			if irFunc != nil { // 出错时 lifter 可能返回 nil，直接解引用会 panic（CI 上真的发生过）
				for _, u := range irFunc.Unsupported {
					fmt.Fprintf(os.Stderr, "      %s", u)
					fmt.Fprintln(os.Stderr)
				}
			}
			os.Exit(1)
		}
		if !keepSelfChecks && bytesAt != nil {
			if n := dropRuntimeSelfChecks(irFunc, bytesAt); n > 0 {
				fmt.Printf("    %s: 丢弃 %d 条运行期自校验调用（VM 内无意义，且会冲掉 guest 寄存器）", name, n)
				fmt.Println()
			}
		}
		gen, err := vm.Generate(irFunc)
		if err != nil {
			return nil, err
		}
		// 把字节码里的操作码换成该 blob 的实际编码（操作数不动）
		mapped, err := vm.Remap(gen.Code, opcodeMap)
		if err != nil {
			return nil, err
		}
		gen.Code = mapped
		if bytecodeLimitFlag > 0 && len(gen.Code) > bytecodeLimitFlag {
			return nil, fmt.Errorf("%s: 生成的字节码 %d 字节超过解释器缓存槽上限 %d —— 超限时 vm_run 会返回错误码，"+
				"而调用方会把那个返回值当成函数结果（静默算错，实测表现为崩在第三方库里）。"+
				"修法：调大 stub 里的 VM_BC_SLOT_SIZE 后重编 blob", name, len(gen.Code), bytecodeLimitFlag)
		}
		fmt.Printf("    %s: RVA=0x%X native=%dB -> %d IR -> %dB bytecode",
			name, found.RVA, len(found.Code), len(irFunc.Insns), len(gen.Code))
		fmt.Println()
		if verbose {
			for i := range irFunc.Insns {
				in := &irFunc.Insns[i]
				fmt.Printf("      IR[%02d] %-8s w=%-2d kind=%d dst=%d a=%d b=%d imm=0x%X disp=%d target=%d src=+0x%X",
					i, in.Op.String(), in.Width, in.Kind, in.Dst, in.A, in.B, in.Imm, in.Disp, in.Target, in.SrcOff)
				fmt.Println()
			}
		}
		specs = append(specs, inject.FuncSpec{Name: name, RVA: found.RVA, Code: gen.Code, NativeSize: len(found.Code)})
	}
	return specs, nil
}

func packPE(exe, outPath string, stub []byte, entryOff, frameSkew int, descMagic uint32, patchKey [8]byte, verifyFn, unpackFn, scratchOff, scratchLen, bssOff, bssSize, xmmOff, tmpOff int, funcs []string, opcodeMap *vm.OpcodeMap, enc inject.EncryptFunc, arch inject.Arch, verbose bool, section, report string) *inject.Result {
	f, err := pe.Open(exe)
	must(err)
	if f.Machine != pe.MachineAMD64 && f.Machine != pe.MachineARM64 {
		fatalf("只支持 x86-64 / arm64 的 PE，该文件 Machine=0x%X", f.Machine)
	}
	fmt.Printf("[*] 目标: %s", f.Summary())

	// 按目标架构选 lifter（与 packELF 同构）：arm64 的 PE 用 AArch64 lifter，同样吃 frameSkew。
	// 此前这里只认 AMD64 并直接 fatal —— 这就是 Windows/arm64 端到端缺的那一半。
	readRVA := func(rva uint32, n int) []byte {
		off, err := f.RVAtoOffset(rva)
		if err != nil || off < 0 || off+n > len(f.Data) {
			return nil
		}
		return f.Data[off : off+n]
	}
	var lifter liftIface
	if f.Machine == pe.MachineARM64 {
		fmt.Printf("[*] 目标架构: arm64（AArch64 lifter）")
		fmt.Println()
		a64 := &arm64lift.Lifter{ImageBase: f.ImageBase, FrameSkew: uint64(frameSkew)}
		lifter = a64Adapter{a64}
	} else {
		lx := x64.NewLifter(f.ImageBase)
		lx.SetFrameSkew(int64(frameSkew))
		// SIMD：XMM 寄存器堆在 blob 的 .bss 里，符号表给出它在 blob 内的偏移；
		// 目标镜像里的 RVA = 预测的 payload RVA + 该偏移（Apply 用同一个 NextRVA 计算，是确定的）。
		//
		// **当前默认关闭**：SIMD 位搬运的语义已在参考 VM 里逐字节验证通过
		// （见 internal/lift/x64/simd_test.go），但在真实 blob 上运行会访问违例，原因未定位。
		// 与其带着崩的路径，不如保持"SIMD 一律拒绝"（fail-fast），等定位后再打开。
		if xmmOff > 0 {
			xr := f.NextRVA() + uint32(xmmOff)
			fmt.Printf("[*] XMM 寄存器堆: blob off=0x%X → 镜像 RVA=0x%X", xmmOff, xr)
			fmt.Println()
			lx.SetXMMArea(xr)
		}
		if tmpOff > 0 {
			lx.SetScratchArea(f.NextRVA() + uint32(tmpOff))
		}
		// 跳转表需要按 RVA 读镜像（PE：RVA→文件偏移）
		lx.SetImageReader(readRVA)
		lifter = lx
	}
	_ = readRVA
	specs, err := liftAll(lifter, funcs, func(n string) (*scan.Found, error) {
		return scan.FindFunction(exe, f, n)
	}, opcodeMap, verbose, func(rva uint32, n int) ([]byte, bool) { return peRvaBytes(f.Data, rva, n) }, keepSelfChecksFlag != nil && *keepSelfChecksFlag)
	must(err)

	// 原镜像整体加密：默认对 x86-64 的 EXE 开启；不支持/不合适的情形**跳过并说明**，
	// 绝不 fatalf —— 它是默认开的功能，不能把 ARM64 或 DLL 这类目标直接卡死。
	var imgSecs []inject.ImgSection
	var imgTLS []uint64
	var tlsDirCopy []byte
	var loadCfgCopy []byte
	imgSkip := ""
	switch {
	case !encImageEnabled:
		imgSkip = "已用 -no-enc-image 关闭"
	case imgAEAD == nil:
		imgSkip = "-no-encrypt（没有主密钥，无法验签/解密）"
	case f.Machine != pe.MachineAMD64 && f.Machine != pe.MachineARM64:
		imgSkip = "只支持 x86-64 / arm64 的 PE"
	case f.Characteristics&0x2000 != 0 && !encImageDLLEnabled:
		imgSkip = "目标是 DLL（已用 -no-enc-image-dll 关闭）"
	}
	if imgSkip == "" {
		// 候选节 -> 保护标志（bit0 执行 / bit1 可写）。数据目录守卫统一把关：
		// 除 TLS 目录（会被原样搬进 payload 并重指）之外，任何"加载器在入口点之前要读/要写"的
		// 目录落在候选节里，这一节就跳过 —— 不同链接器会把 .idata/.rdata/.data 合并，不能假设 mingw 的布局。
		// 候选集可由 -enc-image-sections 覆盖（默认三节）；flags: bit0 执行 / bit1 可写。
		allCand := []struct {
			name  string
			flags uint32
		}{
			{".text", 1},
			{".rdata", 0},
			{".data", 2},
		}
		cand := allCand
		if encImageSectionList != "" {
			cand = nil
			for _, want := range strings.Split(encImageSectionList, ",") {
				want = strings.TrimSpace(want)
				for _, c := range allCand {
					if c.name == want {
						cand = append(cand, c)
					}
				}
			}
		}
		for _, c := range cand {
			for _, s := range f.Sections {
				if s.Name != c.name || s.SizeOfRawData == 0 {
					continue
				}
				if why := resolveLoaderConflict(&loadCfgCopy, f, s); why != "" {
					fmt.Printf("[*] 原镜像整体加密：跳过 %s（%s）", s.Name, why)
					fmt.Println()
					continue
				}
				imgSecs = append(imgSecs, inject.ImgSection{RVA: s.VirtualAddress, Size: s.SizeOfRawData, Flags: c.flags})
			}
		}
		if len(imgSecs) == 0 && imgSkip == "" {
			imgSkip = "没有可安全加密的节"
		}
		if imgSkip == "" && len(imgSecs) == 0 {
			imgSkip = "找不到 .text"
		}
	}
	if imgSkip != "" {
		fmt.Printf("[*] 原镜像整体加密：跳过（%s）", imgSkip)
		fmt.Println()
		imgSecs = nil
	} else {
		if cbs := tlsCallbacks(f); len(cbs) > 0 {
			fmt.Printf("[*] 目标有 %d 个 TLS 回调：把自己的自解密回调插到数组最前面", len(cbs))
			fmt.Println()
			imgTLS = cbs
		}
		for _, s := range imgSecs {
			fmt.Printf("[*] 原镜像整体加密：%s RVA=0x%X size=0x%X（入口自解密）", sectionNameOfRVA(f, s.RVA), s.RVA, s.Size)
			fmt.Println()
		}
		// TLS 目录如果落在被加密的节里，加载器会在我们之前读它 —— 搬到 payload 并把数据目录指过来。
		if dir := tlsDirectoryRVA(f); dir != 0 {
			for _, s := range imgSecs {
				if s.RVA <= dir && dir < s.RVA+s.Size {
					to, err := f.RVAtoOffset(dir)
					if err != nil || to < 0 || to+40 > len(f.Data) {
						fatalf("TLS 目录（RVA 0x%X）读不出来，无法整体加密 %s", dir, sectionNameOfRVA(f, dir))
					}
					tlsDirCopy = append([]byte(nil), f.Data[to:to+40]...)
					fmt.Printf("[*] TLS 目录在 %s 里：搬到 payload（加载器在入口点之前要读它）", sectionNameOfRVA(f, dir))
					fmt.Println()
				}
			}
		}
	}
	entryRVA, _ := inject.EntryRVA(f)
	res, err := inject.Apply(f, inject.Options{SectionName: section, SectionNameB: sectionNames[1], SectionNameC: sectionNames[2], Stub: stub, StubEntry: entryOff, Funcs: specs, Encrypt: enc, Arch: arch,
		DescMagic: descMagic, PatchKey: patchKey, Verbose: verbose, ScratchOff: scratchOff, ScratchLen: scratchLen, BSSOff: bssOff, BSSSize: bssSize,
		ImgSections: imgSecs, ImageBase: f.ImageBase, UnpackFn: unpackFn, ImgTlsCallbacks: imgTLS, TlsDirCopy: tlsDirCopy, LoadCfgCopy: loadCfgCopy,
		Wipe:      wipeEnabled,
		EntryHook: patchKey != ([8]byte{}) && verifyFn >= 0 && entryRVA != 0,
		VerifyFn:  verifyFn,
		EntryRVA:  entryRVA})
	must(err)
	if len(imgSecs) > 0 {
		if imgAEAD == nil {
			fatalf("-enc-image 需要主密钥（不能与 -no-encrypt 同时用）")
		}
		if err := encryptImageSections(f, res, imgAEAD); err != nil {
			fatalf("原镜像加密失败: %v", err)
		}
		clearDynamicBase(f)
		stripRelocations(f)
		tlsDir := tlsDirectoryRVA(f)
		if len(loadCfgCopy) > 0 && res.LoadCfgRVA != 0 {
			if err := setLoadConfigDirectoryRVA(f, res.LoadCfgRVA); err != nil {
				fatalf("重指 LOAD_CONFIG 数据目录失败: %v", err)
			}
			fmt.Printf("[*] LOAD_CONFIG 数据目录已重指到 payload RVA=0x%X", res.LoadCfgRVA)
			fmt.Println()
		}
		if len(tlsDirCopy) > 0 && res.TlsDirRVA != 0 {
			if err := setTLSDirectoryRVA(f, res.TlsDirRVA); err != nil {
				fatalf("重指 TLS 数据目录失败: %v", err)
			}
			tlsDir = res.TlsDirRVA
		}
		if res.ImgTlsArrayRVA != 0 {
			if err := setTLSCallbacks(f, tlsDir, f.ImageBase+uint64(res.ImgTlsArrayRVA)); err != nil {
				fatalf("改写 TLS 回调数组失败: %v", err)
			}
		}
		fmt.Println("[*] 原镜像 .text 已原地加密，并清除 DYNAMIC_BASE（加载器因此不做重定位）")
	}
	must(f.Save(outPath))
	fmt.Printf("[*] 新节 %s: RVA=0x%X size=0x%X | vm_entry RVA=0x%X",
		section, res.SectionRVA, res.SectionSize, res.StubEntryRVA)
	fmt.Println()
	if err := inject.WriteReport(reportOrDevNull(report), res); err != nil {
		_ = err
	}
	return res
}

func packELF(exe, outPath string, stub []byte, entryOff, frameSkew int, descMagic uint32, patchKey [8]byte, verifyFn, unpackFn, scratchOff, scratchLen, bssOff, bssSize, xmmOff, tmpOff int, funcs []string, opcodeMap *vm.OpcodeMap, enc inject.EncryptFunc, arch inject.Arch, verbose bool, report string) *inject.Result {
	f, err := elfload.Open(exe)
	must(err)
	imageBase := f.ImageBase()
	fmt.Printf("[*] 目标: %s", f.Summary())
	fmt.Println()

	// 按目标架构选 lifter：x86-64 走原来的路径，AArch64 走自己的 lifter（同样吃 frameSkew）。
	var lifter liftIface
	if f.Machine == elfload.EM_AARCH64 {
		fmt.Printf("[*] 目标架构: arm64（AArch64 lifter）")
		fmt.Println()
		a64 := &arm64lift.Lifter{ImageBase: imageBase, FrameSkew: uint64(frameSkew)}
		lifter = a64Adapter{a64}
	} else {
		lx := x64.NewLifter(imageBase)
		lx.SetFrameSkew(int64(frameSkew))
		// SIMD：XMM 寄存器堆同上（ELF 里 payload 的 VA 由 NextVA 决定，也是确定的）
		if xmmOff > 0 {
			lx.SetXMMArea(uint32(f.NextVA()-imageBase) + uint32(xmmOff))
		}
		if tmpOff > 0 {
			lx.SetScratchArea(uint32(f.NextVA()-imageBase) + uint32(tmpOff))
		}
		// 跳转表需要按 RVA 读镜像（ELF：RVA + imageBase → VA）
		lx.SetImageReader(func(rva uint32, n int) []byte {
			b, err := f.ReadVA(imageBase+uint64(rva), n)
			if err != nil {
				return nil
			}
			return b
		})
		lifter = lx
	}
	specs, err := liftAll(lifter, funcs, func(n string) (*scan.Found, error) {
		return scan.FindFunctionELF(exe, imageBase, n)
	}, opcodeMap, verbose, nil, keepSelfChecksFlag != nil && *keepSelfChecksFlag)
	must(err)

	entryRVA := uint32(0)
	if f.Entry > imageBase && f.Entry-imageBase <= 0xFFFFFFFF {
		entryRVA = uint32(f.Entry - imageBase)
	}
	// ELF 整体加密（默认关）：只做 ET_EXEC —— PIE/ET_DYN 会被 ld.so 重定位写进密文，
	// 解密出来就是垃圾（和 DLL 那边同一个道理），需要单独的方案。
	var imgSecs []inject.ImgSection
	if encImageELFEnabled {
		switch {
		case f.Machine != elfload.EM_X86_64 && f.Machine != elfload.EM_AARCH64:
			fmt.Println("[*] ELF 整体加密：跳过（只支持 x86-64 与 aarch64）")
		case f.EType != 2:
			fmt.Println("[*] ELF 整体加密：跳过（只支持 ET_EXEC；PIE 会被重定位破坏密文）")
		case imgAEAD == nil:
			fmt.Println("[*] ELF 整体加密：跳过（没有主密钥）")
		default:
			for _, p := range f.Progs {
				if p.Type != 1 || p.Flags&elfload.PF_X == 0 || p.Filesz == 0 {
					continue
				}
				// 第一个 LOAD 段往往**从文件偏移 0 开始**（Go 的 ET_EXEC 就是），
				// 也就是说 ELF 头与程序头表都在这个段里 —— 加载器要从**文件**读它们，
				// 绝不能加密（CI 第一次跑就抓到了：e_entry 被加密后读出来是垃圾）。
				// 跳过 [0, align_up(程序头表末尾))，第 0 页保持明文。
				skip := uint64(f.Phoff) + uint64(f.Phnum)*uint64(f.Phentsize)
				skip = (skip + 0xFFF) &^ 0xFFF
				if skip < 0x1000 {
					skip = 0x1000
				}
				if p.Filesz <= skip {
					fmt.Println("[*] ELF 整体加密：跳过（可执行段全落在文件头那一页里）")
					break
				}
				imgSecs = append(imgSecs, inject.ImgSection{
					RVA:   uint32(p.Vaddr - imageBase + skip),
					Size:  uint32(p.Filesz - skip),
					Flags: 1,
				})
				fmt.Printf("[*] ELF 整体加密：PT_LOAD(X) va=0x%X 跳过头部 %d 字节，加密 %d 字节（入口自解密）", p.Vaddr, skip, p.Filesz-skip)
				fmt.Println()
				break
			}
			// 只读数据节也一起加密（PE 侧的 .rdata/.data 早就做了，ELF 侧要对齐）：
			//   .rodata    -- 字符串/常量表（"文件里读到程序在干什么"的最大来源）
			//   .gopclntab -- Go 运行期元数据（同样只在入口点之后才被读）
			// 动态链接器/初始化器在入口点之前要用的节一律排除（见 elfLoaderBlockedNames）。
			for _, sc := range elfSections(elfRawBytes(exe)) {
				if !elfDataCandidates[sc.name] || elfLoaderBlockedNames[sc.name] || sc.size == 0 {
					continue
				}
				if sc.addr < imageBase {
					continue
				}
				overlap := false
				for _, s0 := range imgSecs {
					lo, hi := imageBase+uint64(s0.RVA), imageBase+uint64(s0.RVA+s0.Size)
					if sc.addr < hi && sc.addr+sc.size > lo {
						overlap = true
						break
					}
				}
				if overlap {
					continue
				}
				imgSecs = append(imgSecs, inject.ImgSection{RVA: uint32(sc.addr - imageBase), Size: uint32(sc.size), Flags: 0})
				fmt.Printf("[*] ELF 整体加密：%s RVA=0x%X size=0x%X（只读数据）", sc.name, sc.addr-imageBase, sc.size)
				fmt.Println()
			}
			if len(imgSecs) == 0 {
				fmt.Println("[*] ELF 整体加密：跳过（找不到可加密的可执行段）")
			}
		}
	}
	res, err := inject.ApplyELF(f, inject.Options{SectionName: ".vmp", Stub: stub, StubEntry: entryOff, Funcs: specs, Encrypt: enc, Arch: arch,
		DescMagic: descMagic, PatchKey: patchKey, Verbose: verbose, BSSOff: bssOff, BSSSize: bssSize,
		ImgSections: imgSecs, ImageBase: 0, UnpackFn: unpackFn,
		Wipe:          wipeEnabled,
		EntryHook:     patchKey != ([8]byte{}) && verifyFn >= 0 && entryRVA != 0 && f.Machine == elfload.EM_X86_64,
		EntryHookSysV: true,
		VerifyFn:      verifyFn,
		EntryRVA:      entryRVA})
	must(err)
	if len(imgSecs) > 0 {
		if err := encryptImageSectionsELF(f, imageBase, res, imgAEAD); err != nil {
			fatalf("ELF 原镜像加密失败: %v", err)
		}
	}
	must(f.Save(outPath))
	fmt.Printf("[*] 新 PT_LOAD: RVA=0x%X size=0x%X | vm_entry RVA=0x%X",
		res.SectionRVA, res.SectionSize, res.StubEntryRVA)
	fmt.Println()
	return res
}

// sectionNames：本次打包实际使用的三个节名（main 里决定，packPE 里读取）。
// bytecodeLimitFlag：解释器缓存槽容量上限（从 blob 的 vm_bc_slot_size 常量读出）。
// 超限时 vm_run 会返回错误码，而调用方会把返回值当函数结果 —— 静默算错，必须在打包期拦住。
var bytecodeLimitFlag int

// bytecodeLimit 从 blob 里读 vm_bc_slot_size：它是个 const，值就写在 blob 的 .rdata 里。
func bytecodeLimit(syms map[string]int, stub []byte) int {
	off, ok := syms["vm_bc_slot_size"]
	if !ok || off+8 > len(stub) {
		return 0 // 老 blob：取不到就不检查
	}
	return int(binary.LittleEndian.Uint64(stub[off:]))
}

var sectionNames [3]string

// sectionNamesFor：用户显式给了 -section 就用它（并按老规矩 +b/+c 派生）；
// 否则生成三个**互不相关**的随机名 —— 固定/派生节名本身就是可识别特征。
func sectionNamesFor(base string) string {
	if base != "" {
		sectionNames = [3]string{base, base + "b", base + "c"}
		return base
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	mk := func() string {
		b := make([]byte, 7)
		for i := range b {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			b[i] = alphabet[n.Int64()]
		}
		return "." + string(b)
	}
	for i := 0; i < 3; i++ {
		for {
			n := mk()
			dup := false
			for j := 0; j < i; j++ {
				if sectionNames[j] == n {
					dup = true
				}
			}
			if !dup {
				sectionNames[i] = n
				break
			}
		}
	}
	return sectionNames[0]
}

// keepSelfChecksFlag：由 main 里 flag.Parse 设定，packPE/packELF 里读取。
var keepSelfChecksFlag *bool

// wipeEnabled：是否抹除被保护函数的原生机器码（-wipe，默认开）。
var wipeEnabled bool

// encImageEnabled：是否把原镜像 .text 整体加密（默认对 x86-64 EXE 开启，-no-enc-image 关闭）。
var encImageEnabled bool

// encImageSectionList：-enc-image-sections 的取值（空 = 用默认候选集）。
var encImageSectionList string

// encImageELFEnabled：是否对 ELF 也整体加密（**默认关，显式 opt-in**；只支持 ET_EXEC/x86-64）。
// 入口路径本身已在 CI 的 linux-amd64 上真机验证（run #293）；但把它切成默认开会连累
// 一条**读目标字节**的老路径：tools/verify_linux_payload 的载荷探针要从打包文件里读函数入口的
// 补丁字节来喂给被测载荷，而 .text 加密后那些字节是密文（run #294 现场：
// patch bytes=BD047B120F + 六处 missing/mismatch）。所以在"探针也改成不依赖明文"之前，
// 保持 opt-in。
var encImageELFEnabled bool

// encImageDLLEnabled：是否对 DLL 也加密（默认**开**；-no-enc-image-dll 关闭）。
// DLL 只有在"落在首选基址"时才成立：打包端已拆掉重定位表，落不下会明确失败。
var encImageDLLEnabled bool

// imgAEAD：原镜像加密用的 AEAD（与字节码同一个主密钥；-no-encrypt 时为空）。
var imgAEAD cipher.AEAD

func reportOrDevNull(p string) string { return p }

// isSecurityCookieCheck 判定目标是不是 MSVC 的 __security_check_cookie：
// 入口字节形如 48 3B 0D xx xx xx xx 75 01 C3（cmp rcx,[rip+disp] / jne +1 / ret）。
// 为什么必须识别它：它是编译器内建，调用方默认它**不修改 RAX**（实现里只有 cmp/jne/ret），
// 而我们的 CALLN 会无条件把 guest 的 RAX 覆盖成返回值 —— 实测导致被保护函数返回垃圾指针并崩溃。
// 实测的两种形态（微软 CRT）：
//
//	48 3B 0D xx xx xx xx 75 01 C3          （简单版：不等就直接跳到报告函数）
//	48 3B 0D xx xx xx xx 75 10 48 C1 C1 .. （带 cookie 解密分支）
//
// 所以判定条件放宽为：cmp rcx,[rip+disp] + 紧跟 jne，且后续 24 字节内出现 ror/rol rcx 与 ret。
func isSecurityCookieCheck(code []byte) bool {
	if len(code) < 16 {
		return false
	}
	if !(code[0] == 0x48 && code[1] == 0x3B && code[2] == 0x0D && code[7] == 0x75) {
		return false
	}
	tail := code[8:min(len(code), 32)]
	sawRot, sawRet := false, false
	for i := 0; i+2 < len(tail); i++ {
		if tail[i] == 0x48 && tail[i+1] == 0xC1 && (tail[i+2] == 0xC1 || tail[i+2] == 0xC9) {
			sawRot = true
		}
		if tail[i] == 0xC3 {
			sawRet = true
		}
	}
	return sawRot && sawRet
}

// dropRuntimeSelfChecks 在 IR 上删掉这类调用，返回删除条数。
func dropRuntimeSelfChecks(fn *ir.Func, bytesAt func(rva uint32, n int) ([]byte, bool)) int {
	out := fn.Insns[:0]
	dropped := 0
	for _, in := range fn.Insns {
		if in.Op == ir.CallN {
			if b, ok := bytesAt(uint32(in.Imm), 48); ok && isSecurityCookieCheck(b) {
				dropped++
				continue
			}
		}
		out = append(out, in)
	}
	fn.Insns = out
	return dropped
}

// peRvaBytes 取 PE 镜像里 RVA 处的 n 个字节（用于识别被调函数的入口模式）。
func peRvaBytes(d []byte, rva uint32, n int) ([]byte, bool) {
	if len(d) < 0x40 {
		return nil, false
	}
	peOff := int(binary.LittleEndian.Uint32(d[0x3C:]))
	if peOff+24 > len(d) || peOff < 0 {
		return nil, false
	}
	nsec := int(binary.LittleEndian.Uint16(d[peOff+6:]))
	optSize := int(binary.LittleEndian.Uint16(d[peOff+20:]))
	base := peOff + 24 + optSize
	for i := 0; i < nsec; i++ {
		o := base + i*40
		if o+40 > len(d) {
			break
		}
		vsize := binary.LittleEndian.Uint32(d[o+8:])
		va := binary.LittleEndian.Uint32(d[o+12:])
		rsize := binary.LittleEndian.Uint32(d[o+16:])
		roff := binary.LittleEndian.Uint32(d[o+20:])
		span := vsize
		if rsize > span {
			span = rsize
		}
		if rva >= va && rva < va+span {
			off := roff + (rva - va)
			if int(off)+n > len(d) {
				return nil, false
			}
			return d[off : int(off)+n], true
		}
	}
	return nil, false
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[!] "+format, a...)
	fmt.Fprintln(os.Stderr)
	os.Exit(1)
}

// encryptImageSections 按解密表把原镜像的节**原地**加密，并把 AEAD 标签回填进表里。
// 与 blob 里的 vm_unpack_image 逐字节对齐：nonce = rva||size||salt，AAD = rva||size，
// AEAD 的数据流从 counter=1 开始（Go 的 chacha20poly1305 正是这个约定）。
func encryptImageSections(f *pe.File, res *inject.Result, aead cipher.AEAD) error {
	off, err := f.RVAtoOffset(res.ImgTableRVA)
	if err != nil {
		return err
	}
	if off < 0 || off+res.ImgTableLen > len(f.Data) || res.ImgTableLen < 24 {
		return fmt.Errorf("解密表越界（off=0x%X len=%d）", off, res.ImgTableLen)
	}
	tbl := f.Data[off : off+res.ImgTableLen]
	salt := binary.LittleEndian.Uint32(tbl[8:])
	count := binary.LittleEndian.Uint32(tbl[12:])
	if int(24+count*32) > len(tbl) {
		return fmt.Errorf("解密表条目数 %d 超出表长 %d", count, len(tbl))
	}
	for i := uint32(0); i < count; i++ {
		e := tbl[24+i*32:]
		rva := binary.LittleEndian.Uint32(e[0:])
		size := binary.LittleEndian.Uint32(e[4:])
		so, err := f.RVAtoOffset(rva)
		if err != nil {
			return err
		}
		if so < 0 || so+int(size) > len(f.Data) {
			return fmt.Errorf("节 0x%X（%d 字节）越界", rva, size)
		}
		var nonce [12]byte
		binary.LittleEndian.PutUint32(nonce[0:], rva)
		binary.LittleEndian.PutUint32(nonce[4:], size)
		binary.LittleEndian.PutUint32(nonce[8:], salt)
		var aad [8]byte
		binary.LittleEndian.PutUint32(aad[0:], rva)
		binary.LittleEndian.PutUint32(aad[4:], size)
		sealed := aead.Seal(nil, nonce[:], f.Data[so:so+int(size)], aad[:])
		copy(f.Data[so:so+int(size)], sealed[:size])
		copy(e[16:32], sealed[size:])
	}
	return nil
}

// stripRelocations 把重定位表整个拆掉：数据目录清零 + 该节内容清零 + 置 IMAGE_FILE_RELOCS_STRIPPED。
//
// 为什么必须这么做：整体加密是在**文件字节**上做的，加载器一旦按重定位改写 .text，密文就被破坏，
// 解密出来就是垃圾。清 DYNAMIC_BASE 只挡"系统为了 ASLR 主动重定位"，挡不住强制的镜像重定位
// （Windows 的 Mandatory ASLR 对 DLL 就会这么做 —— 实测：DLL 只加密 .text 也 1114）。
// 拆掉重定位表之后，加载器**只能**落在首选基址；落不下就明确失败，而不是悄悄跑飞。
func stripRelocations(f *pe.File) {
	const relocDir = 5
	o := f.OptHeaderOffset + 112 + relocDir*8
	if o+8 <= len(f.Data) {
		rva := binary.LittleEndian.Uint32(f.Data[o:])
		binary.LittleEndian.PutUint32(f.Data[o:], 0)
		binary.LittleEndian.PutUint32(f.Data[o+4:], 0)
		if rva != 0 {
			for _, s := range f.Sections {
				if s.VirtualAddress != rva || s.SizeOfRawData == 0 {
					continue
				}
				so, err := f.RVAtoOffset(s.VirtualAddress)
				if err != nil || so < 0 || so+int(s.SizeOfRawData) > len(f.Data) {
					continue
				}
				for i := so; i < so+int(s.SizeOfRawData); i++ {
					f.Data[i] = 0
				}
			}
		}
	}
	coff := f.Lfanew + 22 // COFF Characteristics
	if coff+2 <= len(f.Data) {
		v := binary.LittleEndian.Uint16(f.Data[coff:])
		binary.LittleEndian.PutUint16(f.Data[coff:], v|0x0001) // IMAGE_FILE_RELOCS_STRIPPED
	}
}

// encryptImageSectionsELF 与 PE 版逐字节等价，只是按 ELF 的 VA 读/写。
// ImageBase 传 0 表示"运行期不强制校验基址"（ET_EXEC 下基址就是链接地址；PIE 我们不支持）。
func encryptImageSectionsELF(f *elfload.File, imageBase uint64, res *inject.Result, aead cipher.AEAD) error {
	off, err := f.VAtoOffset(imageBase + uint64(res.ImgTableRVA))
	if err != nil {
		return err
	}
	if off < 0 || off+res.ImgTableLen > len(f.Data) || res.ImgTableLen < 24 {
		return fmt.Errorf("解密表越界（off=0x%X len=%d）", off, res.ImgTableLen)
	}
	tbl := f.Data[off : off+res.ImgTableLen]
	salt := binary.LittleEndian.Uint32(tbl[8:])
	count := binary.LittleEndian.Uint32(tbl[12:])
	if int(24+count*32) > len(tbl) {
		return fmt.Errorf("解密表条目数 %d 超出表长 %d", count, len(tbl))
	}
	for i := uint32(0); i < count; i++ {
		e := tbl[24+i*32:]
		rva := binary.LittleEndian.Uint32(e[0:])
		size := binary.LittleEndian.Uint32(e[4:])
		buf, err := f.ReadVA(imageBase+uint64(rva), int(size))
		if err != nil {
			return err
		}
		var nonce [12]byte
		binary.LittleEndian.PutUint32(nonce[0:], rva)
		binary.LittleEndian.PutUint32(nonce[4:], size)
		binary.LittleEndian.PutUint32(nonce[8:], salt)
		var aad [8]byte
		binary.LittleEndian.PutUint32(aad[0:], rva)
		binary.LittleEndian.PutUint32(aad[4:], size)
		sealed := aead.Seal(nil, nonce[:], buf, aad[:])
		if err := f.WriteVA(imageBase+uint64(rva), sealed[:size]); err != nil {
			return err
		}
		copy(e[16:32], sealed[size:])
	}
	return nil
}

// clearDynamicBase 清掉 DYNAMIC_BASE：加载器因此不会重定位镜像。
// 密文是在**文件字节**上做的，一旦加载器按重定位写了 .text，解密出来的就是垃圾；
// vm_unpack_image 还会在"实际基址 != 首选基址"时直接拒绝执行（fail-fast）。
func clearDynamicBase(f *pe.File) {
	const dllCharOff = 70 // PE32+ 可选头里 DllCharacteristics 的偏移（+0x46）
	o := f.OptHeaderOffset + dllCharOff
	if o+2 > len(f.Data) {
		return
	}
	v := binary.LittleEndian.Uint16(f.Data[o:])
	binary.LittleEndian.PutUint16(f.Data[o:], v&^uint16(0x40))
}

// tlsCallbacks 读出目标原有的 TLS 回调 VA 列表（没有就返回 nil）。
// 注意：仅仅存在 TLS 目录是无害的（mingw 的 exe 几乎都有），关键是**回调**——它们在
// 入口点之前运行，那时 .text 还是密文，所以我们必须把自己的回调插到数组最前面。
func tlsCallbacks(f *pe.File) []uint64 {
	o := f.OptHeaderOffset + 112 + 9*8
	if o+8 > len(f.Data) {
		return nil
	}
	dirRVA := binary.LittleEndian.Uint32(f.Data[o:])
	if dirRVA == 0 {
		return nil
	}
	to, err := f.RVAtoOffset(dirRVA)
	if err != nil || to < 0 || to+40 > len(f.Data) {
		return nil
	}
	cbVA := binary.LittleEndian.Uint64(f.Data[to+24:]) // IMAGE_TLS_DIRECTORY64.AddressOfCallBacks
	if cbVA == 0 || cbVA < f.ImageBase {
		return nil
	}
	co, err := f.RVAtoOffset(uint32(cbVA - f.ImageBase))
	if err != nil || co < 0 {
		return nil
	}
	var out []uint64
	for i := 0; i < 64 && co+i*8+8 <= len(f.Data); i++ {
		v := binary.LittleEndian.Uint64(f.Data[co+i*8:])
		if v == 0 {
			break
		}
		out = append(out, v)
	}
	return out
}

// setTLSCallbacks 把 TLS 目录里的 AddressOfCallBacks 指向 payload 里的新数组
// （数组第 0 项是我们的自解密 thunk，后面接原有的回调）。
func setTLSCallbacks(f *pe.File, dirRVA uint32, va uint64) error {
	if dirRVA == 0 {
		return fmt.Errorf("没有 TLS 目录")
	}
	to, err := f.RVAtoOffset(dirRVA)
	if err != nil {
		return err
	}
	if to < 0 || to+32 > len(f.Data) {
		return fmt.Errorf("TLS 目录越界")
	}
	binary.LittleEndian.PutUint64(f.Data[to+24:], va)
	return nil
}

// elfRawBytes 读原始镜像文件：挑候选节要按**原始布局**，不能用注入流程里的缓冲区。
func elfRawBytes(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

// elfDataCandidates：ELF 侧额外纳入整体加密的"只读数据"节。
var elfDataCandidates = map[string]bool{".rodata": true, ".gopclntab": true}

// elfLoaderBlockedNames：这些节在**入口点之前**就被动态链接器/初始化器读或调用，绝不能加密。
// （当前候选集里本来不含它们，这里显式列出是为了"以后加候选时不会误踩"。）
var elfLoaderBlockedNames = map[string]bool{
	".dynamic": true, ".dynsym": true, ".dynstr": true, ".hash": true,
	".gnu.hash": true, ".gnu.version": true, ".gnu.version_d": true, ".gnu.version_r": true,
	".rela.dyn": true, ".rela.plt": true, ".rel.dyn": true, ".rel.plt": true,
	".got": true, ".got.plt": true, ".plt": true, ".interp": true,
	".init_array": true, ".fini_array": true, ".init": true, ".fini": true,
	".ctors": true, ".dtors": true,
}

// elfSection 是 ELF 侧加密候选需要的最小信息。
type elfSection struct {
	name string
	addr uint64
	size uint64
}

// elfSections 只读节头表里的名字/地址/大小（ELF64 节头：name@0 type@4 flags@8 addr@16 off@24 size@32）。
func elfSections(d []byte) []elfSection {
	// 必须喂**原始镜像文件**的字节：f.Data 是注入流程改写过的缓冲区。
	// 第一版从这里读节名字符串表 -> 名字是垃圾 -> 候选节一个都没进去（实测暴露面 0 变化）；
	// 第二版连节头表都读不到，直接返回 nil。
	if len(d) < 0x40 {
		return nil
	}
	shoff := binary.LittleEndian.Uint64(d[0x28:])
	shentsize := binary.LittleEndian.Uint16(d[0x3A:])
	shnum := binary.LittleEndian.Uint16(d[0x3C:])
	shstrndx := binary.LittleEndian.Uint16(d[0x3E:])
	if shoff == 0 || shnum == 0 || shentsize == 0 || int(shstrndx) >= int(shnum) {
		return nil
	}
	if int(shoff)+int(shnum)*int(shentsize) > len(d) {
		return nil
	}
	// 注意第五个返回值是 sh_offset：section name 字符串表的**文件偏移**要用它。
	// 第一版这里只取了 (name, addr, size, type)，于是 strOff 拿到的是 shstrtab 的 sh_name（通常是 0），
	// 解析出来的节名全是空串 -> 候选集一个都没命中（实测"暴露面 0 变化"）。
	get := func(i int) (uint32, uint64, uint64, uint64, uint32) {
		o := int(shoff) + i*int(shentsize)
		return binary.LittleEndian.Uint32(d[o:]), binary.LittleEndian.Uint64(d[o+16:]),
			binary.LittleEndian.Uint64(d[o+24:]), binary.LittleEndian.Uint64(d[o+32:]),
			binary.LittleEndian.Uint32(d[o+4:])
	}
	_, _, strOff, strSize, _ := get(int(shstrndx))
	var out []elfSection
	for i := 0; i < int(shnum); i++ {
		nameOff, addr, _, size, typ := get(i)
		if typ == 8 /* SHT_NOBITS */ || size == 0 || nameOff >= uint32(strSize) {
			continue
		}
		off := int(strOff) + int(nameOff)
		if off >= len(d) {
			continue
		}
		e := off
		for e < len(d) && d[e] != 0 {
			e++
		}
		out = append(out, elfSection{name: string(d[off:e]), addr: addr, size: size})
	}
	return out
}

// loaderDirConflict 返回"加载器在入口点之前要用、且落在该节里"的数据目录名；空串 = 可以整节加密。
// TLS 目录（索引 9）不在此列：它会被原样搬进 payload 并把数据目录指过来（见 packPE 里的搬迁）。
// SECURITY 项存的是文件偏移而非 RVA、DEBUG 只有调试器读，两者都不算冲突。
func loaderDirConflict(f *pe.File, s pe.Section) string {
	dirs := []struct {
		idx  int
		name string
	}{
		{1, "IMPORT"}, {2, "RESOURCE"}, {3, "EXCEPTION"}, {5, "BASERELOC"},
		{10, "LOADCONFIG"}, {11, "BOUNDIMPORT"}, {12, "IAT"}, {13, "DELAYIMPORT"}, {14, "CLR"},
	}
	end := s.VirtualAddress + s.SizeOfRawData
	for _, d := range dirs {
		o := f.OptHeaderOffset + 112 + d.idx*8
		if o+8 > len(f.Data) {
			continue
		}
		rva := binary.LittleEndian.Uint32(f.Data[o:])
		size := binary.LittleEndian.Uint32(f.Data[o+4:])
		if rva == 0 {
			continue
		}
		if rva < end && rva+size > s.VirtualAddress {
			return d.name + " 目录落在这一节里（加载器在入口点之前要用）"
		}
	}
	return ""
}

// resolveLoaderConflict 判断"这一节能不能整体加密"。返回空串=可以。
// LOAD_CONFIG（索引 10）是唯一可以就地解决的冲突：它只是"加载器在入口点之前读一次"的结构，
// 把副本搬进 payload、再把数据目录指过去，这一节就能加密了（与 TLS 目录同一套做法）。
func resolveLoaderConflict(loadCfgCopy *[]byte, f *pe.File, s pe.Section) string {
	why := loaderDirConflict(f, s)
	if why == "" || !strings.HasPrefix(why, "LOADCONFIG") || *loadCfgCopy != nil {
		return why
	}
	rva, size := loadConfigDirRVASize(f)
	if rva == 0 || size < 4 {
		return why
	}
	to, err := f.RVAtoOffset(rva)
	if err != nil || to < 0 || to+int(size) > len(f.Data) {
		return why
	}
	*loadCfgCopy = append([]byte(nil), f.Data[to:to+int(size)]...)
	fmt.Printf("[*] LOAD_CONFIG 目录（%d 字节）落在 %s 里：搬到 payload，%s 一并整体加密", size, s.Name, s.Name)
	fmt.Println()
	return ""
}

// loadConfigDirRVASize 返回 LOAD_CONFIG 数据目录（索引 10）的 (RVA, size)。
func loadConfigDirRVASize(f *pe.File) (uint32, uint32) {
	o := f.OptHeaderOffset + 112 + 10*8
	if o+8 > len(f.Data) {
		return 0, 0
	}
	return binary.LittleEndian.Uint32(f.Data[o:]), binary.LittleEndian.Uint32(f.Data[o+4:])
}

// setLoadConfigDirectoryRVA 把 LOAD_CONFIG 数据目录重新指向 payload 里的那份副本。
func setLoadConfigDirectoryRVA(f *pe.File, rva uint32) error {
	o := f.OptHeaderOffset + 112 + 10*8
	if o+8 > len(f.Data) {
		return fmt.Errorf("没有 LOAD_CONFIG 目录项")
	}
	binary.LittleEndian.PutUint32(f.Data[o:], rva)
	return nil
}

// tlsDirectoryRVA 返回 TLS 数据目录指向的 RVA（0 = 没有）。
func tlsDirectoryRVA(f *pe.File) uint32 {
	o := f.OptHeaderOffset + 112 + 9*8
	if o+8 > len(f.Data) {
		return 0
	}
	return binary.LittleEndian.Uint32(f.Data[o:])
}

// setTLSDirectoryRVA 把 TLS 数据目录重新指向 payload 里的那份副本。
func setTLSDirectoryRVA(f *pe.File, rva uint32) error {
	o := f.OptHeaderOffset + 112 + 9*8
	if o+8 > len(f.Data) {
		return fmt.Errorf("没有 TLS 目录项")
	}
	binary.LittleEndian.PutUint32(f.Data[o:], rva)
	return nil
}

// sectionNameOfRVA 只是为了日志说清楚"哪个节"。
func sectionNameOfRVA(f *pe.File, rva uint32) string {
	for _, s := range f.Sections {
		span := s.VirtualSize
		if s.SizeOfRawData > span {
			span = s.SizeOfRawData
		}
		if s.VirtualAddress <= rva && rva < s.VirtualAddress+span {
			return s.Name
		}
	}
	return "?"
}

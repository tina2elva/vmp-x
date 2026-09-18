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
	dumpBytecode := flag.String("dumpbytecode", "", "把每个函数的**明文**字节码转储到该目录（诊断用）")
	mapPath := flag.String("map", "", "MSVC MAP 文件：目标没有 COFF 符号表时用它按名字定位函数")
	reportPath := flag.String("report", "", "注入报告 JSON 路径（可选）")
	section := flag.String("section", "", "注入节名（仅 PE；留空则每次构建随机生成三个互不相关的名字）")
	verbose := flag.Bool("v", false, "打印 IR 详情")
	keepSelfChecksFlag = flag.Bool("keep-selfchecks", false, "保留运行期自校验调用（默认丢弃；仅用于对照实验）")
	var funcs multiFlag
	flag.Var(&funcs, "func", "要保护的函数名（可重复）")
	flag.Parse()

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
		res = packELF(*exe, outPath, stub, entryOff, man.FrameSkew, man.DescMagic, patchKey, verifyFnELF, scratchOff, scratchLen, man.BSSOff, man.BSSSize, man.Symbols["vm_xmm"], man.Symbols["vm_tmp"], funcs, opcodeMap, enc, arch, *verbose, *reportPath)
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
		res = packPE(*exe, outPath, stub, entryOff, man.FrameSkew, man.DescMagic, patchKey, verifyFn, scratchOff, scratchLen, man.BSSOff, man.BSSSize, man.Symbols["vm_xmm"], man.Symbols["vm_tmp"], funcs, opcodeMap, enc, arch, *verbose, *section, *reportPath)
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
				fmt.Printf("      IR[%02d] %-8s w=%-2d kind=%d dst=%d a=%d b=%d imm=0x%X disp=%d target=%d",
					i, in.Op.String(), in.Width, in.Kind, in.Dst, in.A, in.B, in.Imm, in.Disp, in.Target)
				fmt.Println()
			}
		}
		specs = append(specs, inject.FuncSpec{Name: name, RVA: found.RVA, Code: gen.Code})
	}
	return specs, nil
}

func packPE(exe, outPath string, stub []byte, entryOff, frameSkew int, descMagic uint32, patchKey [8]byte, verifyFn, scratchOff, scratchLen, bssOff, bssSize, xmmOff, tmpOff int, funcs []string, opcodeMap *vm.OpcodeMap, enc inject.EncryptFunc, arch inject.Arch, verbose bool, section, report string) *inject.Result {
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

	entryRVA, _ := inject.EntryRVA(f)
	res, err := inject.Apply(f, inject.Options{SectionName: section, SectionNameB: sectionNames[1], SectionNameC: sectionNames[2], Stub: stub, StubEntry: entryOff, Funcs: specs, Encrypt: enc, Arch: arch,
		DescMagic: descMagic, PatchKey: patchKey, Verbose: verbose, ScratchOff: scratchOff, ScratchLen: scratchLen, BSSOff: bssOff, BSSSize: bssSize,
		EntryHook: patchKey != ([8]byte{}) && verifyFn >= 0 && entryRVA != 0,
		VerifyFn:  verifyFn,
		EntryRVA:  entryRVA})
	must(err)
	must(f.Save(outPath))
	fmt.Printf("[*] 新节 %s: RVA=0x%X size=0x%X | vm_entry RVA=0x%X",
		section, res.SectionRVA, res.SectionSize, res.StubEntryRVA)
	fmt.Println()
	if err := inject.WriteReport(reportOrDevNull(report), res); err != nil {
		_ = err
	}
	return res
}

func packELF(exe, outPath string, stub []byte, entryOff, frameSkew int, descMagic uint32, patchKey [8]byte, verifyFn, scratchOff, scratchLen, bssOff, bssSize, xmmOff, tmpOff int, funcs []string, opcodeMap *vm.OpcodeMap, enc inject.EncryptFunc, arch inject.Arch, verbose bool, report string) *inject.Result {
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
	res, err := inject.ApplyELF(f, inject.Options{SectionName: ".vmp", Stub: stub, StubEntry: entryOff, Funcs: specs, Encrypt: enc, Arch: arch,
		DescMagic: descMagic, PatchKey: patchKey, Verbose: verbose, BSSOff: bssOff, BSSSize: bssSize,
		EntryHook:     patchKey != ([8]byte{}) && verifyFn >= 0 && entryRVA != 0 && f.Machine == elfload.EM_X86_64,
		EntryHookSysV: true,
		VerifyFn:      verifyFn,
		EntryRVA:      entryRVA})
	must(err)
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

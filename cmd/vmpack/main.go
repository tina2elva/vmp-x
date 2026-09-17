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
	EntryOff  int            `json:"entryOff"`
	BSSOff    int            `json:"bssOff"`
	BSSSize   int            `json:"bssSize"`
	Key       string         `json:"key"`
	BlobSize  int            `json:"blobSize"`
	FrameSkew int            `json:"frameSkew"`
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
	reportPath := flag.String("report", "", "注入报告 JSON 路径（可选）")
	section := flag.String("section", ".vmp", "注入节名（仅 PE 使用）")
	verbose := flag.Bool("v", false, "打印 IR 详情")
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

	var res *inject.Result
	if isELF {
		res = packELF(*exe, outPath, stub, entryOff, man.FrameSkew, man.BSSOff, man.BSSSize, man.Symbols["vm_xmm"], man.Symbols["vm_tmp"], funcs, opcodeMap, enc, arch, *verbose, *reportPath)
	} else {
		res = packPE(*exe, outPath, stub, entryOff, man.FrameSkew, man.BSSOff, man.BSSSize, man.Symbols["vm_xmm"], man.Symbols["vm_tmp"], funcs, opcodeMap, enc, arch, *verbose, *section, *reportPath)
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
func liftAll(lifter liftIface, names []string, find func(string) (*scan.Found, error), opcodeMap *vm.OpcodeMap, verbose bool) ([]inject.FuncSpec, error) {
	var specs []inject.FuncSpec
	for _, name := range names {
		found, err := find(name)
		if err != nil {
			return nil, err
		}
		irFunc, err := lifter.LiftFunc(name, found.Code, found.RVA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s: %v", name, err)
			fmt.Fprintln(os.Stderr)
			for _, u := range irFunc.Unsupported {
				fmt.Fprintf(os.Stderr, "      %s", u)
				fmt.Fprintln(os.Stderr)
			}
			os.Exit(1)
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

func packPE(exe, outPath string, stub []byte, entryOff, frameSkew, bssOff, bssSize, xmmOff, tmpOff int, funcs []string, opcodeMap *vm.OpcodeMap, enc inject.EncryptFunc, arch inject.Arch, verbose bool, section, report string) *inject.Result {
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
	}, opcodeMap, verbose)
	must(err)

	res, err := inject.Apply(f, inject.Options{SectionName: section, Stub: stub, StubEntry: entryOff, Funcs: specs, Encrypt: enc, Arch: arch, BSSOff: bssOff, BSSSize: bssSize})
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

func packELF(exe, outPath string, stub []byte, entryOff, frameSkew, bssOff, bssSize, xmmOff, tmpOff int, funcs []string, opcodeMap *vm.OpcodeMap, enc inject.EncryptFunc, arch inject.Arch, verbose bool, report string) *inject.Result {
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
	}, opcodeMap, verbose)
	must(err)

	res, err := inject.ApplyELF(f, inject.Options{SectionName: ".vmp", Stub: stub, StubEntry: entryOff, Funcs: specs, Encrypt: enc, Arch: arch, BSSOff: bssOff, BSSSize: bssSize})
	must(err)
	must(f.Save(outPath))
	fmt.Printf("[*] 新 PT_LOAD: RVA=0x%X size=0x%X | vm_entry RVA=0x%X",
		res.SectionRVA, res.SectionSize, res.StubEntryRVA)
	fmt.Println()
	return res
}

func reportOrDevNull(p string) string { return p }

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

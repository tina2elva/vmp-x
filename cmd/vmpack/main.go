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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vmpx/vmp-x/internal/cred"
	arm64dec "github.com/vmpx/vmp-x/internal/decode/arm64"
	x64dec "github.com/vmpx/vmp-x/internal/decode/x64"
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
	EntryOff    int    `json:"entryOff"`
	BSSOff      int    `json:"bssOff"`
	BSSSize     int    `json:"bssSize"`
	Key         string `json:"key"`
	KeyExternal bool   `json:"keyExternal"` // 1b：外置密钥模式（运行期强制只在该模式的 blob 里编入）
	BlobSize    int    `json:"blobSize"`
	FrameSkew   int    `json:"frameSkew"`
	// DescMagic：blob 期望的描述符魔数（现在**每次构建都随机**，见 vmpbuild）。
	DescMagic uint32 `json:"descMagic"`
	// FieldMaskSalt：描述符/表的字段混淆掩码种子（见 internal/inject/fields.go）。
	FieldMaskSalt uint32         `json:"fieldMaskSalt"`
	Symbols       map[string]int `json:"symbols"`
	OpcodeMap     map[string]int `json:"opcodeMap"` // 本 blob 的操作码编码（M2 起每 blob 随机）
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
	stripRelocs := flag.Bool("strip-relocs", false, "退回旧行为：拆掉重定位表 + 清 DYNAMIC_BASE（放弃 ASLR）。默认**保留**，运行期按「先减回去→解密→再加回来」处理")
	flag.BoolVar(&encImageELFData, "enc-image-elf-data", false, "ELF 侧把 .rodata/.gopclntab 也纳入整体加密（实验：CI 上 aarch64 会 SIGSEGV，默认关）")
	noEncImageELF := flag.Bool("no-enc-image-elf", false, "对 ET_EXEC 的 ELF 关闭原镜像整体加密（默认开；探针已改为合成补丁字节，不再依赖明文）")
	credFlag := flag.String("cred", "", "构建凭据路径（默认 $VMPX_CRED 或工具同目录 vmpx.cred）；仅当工具烘焙了厂商根公钥时才校验")
	vendorFlag := flag.String("vendor", "", "本次构建声明的 vendorID；工具授权开启时会强制与凭据里的一致")
	verify := flag.Bool("verify", false, "自检：跑一遍原始与受保护产物并比对输出，不一致就**删除产物**并失败退出")
	verifyArgs := flag.String("verify-args", "", "自检运行时传给产物的参数（空格分隔）")
	verifyFilter := flag.String("verify-filter", "", "自检比对前丢掉匹配该正则的行（例如地址行 '^\\['）")
	verifyTimeout := flag.Int("verify-timeout", 30, "自检单次运行的超时（秒）")
	licVendor := flag.String("license-vendor", "", "运行期强制：烘进产物的 vendorID（需 -key-external 构建的 blob）")
	licProduct := flag.String("license-product", "", "运行期强制：该产物代表哪个产品（productID）")
	licPub := flag.String("license-pub", "", "运行期强制：授权签发者的 ECDSA P-256 公钥（64 字节 X||Y 的 hex，或 .pub 文件）")
	dongleKey := flag.String("dongle-key", "", "主密钥来自 Sentinel 加密狗：<fileID>:<offset>（严格模式：不回退文件/环境变量）")
	dongleVC := flag.String("dongle-vendor-code", "", "Sentinel vendor code（hasp_login 用）")
	dongleFeat := flag.Uint("dongle-feature", 0, "Sentinel feature id（hasp_login 用）")
	dongleDLL := flag.String("dongle-dll", "", "Sentinel 运行时 DLL 名（默认 hasp_windows.dll）")
	dongleFake := flag.String("dongle-fake-file", "", "测试用：假狗文件（kind=3；路径需为 \\??\\D:\\... 形式）")
	licDongle := flag.Uint("license-dongle", 0, "运行期授权改为**问狗**：给出该产品的 feature id（kind=2；不再读 .vmplic.bin）")
	dumpBytecode := flag.String("dumpbytecode", "", "把每个函数的**明文**字节码转储到该目录（诊断用）")
	mapPath := flag.String("map", "", "MSVC MAP 文件：目标没有 COFF 符号表时用它按名字定位函数")
	reportPath := flag.String("report", "", "注入报告 JSON 路径（可选）")
	section := flag.String("section", "", "注入节名（仅 PE；留空则每次构建随机生成三个互不相关的名字）")
	verbose := flag.Bool("v", false, "打印 IR 详情")
	keepSelfChecksFlag = flag.Bool("keep-selfchecks", false, "保留运行期自校验调用（默认丢弃；仅用于对照实验）")
	var funcs multiFlag
	flag.Var(&funcs, "func", "要保护的函数名（可重复）")
	flag.Parse()
	// 工具授权（docs/STRENGTH.md 4.4-1）：只有工具**烘焙了厂商根公钥**时才校验（发布构建），
	// 开发构建留空 => 关闭校验，现有 CI/gates 不受影响。
	if err := cred.Require(*credFlag, *vendorFlag); err != nil {
		fmt.Fprintf(os.Stderr, "[!] 工具授权校验失败: %v\n", err)
		os.Exit(8)
	}
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
	if *dongleKey != "" || *dongleFake != "" {
		off, ok := man.Symbols["vm_key_src"]
		if !ok {
			fatalf("该 blob 里没有 vm_key_src 符号（只有 -key-external 构建的 blob 才有 Sentinel 后端）")
		}
		if !man.KeyExternal {
			fatalf("-dongle-* 需要 -key-external 构建出来的 blob")
		}
		if off < 0 || off+280 > len(stub) {
			fatalf("vm_key_src 偏移 0x%X 越界", off)
		}
		putStr := func(at int, s string, cap int) {
			if len(s) >= cap {
				fatalf("字段太长（%d >= %d）: %s", len(s), cap, s)
			}
			for i := 0; i < cap; i++ {
				stub[off+at+i] = 0
			}
			copy(stub[off+at:off+at+cap], s)
		}
		binary.LittleEndian.PutUint32(stub[off+16:], 32) // length：主密钥固定 32 字节
		if *dongleFake != "" {
			binary.LittleEndian.PutUint32(stub[off+0:], 3)
			putStr(152, *dongleFake, 128)
			fmt.Printf("[*] 主密钥来源：假狗文件（kind=3）%s\n", *dongleFake)
		} else {
			parts := strings.Split(*dongleKey, ":")
			if len(parts) != 2 {
				fatalf("-dongle-key 形式应为 <fileID>:<offset>")
			}
			fid, e1 := strconv.ParseUint(parts[0], 10, 32)
			ofs, e2 := strconv.ParseUint(parts[1], 10, 32)
			if e1 != nil || e2 != nil {
				fatalf("-dongle-key 的两个数字解析失败")
			}
			binary.LittleEndian.PutUint32(stub[off+0:], 2) // kind=2 真狗
			binary.LittleEndian.PutUint32(stub[off+4:], uint32(*dongleFeat))
			binary.LittleEndian.PutUint32(stub[off+8:], uint32(fid))
			binary.LittleEndian.PutUint32(stub[off+12:], uint32(ofs))
			putStr(24, *dongleVC, 64)
			putStr(88, *dongleDLL, 64)
			fmt.Printf("[*] 主密钥来源：Sentinel 加密狗（kind=2，fileID=%d offset=%d feature=%d，严格模式不回退）\n", fid, ofs, *dongleFeat)
		}
		// 打完补丁必须重算自哈希（vm_key_src 在 [0,bssOff) 内，见 STATUS #399 那次教训）
		if hoff, ok2 := man.Symbols["vm_self_hash"]; ok2 && man.BSSOff > 0 {
			h := uint32(2166136261)
			for _, b := range stub[:man.BSSOff] {
				h = (h ^ uint32(b)) * 16777619
			}
			binary.LittleEndian.PutUint32(stub[hoff:], h)
			fmt.Printf("[*] 已按补丁重算自哈希（覆盖 [0, 0x%X)）\n", man.BSSOff)
		}
	}
	if *licDongle != 0 {
		loff, ok := man.Symbols["vm_license_meta"]
		koff, ok2 := man.Symbols["vm_key_src"]
		if !ok || !ok2 {
			fatalf("-license-dongle 需要 -key-external 构建的 blob（要同时有 vm_license_meta 与 vm_key_src）")
		}
		if loff < 0 || loff+76 > len(stub) || koff < 0 || koff+284 > len(stub) {
			fatalf("元数据偏移越界")
		}
		binary.LittleEndian.PutUint32(stub[loff+0:], 2)                    // kind=2：授权问狗
		binary.LittleEndian.PutUint32(stub[koff+280:], uint32(*licDongle)) // vm_key_src.licFeature
		if hoff, ok3 := man.Symbols["vm_self_hash"]; ok3 && man.BSSOff > 0 {
			h := uint32(2166136261)
			for _, b := range stub[:man.BSSOff] {
				h = (h ^ uint32(b)) * 16777619
			}
			binary.LittleEndian.PutUint32(stub[hoff:], h)
		}
		fmt.Printf("[*] 授权来源：Sentinel 加密狗（feature=%d；kind=2 严格模式，不看 .vmplic.bin）\n", *licDongle)
	}
	if *licVendor != "" || *licProduct != "" || *licPub != "" {
		off, ok := man.Symbols["vm_license_meta"]
		if !ok {
			fatalf("该 blob 里没有 vm_license_meta 符号（运行期强制目前只编入 -key-external 的 blob）")
		}
		if !man.KeyExternal {
			fatalf("-license-* 需要 -key-external 构建出来的 blob（运行期强制只在外置密钥模式下编入）")
		}
		if *licVendor == "" || *licProduct == "" || *licPub == "" {
			fatalf("-license-vendor / -license-product / -license-pub 必须同时给")
		}
		pub, err := readLicensePub(*licPub)
		must(err)
		vh := sha256.Sum256([]byte(*licVendor))
		ph := sha256.Sum256([]byte(*licProduct))
		if off < 0 || off+12+64 > len(stub) {
			fatalf("vm_license_meta 偏移 0x%X 越界（blob %d 字节）", off, len(stub))
		}
		binary.LittleEndian.PutUint32(stub[off+0:], 1) // kind = 1（启用）
		binary.LittleEndian.PutUint32(stub[off+4:], binary.LittleEndian.Uint32(vh[0:4]))
		binary.LittleEndian.PutUint32(stub[off+8:], binary.LittleEndian.Uint32(ph[0:4]))
		copy(stub[off+12:off+76], pub)
		fmt.Printf("[*] 运行期强制已启用：vendorID=%s productID=%s 签发者公钥前 8 字节=%X\n",
			*licVendor, *licProduct, pub[0:8])
		// 自哈希覆盖 [0, bssOff) —— **包含 .data**，而我们刚改了 .data 里的元数据，
		// 所以必须按同一套 FNV-1a 参数重算，否则 vm_selfcheck() 会直接 trap（实测就是这个坑）。
		if hoff, ok := man.Symbols["vm_self_hash"]; ok && man.BSSOff > 0 {
			h := uint32(2166136261)
			for _, b := range stub[:man.BSSOff] {
				h = (h ^ uint32(b)) * 16777619
			}
			binary.LittleEndian.PutUint32(stub[hoff:], h)
			fmt.Printf("[*] 已按补丁重算自哈希（覆盖 [0, 0x%X)）\n", man.BSSOff)
		}
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
		imgMaster = key
		enc = func(plain []byte, aad []byte, entryKey [32]byte) ([]byte, [12]byte, [16]byte, error) {
			// 每条目一把派生密钥（KDF 见 internal/inject/kdf.go）：AEAD 在闭包里按条目现建，
			// 主密钥本身不再直接用于密封字节码。
			aead, err := chacha20poly1305.New(entryKey[:])
			must(err)
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
		case pe.MachineI386:
			// 32 位（PE32）：blob 用 stub/win/x86（i686 工具链编，见 docs/PE32.md）。
			// 编码层面与 x86-64 同构（E8/E9 rel32），差异是 PE 重定位类型（HIGHLOW=3）与
			// 32 位指针宽度；blob 里的绝对引用已在 blob 内被登记成基址站点表。
			arch = inject.ArchX86
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
		res = packELF(*exe, outPath, stub, entryOff, man.FrameSkew, man.DescMagic, patchKey, imgMaster, man.FieldMaskSalt, verifyFnELF, man.Symbols["vm_unpack_image"], scratchOff, scratchLen, man.BSSOff, man.BSSSize, man.Symbols["vm_xmm"], man.Symbols["vm_tmp"], funcs, opcodeMap, enc, arch, *verbose, *reportPath)
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
		res = packPE(*exe, outPath, stub, entryOff, man.FrameSkew, man.DescMagic, patchKey, imgMaster, man.FieldMaskSalt, *stripRelocs, verifyFn, man.Symbols["vm_unpack_image"], scratchOff, scratchLen, man.Symbols["vm_reloc_tab"], man.BSSOff, man.BSSSize, man.Symbols["vm_xmm"], man.Symbols["vm_tmp"], funcs, opcodeMap, enc, arch, *verbose, *section, *reportPath)
	}

	for _, p := range res.Placements {
		fmt.Printf("    %-16s desc=0x%-7X thunk=0x%-7X code=0x%-7X patch=[%s]",
			p.Name, p.DescRVA, p.ThunkRVA, p.CodeRVA, p.EntryPatchHex)
		fmt.Println()
	}
	if *verify {
		if err := verifyArtifact(*exe, outPath, *verifyArgs, *verifyFilter, *verifyTimeout); err != nil {
			_ = os.Remove(outPath)
			fatalf("自检未通过，产物已删除（不让「看起来正常、实际算错」的东西流出去）: %v\n    定位是哪个函数：powershell -NoProfile -File tools/diffcheck.ps1 -Exe <原产物> -Map <map>", err)
		}
		fmt.Println("[*] 自检通过：受保护产物的输出与原始一致")
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

func packPE(exe, outPath string, stub []byte, entryOff, frameSkew int, descMagic uint32, patchKey [8]byte, master []byte, fieldMaskSalt uint32, stripRelocs bool, verifyFn, unpackFn, scratchOff, scratchLen, relocTabOff, bssOff, bssSize, xmmOff, tmpOff int, funcs []string, opcodeMap *vm.OpcodeMap, enc inject.EncryptFunc, arch inject.Arch, verbose bool, section, report string) *inject.Result {
	f, err := pe.Open(exe)
	must(err)
	if f.Machine != pe.MachineAMD64 && f.Machine != pe.MachineARM64 && f.Machine != pe.MachineI386 {
		fatalf("只支持 x86-64 / arm64 / i386 的 PE，该文件 Machine=0x%X", f.Machine)
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
		// i386 目标必须用 Mode32 的 lifter（绝对 [disp32] 寻址、字节序/宽度都不同）。
		lx := x64.NewLifterMode(f.ImageBase, x64dec.Mode64)
		if f.Is32Bit() {
			lx = x64.NewLifterMode(f.ImageBase, x64dec.Mode32)
		}
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
	var origTLSRVA uint32 // 原镜像 TLS 目录的 RVA（搬进 payload 之后要用它平移重定位项）
	var imgTLS []uint64
	var tlsDirCopy []byte
	var loadCfgCopy []byte
	imgSkip := ""
	switch {
	case !encImageEnabled:
		imgSkip = "已用 -no-enc-image 关闭"
	case imgMaster == nil:
		imgSkip = "-no-encrypt（没有主密钥，无法验签/解密）"
	case f.Machine != pe.MachineAMD64 && f.Machine != pe.MachineARM64:
		imgSkip = "原镜像整体加密目前只支持 x86-64 / arm64（i386 先跳过这一项）"
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
		origTLSRVA = tlsDirectoryRVA(f)
		if dir := origTLSRVA; dir != 0 {
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
		DescMagic: descMagic, PatchKey: patchKey, Master: master, FieldMaskSalt: fieldMaskSalt, Verbose: verbose, ScratchOff: scratchOff, ScratchLen: scratchLen, BSSOff: bssOff, BSSSize: bssSize,
		ImgSections: imgSecs, ImageBase: f.ImageBase, UnpackFn: unpackFn, ImgTlsCallbacks: imgTLS, TlsDirCopy: tlsDirCopy, LoadCfgCopy: loadCfgCopy,
		Wipe: wipeEnabled,
		/* 入口 hook 只有 amd64/arm64 的实现；i386 上装了会写进 **x86-64 指令**（实测入口处
		 * 变成 `51 52 41 50 48 8d 0d …`，在 32 位进程里全是垃圾 ⇒ 立刻 0xC0000005）。
		 * i386 不装 hook（镜像整体加密本来就跳过），需要校验时用 -verify 另行处理。 */
		EntryHook: patchKey != ([8]byte{}) && verifyFn >= 0 && entryRVA != 0 && f.Machine != pe.MachineI386,
		VerifyFn:  verifyFn,
		EntryRVA:  entryRVA})
	must(err)
	/* -strip-relocs 的实现（拆表 + 清 DYNAMIC_BASE）与"镜像是否整体加密"**无关**：
	 * 原来它嵌在 if len(imgSecs)>0 里 ⇒ i386（跳过镜像加密）根本不会清 DYNAMIC_BASE，
	 * 加载器于是仍按 ASLR 重定位，而预置值是按首选基址写的（实测现象诡异）。 */
	if stripRelocs {
		clearDynamicBase(f)
		stripRelocations(f)
		fmt.Println("[*] -strip-relocs：重定位表已拆、DYNAMIC_BASE 已清（本产物失去 ASLR）")
	} else {

		if len(imgSecs) > 0 {
			if imgMaster == nil {
				fatalf("-enc-image 需要主密钥（不能与 -no-encrypt 同时用）")
			}
			if err := encryptImageSections(f, res, imgMaster, fieldMaskSalt); err != nil {
				fatalf("原镜像加密失败: %v", err)
			}
			// (6) 默认**保留**重定位与 ASLR：加载器会在入口点之前按 delta 重定位镜像，而那些位置
			// 此刻还是密文 —— 运行期按 #381 的方案「先减回去 → 解密 → 再加回来」（见 vm_unpack_image）。
			// -strip-relocs 可以退回旧行为（拆表 + 清 DYNAMIC_BASE，代价是失去 ASLR）。
			fmt.Println("[*] 重定位与 DYNAMIC_BASE 保留（ASLR 生效；运行期自解密会把加载器的重定位搬回明文）")
			// (6) payload 里那些**绝对 VA** 也必须让加载器重定位，否则它们仍指向首选基址。
			// 实测漏掉它们：加载器按 TLS 回调数组跳到"首选基址 + rva"的旧地址 -> 0xC0000005。
			// payload 节不参与整体加密，所以运行期不需要对它们做"先减后加"。
		}

	}
	/* payload 的基址重定位与镜像加密**无关**：原来嵌在 if len(imgSecs)>0 里，
	 * 于是 i386（跳过镜像加密）与 -no-enc-image 的情形下这段根本不执行 —— 实测因此
	 * 打包产物能跑但结果错。现在移到外面，并保留"拆表时不追加"的语义。 */
	/* 注意：**预置**（把字段改成"首选基址下的绝对 VA"）必须无条件做；
	 * 只有"追加 HIGHLOW 项"才依赖保留镜像重定位。原来整块都在 `if !stripRelocs` 里 ⇒
	 * strip 模式下字段保持 blob 相对偏移 ⇒ 运行时去写 0x8810 这种未映射地址 ⇒ 0xC0000005（实测）。 */
	{
		var items [][2]uint32
		if origTLSRVA != 0 && res.TlsDirRVA != 0 {
			for _, e := range origRelocEntries(f) {
				if e[1] >= origTLSRVA && e[1] < origTLSRVA+40 {
					items = append(items, [2]uint32{e[0], res.TlsDirRVA + (e[1] - origTLSRVA)})
				}
			}
		}
		/* 重定位类型与指针宽度都按镜像位宽选：
		 *   PE32+ : IMAGE_REL_BASED_DIR64 = 10，8 字节
		 *   PE32  : IMAGE_REL_BASED_HIGHLOW = 3，4 字节 */
		relType := uint32(10)
		ptrSize := uint32(8)
		if f.Is32Bit() {
			relType = 3
			ptrSize = 4
		}
		if !stripRelocs && res.ImgTlsArrayRVA != 0 {
			for i := 0; i < 1+len(imgTLS); i++ { // 终止项是 0，不需要（也不该）重定位
				items = append(items, [2]uint32{relType, res.ImgTlsArrayRVA + uint32(i)*ptrSize})
			}
		}
		/* blob 里的**基址相关站点**（i386 的 DIR32 ⇒ vmpbuild 记进了 blob 末尾的表）：
		 * 字段存的是"blob 相对偏移"，必须由加载器加上镜像基址。这是"入口自修复"的
		 * **标准替代**：交给加载器一次性完成，既不会重复施加，也天然支持 ASLR。 */
		if relocTabOff > 0 && relocTabOff+4 <= len(stub) && res.SectionRVA != 0 {
			n := int(binary.LittleEndian.Uint32(stub[relocTabOff:]))
			for i := 0; i < n; i++ {
				p := relocTabOff + 4 + i*4
				if p+4 > len(stub) {
					break
				}
				site := binary.LittleEndian.Uint32(stub[p:])
				rva := res.SectionRVA + site
				/* 关键：HIGHLOW 的语义是"字段 += 实际基址 − 首选基址"，
				 * 所以字段里必须先放**首选基址下的绝对 VA**；blob 里存的是"blob 相对偏移"，
				 * 这里再补上"首选基址 + payload RVA"。少了这一步就是"加载器加完仍不是有效地址"。 */
				if off, e := f.RVAtoOffset(rva); e == nil && off >= 0 && off+4 <= len(f.Data) {
					cur := binary.LittleEndian.Uint32(f.Data[off:])
					binary.LittleEndian.PutUint32(f.Data[off:], uint32(f.ImageBase)+res.SectionRVA+cur)
				}
				if !stripRelocs {
					items = append(items, [2]uint32{relType, rva})
				}
			}
			fmt.Printf("[*] blob 基址站点预置了 %d 个（追加重定位项=%v）", n, !stripRelocs)
			fmt.Println()
		}
		/* **无条件**调用：即使 items 为空，也要让"目标没有 .reloc 就新建一个"那段被执行
		 * （Windows/ARM64 的 freestanding 目标正是 items 为空、却需要这个节的情形）。
		 * 对有重定位目录的目标（x64 等）：建节是 no-op、追加按 items 是否为空自然跳过 ⇒ 行为不变。 */
		if err := appendRelocs(f, items); err != nil {
			fatalf("补 payload 重定位项失败: %v", err)
		}
		if len(items) > 0 {
			fmt.Printf("[*] payload 里的绝对 VA 补了 %d 个重定位项（ASLR 下必须）", len(items))
			fmt.Println()
		}
	}
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
	if stripRelocs {
		fmt.Println("[*] 原镜像已原地加密，并清除 DYNAMIC_BASE（加载器因此不做重定位）")
	} else {
		fmt.Println("[*] 原镜像已原地加密（重定位保留：运行期先减回去、解密、再加回来）")
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

func packELF(exe, outPath string, stub []byte, entryOff, frameSkew int, descMagic uint32, patchKey [8]byte, master []byte, fieldMaskSalt uint32, verifyFn, unpackFn, scratchOff, scratchLen, bssOff, bssSize, xmmOff, tmpOff int, funcs []string, opcodeMap *vm.OpcodeMap, enc inject.EncryptFunc, arch inject.Arch, verbose bool, report string) *inject.Result {
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
		case imgMaster == nil:
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
			elfRaw := elfRawBytes(exe)
			// aarch64 上默认不做只读数据节：CI 实测必然 SIGSEGV（两个假设都被否，见 docs/STATUS.md 376）。
			// x86-64 上这条路径经 CI 真跑验证可用，故默认打开；要试 aarch64 用 -enc-image-elf-data。
			a64 := len(elfRaw) > 0x14 && binary.LittleEndian.Uint16(elfRaw[0x12:]) == 0xB7
			if a64 && !encImageELFData {
				fmt.Println("[*] ELF 整体加密：跳过只读数据节（aarch64 尚不支持，见 docs/STATUS.md 376）")
			}
			for _, sc := range elfSections(elfRaw) {
				if a64 && !encImageELFData {
					break
				}
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
		DescMagic: descMagic, PatchKey: patchKey, Master: master, FieldMaskSalt: fieldMaskSalt, Verbose: verbose, BSSOff: bssOff, BSSSize: bssSize,
		ImgSections: imgSecs, ImageBase: 0, UnpackFn: unpackFn,
		Wipe:          wipeEnabled,
		EntryHook:     patchKey != ([8]byte{}) && verifyFn >= 0 && entryRVA != 0 && f.Machine == elfload.EM_X86_64,
		EntryHookSysV: true,
		VerifyFn:      verifyFn,
		EntryRVA:      entryRVA})
	must(err)
	if len(imgSecs) > 0 {
		if err := encryptImageSectionsELF(f, imageBase, res, imgMaster, fieldMaskSalt); err != nil {
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

// encImageELFData：ELF 侧是否连 .rodata/.gopclntab 一起加密（实验开关，见 -enc-image-elf-data）。
var encImageELFData bool

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

// imgMaster：blob 主密钥（-no-encrypt 时为空）。原镜像每个节的加解密密钥由它按 KDF 现推：
// K_s = KDFEntry(master, rva = 节 RVA, salt = 表头 salt)，运行期 vm_unpack_image 同样现推。
var imgMaster []byte

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
func encryptImageSections(f *pe.File, res *inject.Result, master []byte, fieldMaskSalt uint32) error {
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
		// 每个节一把派生密钥（与运行期 vm_unpack_image 现推的算式一致；nonce/aad 不变）。
		k := inject.KDFEntry(master, rva, salt)
		aead, err := chacha20poly1305.New(k[:])
		if err != nil {
			return err
		}
		sealed := aead.Seal(nil, nonce[:], f.Data[so:so+int(size)], aad[:])
		copy(f.Data[so:so+int(size)], sealed[:size])
		copy(e[16:32], sealed[size:])
	}
	// (3) 字段混淆：表头的 count/selfRVA/保留（偏移 12..24）与每条目的 rva/size/flags（0..12）。
	// 必须放在**加密之后** —— 上面的循环要读明文 rva/size 去定位节。
	if len(master) == 32 {
		mimg := inject.FieldMask(master, inject.FieldMaskDomainImage, fieldMaskSalt)
		inject.XorMask(tbl, 12, 12, mimg[0:12])
		for i := uint32(0); i < count; i++ {
			inject.XorMask(tbl[24+i*32:], 0, 12, mimg[12:24])
		}
	}
	return nil
}

// readLicensePub 读签发者公钥：64 字节 hex 字面量，或一个文件（hex 文本，或 64 字节原始）。
func readLicensePub(s string) ([]byte, error) {
	trimmed := strings.TrimSpace(s)
	if b, err := hex.DecodeString(trimmed); err == nil && len(b) == 64 {
		return b, nil
	}
	raw, err := os.ReadFile(s)
	if err != nil {
		return nil, fmt.Errorf("-license-pub 既不是 128 位 hex，也读不到该文件: %w", err)
	}
	if len(raw) == 64 {
		return raw, nil
	}
	if b, err := hex.DecodeString(strings.TrimSpace(string(raw))); err == nil && len(b) == 64 {
		return b, nil
	}
	return nil, fmt.Errorf("-license-pub 文件既不是 64 字节原始公钥，也不是 128 位 hex 文本")
}

// verifyArtifact 是 -verify 的实现：同一个程序跑两遍（原始 / 受保护），比对标准输出+错误输出。
// 为什么把它放进 vmpack 而不是只留一个外部脚本：目标是「要么正确、要么明确拒绝」——
// 拒绝这件事必须在**产出端**发生，否则默认路径仍然会给出一个算错的产物。
func verifyArtifact(orig, packed, args, filter string, timeoutSec int) error {
	filt := func(s string) string {
		if filter == "" {
			return strings.TrimSpace(s)
		}
		re, err := regexp.Compile(filter)
		if err != nil {
			return strings.TrimSpace(s)
		}
		var keep []string
		for _, ln := range strings.Split(s, "\n") {
			if !re.MatchString(ln) {
				keep = append(keep, ln)
			}
		}
		return strings.TrimSpace(strings.Join(keep, "\n"))
	}
	run := func(exe string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
		defer cancel()
		var argv []string
		if args != "" {
			argv = strings.Fields(args)
		}
		cmd := exec.CommandContext(ctx, exe, argv...)
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		return filt(buf.String()), err
	}
	want, err1 := run(orig)
	got, err2 := run(packed)
	if err1 != nil && want == "" {
		return fmt.Errorf("原始产物跑不起来（%v）—— 自检无意义，请先用 -verify-args 配对参数", err1)
	}
	if want == got {
		return nil
	}
	// 报第一处差异，便于一眼看出问题
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var a, b string
		if i < len(wl) {
			a = wl[i]
		}
		if i < len(gl) {
			b = gl[i]
		}
		if a != b {
			hint := ""
			if err2 != nil {
				hint = fmt.Sprintf("（受保护产物退出异常: %v）", err2)
			}
			return fmt.Errorf("第 %d 行不同%s：原始=[%s] 受保护=[%s]", i+1, hint, a, b)
		}
	}
	return fmt.Errorf("输出不同（原始 %d 行 / 受保护 %d 行）", len(wl), len(gl))
}

// dirBase 返回**数据目录**数组在文件里的起始偏移。
// 两者不同只因为 NumberOfRvaAndSizes 的位置不同（它前面是 PE32 独有的 BaseOfData + 4 字节 ImageBase）：
//
//	PE32  : NumberOfRvaAndSizes @ 92, 数据目录 @ 96
//	PE32+ : NumberOfRvaAndSizes @ 108, 数据目录 @ 112
//
// 其余字段（含 DllCharacteristics@70）在 ImageBase 之后会自动对齐，所以只有这一处需要分位宽。
func dirBase(f *pe.File) int {
	if f.Is32Bit() {
		return f.OptHeaderOffset + 96
	}
	return f.OptHeaderOffset + 112
}

// origRelocEntries 读出原镜像的重定位项（type, rva）。stripRelocations 之后就再也读不到了。
func origRelocEntries(f *pe.File) [][2]uint32 {
	const relocDir = 5
	o := dirBase(f) + relocDir*8
	if o+8 > len(f.Data) {
		return nil
	}
	rva := binary.LittleEndian.Uint32(f.Data[o:])
	size := binary.LittleEndian.Uint32(f.Data[o+4:])
	if rva == 0 || size < 8 {
		return nil
	}
	off, err := f.RVAtoOffset(rva)
	if err != nil || off < 0 || off+int(size) > len(f.Data) {
		return nil
	}
	var out [][2]uint32
	end := off + int(size)
	for p := off; p+8 <= end; {
		page := binary.LittleEndian.Uint32(f.Data[p:])
		blk := binary.LittleEndian.Uint32(f.Data[p+4:])
		if blk < 8 || p+int(blk) > end {
			break
		}
		for q := p + 8; q+2 <= p+int(blk); q += 2 {
			v := binary.LittleEndian.Uint16(f.Data[q:])
			t := uint32(v >> 12)
			if t == 0 {
				continue
			}
			out = append(out, [2]uint32{t, page + uint32(v&0xFFF)})
		}
		p += int(blk)
	}
	return out
}

// appendRelocs 往 .reloc 尾部追加 DIR64 重定位项（按页分组），并同步数据目录 Size 与节 VirtualSize。
// 只用于 payload 自己的绝对 VA —— 它们在**不被加密**的节里，加载器改了就是对的。
func appendRelocs(f *pe.File, items [][2]uint32) error {
	const relocDir = 5
	do := dirBase(f) + relocDir*8
	rva := binary.LittleEndian.Uint32(f.Data[do:])
	size := binary.LittleEndian.Uint32(f.Data[do+4:])
	if rva == 0 {
		/* 目标**没有重定位目录**时自己建一个（STATUS #520）：
		 * freestanding 链接的目标（例如 Windows/ARM64 的 testdata/arm64/target_win.c）没有绝对引用，
		 * lld 因此不生成 .reloc。但 payload 里的绝对 VA 站点是打包端按**首选基址**预置的
		 * （见上面 `uint32(f.ImageBase)+res.SectionRVA+cur`），一旦加载器把它装到别处（ASLR），
		 * 这些站点就是过期的 ⇒ 运行期必然 0xC0000005。
		 * 所以这里补一个 .reloc 节：先放一个合法的空块（page=0,size=8，无条目），
		 * 随后本函数照常在它后面追加真正的条目，并把数据目录 5 指过去。 */
		pad := make([]byte, 8) /* 空块：SizeOfBlock = 8，无条目 */
		binary.LittleEndian.PutUint32(pad[4:], 8)
		sec, serr := f.AddSection(".reloc", pad, 0x42000040) /* READ|INITIALIZED_DATA|DISCARDABLE */
		if serr != nil {
			return fmt.Errorf("目标没有 .reloc 且新建节失败: %w", serr)
		}
		binary.LittleEndian.PutUint32(f.Data[do:], sec.VirtualAddress)
		binary.LittleEndian.PutUint32(f.Data[do+4:], 8)
		rva = sec.VirtualAddress
		size = 8
		fmt.Printf("[!] 目标没有重定位目录 ⇒ 已新建 .reloc 节（RVA=0x%X）供 payload 站点使用", rva)
		fmt.Println()
	}
	/* items 为空 ⇒ 没有需要追加的条目，到此为止。**这个判断必须在建节之后**：建节那一段正是要负责
	 * "目标本来就没有 .reloc"的情形，而那种情形下 items 往往也是空的（#521 因把提前返回放在最前面
	 * 而让建节永远不执行；也因去掉它而让 x64 的空 items 路径把产物写坏 ⇒ 现在两者兼得）。 */
	if len(items) == 0 {
		return nil
	}
	off, err := f.RVAtoOffset(rva)
	if err != nil || off < 0 {
		return fmt.Errorf("没有 .reloc 目录")
	}
	var target *pe.Section
	for i := range f.Sections {
		if f.Sections[i].VirtualAddress == rva {
			target = &f.Sections[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf(".reloc 不在独立节里，无法追加")
	}
	so, err := f.RVAtoOffset(target.VirtualAddress)
	if err != nil || so < 0 {
		return err
	}
	room := int(target.SizeOfRawData)
	pos := off + int(size)
	groups := map[uint32][]uint16{}
	for _, it := range items {
		/* 类型必须**随项保留**：PE32 用 HIGHLOW(3)、PE32+ 用 DIR64(10)。
		 * 这里原来只认 10 ⇒ i386 的站点被**静默丢弃**（实测：打包产物里一条都没加进去，
		 * 数据目录 Size 也停留在原值 564）。 */
		if it[0] != 10 && it[0] != 3 {
			continue
		}
		groups[it[1]&^0xFFF] = append(groups[it[1]&^0xFFF], uint16(it[0]<<12)|uint16(it[1]&0xFFF))
	}
	pages := make([]uint32, 0, len(groups))
	for p := range groups {
		pages = append(pages, p)
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i] < pages[j] })
	/* 先把新块拼进内存：这样"原地追加"与"新建承载节"两条路可以共用同一份字节。 */
	var add []byte
	for _, pg := range pages {
		offs := groups[pg]
		/* PE 要求同一页内的项按偏移升序；追加的项目与原有项目混在一起时更需要显式排序。 */
		sort.Slice(offs, func(a, b2 int) bool { return (offs[a] & 0xFFF) < (offs[b2] & 0xFFF) })
		blk := 8 + len(offs)*2
		hdr := make([]byte, blk)
		binary.LittleEndian.PutUint32(hdr[0:], pg)
		binary.LittleEndian.PutUint32(hdr[4:], uint32(blk))
		for i, e := range offs {
			binary.LittleEndian.PutUint16(hdr[8+i*2:], e)
		}
		add = append(add, hdr...)
	}
	if pos+len(add) <= so+room && pos+len(add) <= len(f.Data) {
		copy(f.Data[pos:], add)
		newSize := uint32(pos - off + len(add))
		binary.LittleEndian.PutUint32(f.Data[do+4:], newSize)
		if target.VirtualSize < newSize {
			target.VirtualSize = newSize
		}
		return nil
	}
	/* .reloc 的 raw 余量不够。它后面在**文件里**还压着别的节的原始数据，所以不能就地扩展；
	 * 而加载器只按数据目录读**一段连续**的重定位块，于是把「原有块 + 新块」整体搬进一个**新的承载节**，
	 * 再把目录指向它（旧的 .reloc 内容就变成无人引用的死字节）。
	 * 原有块要按块长逐个拷：目录 Size 可能带尾部填充，整段照搬会被加载器当成一个畸形块。 */
	var carrier []byte
	for p := 0; p+8 <= int(size); {
		blkLen := int(binary.LittleEndian.Uint32(f.Data[off+p+4:]))
		if blkLen < 8 || p+blkLen > int(size) {
			break
		}
		carrier = append(carrier, f.Data[off+p:off+p+blkLen]...)
		p += blkLen
	}
	carrier = append(carrier, add...)
	/* 0x40000040 = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ */
	sec, err := f.AddSection(".vreloc", carrier, 0x40000040)
	if err != nil {
		return fmt.Errorf(".reloc 空间不足（需要 %d 字节，剩 %d），且新建承载节失败: %w", len(add), so+room-pos, err)
	}
	binary.LittleEndian.PutUint32(f.Data[do:], sec.VirtualAddress)
	binary.LittleEndian.PutUint32(f.Data[do+4:], uint32(len(carrier)))
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
	o := dirBase(f) + relocDir*8
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
func encryptImageSectionsELF(f *elfload.File, imageBase uint64, res *inject.Result, master []byte, fieldMaskSalt uint32) error {
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
		// 与 PE 版逐字节同构：每个节一把派生密钥。
		k := inject.KDFEntry(master, rva, salt)
		aead, err := chacha20poly1305.New(k[:])
		if err != nil {
			return err
		}
		sealed := aead.Seal(nil, nonce[:], buf, aad[:])
		if err := f.WriteVA(imageBase+uint64(rva), sealed[:size]); err != nil {
			return err
		}
		copy(e[16:32], sealed[size:])
	}
	// 同 PE 版：表头 12..24 与每条目 0..12 加掩码，位置同样在加密之后。
	if len(master) == 32 {
		mimg := inject.FieldMask(master, inject.FieldMaskDomainImage, fieldMaskSalt)
		inject.XorMask(tbl, 12, 12, mimg[0:12])
		for i := uint32(0); i < count; i++ {
			inject.XorMask(tbl[24+i*32:], 0, 12, mimg[12:24])
		}
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
	o := dirBase(f) + 9*8
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
		o := dirBase(f) + d.idx*8
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
	o := dirBase(f) + 10*8
	if o+8 > len(f.Data) {
		return 0, 0
	}
	return binary.LittleEndian.Uint32(f.Data[o:]), binary.LittleEndian.Uint32(f.Data[o+4:])
}

// setLoadConfigDirectoryRVA 把 LOAD_CONFIG 数据目录重新指向 payload 里的那份副本。
func setLoadConfigDirectoryRVA(f *pe.File, rva uint32) error {
	o := dirBase(f) + 10*8
	if o+8 > len(f.Data) {
		return fmt.Errorf("没有 LOAD_CONFIG 目录项")
	}
	binary.LittleEndian.PutUint32(f.Data[o:], rva)
	return nil
}

// tlsDirectoryRVA 返回 TLS 数据目录指向的 RVA（0 = 没有）。
func tlsDirectoryRVA(f *pe.File) uint32 {
	o := dirBase(f) + 9*8
	if o+8 > len(f.Data) {
		return 0
	}
	return binary.LittleEndian.Uint32(f.Data[o:])
}

// setTLSDirectoryRVA 把 TLS 数据目录重新指向 payload 里的那份副本。
func setTLSDirectoryRVA(f *pe.File, rva uint32) error {
	o := dirBase(f) + 9*8
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

// vmpbuild - 构建可注入的 VM 解释器 blob。
//
// 它做四件事：
//  1. 把 C 源码 stage 到 ASCII 临时目录后编译（msys2 工具链不支持非 ASCII 路径），
//     编译参数保证无 libc、无编译器辅助函数、无 unwind 表。
//  2. 解析 .o —— COFF（Windows 工具链）与 ELF 可重定位目标（Linux 工具链）都读，
//     直接读符号表与节重定位，而不是去解析 objdump 的文本输出（见 objfile.go）。
//  3. 把 .text/.rdata/.rodata/.data 拼成一个 blob，并把节内 PC-relative 重定位**自行解析**：
//     blob 是整块搬运的，节间相对距离由我们决定，所以 PC-relative 引用必须重算，
//     绝对引用则直接判为失败（不可注入）。
//  4. 输出 blob + manifest.json（入口偏移、符号表、校验和、重定位统计）。
//
// 失败即报错：任何指向 blob 之外的符号、任何绝对重定位都会让构建失败。
package main

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vmpx/vmp-x/internal/cred"
	"github.com/vmpx/vmp-x/internal/inject"
	"github.com/vmpx/vmp-x/internal/sentinel"
)

// vmKeyCheckRVA：密钥校验值（KCV）派生时用的"槽位"常量，与 VM_KEY_CHECK_SALT（每次构建随机）
// 一起做域分离 —— KCV 只是主密钥的函数，拿不到主密钥就推不出来。
const vmKeyCheckRVA = uint32(0x4B45594B) // "KEYK"

const (
	relAMD64Addr64   = 0x0001
	relAMD64Addr32   = 0x0002
	relAMD64Addr32NB = 0x0003
	relAMD64Rel32    = 0x0004
	relAMD64Rel32N   = 0x0009 // REL32_1 .. REL32_5
)

type sectInfo struct {
	Name    string `json:"name"`
	BlobOff int    `json:"blobOff"`
	Size    int    `json:"size"`
}

// release 构建开关与本次构建的描述符魔数（由 main 从 flag 设置，compile 读）。
var (
	releaseBuild bool
	releaseMagic uint32 = 0x4B504D56 // 默认与 vm_abi.h 的固定值一致
)

type manifest struct {
	Source       string `json:"source"`
	Entry        string `json:"entry"`
	EntryOff     int    `json:"entryOff"`
	BlobSize     int    `json:"blobSize"`
	SHA256       string `json:"sha256"`
	FrameSize    int    `json:"frameSize"`
	Margin       int    `json:"margin"`
	FrameSkew    int    `json:"frameSkew"`
	MaxStubFrame int    `json:"maxStubStackFrame"`
	// DescMagic：本 blob 期望的描述符魔数。release 构建里它是**每次构建随机**的，
	// 这样发布产物里不存在固定 4 字节特征（原来那个特征就是字符串 "VMPK"）。
	DescMagic uint32 `json:"descMagic"`
	// FieldMaskSalt：描述符/解密表/校验表里那些标量字段（RVA、长度、标志）的**混淆掩码**种子，
	// 掩码由 KDFEntry(master, 域常量, FieldMaskSalt) 现推（见 internal/inject/fields.go）。
	FieldMaskSalt uint32         `json:"fieldMaskSalt"`
	BSSOff        int            `json:"bssOff"`  // blob 里可写数据（.bss）的起始偏移
	BSSSize       int            `json:"bssSize"` // 可写数据大小：这一段必须单独映射成 RW
	RelocsTotal   int            `json:"relocsTotal"`
	RelocsPatch   int            `json:"relocsPatched"`
	Sections      []sectInfo     `json:"sections"`
	Symbols       map[string]int `json:"symbols"`
	OpcodeMap     map[string]int `json:"opcodeMap"`   // 逻辑操作码名 -> 本 blob 的实际编码
	Key           string         `json:"key"`         // AEAD 主密钥（hex）；M2.2 用，定位见 DESIGN §2
	KeyExternal   bool           `json:"keyExternal"` // 1b：外置密钥模式（运行期强制只在该模式下编入）
	Guest         string         `json:"guest"`       // 客户机 ISA：x86-64 / arm64
	RegCount      int            `json:"regCount"`    // ctx 的寄存器槽位数：18（x86-64）/ 35（arm64）
	UndefinedSym  []string       `json:"undefinedSymbols,omitempty"`
}

func main() {
	src := flag.String("src", "stub/win/x64", "stub 源码目录")
	obj := flag.String("obj", "", "已有 .o 路径（留空则先编译）")
	entry := flag.String("entry", "vm_entry", "入口符号名")
	out := flag.String("out", "internal/inject/vm_interp.bin", "输出 blob")
	man := flag.String("manifest", "internal/inject/vm_interp.json", "输出 manifest")
	cc := flag.String("cc", "gcc", "编译器")
	keep := flag.Bool("keep", false, "保留临时目录")
	tmpRoot := flag.String("tmp", "", "临时目录（默认系统临时目录；必须是 ASCII 路径）")
	objdump := flag.String("objdump", "objdump", "objdump 路径（用于测量解释器栈帧）")
	release := flag.Bool("release", false, "release 构建：去掉全部诊断代码，描述符魔数每次构建随机")
	stageRoot := flag.String("stage-root", "stub", "要整体 stage 的源码树根（BLOB.sources 的路径相对它）")
	randomOpcodes := flag.Bool("random-opcodes", true, "为本次构建生成随机的 VM 操作码映射（默认开启）")
	guest := flag.String("guest", "x86-64", "客户机 ISA：x86-64（默认）或 arm64")
	merge := flag.String("merge", "ld", "目标文件合并方式：ld（GNU ld -r）或 go（内置直拼，COFF 用它）")
	keyExternal := flag.Bool("key-external", false, "主密钥外置（1b）：blob 里只放占位密钥 + 密钥校验值，真主密钥运行期从外部取")
	keyOut := flag.String("key-out", "", "配合 -key-external：把真主密钥以 64 位 hex 文本写到该文件（部署时放到 <产物>.vmpkey 即可）")
	keyIn := flag.String("key-in", "", "**指定**主密钥而不是随机生成：64 位 hex 字面量，或一个文件（32 字节原始密钥 / 64 位 hex 文本）。用于跨版本、跨构建复用同一把钥匙")
	credFlag := flag.String("cred", "", "构建凭据路径（默认 $VMPX_CRED 或工具同目录 vmpx.cred）；仅当工具烘焙了厂商根公钥时才校验")
	vendorFlag := flag.String("vendor", "", "本次构建声明的 vendorID；工具授权开启时会强制与凭据里的一致")
	verbose := flag.Bool("v", false, "打印符号与重定位详情")
	flag.Parse()
	// 工具授权（docs/STRENGTH.md 4.4-1）：只有工具**烘焙了厂商根公钥**时才校验（发布构建），
	// 开发构建留空 => 关闭校验，现有 CI/gates 不受影响。
	if err := cred.Require(*credFlag, *vendorFlag); err != nil {
		fmt.Fprintf(os.Stderr, "[!] 工具授权校验失败: %v\n", err)
		os.Exit(8)
	}

	// release 构建：必须在这里就定下来 —— compile() 在下面几步内就会被调用，
	// 之前放在 measureMaxFrame 旁边导致 -DVM_RELEASE 根本没进编译（.text 反而更大）。
	if *release {
		releaseBuild = true
	}
	// 描述符魔数**默认每次构建随机**（原来只有 -release 才随机，非 release 是固定的 "VMPK"，
	// 那正是一个可被签名/扫描的 4 字节特征）。运行期不读这个字段（只在 manifest 里给打包器用），
	// 所以随时随机化不影响任何行为。
	releaseMagic = rand.Uint32()

	tmp, err := os.MkdirTemp(*tmpRoot, "vmpbuild-")
	must(err)
	if !*keep {
		defer os.RemoveAll(tmp)
	}
	if !isASCII(tmp) {
		fatalf("临时目录必须是非 ASCII 路径会破坏 msys2 工具链: %s", tmp)
	}

	// 构建期随机操作码映射：每个 blob 一套独立编码。
	// 生成的 vm_opcode_values.h 放进临时目录，编译时用 -include 强制先包含它，
	// 于是解释器里的 OP_* 常量就是本 blob 的实际编码（编译期常量，零运行时开销）。
	opcodeValuesPath, opMap, err := generateOpcodeValues(tmp, *randomOpcodes)
	must(err)
	// 主密钥外置（1b）：只实现了 Windows/x64 的取钥路径（PEB → KERNEL32 → CreateFileA /
	// GetEnvironmentVariableA）。别的目标一律**构建失败** —— 宁可现在报错，也不要产出一个
	// 注定起不来的产物（那会在部署现场变成"程序莫名其妙退出"）。
	targetRel := filepath.ToSlash(strings.TrimPrefix(filepath.ToSlash(*src), "stub/"))
	// 1b 取钥实现按平台逐个落地；未落地的平台一律**构建失败**（见上面的理由）。
	keyExternalOK := map[string]bool{
		"win/x64":     true, // PEB -> KERNEL32 -> ntdll 取钥
		"win/x86":     true, // 同上，但 PEB 走 fs:[0x30]，LDR/PP/导出目录与 NT 结构体都是 32 位版本
		"linux/amd64": true, // syscall(2)：/proc/self/environ + <产物>.vmpkey（open/read/close）
		"linux/arm64": true, // 同上，但 aarch64 只有 openat/readlinkat（多一个 AT_FDCWD 参数）
		// "win/arm64"：诊断进行中（#507-#519）。已确证：`.vmp` 扩展名无法被 PowerShell 启动（改名 .exe 即可，`#517`）；
		// 产物能跑并返回 0xC0DE0002（"delta != 0 且无重定位表"拒绝）；目标与产物的 ImageBase 都是 0x140000000，
		// 表头也写的是 f.ImageBase ⇒ **delta 本应为 0**，所以拒绝为何触发仍未解释 ⇒ 下一步把 base/wantBase/delta/rr
		// 编码进退出码或写进文件。修好前保持 fail-fast。
	}
	if *keyExternal && !keyExternalOK[targetRel] {
		fatalf("-key-external 尚未实现该目标的取钥路径（收到目标 %s）", targetRel)
	}
	keyPath, keyHex, fieldMaskSalt, err := generateKeyFile(tmp, *keyExternal, *keyIn)
	must(err)
	if *keyOut != "" {
		// 写的是 64 位 hex **文本**：部署时把它设成环境变量 VMPX_KEY（运行期的取钥路径
		// 见 stub/win/x64/vm_interp.c 的 1b 段：直接读 PEB 的环境块，不调用 kernel32）。
		if werr := os.MkdirAll(filepath.Dir(*keyOut), 0o755); werr != nil {
			must(werr)
		}
		if werr := os.WriteFile(*keyOut, []byte(keyHex), 0o600); werr != nil {
			fatalf("写主密钥文件失败: %v", werr)
		}
		fmt.Printf("[*] 主密钥已写到 %s（64 位 hex 文本；部署时改名为 <产物全路径>.vmpkey）", *keyOut)
		fmt.Println()
	}
	_ = keyPath
	keyRel := ""
	_ = keyRel
	if *verbose {
		fmt.Printf("[*] opcode map: %d entries (random=%v)\n", len(opMap), *randomOpcodes)
	}

	// 汇编/编译：先各自成对象；合并方式可选
	//   -merge ld  ：GNU ld -r 合并（x86-64 一直用的路径，默认）
	//   -merge go  ：内置直拼（COFF 没有 ld -r 的等价物，Windows/arm64 走这条）
	objs := []string{*obj}
	if *obj == "" {
		objs, err = compile(*cc, *stageRoot, *src, tmp, opcodeValuesPath, keyPath, *guest, *verbose)
		must(err)
	}
	var merged *mergedBlob
	var single *objFile
	/* 基址重定位站点（i386 的 DIR32）与表偏移：自哈希必须与加载期的补丁规则一致。 */
	var absSites []int
	relocTabOff := 0
	objPath := ""
	switch *merge {
	case "go":
		parsed := make([]*objFile, 0, len(objs))
		for _, p := range objs {
			ob, err := readObject(p)
			must(err)
			parsed = append(parsed, ob)
		}
		merged, err = buildBlobMulti(parsed)
		must(err)
		objPath = objs[0]
		_ = parsed
	case "ld", "":
		objPath = objs[0]
		if len(objs) > 1 {
			objPath, err = mergeWithLd(tmp, objs, *verbose)
			must(err)
		}
		ob, err := readObject(objPath)
		must(err)
		single = ob
	default:
		fatalf("-merge 只支持 ld 或 go（收到 %q）", *merge)
	}

	frameSize, margin, skewExtra, err := readABIConstants(*src)
	must(err)
	// 多目标直拼时 objPath 只是第一个对象，栈帧要**在所有对象上取最大**
	maxFrame := 0
	for _, p := range objs {
		f, err := measureMaxFrame(*objdump, p, *verbose)
		must(err)
		if f > maxFrame {
			maxFrame = f
		}
	}
	if len(objs) == 0 {
		maxFrame, err = measureMaxFrame(*objdump, objPath, *verbose)
		must(err)
	}
	if maxFrame+512 >= margin {
		fatalf("VM_MARGIN(0x%X) 对解释器最大栈帧(0x%X) 来说太小：模拟栈会与宿主栈重叠", margin, maxFrame)
	}
	frameSkew := frameSize + skewExtra + margin

	var (
		sections []sectInfo
		blob     []byte
		nReloc   int
		syms     = map[string]int{}
	)
	if merged != nil {
		sections = merged.Sections
		blob = merged.Data
		nReloc, err = merged.applyAllRelocs(parsedObjs(objs), *verbose)
		must(err)
		merged.emitAbsTable() /* 必须在 reloc 应用之后：那时基址相关站点才被登记 */
		must(err)
		/* 重要：表是 append 上去的，可能**重新分配** m.Data ⇒ 必须在这里重新取切片，
		 * 否则写文件用的还是旧数组、旧长度（实测：符号有了、文件里却没有表）。 */
		blob = merged.Data
		absSites = merged.absSites
		if v, ok := merged.symOff["vm_reloc_tab"]; ok {
			relocTabOff = v
		}
		for k, v := range merged.symOff {
			syms[k] = v
		}
	} else {
		var secBlobOff map[int]int
		sections, blob, secBlobOff, err = buildBlobObj(single)
		must(err)
		nReloc, err = applyRelocsObj(single, blob, secBlobOff, *verbose)
		must(err)
		for _, s := range single.Symbols {
			if s.Sec >= 0 {
				if off, ok := secBlobOff[s.Sec]; ok {
					syms[s.Name] = off + int(s.Value)
				}
			}
		}
	}

	entryOff, ok := syms[*entry]
	if !ok {
		keys := make([]string, 0, len(syms))
		for k := range syms {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fatalf("入口符号 %q 不在 blob 中；可用符号: %s", *entry, strings.Join(keys, ", "))
	}

	must(os.MkdirAll(filepath.Dir(*out), 0o755))
	must(os.MkdirAll(filepath.Dir(*out), 0o755))
	must(os.WriteFile(*out, blob, 0o644))

	// 可写数据区间：sections 里名为 .bss 的那一段（buildBlob* 已保证它在最后）
	bssOff, bssSize := 0, 0
	for _, s := range sections {
		if s.Name == ".bss" && s.Size > 0 {
			// 长度按节对齐补齐：blob 里 .bss 后面已经补过零，注入器要按补齐后的长度划段
			bssOff = s.BlobOff
			bssSize = (s.Size + 0xFFF) &^ 0xFFF
		}
	}

	// (g) 解释器/桩代码段自哈希：把 [0, bssOff) 的 FNV-1a 与两个偏移写进 blob 里的三个全局
	// （它们在 .bss，位于被哈希区间之外，所以不会自我指涉）。运行时由 vm_selfcheck() 重算比对。
	if off, ok := syms["vm_self_hash"]; ok && bssOff > 0 {
		/* 自哈希必须**跳过基址重定位站点**（这些字节按 0 参与运算）——
		 * 否则加载期把站点 += base 之后，运行时重算的哈希必然对不上。
		 * 实测：i686 上正是这样被 vm_selfcheck 的 ud2 拒绝的（896/920 个站点字节落在哈希区间内）。
		 * 运行期 vm_selfcheck 用同一套规则（经 vm_reloc_tab_off 找到表）。 */
		siteByte := make([]bool, len(blob))
		for _, s := range absSites {
			for k := 0; k < 4 && s+k < len(siteByte); k++ {
				siteByte[s+k] = true
			}
		}
		h := uint32(2166136261)
		for i, b := range blob[:bssOff] {
			if i < len(siteByte) && siteByte[i] {
				b = 0
			}
			h = (h ^ uint32(b)) * 16777619
		}
		binary.LittleEndian.PutUint32(blob[off:], h)
		if o4, ok4 := syms["vm_reloc_tab_off"]; ok4 {
			binary.LittleEndian.PutUint32(blob[o4:], uint32(relocTabOff))
		}
		if o2, ok2 := syms["vm_self_len"]; ok2 {
			binary.LittleEndian.PutUint64(blob[o2:], uint64(bssOff))
		}
		if o3, ok3 := syms["vm_code_off"]; ok3 {
			binary.LittleEndian.PutUint64(blob[o3:], uint64(entryOff))
		}
		must(os.MkdirAll(filepath.Dir(*out), 0o755))
		must(os.WriteFile(*out, blob, 0o644))
	}

	sum := sha256.Sum256(blob)
	m := manifest{
		Source:        *src,
		Entry:         *entry,
		EntryOff:      entryOff,
		FrameSize:     frameSize,
		Margin:        margin,
		FrameSkew:     frameSkew,
		Guest:         *guest,
		RegCount:      regCountFor(*guest),
		MaxStubFrame:  maxFrame,
		DescMagic:     releaseMagic,
		FieldMaskSalt: fieldMaskSalt,
		BlobSize:      len(blob),
		SHA256:        fmt.Sprintf("%x", sum[:]),
		RelocsTotal:   nReloc,
		RelocsPatch:   nReloc,
		Sections:      sections,
		Symbols:       syms,
		OpcodeMap:     opMap,
		BSSOff:        bssOff,
		BSSSize:       bssSize,
		Key:           keyHex,
		KeyExternal:   *keyExternal,
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	must(os.MkdirAll(filepath.Dir(*man), 0o755))
	must(os.WriteFile(*man, b, 0o644))

	fmt.Printf("[+] blob: %s (%d bytes), entry %s @ +0x%X\n", *out, len(blob), *entry, entryOff)
	for _, s := range sections {
		fmt.Printf("    %-8s blobOff=0x%-6X size=0x%X\n", s.Name, s.BlobOff, s.Size)
	}
	fmt.Printf("    relocations resolved internally: %d\n", nReloc)
	fmt.Printf("    stack: frame=%d margin=0x%X frameSkew=%d | stub max frame=0x%X\n", frameSize, margin, frameSkew, maxFrame)
	fmt.Printf("    guest=%s regCount=%d（宿主 harness 必须用同一套 ctx 布局，否则会以 rc=1 的形式静默失败）\n",
		*guest, regCountFor(*guest))
	fmt.Printf("[+] manifest: %s\n", *man)
}

// regCountFor 返回客户机的 ctx 槽位数。写进 manifest 是为了让调用方（测试/harness）
// 能在运行前就发现"harness 与 blob 布局不一致"——这个坑真踩过一次：
// 少给 harness 传 -DVM_REG_COUNT=35，症状就是解释器 rc=1，排查了很久。
func regCountFor(guest string) int {
	switch guest {
	case "arm64":
		return 35
	case "x86-64", "x86-32":
		// 32 位客户机仍用 18 个槽位：IR 里 EAX..EDI 映射到 RAX..RDI，R8-R15 只是不用。
		// 这样 ctx 布局与 x86-64 完全一致，harness 不用换（-DVM_REG_COUNT 也不用传）。
		return 18
	default:
		fatalf("未知的客户机 ISA %q（支持 x86-64 / x86-32 / arm64）", guest)
		return 0
	}
}

// generateOpcodeValues 生成 vm_opcode_values.h（默认或随机映射），返回文件路径与"名字->编码"表。
//
// 随机映射的意义：每个 blob 的操作码字节都不一样，静态特征扫描失效。
// 解释器用编译期常量分发，所以随机化**不带来任何运行时开销**。
func generateOpcodeValues(tmp string, random bool) (string, map[string]int, error) {
	outDir := filepath.Join(tmp, "opcodes")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", nil, err
	}
	outPath := filepath.Join(outDir, "vm_opcode_values.h")
	nl := string(rune(10))

	type entry struct {
		name string
		val  int
	}
	// 顺序与 stub/win/x64/vm_opcode_values.h 及 internal/vm/opcodes.go 一致（有交叉校验测试）
	entries := []entry{
		{"VM_OP_HALT", 0x00}, {"VM_OP_NOP", 0x01}, {"VM_OP_RET", 0x02},
		{"VM_OP_MOV_RR", 0x10}, {"VM_OP_MOV_RI", 0x11}, {"VM_OP_MOV_RI32", 0x12}, {"VM_OP_LEA", 0x13},
		{"VM_OP_ALU_RR", 0x20}, {"VM_OP_ALU_RI", 0x21}, {"VM_OP_ALU_U", 0x22},
		{"VM_OP_CMP_RR", 0x23}, {"VM_OP_CMP_RI", 0x24},
		{"VM_OP_EXT", 0x30},
		{"VM_OP_LOAD", 0x40}, {"VM_OP_STORE", 0x41}, {"VM_OP_ATOMIC", 0x42}, {"VM_OP_FP", 0x43},
		{"VM_OP_PUSH_R", 0x50}, {"VM_OP_PUSH_I", 0x51}, {"VM_OP_POP_R", 0x52},
		{"VM_OP_JCC", 0x60}, {"VM_OP_JMP", 0x61}, {"VM_OP_JBZ", 0x62}, {"VM_OP_JBNZ", 0x63},
		{"VM_OP_CALLN", 0x70}, {"VM_OP_CALLR", 0x71},
	}

	vals := make([]int, len(entries))
	for i, e := range entries {
		vals[i] = e.val
	}
	if random {
		pool := make([]int, 0, 254)
		for v := 1; v <= 0xFE; v++ {
			pool = append(pool, v)
		}
		// 操作码映射同样是"每构建随机"的混淆项：也用密码学随机源（用可预测种子等于把映射送出去）。
		seed, serr := cryptoRandU64()
		if serr != nil {
			return "", nil, serr
		}
		rnd := rand.New(rand.NewSource(int64(seed)))
		rnd.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
		copy(vals, pool)
	}

	var sb strings.Builder
	sb.WriteString("/* 由 cmd/vmpbuild 生成：本 blob 的 VM 操作码编码 */" + nl)
	sb.WriteString("#ifndef VM_OPCODE_VALUES_H" + nl + "#define VM_OPCODE_VALUES_H" + nl)
	opMap := map[string]int{}
	for i, e := range entries {
		fmt.Fprintf(&sb, "#define %s 0x%02X"+nl, e.name, vals[i])
		opMap[strings.TrimPrefix(e.name, "VM_")] = vals[i]
	}
	sb.WriteString("#endif" + nl)
	if err := os.WriteFile(outPath, []byte(sb.String()), 0o644); err != nil {
		return "", nil, err
	}
	return outPath, opMap, nil
}

// cryptoRandU32 / cryptoRandU64：密码学随机源。主密钥、各种 salt、每构建随机的混淆种子都必须走这里
// —— 以前用 math/rand + 时间种子，输出可预测（等于把密钥送出去）。
func cryptoRandU32() (uint32, error) {
	var b [4]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("crypto/rand 不可用: %w", err)
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func cryptoRandU64() (uint64, error) {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("crypto/rand 不可用: %w", err)
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

// generateKeyFile 生成本 blob 的 AEAD 主密钥（vm_crypto_key.h，宏形式：避免外部符号引用
// 在 mingw 下变成 .rdata$.refptr 绝对指针表，那是位置无关 blob 不能接受的）。
//
// 定位：密钥最终在 blob 里，因此这不是密码学级保护（见 docs/DESIGN.md §2）——
// 它挡住静态分析，真正的级别需要 KeyProvider 的 TPM/TEE/远程证明。
// external=true 时（1b）：blob 里放的 VM_KEY_BYTES 是**独立的随机占位密钥**（不是真密钥的任何
// 变形 —— 否则等于把真密钥泄露出去），真主密钥只出现在 manifest 里（vmpack 要用）+ 可选的 -key-out。
// 无论哪种模式都写一个 16 字节密钥校验值（KCV）= KDFEntry(真主密钥, "KEYK", 每构建随机 salt)[0:16]：
// 运行期在**任何解密之前**用它判定"手里这把主密钥对不对"，不对就走专用退出码 0xC0DE0007。
// loadKeyIn：-key-in 既接受 64 位 hex 字面量，也接受文件路径（32 字节原始密钥，或 64 位 hex 文本）。
// 存在的意义：让"同一把主密钥"能跨工具升级、跨构建复用 —— 否则每次 vmpbuild 都会生成新钥匙，
// 客户升级一次工具就得把所有已发出的 .vmpkey 换一遍。
func loadKeyIn(s string) ([]byte, error) {
	// 上了狗之后主密钥可以直接从狗里读，**不落地**：-key-in dongle:<fileID>:<offset>:<length>
	// 需要 VMPX_SENTINEL_VENDOR_CODE（真狗）或 VMPX_SENTINEL_FAKE（假后端，测试/演示）。
	if strings.HasPrefix(s, "dongle:") {
		parts := strings.Split(strings.TrimPrefix(s, "dongle:"), ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("dongle: 形式应为 dongle:<fileID>:<offset>:<length>")
		}
		fid, e1 := strconv.ParseUint(parts[0], 10, 32)
		off, e2 := strconv.ParseUint(parts[1], 10, 32)
		ln, e3 := strconv.ParseUint(parts[2], 10, 32)
		if e1 != nil || e2 != nil || e3 != nil {
			return nil, fmt.Errorf("dongle: 的三个数字解析失败: %v/%v/%v", e1, e2, e3)
		}
		if ln != 32 {
			return nil, fmt.Errorf("主密钥是 32 字节，请用 dongle:%d:%d:32", fid, off)
		}
		be, oerr := sentinel.Open(sentinel.Options{VendorCode: os.Getenv("VMPX_SENTINEL_VENDOR_CODE"), DLLPath: os.Getenv("VMPX_SENTINEL_DLL")})
		if oerr != nil {
			return nil, fmt.Errorf("打开 Sentinel 后端失败: %w", oerr)
		}
		if lerr := be.Login(os.Getenv("VMPX_SENTINEL_VENDOR_CODE"), 0); lerr != nil {
			return nil, fmt.Errorf("狗登录失败: %w", lerr)
		}
		defer func() { _ = be.Logout() }()
		k, rerr := be.ReadMemory(uint32(fid), uint32(off), uint32(ln))
		if rerr != nil {
			return nil, fmt.Errorf("从狗里读主密钥失败: %w", rerr)
		}
		return k, nil
	}
	if isHex64(s) {
		return hex.DecodeString(s)
	}
	b, err := os.ReadFile(s)
	if err != nil {
		return nil, fmt.Errorf("-key-in 既不是 64 位 hex，也读不到该文件: %w", err)
	}
	if len(b) == 32 {
		return b, nil
	}
	if k, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(k) == 32 {
		return k, nil
	}
	return nil, fmt.Errorf("-key-in 文件既不是 32 字节原始密钥，也不是 64 位 hex 文本")
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func generateKeyFile(tmp string, external bool, keyIn string) (string, string, uint32, error) {
	nl := string(rune(10))
	outDir := filepath.Join(tmp, "opcodes")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", "", 0, err
	}
	// **必须用密码学随机源**：这里以前是 math/rand + 时间种子（time.Now().UnixNano() ^ 常量）。
	// 那个 PRNG 的输出完全可预测 —— 攻击者只要知道大致的构建时间，就能把主密钥枚举出来，
	// 于是"产物不自足"这件事就白做了（密钥文件也不用拿了）。主密钥、KCV salt、掩码 salt、
	// 占位密钥，一个都不能用可预测的随机。
	key := make([]byte, 32)
	if keyIn != "" {
		k, err := loadKeyIn(keyIn)
		if err != nil {
			return "", "", 0, err
		}
		copy(key, k)
		// 只报来源，**绝不打印密钥本身**。
		fmt.Println("[*] 主密钥来自 -key-in（复用同一把钥匙；跨工具升级也保持一致）")
	} else if _, err := crand.Read(key); err != nil {
		return "", "", 0, fmt.Errorf("crypto/rand 不可用: %w", err)
	}
	checkSalt, err := cryptoRandU32()
	if err != nil {
		return "", "", 0, err
	}
	fieldMaskSalt, err := cryptoRandU32()
	if err != nil {
		return "", "", 0, err
	}
	kcv := inject.KDFEntry(key, vmKeyCheckRVA, checkSalt)

	baked := key
	if external {
		baked = make([]byte, 32)
		if _, err := crand.Read(baked); err != nil {
			return "", "", 0, err
		}
	}
	var sb strings.Builder
	sb.WriteString("/* 由 cmd/vmpbuild 生成：本 blob 的 AEAD 主密钥 */" + nl)
	sb.WriteString("#ifndef __ASSEMBLER__" + nl)
	if external {
		sb.WriteString("/* 1b：blob 里不放真主密钥，只有一个随机占位密钥；真密钥运行期从外部取 */" + nl)
		sb.WriteString("#define VM_KEY_EXTERNAL 1" + nl)
	}
	sb.WriteString("#define VM_KEY_BYTES {")
	for i, b := range baked {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "0x%02X", b)
	}
	sb.WriteString("}" + nl)
	// 字段混淆掩码的种子（描述符/解密表/校验表里的 RVA、长度、标志都用它派生掩码）。
	// 放 manifest 是为了让 vmpack 与运行期各自能现推出同一组掩码；它本身不是秘密，
	// 但没有主密钥就推不出掩码（真正的秘密仍是主密钥）。
	sb.WriteString(fmt.Sprintf("#define VM_FIELD_MASK_SALT 0x%08Xu"+nl, fieldMaskSalt))
	// 三个域常量集中在这里发出去（单一来源是 internal/inject/fields.go），C 侧只做异或。
	sb.WriteString(fmt.Sprintf("#define VM_FIELD_MASK_DESC   0x%08Xu"+nl, inject.FieldMaskDomainDesc))
	sb.WriteString(fmt.Sprintf("#define VM_FIELD_MASK_IMAGE  0x%08Xu"+nl, inject.FieldMaskDomainImage))
	sb.WriteString(fmt.Sprintf("#define VM_FIELD_MASK_VERIFY 0x%08Xu"+nl, inject.FieldMaskDomainVerify))
	// KCV：不泄露主密钥（ChaCha20 块输出的截断 + 随机 salt），但足以判定密钥对不对。
	sb.WriteString(fmt.Sprintf("#define VM_KEY_CHECK_SALT 0x%08Xu"+nl, checkSalt))
	sb.WriteString(fmt.Sprintf("#define VM_KEY_CHECK_RVA 0x%08Xu"+nl, vmKeyCheckRVA))
	sb.WriteString("#define VM_KEY_CHECK_LEN 16" + nl)
	sb.WriteString("#define VM_KEY_CHECK_BYTES {")
	for i := 0; i < 16; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "0x%02X", kcv[i])
	}
	sb.WriteString("}" + nl)
	// ChaCha 的 sigma 常量按**本次构建**随机化：规范值就是那 16 个 ASCII 字节，
	// 静态分析一眼就能认出用的是哪种流密码。这里存 (规范值 ^ mask)，mask 只存在于本次构建。
	sigmaMask := uint32(key[0]) | uint32(key[1])<<8 | uint32(key[2])<<16 | uint32(key[3])<<24
	sb.WriteString(fmt.Sprintf("#define VM_SIGMA_MASK 0x%08Xu"+nl, sigmaMask))
	for i, w := range []uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574} {
		sb.WriteString(fmt.Sprintf("#define VM_SIGMA_OBF%d 0x%08Xu"+nl, i, w^sigmaMask))
	}
	sb.WriteString("#endif" + nl)
	p := filepath.Join(outDir, "vm_crypto_key.h")
	if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
		return "", "", 0, err
	}
	return p, fmt.Sprintf("%x", key), fieldMaskSalt, nil
}

// appendUnique 只在列表里还没有这个名字时才追加（BLOB.sources 与内置追加可能重叠）。
func appendUnique(list []string, name string) []string {
	for _, s := range list {
		if s == name {
			return list
		}
	}
	return append(list, name)
}

func compile(cc, stageRoot, src, tmp, opcodeValuesPath, keyPath, guest string, verbose bool) ([]string, error) {
	// 把整个 stageRoot（默认 stub/）树按原样拷进 ASCII 临时目录。
	// 这样平台目录之间可以互相引用（例如 Linux 复用 win/x64 的 vm_interp.c），
	// 而不需要复制出会漂移的两份实现。
	if err := stageTree(stageRoot, tmp); err != nil {
		return nil, err
	}

	platformRel, err := filepath.Rel(stageRoot, src)
	if err != nil {
		return nil, err
	}
	platformRel = filepath.ToSlash(platformRel)
	platformDir := filepath.Join(tmp, filepath.FromSlash(platformRel))
	if _, err := os.Stat(filepath.Join(platformDir, "vm_abi.h")); err != nil {
		return nil, fmt.Errorf("平台目录 %s 缺少 vm_abi.h", platformRel)
	}
	// 编译器目标 ABI：mingw 编译出来的 blob 内部是 Win64 约定，
	// 即使在为 Linux 构建时也必须告诉入口（否则调用 vm_run 会传错寄存器）。
	compilerIsWindows := false
	machine := ""
	if out, derr := exec.Command(cc, "-dumpmachine").Output(); derr == nil {
		machine = strings.ToLower(string(out))
		// 必须覆盖**所有** Windows 目标三元组：mingw（x86_64-w64-mingw32）之外，还有原生 Windows/ARM64 上
		// clang 的默认目标 aarch64-pc-windows-msvc —— 它既不含 "mingw" 也不含 "w64"，只认这两个会让
		// win/arm64 漏掉 VM_BLOB_USES_WIN64（探针实测），进而让 1b 的守卫误报 #error（STATUS #500）。
		compilerIsWindows = strings.Contains(machine, "mingw") || strings.Contains(machine, "w64") ||
			strings.Contains(machine, "windows") || strings.Contains(machine, "msvc") ||
			strings.Contains(machine, "win32")
	}
	// -mno-red-zone 是 x86 专有选项：aarch64-linux-gnu-gcc 之类会直接报 unrecognized。
	// 只在 x86 宿主（或探测不到目标时）加上它。
	isX86Host := machine == "" || strings.Contains(machine, "x86_64") || strings.Contains(machine, "amd64") || strings.Contains(machine, "i686")
	if verbose && compilerIsWindows {
		fmt.Println("[*] 编译器目标是 Windows ABI：将定义 VM_BLOB_USES_WIN64")
	}

	common := []string{
		"-c", "-O1", "-std=c11", // -O2 会把解释器编译错（见 STATUS 第 71/72 轮），先用 -O1
		"-ffreestanding", "-nostdlib", "-fno-builtin",
		"-fno-stack-protector", "-fno-asynchronous-unwind-tables",
		"-fno-unwind-tables", "-fno-ident",
		"-fno-jump-tables",
		// 解释器里有大量类型双关（u64 ↔ u8* ↔ double/float）。没有这个开关时，
		// 把浮点写回加进来会让 gcc 对**整个函数**启用更激进的别名假设，
		// 结果连不执行浮点的函数都算错（实测就是这么来的）。
		"-fno-strict-aliasing",
		// 注：曾试过 -fstack-clash-protection（当时怀疑 Windows 哨兵页），实测并不能修复那个崩溃，
		"-Wall", "-Wextra",
	}
	if isX86Host {
		common = append(common, "-mno-red-zone")
	}
	// aarch64 上 gcc 默认开启 outline-atomics：__atomic_*（缓存锁、in-use 计数、以及 OP_ATOMIC）
	// 会变成对 libgcc 助手（例如 __aarch64_swp4_acq）的调用，而我们的 blob 是 freestanding、
	// 不带 libgcc —— CI 的 linux-arm64 作业报的就是这个符号。
	// -mno-outline-atomics 让它改成内联的 LL/SC 循环，语义不变。
	// 注意：clang 不认这个选项（Windows/arm64 原生 runner 用的是 clang）——只对 gcc 加。
	isClang := strings.Contains(strings.ToLower(filepath.Base(cc)), "clang") || strings.Contains(machine, "msvc")
	if (strings.Contains(machine, "aarch64") || strings.Contains(machine, "arm64")) && !isClang {
		common = append(common, "-mno-outline-atomics")
	}
	if releaseBuild {
		common = append(common, "-DVM_RELEASE=1",
			fmt.Sprintf("-DVM_DESC_MAGIC=0x%Xu", releaseMagic))
	}

	// 只编译 BLOB.sources 里显式列出的文件（测试/工具程序不能被链进 blob）
	sources, err := readSourceList(src)
	if err != nil {
		return nil, err
	}
	// 加密支持：解释器固定编进 vm_crypto.c；密钥用 -include 注入（见下）。
	// 注意：这两个文件可能**已经**写在 BLOB.sources 里 —— 重复追加会被编译两次，
	// 于是同名全局符号在两个目标文件里各定义一次，合并时报"全局符号重复"
	// （CI 的 linux-arm64 作业就死在 arm64_mask_w 上）。所以按名字去重。
	sources = appendUnique(sources, "win/x64/vm_crypto.c")
	sources = appendUnique(sources, "win/x64/vm_kdf.c")
	if guest == "arm64" {
		// ARM64 客户机：标志位/条件码语义来自 stub/arm64 的独立模块
		sources = appendUnique(sources, "arm64/guest_semantics_arm64.c")
	}

	var objs []string
	for _, srcName := range sources {
		srcPath := filepath.Join(tmp, filepath.FromSlash(srcName))
		if _, err := os.Stat(srcPath); err != nil {
			return nil, fmt.Errorf("BLOB.sources 里的 %s 不存在（路径相对 %s）", srcName, stageRoot)
		}
		objName := strings.ReplaceAll(srcName, "/", "_") + ".o"
		// -include 强制先包含平台的 vm_abi.h：
		// 同一个 vm_interp.c 因此可以用不同 ABI 头编译（Windows / Linux）。
		// 描述符魔数走一个生成头：C 与 .S 都要拿到**同一个**值（release 每次构建随机）。
		// 只靠 -D 曾经在汇编这一侧不生效，现象是 release 产物里 stub 校验的仍是默认魔数、
		// 描述符却是随机值 → 校验失败 → 按"没有描述符"走 → 空指针访问违例。
		descHdr := filepath.Join(tmp, "desc_magic.h")
		if _, err := os.Stat(descHdr); err != nil {
			// 同时发出高低 16 位：aarch64 的入口汇编只能用 movz/movk 拼常数，
			// 不能再像以前那样把 "VMPK" 写死在汇编里（魔数现在每次构建都随机）。
			if werr := os.WriteFile(descHdr, []byte(fmt.Sprintf(
				// LO/HI 不带 u 后缀：它们是给**汇编器**（aarch64 的 movz/movk 立即数）吃的。
				"#ifndef VM_DESC_MAGIC\n#define VM_DESC_MAGIC 0x%Xu\n#define VM_DESC_MAGIC_LO 0x%X\n#define VM_DESC_MAGIC_HI 0x%X\n#endif\n",
				releaseMagic, releaseMagic&0xFFFF, (releaseMagic>>16)&0xFFFF)), 0o644); werr != nil {
				return nil, werr
			}
		}
		args := append(append([]string{}, common...),
			"-include", descHdr,
			"-include", filepath.Join(platformDir, "vm_abi.h"),
			"-include", opcodeValuesPath,
			"-include", keyPath)
		// 共享头文件（vm_types.h / vm_opcodes.h）住在 win/x64 下：任何平台目录都要能包含到它，
		// 否则 linux/arm64 这类平台的 guest_semantics_arm64.h 会找不到 vm_types.h（CI 实测过）。
		args = append(args, "-I", filepath.Join(tmp, "win", "x64"))
		if guest == "x86-32" {
			// 32 位 x86 客户机：与 x86-64 **共用**同一套解释器与语义模块，
			// 只多一个编译期开关 —— 它把栈槽宽度换成 4 字节（push/pop/call/ret）。
			// 运算部分不需要特判：每条 IR 自带宽度。
			args = append(args, "-DVM_GUEST_X86_32=1")
		}
		if guest == "arm64" {
			// ARM64 客户机：语义模块在 arm64/ 下，它自己又 include vm_types.h
			args = append(args,
				// aarch64 上非 PIC 代码会经字面量池产生绝对重定位，而我们的合并器按设计拒绝绝对重定位；
				// 统一按位置无关来编，让 GNU 工具链也只生成 PC 相对形式。
				// -fPIC 已撤销：clang 的 aarch64-pc-windows-msvc 不支持它；真正的修法见下面的 -fno-pie
				"-DVM_GUEST_ARM64=1", "-DVM_REG_COUNT=35",
				"-I", platformDir,
				"-I", filepath.Join(tmp, "arm64"))
			// Ubuntu 的 gcc 默认 PIE：arm64 上会为全局符号生成 GOT 引用（R_AARCH64_ADR_GOT_PAGE），
			// 而合并器按设计只接受 PC 相对形式。只在 arm64 且非 Windows 编译器（即 Linux 交叉 GNU 工具链）上关掉 PIE ——
			// 加到 x86-64 会让它改用绝对 32 位寻址（R_X86_64_32S），反而把 linux-amd64 弄红（已经发生过）。
			if !compilerIsWindows {
				args = append(args, "-fno-pie")
			}
		}
		// 运行期补丁比对：**所有目标**都打开。
		// 曾经只在 Windows 目标上打开，因为我在 ELF 上复算出"期望值与实际字节对不上"——
		// 事后查明那两次复算都用了过期/张冠李戴的 artifact（本项目第五次"工具与被测对象不同步"）：
		// 用同一次构建的产物复算，PE 与 ELF 的 FNV(key[:8] || patch) 与描述符 pad 都完全一致。
		// 目前只在 Windows 目标上打开：公式两边其实是一致的（用同一次构建的产物复算，PE 与 ELF 的
		// FNV(key[:8] || patch) 都与描述符 pad 相符 —— 我此前两次"对不上"都是拿了过期/张冠李戴的 artifact，
		// 这是本项目第五次"工具与被测对象不同步"）。但把宏对所有目标打开后，ELF 载荷测试仍失败，
		// 且不是被 trap 拦下而是结果错乱 —— 说明 ELF 路径另有原因（疑似 blob 变大后与注入/映射相关），
		// 记为待查项；先保住已验证的 PE 运行期校验。
		// 运行期补丁比对：所有目标都打开。ELF 上"对不上"的两次都是测量/夹具问题（夹具只映射 payload 段，
		// 目标入口页不在映射里 → 校验读不到补丁字节 → trap），现在夹具会补映射补丁页，故两边一致。
		args = append(args, "-DVM_INVM_PATCHCHECK=1")
		// 同一个 vm_interp.c 会为目标平台各编一份：运行期能力（改页保护）必须按**目标 OS** 选，
		// 不能按编译宿主的 ABI 选 —— 否则 Linux 载荷里会编进 PEB/VirtualProtect 那一套。
		//
		// 注意：这个判断**不能**放进下面的 compilerIsWindows 分支里。第一版就是那样写的，
		// 于是**在 Linux 上用原生 gcc 编** Linux 载荷时 VM_BLOB_TARGET_LINUX 根本没定义，
		// 编进去的是 #else 的桩（返回 -9）→ 入口蹦床 fail-fast 命中 ud2 → 加密后的 ELF 直接
		// SIGILL（CI run #289 现场；线索是构建期那条 "'vm_img_done' defined but not used" 警告）。
		if strings.Contains(filepath.ToSlash(src), "linux") {
			args = append(args, "-DVM_BLOB_TARGET_LINUX=1")
		}
		if compilerIsWindows {
			args = append(args, "-DVM_BLOB_USES_WIN64=1")
			// 32 位 Windows 宿主（i686 mingw）：告诉 C 源"这是一条受支持的 Windows 宿主"，
			// 但它**不等于** x86_64 —— 真·x64 的内联汇编块仍只在 __x86_64__/_M_X64 下编译。
			if strings.Contains(machine, "i686") || strings.Contains(machine, "i386") {
				args = append(args, "-DVM_HOST_X86_32=1")
			}
		}
		args = append(args, "-o", objName, srcPath)
		if verbose {
			fmt.Println("[*]", cc, strings.Join(args, " "))
		}
		cmd := exec.Command(cc, args...)
		cmd.Dir = tmp
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		combined, err := cmd.CombinedOutput()
		if len(combined) > 0 {
			fmt.Fprint(os.Stderr, string(combined))
		}
		if err != nil {
			return nil, fmt.Errorf("编译 %s 失败: %w", srcName, err)
		}
		// 返回**绝对路径**：多目标直拼要直接读它们，而 cmd.Dir 只是编译时的工作目录
		objs = append(objs, filepath.Join(tmp, objName))
	}
	if len(objs) == 0 {
		return nil, fmt.Errorf("目录 %s 里没有可编译的源文件", src)
	}

	return objs, nil
}

// parsedObjs 读取一批目标文件（多目标直拼的输入）
func parsedObjs(paths []string) []*objFile {
	out := make([]*objFile, 0, len(paths))
	for _, p := range paths {
		ob, err := readObject(p)
		must(err)
		out = append(out, ob)
	}
	return out
}

// mergeWithLd 用 GNU ld -r 把多个目标文件合并成一个（x86-64 路径一直用它）
func mergeWithLd(tmp string, objs []string, verbose bool) (string, error) {
	out := filepath.Join(tmp, "vm_all.o")
	ldArgs := append([]string{"-r", "-o", out}, objs...)
	if verbose {
		fmt.Println("[*] ld", strings.Join(ldArgs, " "))
	}
	ldCmd := exec.Command("ld", ldArgs...)
	ldCmd.Dir = tmp
	ldOut, err := ldCmd.CombinedOutput()
	if len(ldOut) > 0 {
		fmt.Fprint(os.Stderr, string(ldOut))
	}
	if err != nil {
		return "", fmt.Errorf("ld -r 合并失败（可用 -merge go 走内置直拼）: %w", err)
	}
	return out, nil
}

// stageTree 递归复制目录树（保留相对路径）
func stageTree(root, dst string) error {
	return filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}

// readSourceList 读取 BLOB.sources（每行一个文件名，# 开头为注释）
func readSourceList(dir string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "BLOB.sources"))
	if err != nil {
		return nil, fmt.Errorf("读取 BLOB.sources 失败: %w", err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("BLOB.sources 为空")
	}
	return out, nil
}

// readABIConstants 从 vm_abi.h 读取帧大小与栈余量（单一事实来源在 C 头文件里）
func readABIConstants(src string) (frameSize, margin, skewExtra int, err error) {
	b, err := os.ReadFile(filepath.Join(src, "vm_abi.h"))
	if err != nil {
		return 0, 0, 0, err
	}
	re := regexp.MustCompile("(?m)^#define\\s+(VM_FRAME_SIZE|VM_MARGIN|VM_FRAME_SKEW_EXTRA)\\s+(0x[0-9A-Fa-f]+|\\d+)")
	got := map[string]int{}
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		v, perr := strconv.ParseInt(m[2], 0, 64)
		if perr != nil {
			return 0, 0, 0, perr
		}
		got[m[1]] = int(v)
	}
	if got["VM_FRAME_SIZE"] == 0 || got["VM_MARGIN"] == 0 {
		return 0, 0, 0, fmt.Errorf("vm_abi.h 里缺少 VM_FRAME_SIZE / VM_MARGIN")
	}
	// 只在**旧头文件里缺少该宏**时按 16 兼容；显式写 0 的必须保持 0。
	// arm64 平台就是显式 0（BL 不压栈，没有 x86 那种返回地址额外 8 字节）。
	// 之前用 == 0 判断，会把它的 0 改成 16，于是 lifter 对 [sp+disp]（disp>=0，调用方帧）的换算整体偏 16 字节。
	if _, present := got["VM_FRAME_SKEW_EXTRA"]; !present {
		got["VM_FRAME_SKEW_EXTRA"] = 16
	}
	return got["VM_FRAME_SIZE"], got["VM_MARGIN"], got["VM_FRAME_SKEW_EXTRA"], nil
}

// measureMaxFrame 用 objdump 统计各函数的最大 sub rsp，作为 VM_MARGIN 的安全性依据
func measureMaxFrame(objdump, obj string, verbose bool) (int, error) {
	out, err := exec.Command(objdump, "-d", obj).CombinedOutput()
	if err != nil {
		// 不能因为量不到就把构建掐死：Windows/arm64 原生 runner 上没有 GNU objdump。
		// 但也不能静默 —— 用 [!] 打出来（CI 的注解通道会带上它），并让保守的 margin 兜底。
		fmt.Printf("[!] objdump 不可用（%v）：VM_MARGIN 的守卫这次跑不了，按 0 处理，请确认 margin 足够大\n", err)
		return 0, nil
	}
	cur := ""
	max := 0
	reFn := regexp.MustCompile("^[0-9a-f]+ <([^>]+)>:")
	reSub := regexp.MustCompile("sub\\s+\\$0x([0-9a-f]+),%rsp")
	// AArch64：帧分配是 `sub sp, sp, #imm` 或前索引 `str/stp ...[sp, #-imm]!`
	reSubA64 := regexp.MustCompile("sub\\s+sp,\\s+sp,\\s+#0x([0-9a-f]+)")
	rePreA64 := regexp.MustCompile("\\[sp,\\s+#-0x([0-9a-f]+)\\]!")
	// AArch64 的大帧：`mov x9, #N` 之后 `sub sp, sp, x9`（stub 就是这样分配 4688 字节帧的，
	// 因为 4688 超过 sub 的 imm12 范围）。之前的模式只认 `sub sp, sp, #imm`，于是量出来 0。
	reMovA64 := regexp.MustCompile("mov\\s+x[0-9]+,\\s+#0x([0-9a-f]+)")
	reSubReg := regexp.MustCompile("sub\\s+sp,\\s+sp,\\s+x[0-9]+")
	pendingA64 := ""
	for _, line := range strings.Split(string(out), "\n") {
		if m := reFn.FindStringSubmatch(line); m != nil {
			cur = m[1]
		}
		record := func(hexv string) {
			v, _ := strconv.ParseInt(hexv, 16, 64)
			if verbose {
				fmt.Printf("    [frame] %-24s 0x%X\n", cur, v)
			}
			if int(v) > max {
				max = int(v)
			}
		}
		if m := reSub.FindStringSubmatch(line); m != nil {
			record(m[1])
		}
		if m := reSubA64.FindStringSubmatch(line); m != nil {
			record(m[1])
		}
		if m := reMovA64.FindStringSubmatch(line); m != nil {
			pendingA64 = m[1]
		}
		if pendingA64 != "" && reSubReg.MatchString(line) {
			record(pendingA64)
			pendingA64 = ""
		}
		if m := rePreA64.FindStringSubmatch(line); m != nil {
			record(m[1])
		}
	}
	if max == 0 {
		// 测量失效必须吵出来：这个值决定 margin 是否够用，静默为 0 会让守卫形同虚设（曾经的假绿）。
		fmt.Printf("[warn] 未能从 %s 量到任何栈帧（maxStubStackFrame=0）：VM_MARGIN 的守卫将失去意义，请检查 objdump 语法\n", obj)
	}
	return max, nil
}

// buildBlob 按顺序拼接需要保留的节，并记录每个节在 blob 中的偏移
func isASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", a...)
	os.Exit(1)
}

var _ = io.Discard

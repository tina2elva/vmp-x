// Package coverage 量化"真实编译产物里有多少代码能被我们的 lifter 翻译"。
//
// 为什么需要它：这个 PoC 一直只在几个手写目标程序上验证过。要判断"能不能拿真实程序来用"，
// 必须有一手的覆盖率数字，而不是感觉。
//
// 函数边界的来源（不猜地址，宁可少算）：
//   - ELF：符号表的 STT_FUNC + Size（Go/gcc 默认不 strip）；
//   - PE ：.pdata 的 RUNTIME_FUNCTION 表（x86-64 Windows 上这是**权威**边界来源，
//     stripped 的 DLL 也有），因此能覆盖 C/C++ 运行时这类真实代码。
package coverage

import (
	"debug/elf"
	"debug/pe"
	"fmt"
	"sort"
	"strings"

	arm64dec "github.com/vmpx/vmp-x/internal/decode/arm64"
	x64dec "github.com/vmpx/vmp-x/internal/decode/x64"
	"github.com/vmpx/vmp-x/internal/ir"
	arm64 "github.com/vmpx/vmp-x/internal/lift/arm64"
	"github.com/vmpx/vmp-x/internal/lift/x64"
)

// curArch：当前分析的客户机 ISA（"x86-64" / "arm64"）。由 analyzeELF/analyzePE 设置，
// analyzeFunc 据此选择解码器与 lifter。
var curArch = "x86-64"

// FuncStat 单个函数的分析结果
type FuncStat struct {
	Name    string
	RVA     uint32
	Bytes   int
	Instrs  int
	Bad     int
	Reasons []string
	Note    string
}

// OnlyFuncs：只统计这些名字的函数（空表示全部；PE 的 .pdata 没有名字，故只对 ELF 生效）
var OnlyFuncs []string

// Report 一个文件的覆盖率报告
type Report struct {
	img         func(rva uint32, n int) []byte // 镜像读取（跳转表）
	Path        string
	Kind        string // "ELF" / "PE"
	Arch        string
	Funcs       int
	Full        int // 整段可翻译
	Partial     int // 部分可翻译
	None        int // 一条都翻不了
	FuncInstrs  int
	FuncBad     int
	ReasonTop   map[string]int
	MnemonicTop map[string]int
	SPLostTop   map[string]int      // "弄丢 RSP 跟踪"的指令（Go 二进制里的大头）
	Examples    map[string][]string // 每个原因给出最多 3 个具体指令样本（便于决定下一步补什么）
	Sample      []FuncStat          // 少量代表性失败样本（便于定位）
	Note        string
}

// Analyze 分析一个 PE/ELF 文件
func Analyze(path string) (*Report, error) {
	if isELF(path) {
		return analyzeELF(path)
	}
	return analyzePE(path)
}

func isELF(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// analyzeFunc 逐条解码 + 整体 lift，统计指令级与函数级可翻译性
func analyzeFunc(r *Report, name string, rva uint32, code []byte) FuncStat {
	st := FuncStat{Name: name, RVA: rva, Bytes: len(code)}
	var fn *ir.Func
	if curArch == "arm64" {
		// AArch64：定长 4 字节指令，先整体解码再 Lift（解码失败时如实记录到哪停）。
		insns, derr := arm64dec.DecodeRange(code, uint64(rva), 0)
		if len(insns) == 0 {
			st.Note = fmt.Sprintf("解码失败: %v", derr)
			return st
		}
		st.Instrs = len(insns)
		lf := &arm64.Lifter{}
		fn = &ir.Func{Name: name, RVA: rva, Size: len(code)}
		lf.Lift(fn, insns)
	} else {
		// 逐条解码（自己循环，这样"解码到哪一条失败"是精确的）
		off := 0
		for off < len(code) {
			ins, err := x64dec.Decode(code[off:], uint64(off))
			if err != nil || ins.Len() <= 0 {
				st.Note = fmt.Sprintf("解码在 +0x%X 停止: %v", off, err)
				break
			}
			st.Instrs++
			off += ins.Len()
		}
		// 整体 lift：拿 Unsupported 列表
		l := &x64.Lifter{}
		if r.img != nil {
			l.SetImageReader(r.img)
		}
		// 覆盖率只关心"能不能翻译"：给一个假的 XMM 寄存器堆地址即可
		// （真实的堆在 blob 的 .bss 里，由 vmpack 用符号表算出来）。
		l.SetXMMArea(0x40000000)
		// 同理：SIMD 按位运算借通用寄存器时要用 blob 里的暂存槽（vm_tmp）。
		// 不设它的话，含这类指令的函数会被判成『部分可翻译』，覆盖率会凭空变低。
		l.SetScratchArea(0x40001000)
		fn, _ = l.LiftFunc(name, code, rva)
	}
	bad := 0
	if fn != nil {
		bad = len(fn.Unsupported)
		for _, u := range fn.Unsupported {
			reason := u
			mn := "-"
			if i := strings.Index(u, "— "); i >= 0 {
				reason = strings.TrimSpace(u[i+len("— "):])
			}
			// 从 "…: <指令文本> — <原因>" 里取出助记符
			if i := strings.Index(u, ": "); i >= 0 {
				rest := u[i+2:]
				if j := strings.Index(rest, "—"); j > 0 {
					txt := strings.Fields(strings.TrimSpace(rest[:j]))
					if len(txt) > 0 {
						mn = txt[0]
					}
				}
			}
			// "RSP 已被不可跟踪的方式修改（<指令>）"：把 <指令> 单独聚合
			if strings.Contains(reason, "不可跟踪") {
				if a := strings.Index(reason, "（"); a >= 0 {
					if b := strings.Index(reason[a:], "）"); b > 0 {
						r.SPLostTop[reason[a+len("（"):a+b]]++
					}
				}
			}
			if len(r.Examples[reason]) < 3 {
				r.Examples[reason] = append(r.Examples[reason], strings.TrimSpace(u))
			}
			r.ReasonTop[reason]++
			r.MnemonicTop[mn]++
		}
	}
	st.Bad = bad
	return st
}

func (r *Report) addFunc(st FuncStat) {
	r.Funcs++
	r.FuncInstrs += st.Instrs
	r.FuncBad += st.Bad
	switch {
	case st.Instrs == 0:
		r.None++
	case st.Bad == 0:
		r.Full++
	default:
		r.Partial++
	}
	if st.Bad > 0 && len(r.Sample) < 8 && st.Instrs > 0 {
		r.Sample = append(r.Sample, st)
	}
}

func newReport(path, kind, arch string) *Report {
	return &Report{Path: path, Kind: kind, Arch: arch,
		ReasonTop: map[string]int{}, MnemonicTop: map[string]int{}, SPLostTop: map[string]int{}, Examples: map[string][]string{}}
}

// ---------------- ELF ----------------

func analyzeELF(path string) (*Report, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := newReport(path, "ELF", f.Machine.String())
	switch f.Machine {
	case elf.EM_X86_64:
		curArch = "x86-64"
	case elf.EM_AARCH64:
		curArch = "arm64"
	default:
		r.Note = "既不支持 x86-64 也不支持 ARM64，跳过"
		return r, nil
	}
	syms, err := f.Symbols()
	if err != nil {
		return r, nil // 没有符号表：无法得到函数边界，如实留空
	}
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Size == 0 {
			continue
		}
		if len(OnlyFuncs) > 0 && !nameMatches(s.Name) {
			continue
		}
		if int(s.Section) >= len(f.Sections) {
			continue
		}
		sec := f.Sections[s.Section]
		if sec.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		data, derr := sec.Data()
		if derr != nil || s.Value < sec.Addr {
			continue
		}
		off := s.Value - sec.Addr
		if off+uint64(s.Size) > uint64(len(data)) {
			continue
		}
		r.img = func(rva uint32, n int) []byte {
			for _, s2 := range f.Sections {
				if s2.Flags&elf.SHF_ALLOC == 0 || s2.Addr == 0 {
					continue
				}
				va := uint64(rva)
				if va >= s2.Addr && va+uint64(n) <= s2.Addr+s2.Size {
					d2, e2 := s2.Data()
					if e2 != nil {
						return nil
					}
					st := va - s2.Addr
					return d2[st : st+uint64(n)]
				}
			}
			return nil
		}
		st := analyzeFunc(r, s.Name, uint32(off), data[off:off+uint64(s.Size)])
		r.addFunc(st)
	}
	return r, nil
}

// ---------------- PE ----------------

func analyzePE(path string) (*Report, error) {
	df, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer df.Close()
	arch := "unknown"
	switch df.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = "x86-64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		arch = "ARM64"
	}
	r := newReport(path, "PE", arch)
	if df.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		r.Note = "非 x86-64，跳过"
		return r, nil
	}
	// 找 .pdata（RUNTIME_FUNCTION 表）
	var pdata *pe.Section
	for _, s := range df.Sections {
		if s.Name == ".pdata" {
			pdata = s
			break
		}
	}
	if pdata == nil {
		r.Note = "没有 .pdata，无法得到权威函数边界"
		return r, nil
	}
	data, derr := pdata.Data()
	if derr != nil {
		return nil, derr
	}
	for off := 0; off+12 <= len(data); off += 12 {
		begin := le32(data[off:])
		end := le32(data[off+4:])
		if begin == 0 || end <= begin {
			continue
		}
		code, rva, ok := readRVA(df, begin, end-begin)
		if !ok {
			continue
		}
		r.img = func(want uint32, n int) []byte {
			b, _, ok := readRVA(df, want, uint32(n))
			if !ok {
				return nil
			}
			return b
		}
		st := analyzeFunc(r, fmt.Sprintf("sub_%X", begin), rva, code)
		r.addFunc(st)
	}
	return r, nil
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// readRVA 按 RVA 读一段（只支持在同一节内，且节是文件-backed 的）
func readRVA(df *pe.File, rva, size uint32) ([]byte, uint32, bool) {
	for _, s := range df.Sections {
		if rva < s.VirtualAddress || rva+size > s.VirtualAddress+s.VirtualSize {
			continue
		}
		d, err := s.Data()
		if err != nil {
			return nil, 0, false
		}
		start := rva - s.VirtualAddress
		if start+size > uint32(len(d)) {
			return nil, 0, false
		}
		return d[start : start+size], start, true
	}
	return nil, 0, false
}

// nameMatches 名字过滤（后缀匹配，方便 "check_key" 命中 "main.check_key"）
func nameMatches(name string) bool {
	for _, want := range OnlyFuncs {
		if name == want || strings.HasSuffix(name, "."+want) {
			return true
		}
	}
	return false
}

// Top 把 map 排序成 Top-N 列表
func Top(m map[string]int, n int) []string {
	type kv struct {
		K string
		V int
	}
	var xs []kv
	for k, v := range m {
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool {
		if xs[i].V != xs[j].V {
			return xs[i].V > xs[j].V
		}
		return xs[i].K < xs[j].K
	})
	var out []string
	for i := 0; i < len(xs) && i < n; i++ {
		out = append(out, fmt.Sprintf("%-46s %6d", xs[i].K, xs[i].V))
	}
	return out
}

// Package inject 组装 payload（解释器 blob + 描述符 + thunk + 字节码）并写入目标文件。
//
// payload 内部布局（与容器无关）：
//
//	[0 .. len(stub))            解释器 blob（vm_entry 在 StubEntry 处）
//	[align16][desc(16)+thunk(12)] * N
//	[align16][每个函数的字节码]
//
// 所有跨引用都是 PC-relative 或“相对描述符自身”的偏移，因此 payload 整块放到
// 任意地址都不需要重定位表参与。PE 与 ELF 只是“往哪里放、怎么打补丁”不同。
package inject

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
)

const (
	descSize  = 64         // 与 vm_abi.h 的 VM_DESC_SIZE 一致（含 AEAD 的 nonce/tag 字段）
	descMagic = 0x4B504D56 // "VMPK"
)

// FuncSpec 一个待保护函数
type FuncSpec struct {
	Name string
	RVA  uint32 // 相对镜像基址的地址（PE 的 RVA / ELF 的 VA-imageBase）
	Code []byte // VM 字节码
}

// EncryptFunc 加密钩子：把明文字节码密封成密文 + nonce + tag。
// 返回的密文长度必须等于明文长度（ChaCha20 是流密码），这样 payload 布局不受影响。
// aad 把密文绑定到**具体槽位**（selfRVA || funcRVA）：把一段合法密文换到另一个函数位置会验签失败。
type EncryptFunc func(plain []byte, aad []byte) (ct []byte, nonce [12]byte, tag [16]byte, err error)

// Options 注入参数
type Options struct {
	SectionName string
	Stub        []byte
	StubEntry   int // vm_entry 在 stub 内的偏移
	Funcs       []FuncSpec
	// Encrypt 非 nil 时启用 AEAD：解释器在 vm_run 入口验签并解密到帧内缓冲。
	Encrypt EncryptFunc
	// BSSOff/BSSSize 描述 blob 里"可写数据"（.bss）的区间：
	// 它必须被单独映射成一个 **RW** 段，其余部分按 RX 映射（代码段不该可写）。
	BSSOff  int
	BSSSize int
	// Arch 目标架构："x86-64"（默认）或 "arm64"。
	// 影响两处**架构相关**的编码：thunk 的调用指令（E8 rel32 / BL imm26）
	// 与函数入口补丁（E9 rel32 / B imm26）。
	Arch Arch
}

// Arch 目标架构
type Arch string

const (
	ArchX64   Arch = "x86-64"
	ArchARM64 Arch = "arm64"
)

// archInfo 每个架构的编码参数（thunk 长度与入口补丁长度）
func (a Arch) info() (thunkLen, patchLen int, err error) {
	switch a {
	case "", ArchX64:
		return 5, 5, nil // E8 rel32 / E9 rel32
	case ArchARM64:
		// 入口补丁 8 字节：mov x16, x30（先把调用方的返回地址挪到 IP0）+ b thunk
		// 为什么不只用 4 字节的 b：thunk 里的 BL vm_entry 会覆盖 X30（LR），
		// 而 X30 正是客户机期待的"返回地址"——所以必须在进入 thunk 之前把它存到 x16。
		return 4, 8, nil
	default:
		return 0, 0, fmt.Errorf("不支持的目标架构 %q", string(a))
	}
}

// Placement 单个函数的落点信息（地址都是“相对镜像基址”的偏移）
type Placement struct {
	Name          string `json:"name"`
	FuncRVA       uint32 `json:"funcRVA"`
	BytecodeSize  int    `json:"bytecodeBytes"`
	DescRVA       uint32 `json:"descRVA"`
	ThunkRVA      uint32 `json:"thunkRVA"`
	CodeRVA       uint32 `json:"codeRVA"`
	EntryPatch    []byte `json:"-"`
	EntryPatchHex string `json:"entryPatch"`
}

// Payload 组装结果
type Payload struct {
	Data       []byte
	Placements []Placement
	// CodeSize 是可执行部分的长度（payload 的前缀）；[BSSOff, BSSOff+BSSSize)
	// 是可写数据，注入时映射到紧接着的 RW 段。
	CodeSize int
	BSSOff   int
	BSSSize  int
}

// Result 注入结果
type Result struct {
	SectionRVA   uint32      `json:"sectionRVA"`
	SectionSize  int         `json:"sectionSize"`
	StubEntryRVA uint32      `json:"stubEntryRVA"`
	Placements   []Placement `json:"placements"`
}

// BuildPayload 组装 payload；baseRVA 是 payload 将被放置的地址（相对镜像基址）
func BuildPayload(opt Options, baseRVA uint32) (*Payload, error) {
	if len(opt.Stub) == 0 {
		return nil, fmt.Errorf("解释器 blob 为空")
	}
	// 注意用 < 0：内置合并器（-merge go）会把 vm_entry 所在节放在最前面，此时它正好是 0 ——
	// 用 <= 0 会把合法的 blob 判成坏 blob（CI 的 linux-arm64 就报 "vm_entry 偏移 0x0 超出 blob"）。
	// "符号是否存在"由调用方查 manifest 的 symbols 表决定。
	if opt.StubEntry < 0 || opt.StubEntry >= len(opt.Stub) {
		return nil, fmt.Errorf("vm_entry 偏移 0x%X 超出 blob (%d 字节)", opt.StubEntry, len(opt.Stub))
	}
	if len(opt.Funcs) == 0 {
		return nil, fmt.Errorf("没有要保护的函数")
	}

	thunkSize, patchLen, err := opt.Arch.info()
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, len(opt.Stub)+len(opt.Funcs)*(descSize+thunkSize)+4096)
	data = append(data, opt.Stub...)
	align := func(n int) {
		for len(data)%n != 0 {
			data = append(data, 0)
		}
	}
	align(16)

	type slot struct{ descOff, thunkOff int }
	slots := make([]slot, len(opt.Funcs))
	for i := range opt.Funcs {
		slots[i].descOff = len(data)
		data = append(data, make([]byte, descSize)...)
		slots[i].thunkOff = len(data)
		data = append(data, make([]byte, thunkSize)...)
	}
	align(16)

	codeOffs := make([]int, len(opt.Funcs))
	tags := make([][16]byte, len(opt.Funcs))
	nonces := make([][12]byte, len(opt.Funcs))
	for i := range opt.Funcs {
		body := opt.Funcs[i].Code
		if opt.Encrypt != nil {
			aad := make([]byte, 8)
			binary.LittleEndian.PutUint32(aad[0:], baseRVA+uint32(slots[i].descOff)) // selfRVA
			binary.LittleEndian.PutUint32(aad[4:], opt.Funcs[i].RVA)                 // funcRVA
			ct, nonce, tag, err := opt.Encrypt(opt.Funcs[i].Code, aad)
			if err != nil {
				return nil, fmt.Errorf("%s 加密失败: %w", opt.Funcs[i].Name, err)
			}
			if len(ct) != len(opt.Funcs[i].Code) {
				return nil, fmt.Errorf("%s 加密后长度变化（%d -> %d）；AEAD 必须是流密码", opt.Funcs[i].Name, len(opt.Funcs[i].Code), len(ct))
			}
			body = ct
			nonces[i] = nonce
			tags[i] = tag
		}
		codeOffs[i] = len(data)
		data = append(data, body...)
		align(16)
	}

	pl := &Payload{Data: data, CodeSize: len(data) - opt.BSSSize, BSSOff: opt.BSSOff, BSSSize: opt.BSSSize}
	for i, fn := range opt.Funcs {
		d, t, c := slots[i].descOff, slots[i].thunkOff, codeOffs[i]

		binary.LittleEndian.PutUint32(data[d+0:], descMagic)
		binary.LittleEndian.PutUint32(data[d+4:], baseRVA+uint32(d))     // selfRVA（模块基址 = 描述符地址 - selfRVA）
		binary.LittleEndian.PutUint32(data[d+8:], uint32(c-d))           // codeRVA（相对描述符）
		binary.LittleEndian.PutUint32(data[d+12:], uint32(len(fn.Code))) // codeLen（明文长度）
		binary.LittleEndian.PutUint32(data[d+16:], uint32(len(fn.Code))) // encLen（流密码：与 codeLen 相同）
		binary.LittleEndian.PutUint32(data[d+24:], fn.RVA)               // reserved1: 函数入口 RVA（AEAD 的 AAD 用它绑定槽位）
		if opt.Encrypt != nil {
			binary.LittleEndian.PutUint32(data[d+20:], 1) // flags: VM_DESC_FLAG_ENC
			// 结构体布局：8 个 u32 之后才是 nonce/tag（见 vm_abi.h 的 vm_desc_t）
			copy(data[d+32:d+44], nonces[i][:])
			copy(data[d+44:d+60], tags[i][:])
		} else {
			binary.LittleEndian.PutUint32(data[d+20:], 0)
		}

		// thunk: 调用 vm_entry。用 call 而不是“寄存器传描述符”的原因见 vm_abi.h：
		// 调用方可能把活跃值放在 volatile 寄存器里跨调用使用。
		//
		// x86-64：E8 rel32（相对**下一条指令**）
		// ARM64 ：BL imm26（相对**本指令**，PC 即 BL 的地址）
		if opt.Arch == ArchARM64 {
			bl := arm64Branch(0x94000000, int64(opt.StubEntry), int64(t))
			binary.LittleEndian.PutUint32(data[t:], bl)
		} else {
			data[t+0] = 0xE8
			binary.LittleEndian.PutUint32(data[t+1:], uint32(int32(opt.StubEntry-(t+thunkSize))))
		}

		// 函数入口补丁：跳到 thunk
		if len(fn.Code) < patchLen {
			return nil, fmt.Errorf("%s 的字节码过短，无法据此确认函数可被打补丁", fn.Name)
		}
		thunkRVA := baseRVA + uint32(t)
		var patch []byte
		if opt.Arch == ArchARM64 {
			// 8 字节：mov x16, x30 ; b thunk（±128MB 内直接跳）
			b, err := arm64BranchChecked(0x14000000, int64(thunkRVA), int64(fn.RVA)+4)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", fn.Name, err)
			}
			patch = make([]byte, 8)
			binary.LittleEndian.PutUint32(patch[0:], arm64MovX16X30)
			binary.LittleEndian.PutUint32(patch[4:], b)
		} else {
			rel := int64(thunkRVA) - int64(fn.RVA) - 5
			if rel < -0x80000000 || rel > 0x7FFFFFFF {
				return nil, fmt.Errorf("%s 到 thunk 的距离超出 rel32 范围", fn.Name)
			}
			patch = make([]byte, 5)
			patch[0] = 0xE9
			binary.LittleEndian.PutUint32(patch[1:], uint32(int32(rel)))
		}

		pl.Placements = append(pl.Placements, Placement{
			Name:          fn.Name,
			FuncRVA:       fn.RVA,
			BytecodeSize:  len(fn.Code),
			DescRVA:       baseRVA + uint32(d),
			ThunkRVA:      thunkRVA,
			CodeRVA:       baseRVA + uint32(c),
			EntryPatch:    patch,
			EntryPatchHex: fmt.Sprintf("% X", patch),
		})
	}
	return pl, nil
}

// arm64MovX16X30 = "mov x16, x30"（别名 ORR x16, xzr, x30）：把返回地址存进 IP0。
// x16/x17 是 ABI 里专门的"调用内暂存"寄存器，正好用来跨 thunk 传返回地址。
const arm64MovX16X30 = 0xAA1E03F0

// arm64Branch 生成 AArch64 的 B/BL：imm26 = (target - pc) / 4，PC 是**指令本身**的地址。
func arm64Branch(opcode uint32, target, pc int64) uint32 {
	imm := (target - pc) / 4
	return opcode | (uint32(imm) & 0x03FFFFFF)
}

// arm64BranchChecked 带范围检查的版本
func arm64BranchChecked(opcode uint32, target, pc int64) (uint32, error) {
	delta := target - pc
	if delta%4 != 0 {
		return 0, fmt.Errorf("AArch64 分支目标未 4 字节对齐")
	}
	imm := delta / 4
	if imm < -(1<<25) || imm >= (1<<25) {
		return 0, fmt.Errorf("AArch64 分支超出 ±128MB（需要 16 字节绝对跳转，暂不支持）")
	}
	return arm64Branch(opcode, target, pc), nil
}

// WriteReport 输出 JSON 报告
func WriteReport(path string, res *Result) error {
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

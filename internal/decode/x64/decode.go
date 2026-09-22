// Package x64 封装 x86-64 解码，提供线性扫描与严格的“消费字节数”校验。
//
// 为什么需要包一层：
//  1. golang.org/x/arch/x86/x86asm 不认识 CET 的 ENDBR64（F3 0F 1E FA），
//     会把它解成 1 字节的 REP，导致线性扫描整体错位 —— 必须特判。
//  2. 任何“只消费了前缀 / 未知操作码”的情况都必须显式失败，
//     绝不能让上层带着错位的指令流继续翻译（fail-fast）。
//  3. 保留 x86asm.Inst 原始结果（含 PCRel/PCRelOff/DataSize），
//     lifter 需要这些信息来正确处理 RIP-relative 与位宽语义。
package x64

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// Insn 是一条已解码指令
type Insn struct {
	PC   uint64
	Inst x86asm.Inst
	Raw  []byte

	Endbr64 bool // CET 间接跳转着陆点 (F3 0F 1E FA)
	Endbr32 bool // (F3 0F 1E FB)
}

// Len 指令总长度（字节）
func (i Insn) Len() int { return i.Inst.Len }

// Op 操作码
func (i Insn) Op() x86asm.Op { return i.Inst.Op }

// Text 可读反汇编文本
func (i Insn) Text() string {
	if i.Endbr64 {
		return "ENDBR64"
	}
	if i.Endbr32 {
		return "ENDBR32"
	}
	return i.Inst.String()
}

// PCRelTarget 计算 RIP-relative 目标的绝对地址。
// ok=false 表示该指令不含 PC-relative 操作数。
func (i Insn) PCRelTarget() (uint64, bool) {
	if i.Inst.PCRel == 0 {
		return 0, false
	}
	off := i.Inst.PCRelOff
	if off < 0 || off+i.Inst.PCRel > len(i.Raw) {
		return 0, false
	}
	var disp int64
	switch i.Inst.PCRel {
	case 1:
		disp = int64(int8(i.Raw[off]))
	case 2:
		disp = int64(int16(binary.LittleEndian.Uint16(i.Raw[off:])))
	case 4:
		disp = int64(int32(binary.LittleEndian.Uint32(i.Raw[off:])))
	default:
		return 0, false
	}
	return i.PC + uint64(i.Inst.Len) + uint64(disp), true
}

// ErrEmpty 输入为空
var ErrEmpty = errors.New("no bytes to decode")

// legacyPrefix 判断字节是否为传统前缀
func legacyPrefix(b byte) bool {
	switch b {
	case 0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65:
		return true
	}
	return false
}

// 解码模式。现有调用一律 Mode64（行为与历史一致）；PE32（32 位 x86 客户机）用 Mode32。
const (
	Mode32 = 32
	Mode64 = 64
)

// Decode 解码单条指令（mode = 64，保持历史行为）
func Decode(code []byte, pc uint64) (Insn, error) { return DecodeMode(code, pc, Mode64) }

// DecodeMode 按指定模式解码单条指令。
//
// 为什么需要它：x86-32 与 x86-64 的**编码差异**不在少数指令上，而在这些地方 ——
//   - 0x40-0x4F：64 位是 REX 前缀，32 位是 INC/DEC EAX..EDI；
//   - 默认操作数/栈槽宽度：32 位是 4 字节（push eax 推 4 字节）；
//   - ModRM mod=00 rm=101：32 位是**绝对 disp32**，64 位是 RIP-relative（所以 32 位下 PCRel 恒为 0）；
//   - 32 位没有 REX、没有 R8-R15。
//
// 上层（lifter）必须知道自己在哪种模式下翻译，否则会把绝对地址当成 RIP-relative。
func DecodeMode(code []byte, pc uint64, mode int) (Insn, error) {
	if len(code) == 0 {
		return Insn{}, ErrEmpty
	}

	// CET 着陆点：x86asm 无法识别，必须特判
	if len(code) >= 4 && code[0] == 0xF3 && code[1] == 0x0F && code[2] == 0x1E &&
		(code[3] == 0xFA || code[3] == 0xFB) {
		return Insn{
			PC:      pc,
			Inst:    x86asm.Inst{Len: 4},
			Raw:     code[:4],
			Endbr64: code[3] == 0xFA,
			Endbr32: code[3] == 0xFB,
		}, nil
	}

	inst, err := x86asm.Decode(code, mode)
	if err != nil {
		return Insn{}, fmt.Errorf("decode @0x%X (byte 0x%02X): %w", pc, code[0], err)
	}
	if inst.Len <= 0 || inst.Len > len(code) {
		return Insn{}, fmt.Errorf("decode @0x%X: implausible length %d", pc, inst.Len)
	}
	// 错位检测：无法识别时 x86asm 返回 Op(0)/Len(1)
	if inst.Len == 1 && inst.Op == 0 {
		if legacyPrefix(code[0]) {
			return Insn{}, fmt.Errorf("prefix-only decode @0x%X (byte 0x%02X): unsupported/unknown encoding", pc, code[0])
		}
		return Insn{}, fmt.Errorf("unknown opcode 0x%02X @0x%X", code[0], pc)
	}

	return Insn{
		PC:   pc,
		Inst: inst,
		Raw:  code[:inst.Len],
	}, nil
}

// DecodeRange 线性扫描一段代码，返回的指令必须精确覆盖整段（consumed == len(code)）
func DecodeRange(code []byte, base uint64, maxInsns int) ([]Insn, error) {
	return DecodeRangeMode(code, base, maxInsns, Mode64)
}

// DecodeRangeMode 同 DecodeRange，但指定解码模式。
func DecodeRangeMode(code []byte, base uint64, maxInsns int, mode int) ([]Insn, error) {
	if maxInsns <= 0 {
		maxInsns = 1 << 20
	}
	var out []Insn
	off := 0
	for off < len(code) {
		if len(out) >= maxInsns {
			return nil, fmt.Errorf("too many instructions (>%d) in %d bytes", maxInsns, len(code))
		}
		ins, err := DecodeMode(code[off:], base+uint64(off), mode)
		if err != nil {
			return nil, fmt.Errorf("at +0x%X: %w", off, err)
		}
		out = append(out, ins)
		off += ins.Len()
	}
	if off != len(code) {
		return nil, fmt.Errorf("instruction stream desync: consumed %d of %d bytes", off, len(code))
	}
	return out, nil
}

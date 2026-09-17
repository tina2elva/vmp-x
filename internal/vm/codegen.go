// Package vm 把 IR 生成为 VM 字节码。
//
// 这里的字节布局必须与 stub/win/x64/vm_opcodes.h 以及 vm_interp.c 的读取顺序
// 完全一致。两侧的一致性由单元测试（字节级 golden）保证。
package vm

import (
	"encoding/binary"
	"fmt"

	"github.com/vmpx/vmp-x/internal/ir"
)

// 操作码（与 vm_opcodes.h 一致）
const (
	OpHalt    byte = 0x00
	OpNop     byte = 0x01
	OpRet     byte = 0x02
	OpMovRR   byte = 0x10
	OpMovRI   byte = 0x11
	OpMovRI32 byte = 0x12
	OpLea     byte = 0x13
	OpAluRR   byte = 0x20
	OpAluRI   byte = 0x21
	OpAluU    byte = 0x22
	OpCmpRR   byte = 0x23
	OpCmpRI   byte = 0x24
	OpExt     byte = 0x30
	OpLoad    byte = 0x40
	OpStore   byte = 0x41
	OpPushR   byte = 0x50
	OpPushI   byte = 0x51
	OpPopR    byte = 0x52
	OpJcc     byte = 0x60
	OpJmp     byte = 0x61
	OpJbz     byte = 0x62
	OpJbnz    byte = 0x63
	OpCallN   byte = 0x70
	OpCallR   byte = 0x71
	OpAtomic  byte = 0x42 // [op][kind][width][dst][src][base][idx][scale][disp32] = 12B
	OpFp      byte = 0x43 // [op][kind][w][dstOff u32][aOff u32][bOff u32] = 15B
)

// NoReg 表示“无寄存器”
const NoReg = 0xFF

// Size 返回某条 IR 指令生成的字节数
func Size(in *ir.Insn) int {
	switch in.Op {
	case ir.Nop, ir.Ret, ir.Halt:
		return 1
	case ir.MovRR:
		return 4
	case ir.MovRI:
		return 11
	case ir.Lea:
		return 10
	case ir.AluRR:
		return 6
	case ir.AluRI:
		return 9
	case ir.AluU:
		return 5
	case ir.CmpRR:
		return 5
	case ir.CmpRI:
		return 8
	case ir.Ext:
		return 5
	case ir.Load:
		return 11
	case ir.Store:
		return 10
	case ir.PushR, ir.PopR:
		return 2
	case ir.PushI:
		return 5
	case ir.Jmp:
		return 5
	case ir.Jcc:
		return 6
	case ir.JRegZ, ir.JRegNZ:
		return 6
	case ir.CallN:
		return 9
	case ir.CallR:
		return 2
	case ir.Atomic:
		return 12
	case ir.Fp:
		return 15
	}
	return 0
}

// Result 生成结果
type Result struct {
	Code    []byte
	Offsets []int // 每条 IR 指令在字节码中的起始偏移
}

// Generate 两遍生成：先算偏移，再解析分支目标并落字节
func Generate(f *ir.Func) (*Result, error) {
	offsets := make([]int, len(f.Insns))
	total := 0
	for i := range f.Insns {
		offsets[i] = total
		sz := Size(&f.Insns[i])
		if sz == 0 {
			return nil, fmt.Errorf("IR 指令 %d (%v) 没有字节码大小", i, f.Insns[i].Op)
		}
		total += sz
	}

	out := make([]byte, 0, total)
	for i := range f.Insns {
		in := &f.Insns[i]
		switch in.Op {
		case ir.Nop:
			out = append(out, OpNop)
		case ir.Halt:
			out = append(out, OpHalt)
		case ir.Ret:
			out = append(out, OpRet)

		case ir.MovRR:
			out = append(out, OpMovRR, byte(in.Width), byte(in.Dst), byte(in.A))
		case ir.MovRI:
			out = append(out, OpMovRI, byte(in.Width), byte(in.Dst))
			out = appendU64(out, in.Imm)
		case ir.Lea:
			out = append(out, OpLea, byte(in.Width), byte(in.Dst), byte(in.Base), byte(in.Index), in.Scale)
			out = appendU32(out, uint32(in.Disp))

		case ir.AluRR:
			out = append(out, OpAluRR, in.Kind, byte(in.Width), byte(in.Dst), byte(in.A), byte(in.B))
		case ir.AluRI:
			out = append(out, OpAluRI, in.Kind, byte(in.Width), byte(in.Dst), byte(in.A))
			out = appendU32(out, uint32(in.Imm))
		case ir.AluU:
			out = append(out, OpAluU, in.Kind, byte(in.Width), byte(in.Dst), byte(in.A))

		case ir.CmpRR:
			out = append(out, OpCmpRR, in.Kind, byte(in.Width), byte(in.A), byte(in.B))
		case ir.CmpRI:
			out = append(out, OpCmpRI, in.Kind, byte(in.Width), byte(in.A))
			out = appendU32(out, uint32(in.Imm))

		case ir.Ext:
			out = append(out, OpExt, in.Kind, byte(in.SrcW), byte(in.Dst), byte(in.A))

		case ir.Load:
			out = append(out, OpLoad, in.Kind, byte(in.Width), byte(in.Dst), byte(in.Base),
				memIndex(in), memScale(in))
			out = appendU32(out, uint32(in.Disp))
		case ir.Store:
			out = append(out, OpStore, byte(in.Width), byte(in.Base), memIndex(in), memScale(in))
			out = appendU32(out, uint32(in.Disp))
			out = append(out, byte(in.A))

		case ir.PushR:
			out = append(out, OpPushR, byte(in.Dst))
		case ir.PopR:
			out = append(out, OpPopR, byte(in.Dst))
		case ir.PushI:
			out = append(out, OpPushI)
			out = appendU32(out, uint32(in.Imm))

		case ir.Jmp:
			if in.Target < 0 || in.Target >= len(f.Insns) {
				return nil, fmt.Errorf("JMP 目标下标越界: %d", in.Target)
			}
			out = append(out, OpJmp)
			out = appendU32(out, uint32(offsets[in.Target]))
		case ir.Jcc:
			if in.Target < 0 || in.Target >= len(f.Insns) {
				return nil, fmt.Errorf("Jcc 目标下标越界: %d", in.Target)
			}
			out = append(out, OpJcc, byte(in.Cond))
			out = appendU32(out, uint32(offsets[in.Target]))

		case ir.JRegZ, ir.JRegNZ:
			if in.Target < 0 || in.Target >= len(f.Insns) {
				return nil, fmt.Errorf("JReg 目标下标越界: %d", in.Target)
			}
			op := OpJbz
			if in.Op == ir.JRegNZ {
				op = OpJbnz
			}
			out = append(out, op, byte(in.A))
			out = appendU32(out, uint32(offsets[in.Target]))

		case ir.CallN:
			out = append(out, OpCallN)
			out = appendU64(out, in.Imm)

		case ir.CallR:
			out = append(out, OpCallR, byte(in.A))

		case ir.Atomic:
			out = append(out, OpAtomic, in.Kind, byte(in.Width), byte(in.Dst), byte(in.A),
				byte(in.Base), byte(in.Index), in.Scale)
			out = appendU32(out, uint32(in.Disp))

		case ir.Fp:
			out = append(out, OpFp, in.Kind, byte(in.Width))
			out = appendU32(out, uint32(in.Disp))
			out = appendU32(out, uint32(in.Imm))
			out = appendU32(out, uint32(in.Imm2))

		default:
			return nil, fmt.Errorf("不支持的 IR 操作: %v", in.Op)
		}
	}

	if len(out) != total {
		return nil, fmt.Errorf("字节码长度不一致: 预估 %d 实际 %d", total, len(out))
	}
	return &Result{Code: out, Offsets: offsets}, nil
}

// memIndex/memScale 处理索引寻址。
// 注意：索引寄存器 0 就是 RAX（合法索引），**不能**用 0 当“无索引”哨兵——
// “无索引”在 IR 里是 ir.NoReg(0xFF)。（这里踩过一次坑：把 RAX 当无索引，
// 导致 [base+rax*4] 退化成 [base]，结果只在 i==0 时正确。）
func memIndex(in *ir.Insn) byte {
	if in.Index == ir.NoReg {
		return NoReg
	}
	return byte(in.Index)
}

func memScale(in *ir.Insn) byte {
	if in.Index == ir.NoReg || in.Scale == 0 {
		return 1
	}
	return in.Scale
}

func appendU32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendU64(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}

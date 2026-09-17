package main

import (
	"fmt"

	x64dec "github.com/vmpx/vmp-x/internal/decode/x64"
)

func dump(name string, code []byte, pc uint64) {
	ins, err := x64dec.Decode(code, pc)
	if err != nil {
		fmt.Printf("%s: decode err %v\n", name, err)
		return
	}
	fmt.Printf("%s: text=%q op=%v len(args)=%d\n", name, ins.Text(), ins.Op(), len(ins.Inst.Args))
	for i, a := range ins.Inst.Args {
		fmt.Printf("    args[%d] = %#v\n", i, a)
	}
}

func main() {
	dump("imul rcx (48 F7 E9)", []byte{0x48, 0xF7, 0xE9}, 0x1000)
	dump("imul ecx (F7 E9)", []byte{0xF7, 0xE9}, 0x1000)
	// LEA 形式：lea (%r8,%rax,1),%rax   = 49 8D 04 00
	dump("lea (r8,rax,1),rax", []byte{0x49, 0x8D, 0x04, 0x00}, 0x1000)
	// 对照：add %r8,%rax = 4C 01 C0
	dump("add r8,rax", []byte{0x4C, 0x01, 0xC0}, 0x1000)
}

package arm64

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type semCase struct {
	kind, width     uint32
	a, b, shiftLast uint64
	cnt, oldFlags   uint32
}

const (
	kindAdd = iota
	kindSub
	kindLogic
	kindMul
	kindShift
)

func edgeVals(w uint32) []uint64 {
	if w == 32 {
		return []uint64{0, 1, 2, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF, 0x0000FFFF, 0xFFFF0000}
	}
	return []uint64{0, 1, 2, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0x8000000000000001,
		0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0xFFFFFFFF00000000}
}

func genSemCases() []semCase {
	var cases []semCase
	rng := rand.New(rand.NewSource(9137))
	for _, w := range []uint32{32, 64} {
		vals := edgeVals(w)
		mask := MaskW(w)
		for _, a := range vals {
			for _, b := range vals {
				cases = append(cases, semCase{kind: kindAdd, width: w, a: a, b: b})
				cases = append(cases, semCase{kind: kindSub, width: w, a: a, b: b})
				cases = append(cases, semCase{kind: kindLogic, width: w, a: a, b: b})
				cases = append(cases, semCase{kind: kindMul, width: w, a: a, b: b})
				cases = append(cases, semCase{kind: kindShift, width: w, a: b, shiftLast: a & 1, cnt: 0, oldFlags: uint32(a & 15)})
			}
		}
		// 随机补充
		for i := 0; i < 2000; i++ {
			a := rng.Uint64() & mask
			b := rng.Uint64() & mask
			cases = append(cases,
				semCase{kind: kindAdd, width: w, a: a, b: b},
				semCase{kind: kindSub, width: w, a: a, b: b},
				semCase{kind: kindShift, width: w, a: b, shiftLast: a & 1, cnt: uint32(rng.Intn(int(w))), oldFlags: rng.Uint32() & 15})
		}
	}
	return cases
}

func runCase(c semCase) (uint32, uint32) {
	var flags uint32
	switch c.kind {
	case kindAdd:
		r := (c.a + c.b) & MaskW(c.width)
		flags = FlagsAdd(c.a, c.b, r, c.width)
	case kindSub:
		r := (c.a - c.b) & MaskW(c.width)
		flags = FlagsSub(c.a, c.b, r, c.width)
	case kindLogic:
		r := (c.a & c.b) & MaskW(c.width)
		flags = FlagsLogic(r, c.width)
	case kindMul:
		r := (c.a * c.b) & MaskW(c.width)
		flags = FlagsMul(r, c.width)
	default:
		r := c.a & MaskW(c.width)
		flags = FlagsShift(r, c.shiftLast, c.width, c.cnt, c.oldFlags)
	}
	var condbits uint32
	for k := uint32(0); k < 16; k++ {
		if CondHolds(k, flags) {
			condbits |= 1 << k
		}
	}
	return flags, condbits
}

// TestArm64SemanticsAgainstC 把 Go 参考实现与将被编进 blob 的 C 实现做对拍
func TestArm64SemanticsAgainstC(t *testing.T) {
	probe := filepath.FromSlash("../../../build/flags_probe.exe")
	if _, err := os.Stat(probe); err != nil {
		t.Skip("缺少 build/flags_probe.exe，先运行: gcc -O2 -I stub/win/x64 -I stub/arm64 -o build/flags_probe.exe stub/arm64/flags_probe.c stub/arm64/guest_semantics_arm64.c")
	}
	cases := genSemCases()

	dir := t.TempDir()
	casesPath := filepath.Join(dir, "cases.bin")
	resPath := filepath.Join(dir, "results.bin")
	buf := make([]byte, 0, len(cases)*40+4)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(cases)))
	for _, c := range cases {
		buf = binary.LittleEndian.AppendUint32(buf, c.kind)
		buf = binary.LittleEndian.AppendUint32(buf, c.width)
		buf = binary.LittleEndian.AppendUint64(buf, c.a)
		buf = binary.LittleEndian.AppendUint64(buf, c.b)
		buf = binary.LittleEndian.AppendUint64(buf, c.shiftLast)
		buf = binary.LittleEndian.AppendUint32(buf, c.cnt)
		buf = binary.LittleEndian.AppendUint32(buf, c.oldFlags)
	}
	if err := os.WriteFile(casesPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(probe, "batch", casesPath, resPath).CombinedOutput()
	if err != nil {
		t.Fatalf("flags_probe 失败: %v | %s", err, out)
	}
	raw, err := os.ReadFile(resPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(raw); got != uint32(len(cases)) {
		t.Fatalf("结果数量 %d != 用例数量 %d", got, len(cases))
	}
	mismatch := 0
	off := 4
	for i, c := range cases {
		cFlags := binary.LittleEndian.Uint32(raw[off:])
		cCond := binary.LittleEndian.Uint32(raw[off+4:])
		off += 8
		gFlags, gCond := runCase(c)
		if gFlags != cFlags || gCond != cCond {
			mismatch++
			if mismatch <= 10 {
				t.Errorf("case%d kind=%d w=%d a=0x%X b=0x%X cnt=%d old=0x%X: go flags=0x%X cond=0x%04X, c flags=0x%X cond=0x%04X",
					i, c.kind, c.width, c.a, c.b, c.cnt, c.oldFlags, gFlags, gCond, cFlags, cCond)
			}
		}
	}
	if mismatch != 0 {
		t.Fatalf("ARM64 语义对拍不一致 %d/%d", mismatch, len(cases))
	}
	fmt.Printf("ARM64 语义对拍: %d 个用例全部一致（flags + 全部 16 个条件码）\n", len(cases))
}

package vm

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// 客户机语义切换的判别性测试（不需要 ARM64 机器）。
//
// 判别点：CMP(相等) 之后 ARM64 的 C=1（无借位），而 x86 的 CF=0。
// 用 ARM64 条件码 CS(=2，"C 置位") 与 CC(=3，"C 清零") 各跑一次，同一段程序：
//
//	R0 = 5 ; R1 = 5 ; CMP R0, R1 ; JCC <cond> -> L1 ; R2 = 222 ; RET ; L1: R2 = 111 ; RET
//
// ARM64 客户机：C=1 → CS 跳（R2=111），CC 不跳（R2=222）；
// 这正是"借位语义与 x86 相反"的直接证据（x86 下相等时 CF=0，结果会完全反过来）。
func TestGuestSemanticsSwitch(t *testing.T) {
	harness := "../../build/runbc_a64g.exe"
	blob := "../../build/vm_interp_a64g.bin"
	manifest := "../../build/vm_interp_a64g.json"
	const regCount = 35 // ARM64 客户机槽位数（见 vmpbuild -guest arm64）
	for _, p := range []string{harness, blob, manifest} {
		if _, err := os.Stat(filepath.FromSlash(p)); err != nil {
			t.Skipf("缺少 %s（先构建 blob 与 runbc_a64g.exe）", p)
		}
	}

	// buildCode 按给定条件码拼一段字节码。JCC 的目标是**绝对字节码偏移**。
	buildCode := func(cond byte) []byte {
		var code []byte
		mov := func(dst byte, v uint64) {
			code = append(code, OpMovRI, 64, dst)
			code = append(code, u64le(v)...)
		}
		mov(0, 5)
		mov(1, 5)
		code = append(code, OpCmpRR, byte(KCmp), 64, 0, 1)
		code = append(code, OpJcc, cond)
		jmpAt := len(code)
		code = append(code, u32le(0)...)
		mov(2, 222) // 不跳
		code = append(code, OpRet)
		takenAt := len(code)
		mov(2, 111) // 跳
		code = append(code, OpRet)
		copy(code[jmpAt:], u32le(uint32(takenAt)))
		return code
	}

	var man struct {
		Symbols  map[string]int `json:"symbols"`
		Guest    string         `json:"guest"`
		RegCount int            `json:"regCount"`
	}
	mb, err := os.ReadFile(filepath.FromSlash(manifest))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatal(err)
	}
	// 守卫：blob 的 ctx 布局必须与本测试假设一致。少给 harness 传 -DVM_REG_COUNT=35 时，
	// 症状是解释器 rc=1（结构大小不一致），非常难查——这里提前失败并说清原因。
	if man.RegCount != regCount {
		t.Fatalf("blob 的 ctx 槽位数是 %d，测试假设 %d：harness 必须用 -DVM_GUEST_ARM64=1 -DVM_REG_COUNT=%d 编译",
			man.RegCount, regCount, regCount)
	}
	if man.Guest != "arm64" {
		t.Fatalf("blob 的客户机是 %q，本测试需要 arm64 blob（vmpbuild -guest arm64）", man.Guest)
	}

	runCase := func(cond byte) (uint64, uint32, uint32) {
		code := buildCode(cond)
		var buf []byte
		buf = binary.LittleEndian.AppendUint32(buf, 1) // count
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(code)))
		buf = append(buf, make([]byte, 8*regCount)...)
		buf = append(buf, code...)
		dir := t.TempDir()
		cf, rf := filepath.Join(dir, "cases.bin"), filepath.Join(dir, "res.bin")
		if err := os.WriteFile(cf, buf, 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(filepath.FromSlash(harness), "batch",
			filepath.FromSlash(blob), fmt.Sprint(man.Symbols["vm_run"]), cf, rf).CombinedOutput()
		if err != nil {
			t.Fatalf("runbc 失败: %v | %s", err, out)
		}
		res, err := os.ReadFile(rf)
		if err != nil {
			t.Fatal(err)
		}
		// 结果布局见 blob_probe.c run_batch：[base:8][blen:4] 头 + 每用例 [rc:4][flags:4][regs][buf]
		const header = 12
		rc := binary.LittleEndian.Uint32(res[header:])
		flags := binary.LittleEndian.Uint32(res[header+4:])
		r2 := binary.LittleEndian.Uint64(res[header+8+8*2:])
		return r2, rc, flags
	}

	r2cs, rc1, f1 := runCase(2) // CS：需要 C=1
	if rc1 != 0 {
		t.Errorf("CS 用例执行异常 rc=%d", rc1)
	}
	if r2cs != 111 {
		t.Errorf("ARM64 客户机按 CS 应跳转（C=1 无借位）：期望 R2=111，实测 %d（flags=0x%X）", r2cs, f1)
	} else {
		fmt.Printf("ARM64 客户机：CMP 相等后 C=1（flags=0x%X），CS 跳转 ✓ R2=%d\n", f1, r2cs)
	}
	r2cc, rc2, f2 := runCase(3) // CC：需要 C=0
	if rc2 != 0 {
		t.Errorf("CC 用例执行异常 rc=%d", rc2)
	}
	if r2cc != 222 {
		t.Errorf("ARM64 客户机按 CC 应不跳转：期望 R2=222，实测 %d（flags=0x%X）", r2cc, f2)
	} else {
		fmt.Printf("ARM64 客户机：CC 不跳转 ✓ R2=%d（flags=0x%X）\n", r2cc, f2)
	}
}

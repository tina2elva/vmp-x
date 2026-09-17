package inject

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ARM64 宿主通路的端到端（在 CI 里用 qemu-aarch64 跑）：
// 用 stub/linux/arm64 编出来的 blob + 一段手写 ARM64 客户机字节码，
// 生成 payload（BL thunk + 4 字节 B 入口补丁），再由 payload_probe 映射到指定 VA 后调用 thunk。
//
// 验证的是"ARM64 入口 stub（保存/填充/模拟 SP/调用 vm_run/还原）+ 解释器 + 客户机语义"，
// 唯一不在覆盖范围内的是"Linux 加载器把控制权交给被补丁的函数入口"（需要真实 arm64 机器或 qemu 全系统）。
//
// 本地没有 aarch64 工具链/qemu，所以本测试在本地自动跳过。
func TestARM64PayloadUnderQEMU(t *testing.T) {
	qemu := ""
	for _, c := range []string{"qemu-aarch64", "qemu-aarch64-static"} {
		if p, err := exec.LookPath(c); err == nil {
			qemu = p
			break
		}
	}
	blob := filepath.FromSlash("../../build/vm_interp_arm64.bin")
	manifest := filepath.FromSlash("../../build/vm_interp_arm64.json")
	probe := filepath.FromSlash("../../build/payload_probe_arm64")
	for _, p := range []string{qemu, blob, manifest, probe} {
		if p == "" {
			t.Skip("缺少 qemu-aarch64 或 arm64 blob/probe（CI 里由 gcc-aarch64-linux-gnu 与 qemu-user 提供）")
		}
		if _, err := os.Stat(p); err != nil {
			t.Skipf("缺少 %s", p)
		}
	}
	var man struct {
		EntryOff int            `json:"entryOff"`
		Symbols  map[string]int `json:"symbols"`
	}
	mb, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatal(err)
	}
	stub, err := os.ReadFile(blob)
	if err != nil {
		t.Fatal(err)
	}

	// 手写 ARM64 客户机字节码：R0 = R0 + 6 ; RET
	// ALU_RI = [op][kind][width][dst][a][imm32]，kind 的 bit7 = 保持标志位（ARM64 的 ADD 不带 S）
	var code []byte
	code = append(code, 0x21, 0x80|0x00, 64, 0, 0)
	imm := make([]byte, 4)
	binary.LittleEndian.PutUint32(imm, 6)
	code = append(code, imm...)
	code = append(code, 0x02) // RET

	const va = 0x40000000
	pl, err := BuildPayload(Options{
		Stub:      stub,
		StubEntry: man.Symbols["vm_entry"],
		Arch:      ArchARM64,
		Funcs:     []FuncSpec{{Name: "f", RVA: 0x1000, Code: code}},
	}, va)
	if err != nil {
		t.Fatalf("BuildPayload 失败: %v", err)
	}
	dir := t.TempDir()
	plPath := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(plPath, pl.Data, 0o755); err != nil {
		t.Fatal(err)
	}
	thunkOff := pl.Placements[0].ThunkRVA - va
	out, err := exec.Command(qemu, probe, plPath, "0x40000000", fmt.Sprintf("0x%X", thunkOff), "0").CombinedOutput()
	if err != nil {
		t.Fatalf("qemu 执行失败: %v | %s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if got != "6" {
		t.Fatalf("ARM64 payload 返回 %q，期望 6", got)
	}
	t.Logf("ARM64 payload 端到端通过：R0=6（thunkOff=0x%X）", thunkOff)
}

// hexOf 小工具：避免在测试里引入 fmt 的格式化差异
func hexOf(v uint32) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{digits[v&0xF]}, b...)
		v >>= 4
	}
	return string(b)
}

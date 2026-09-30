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
	// 输入必须是**成套**的：blob + 它自己的 manifest + probe。
	// 以前这里直接读 build/ 下的固定路径 ⇒ 只要这台机器上跑过别的脚本就会张冠李戴
	// （实测：e2e_elf_image.sh 也用 BLOB_SRC=stub/linux/arm64 写 build/vm_interp_arm64.bin，
	//  但 json 不是同一份 ⇒ 拿"别人的 blob + 这份 manifest"建载荷，报出与代码无关的
	//  "AArch64 分支超出 ±128MB"，让 `go test ./...` 变成"看 build/ 里恰好有什么"）。
	// 现在只认**显式指定**的目录；没给就醒目的 SKIP —— 不确定性从结构上去掉。
	artDir := os.Getenv("VMP_ARM64_DIR")
	if artDir == "" {
		t.Skip("未设置 VMP_ARM64_DIR：本用例要求显式指定成套的 arm64 blob/manifest/probe 所在目录" +
			"（见 tools/e2e_arm64.sh 里紧挨着产物生成的那次调用）")
	}
	blob := filepath.Join(artDir, "vm_interp_arm64.bin")
	manifest := filepath.Join(artDir, "vm_interp_arm64.json")
	probe := filepath.Join(artDir, "payload_probe_arm64")
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
		// BSSOff/BSSSize：blob 里"可写数据"（.bss）的区间。生产方（vmpack）是从 manifest 填进去的；
		// 本测试原来没填 ⇒ payload 里没有可写窗口，解释器跑起来直接返回 0（实测 check_key(0) = 0，
		// 期望 6）—— 这是本用例"从没真正跑过"的第四个迹象。
		BSSOff  int `json:"bssOff"`
		BSSSize int `json:"bssSize"`
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

	// 坐标系必须自洽：BuildPayload 的 baseRVA 与 FuncSpec.RVA **都是"相对镜像基址的地址"**
	// （见 payload.go 里 RVA 字段的注释；生产调用方 vmpack 两者也都传镜像内 RVA）。
	// 本测试为了把 payload 映射到 va=0x40000000 而把 baseRVA 当 VA 用，于是函数的 RVA 也必须
	// 画在同一空间里 —— 之前写死 0x1000（另一个坐标系），分支距离算出来是 1GB，
	// 直接报 "AArch64 分支超出 ±128MB"。这也解释了为什么这条用例**从来没在任何地方真正跑过**
	// （CI 的 linux-amd64 作业没有 aarch64 产物 ⇒ SKIP；本地同样），所以一直没人发现。
	const va = 0x40000000
	pl, err := BuildPayload(Options{
		Stub:      stub,
		StubEntry: man.Symbols["vm_entry"],
		Arch:      ArchARM64,
		BSSOff:    man.BSSOff,
		BSSSize:   man.BSSSize,
		Funcs:     []FuncSpec{{Name: "f", RVA: va + 0x1000, Code: code}},
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
	// 探针的 CLI 契约：<payload.bin> <va> <thunkOff> <ring_off> <diag_off> <arg>...
	// guest 参数从 **argv[6]** 开始。以前这里只给到 argv[4]，于是那个 "0" 被当成 ring_off、
	// 参数循环一次都不执行、一行结果都不打 —— 这是本用例"从没真正跑过"的第三个痕迹（STATUS #588）。
	out, err := exec.Command(qemu, probe, plPath, "0x40000000", fmt.Sprintf("0x%X", thunkOff),
		"0", "0", "0").CombinedOutput()
	if err != nil {
		t.Fatalf("qemu 执行失败: %v | %s", err, out)
	}
	// 探针把"映射信息"写在 stderr 且**不带换行**，所以 CombinedOutput 里它可能正好落在最后一行；
	// 真正的结果行形如 "  check_key(0) = 6"。按 "check_key(" 定位结果行、取该行 "=" 之后的值 ——
	// 以前直接拿整段输出和 "6" 比，探针一加信息行这条断言就永远不可能成立
	// （这是本用例"从没在任何地方真正跑过"的第二个痕迹，见 STATUS #588）。
	got := ""
	for _, ln := range strings.Split(string(out), "\n") {
		if !strings.Contains(ln, "check_key(") {
			continue
		}
		if i := strings.LastIndex(ln, "="); i >= 0 {
			got = strings.TrimSpace(ln[i+1:])
		}
	}
	if got != "6" {
		t.Fatalf("ARM64 payload 返回 %q，期望 6（原始输出 %q）", got, strings.TrimSpace(string(out)))
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

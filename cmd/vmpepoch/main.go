// vmpepoch - 密钥纪元（key epoch）管理。
//
// 概念：一个"纪元" = 一套 {blob.bin + blob.json + 主密钥}，三者**一一对应**：
//   - blob 里的 KCV = KDF(master, "KEYK", 该 blob 构建时的随机 salt)[0:16]
//     => **一个 blob 只能配一把主密钥**；换密钥就必须重建 blob（约 40KB，vmpbuild 几秒钟）；
//   - 反过来，同一套 blob/key 可以打**任意多个** exe、任意多版本（纪元是"授权边界"，不是"程序"）。
//
// 所以"客户 / 产品线 / 最终客户"该用多细的粒度是策略问题；本工具把纪元登记清楚，
// 让人能回答两个运维问题：
//  1. 这个产物是用哪个纪元打的？（which —— 比对注入段前缀的哈希）
//  2. 这把 .vmpkey 属于哪个纪元？（keyid —— 比对密钥指纹）
//
// 登记表（默认 <cwd>/epochs.json）**不保存密钥本身**，只保存密钥文件路径与指纹
// （sha256 前 8 字节；主密钥是 256 位随机数，存哈希不泄露密钥）。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vmpx/vmp-x/internal/load/pe"
)

type epoch struct {
	Name           string `json:"name"`
	Created        string `json:"created"`
	Note           string `json:"note,omitempty"`
	Source         string `json:"source"`
	Guest          string `json:"guest"`
	Blob           string `json:"blob"`
	BlobSHA256     string `json:"blobSHA256"`
	BlobSize       int64  `json:"blobSize"`
	Manifest       string `json:"manifest"`
	KeyFile        string `json:"keyFile"`
	KeyFingerprint string `json:"keyFingerprint"`
}

type registry struct {
	Epochs []epoch `json:"epochs"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "new":
		cmdNew(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "which":
		cmdWhich(os.Args[2:])
	case "keyid":
		cmdKeyID(os.Args[2:])
	case "cred-issue":
		cmdCredIssue(os.Args[2:])
	case "cred-show":
		cmdCredShow(os.Args[2:])
	case "cert-req":
		cmdCertReq(os.Args[2:])
	case "cert-issue":
		cmdCertIssue(os.Args[2:])
	case "cert-show":
		cmdCertShow(os.Args[2:])
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "lic-new":
		cmdLicNew(os.Args[2:])
	case "lic-edit":
		cmdLicEdit(os.Args[2:])
	case "lic-show":
		cmdLicShow(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print("vmpepoch - key epoch management\n\n" +
		"  vmpepoch new  --name <epoch> [--dir <outdir>] [--key-in <hex|file>] [--src stub/win/x64]\n" +
		"                [--guest arm64] [--note <text>] [--registry epochs.json] [--vmpbuild <path>]\n" +
		"  vmpepoch list [--registry epochs.json]\n" +
		"  vmpepoch which --exe <packed.exe> [--registry epochs.json]\n" +
		"  vmpepoch keyid --key <keyfile> [--registry epochs.json]\n" +
		"\n  license (Sentinel-style, offline, signed by the first-level customer)\n" +
		"  vmpepoch keygen   --out <prefix>\n" +
		"  vmpepoch lic-new  --vendor <id> --dongle <id> --key <priv> --out <lic> [--product ID[@expiry]]...\n" +
		"  vmpepoch lic-edit --lic <lic> --key <priv> [--add ID[@expiry]]... [--del ID]...\n" +
		"  vmpepoch lic-show --lic <lic> [--pub <pub>] [--product <id>]\n\n" +
		"An epoch is one {blob + manifest + master key} triple: one blob matches exactly ONE master key.\n")
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
}

func loadRegistry(path string) *registry {
	r := &registry{}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r
		}
		must(err)
	}
	must(json.Unmarshal(b, r))
	return r
}

func saveRegistry(path string, r *registry) {
	sort.Slice(r.Epochs, func(i, j int) bool { return r.Epochs[i].Created < r.Epochs[j].Created })
	b, err := json.MarshalIndent(r, "", "  ")
	must(err)
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, append(b, 0x0A), 0o644))
}

func sha256File(p string) (string, int64) {
	b, err := os.ReadFile(p)
	must(err)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), int64(len(b))
}

// keyFingerprint 归一化密钥（32 字节原始 / 64 位 hex 文本）后取 sha256 前 8 字节。
func keyFingerprint(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	var key []byte
	if len(b) == 32 {
		key = b
	} else {
		s := strings.TrimSpace(string(b))
		k, derr := hex.DecodeString(s)
		if derr != nil || len(k) != 32 {
			return "", fmt.Errorf("%s 既不是 32 字节原始密钥，也不是 64 位 hex 文本", p)
		}
		key = k
	}
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:8]), nil
}

func cmdNew(args []string) {
	fs := flag.NewFlagSet("new", flag.ExitOnError)
	name := fs.String("name", "", "epoch 名称（必填）")
	dir := fs.String("dir", "", "输出目录（默认 release/<name>）")
	keyIn := fs.String("key-in", "", "指定主密钥：64 位 hex 或文件（不给则随机生成一把新的）")
	src := fs.String("src", "stub/win/x64", "stub 平台目录")
	guest := fs.String("guest", "", "guest ISA（如 arm64；留空 = 默认 x86-64）")
	note := fs.String("note", "", "备注（客户/产品线等）")
	regPath := fs.String("registry", "epochs.json", "登记表")
	vmpbuild := fs.String("vmpbuild", "", "vmpbuild 可执行文件路径（默认与 vmpepoch 同目录）")
	fs.Parse(args)
	if *name == "" {
		fmt.Println("[!] 需要 --name")
		os.Exit(2)
	}
	out := *dir
	if out == "" {
		out = filepath.Join("release", *name)
	}
	blob := filepath.Join(out, "blob.bin")
	man := filepath.Join(out, "blob.json")
	key := filepath.Join(out, "project.vmpkey")

	exe := *vmpbuild
	if exe == "" {
		self, err := os.Executable()
		must(err)
		cand := filepath.Join(filepath.Dir(self), "vmpbuild.exe")
		if _, err := os.Stat(cand); err == nil {
			exe = cand
		} else {
			exe = "vmpbuild"
		}
	}
	argv := []string{"-src", *src, "-out", blob, "-manifest", man, "-entry", "vm_entry", "-key-external", "-key-out", key}
	if *keyIn != "" {
		argv = append(argv, "-key-in", *keyIn)
	}
	if *guest != "" {
		argv = append(argv, "-guest", *guest)
	}
	fmt.Printf("[*] %s %s\n", exe, strings.Join(argv, " "))
	c := exec.Command(exe, argv...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		must(fmt.Errorf("vmpbuild 失败: %w", err))
	}
	blobHash, blobSize := sha256File(blob)
	fp, err := keyFingerprint(key)
	must(err)
	g := *guest
	if g == "" {
		g = "x86-64"
	}
	r := loadRegistry(*regPath)
	for i := range r.Epochs {
		if r.Epochs[i].Name == *name {
			fmt.Printf("[!] 纪元 %s 已存在（换名字，或先从登记表删掉）\n", *name)
			os.Exit(1)
		}
	}
	r.Epochs = append(r.Epochs, epoch{
		Name: *name, Created: time.Now().Format(time.RFC3339), Note: *note, Source: *src, Guest: g,
		Blob: blob, BlobSHA256: blobHash, BlobSize: blobSize, Manifest: man, KeyFile: key, KeyFingerprint: fp,
	})
	saveRegistry(*regPath, r)
	fmt.Printf("[+] epoch %q 登记完成\n", *name)
	fmt.Printf("    blob      : %s (%d bytes, sha256 %s)\n", blob, blobSize, blobHash[:16])
	fmt.Printf("    manifest  : %s\n", man)
	fmt.Printf("    key file  : %s (fingerprint %s)\n", key, fp)
	fmt.Printf("    打包      : vmpack -exe <target> -func ... -blob %s -manifest %s\n", blob, man)
	fmt.Printf("    部署      : 把 %s 复制成 <产物全路径>.vmpkey\n", key)
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	regPath := fs.String("registry", "epochs.json", "登记表")
	fs.Parse(args)
	r := loadRegistry(*regPath)
	if len(r.Epochs) == 0 {
		fmt.Println("(登记表里还没有纪元)")
		return
	}
	fmt.Printf("%-20s %-22s %-14s %-12s %-10s %s\n", "EPOCH", "CREATED", "BLOB-SHA256", "KEY-FP", "GUEST", "NOTE")
	for _, e := range r.Epochs {
		fmt.Printf("%-20s %-22s %-14s %-12s %-10s %s\n", e.Name, e.Created, short(e.BlobSHA256), e.KeyFingerprint, e.Guest, e.Note)
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// which：产物里注入段的前缀就是 blob，比对前缀哈希即可认出纪元（不需要 report）。
func cmdWhich(args []string) {
	fs := flag.NewFlagSet("which", flag.ExitOnError)
	exe := fs.String("exe", "", "被保护的产物")
	regPath := fs.String("registry", "epochs.json", "登记表")
	fs.Parse(args)
	if *exe == "" {
		fmt.Println("[!] 需要 --exe")
		os.Exit(2)
	}
	r := loadRegistry(*regPath)
	f, err := pe.Open(*exe)
	must(err)
	data, err := os.ReadFile(*exe)
	must(err)
	matched := 0
	for _, e := range r.Epochs {
		if e.BlobSize <= 0 {
			continue
		}
		blobBytes, berr := os.ReadFile(e.Blob)
		if berr != nil || int64(len(blobBytes)) != e.BlobSize {
			continue // 纪元登记的 blob 不在本地就没法比前缀（换机器/清过目录时会这样）
		}
		for _, s := range f.Sections {
			if s.SizeOfRawData < 64 {
				continue
			}
			off, err := f.RVAtoOffset(s.VirtualAddress)
			if err != nil || off < 0 || off >= len(data) {
				continue
			}
			// payload 在产物里会被拆成多段（代码段 / .bss 段 / 表段），所以比的是"段的前缀"
			// 与"blob 的同长度前缀"，而不是要求某一整段装得下整个 blob（装不下才是常态）。
			n := int64(s.SizeOfRawData)
			if n > e.BlobSize {
				n = e.BlobSize
			}
			avail := int64(len(data) - off)
			if n > avail {
				n = avail
			}
			if n < 64 || n > int64(len(blobBytes)) {
				continue
			}
			h := sha256.Sum256(data[int64(off) : int64(off)+n])
			hb := sha256.Sum256(blobBytes[:n])
			if hex.EncodeToString(h[:]) == hex.EncodeToString(hb[:]) {
				fmt.Printf("[+] %s 用的是纪元 %q（段 %s，blob %s）\n", *exe, e.Name, s.Name, short(e.BlobSHA256))
				if e.Note != "" {
					fmt.Printf("    备注: %s\n", e.Note)
				}
				matched++
			}
		}
	}
	if matched == 0 {
		fmt.Printf("[?] %s 没匹配到登记表里的任何纪元（没登记 / 不是本工具链打的？）\n", *exe)
		os.Exit(1)
	}
}

func cmdKeyID(args []string) {
	fs := flag.NewFlagSet("keyid", flag.ExitOnError)
	key := fs.String("key", "", "密钥文件（.vmpkey）")
	regPath := fs.String("registry", "epochs.json", "登记表")
	fs.Parse(args)
	if *key == "" {
		fmt.Println("[!] 需要 --key")
		os.Exit(2)
	}
	fp, err := keyFingerprint(*key)
	must(err)
	r := loadRegistry(*regPath)
	hits := 0
	for _, e := range r.Epochs {
		if e.KeyFingerprint == fp {
			fmt.Printf("[+] %s 属于纪元 %q\n", *key, e.Name)
			fmt.Printf("    该纪元的 blob : %s\n", e.Blob)
			fmt.Printf("    可打包的产物  : 任何用该 blob 打的 exe（同一纪元可覆盖多程序、多版本）\n")
			if e.Note != "" {
				fmt.Printf("    备注          : %s\n", e.Note)
			}
			hits++
		}
	}
	if hits == 0 {
		fmt.Printf("[?] %s（指纹 %s）不在登记表里\n", *key, fp)
		os.Exit(1)
	}
}

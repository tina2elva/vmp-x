package main

// 授权（license）工具链 —— 对应客户的 Sentinel 式模型：
//   一级客户（母狗持有者）自己**签发**下游授权；下游拿到的是 <产物>.vmplic（离线、可单独更新）。
//
// 设计要点（与 docs/TODO.md 第 5 项一致）：
//   * 授权内容 = {vendorID, dongleID, products[{productID, expiry}], features{...}}；
//   * 用母狗的签发私钥（Ed25519）签名；受保护产物里只烘**验证公钥**；
//   * 更新授权 = 增删 productID/到期后**重签**（不碰软件、不碰狗里的密钥）；
//   * 本工具只做 签发/查看/更新；**运行期强制**由 blob 侧（或 Sentinel SDK）完成，尚未实现。
//
// 命令：
//   vmpepoch keygen   --out <prefix>
//   vmpepoch lic-new  --vendor <id> --dongle <id> --key <priv> --out <lic> [--product ID[@到期]]...
//   vmpepoch lic-edit --lic <lic> --key <priv> [--add ID[@到期]]... [--del ID]... [--dongle <id>] [--vendor <id>]
//   vmpepoch lic-show --lic <lic> [--pub <pub>] [--product <id>]
//
// 到期写法：2027-12-31（当天 23:59:59 前有效）或 perpetual / 永久。

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type licItem struct {
	ProductID string `json:"productID"`
	Expiry    string `json:"expiry"`
}

type license struct {
	V        int               `json:"v"`
	VendorID string            `json:"vendorID"`
	DongleID string            `json:"dongleID"`
	Issued   string            `json:"issued"`
	Items    []licItem         `json:"items"`
	Features map[string]string `json:"features,omitempty"`
	// Cert：一级客户的「身份证书」（由厂商根密钥签发）。带上它，运行期才能验出
	// “这条授权确实来自某个被厂商承认的 vendorID”，而不是客户自立门户。
	Cert *vendorCert `json:"cert,omitempty"`
	Sig  string      `json:"sig,omitempty"`
}

// canonical 返回被签名的字节：去掉 Sig 后按固定字段序列化
// （结构体字段序固定、map 键有序 => 确定性，两侧无需额外规范化）。
func (l *license) canonical() []byte {
	c := *l
	c.Sig = ""
	b, err := json.Marshal(c)
	must(err)
	return b
}

func (l *license) sign(priv ed25519.PrivateKey) {
	l.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, l.canonical()))
}

func (l *license) verify(pub ed25519.PublicKey) error {
	if l.Sig == "" {
		return fmt.Errorf("授权没有签名（sig 为空）")
	}
	sig, err := base64.StdEncoding.DecodeString(l.Sig)
	if err != nil {
		return fmt.Errorf("签名不是 base64: %w", err)
	}
	if !ed25519.Verify(pub, l.canonical(), sig) {
		return fmt.Errorf("签名验证失败（授权被改动，或不是这把母狗签的）")
	}
	return nil
}

func loadPriv(path string) ed25519.PrivateKey {
	b, err := os.ReadFile(path)
	must(err)
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	must(err)
	if len(raw) != ed25519.PrivateKeySize {
		must(fmt.Errorf("%s 不是 %d 字节的 Ed25519 私钥（hex）", path, ed25519.PrivateKeySize))
	}
	return ed25519.PrivateKey(raw)
}

func loadPub(path string) ed25519.PublicKey {
	b, err := os.ReadFile(path)
	must(err)
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	must(err)
	if len(raw) != ed25519.PublicKeySize {
		must(fmt.Errorf("%s 不是 %d 字节的 Ed25519 公钥（hex）", path, ed25519.PublicKeySize))
	}
	return ed25519.PublicKey(raw)
}

func parseExpiry(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "perpetual" || s == "永久" || s == "never" {
		return "perpetual", nil
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			if layout == "2006-01-02" {
				t = time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC)
			}
			return t.UTC().Format(time.RFC3339), nil
		}
	}
	return "", fmt.Errorf("到期时间格式无法识别: %q（用 2027-12-31 或 perpetual）", s)
}

func parseProduct(s string) (licItem, error) {
	id, exp := s, "perpetual"
	if i := strings.LastIndex(s, "@"); i > 0 {
		id, exp = s[:i], s[i+1:]
	}
	if strings.TrimSpace(id) == "" {
		return licItem{}, fmt.Errorf("产品 ID 为空: %q", s)
	}
	e, err := parseExpiry(exp)
	if err != nil {
		return licItem{}, err
	}
	return licItem{ProductID: strings.TrimSpace(id), Expiry: e}, nil
}

func sortItems(l *license) {
	sort.Slice(l.Items, func(i, j int) bool { return l.Items[i].ProductID < l.Items[j].ProductID })
}

func readLicense(path string) *license {
	b, err := os.ReadFile(path)
	must(err)
	l := &license{}
	must(json.Unmarshal(b, l))
	if l.V != 1 {
		must(fmt.Errorf("不认识的授权版本 v=%d", l.V))
	}
	return l
}

func writeLicense(path string, l *license) {
	b, err := json.MarshalIndent(l, "", "  ")
	must(err)
	must(os.WriteFile(path, append(b, 0x0A), 0o644))
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "vendor-license-key", "输出前缀（生成 <前缀>.priv / <前缀>.pub）")
	fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	must(os.WriteFile(*out+".priv", []byte(hex.EncodeToString(priv)+"\n"), 0o600))
	must(os.WriteFile(*out+".pub", []byte(hex.EncodeToString(pub)+"\n"), 0o644))
	fmt.Printf("[+] 签发密钥对已生成\n")
	fmt.Printf("    私钥: %s.priv   <- 只应存在于母狗/一级客户手里，绝不进产物\n", *out)
	fmt.Printf("    公钥: %s.pub    <- 用 vmpbuild 烘进产物，供运行期验签\n", *out)
}

func cmdLicNew(args []string) {
	fs := flag.NewFlagSet("lic-new", flag.ExitOnError)
	vendor := fs.String("vendor", "", "一级客户 ID（vendorID）")
	dongle := fs.String("dongle", "", "下游设备 ID（dongleID）")
	key := fs.String("key", "", "母狗签发私钥（.priv）")
	certPath := fs.String("cert", "", "本级的身份证（.cert.json）；带上它运行期才能验链")
	rootPub := fs.String("root-pub", "", "厂商根公钥（.pub）：给了就先验一遍证书链再签发")
	out := fs.String("out", "", "输出的授权文件（建议 <产物>.vmplic）")
	prod := multiString{}
	fs.Var(&prod, "product", "授权产品，可多次：ID[@到期]")
	fs.Parse(args)
	if *vendor == "" || *dongle == "" || *key == "" || *out == "" {
		fmt.Println("[!] 需要 --vendor --dongle --key --out")
		os.Exit(2)
	}
	l := &license{V: 1, VendorID: *vendor, DongleID: *dongle, Issued: time.Now().UTC().Format(time.RFC3339)}
	priv := loadPriv(*key)
	if *certPath != "" {
		c := loadCert(*certPath)
		if c.VendorID != *vendor {
			must(fmt.Errorf("证书的 vendorID（%s）与 --vendor（%s）不一致", c.VendorID, *vendor))
		}
		// 关键交叉校验：用来签授权的私钥，必须就是证书里绑定的那把公钥 ——
		// 否则“身份”与“签名者”脱钩，验链就失去意义。
		sub, err := c.pub()
		must(err)
		if !sub.Equal(priv.Public().(ed25519.PublicKey)) {
			must(fmt.Errorf("签发私钥与证书里绑定的公钥不匹配（证书 subjectPub=%s）", c.SubjectPub[:16]))
		}
		if *rootPub != "" {
			must(c.verifyChain(loadPub(*rootPub)))
		}
		l.Cert = c
	}
	for _, s := range prod {
		it, err := parseProduct(s)
		must(err)
		l.Items = append(l.Items, it)
	}
	sortItems(l)
	l.sign(priv)
	writeLicense(*out, l)
	fmt.Printf("[+] 授权已签发: %s（vendor=%s dongle=%s，%d 个产品%s）\n", *out, l.VendorID, l.DongleID, len(l.Items),
		map[bool]string{true: "，含身份证书", false: "，未含身份证书"}[l.Cert != nil])
	for _, it := range l.Items {
		fmt.Printf("    %-24s %s\n", it.ProductID, it.Expiry)
	}
}

func cmdLicEdit(args []string) {
	fs := flag.NewFlagSet("lic-edit", flag.ExitOnError)
	licPath := fs.String("lic", "", "要修改的授权文件")
	key := fs.String("key", "", "母狗签发私钥（.priv）")
	vendor := fs.String("vendor", "", "改 vendorID（可选）")
	dongle := fs.String("dongle", "", "改 dongleID（可选）")
	add := multiString{}
	del := multiString{}
	fs.Var(&add, "add", "增加/覆盖产品：ID[@到期]")
	fs.Var(&del, "del", "删除产品：ID")
	fs.Parse(args)
	if *licPath == "" || *key == "" {
		fmt.Println("[!] 需要 --lic --key")
		os.Exit(2)
	}
	l := readLicense(*licPath)
	if *vendor != "" {
		l.VendorID = *vendor
	}
	if *dongle != "" {
		l.DongleID = *dongle
	}
	for _, s := range add {
		it, err := parseProduct(s)
		must(err)
		replaced := false
		for i := range l.Items {
			if l.Items[i].ProductID == it.ProductID {
				l.Items[i] = it
				replaced = true
			}
		}
		if !replaced {
			l.Items = append(l.Items, it)
		}
	}
	for _, s := range del {
		kept := l.Items[:0]
		for _, it := range l.Items {
			if it.ProductID != strings.TrimSpace(s) {
				kept = append(kept, it)
			}
		}
		l.Items = kept
	}
	sortItems(l)
	l.Issued = time.Now().UTC().Format(time.RFC3339)
	l.sign(loadPriv(*key))
	writeLicense(*licPath, l)
	fmt.Printf("[+] 授权已更新并重签: %s（vendor=%s dongle=%s，%d 个产品）\n", *licPath, l.VendorID, l.DongleID, len(l.Items))
	for _, it := range l.Items {
		fmt.Printf("    %-24s %s\n", it.ProductID, it.Expiry)
	}
}

func cmdLicShow(args []string) {
	fs := flag.NewFlagSet("lic-show", flag.ExitOnError)
	licPath := fs.String("lic", "", "授权文件")
	pub := fs.String("pub", "", "验证公钥（.pub）；给了就验签")
	root := fs.String("root", "", "厂商根公钥（.pub）；给了就验「授权 -> 客户证书 -> 厂商根」整条链")
	product := fs.String("product", "", "顺便判定某产品在该授权下是否可用")
	fs.Parse(args)
	if *licPath == "" {
		fmt.Println("[!] 需要 --lic")
		os.Exit(2)
	}
	l := readLicense(*licPath)
	fmt.Printf("vendorID : %s\ndongleID : %s\nissued   : %s\nproducts :\n", l.VendorID, l.DongleID, l.Issued)
	now := time.Now().UTC()
	for _, it := range l.Items {
		state := "有效"
		if it.Expiry != "perpetual" {
			t, err := time.Parse(time.RFC3339, it.Expiry)
			if err != nil {
				state = "到期时间无法解析"
			} else if now.After(t) {
				state = "已过期"
			}
		}
		fmt.Printf("    %-24s %-24s %s\n", it.ProductID, it.Expiry, state)
	}
	if len(l.Features) > 0 {
		fmt.Printf("features : %v\n", l.Features)
	}
	if *pub != "" {
		if err := l.verify(loadPub(*pub)); err != nil {
			fmt.Printf("[FAIL] %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[OK  ] 授权签名验证通过（确实是这把签发密钥签的，且内容未被改动）")
	}
	if *root != "" {
		if l.Cert == nil {
			fmt.Println("[FAIL] 授权里没有身份证书：无法证明这个 vendorID 是厂商承认的（客户可能在自立门户）")
			os.Exit(1)
		}
		sub, err := l.Cert.pub()
		if err != nil {
			fmt.Printf("[FAIL] %v\n", err)
			os.Exit(1)
		}
		if err := l.verify(sub); err != nil {
			fmt.Printf("[FAIL] 授权签名与证书里绑定的公钥不符: %v\n", err)
			os.Exit(1)
		}
		if err := l.Cert.verifyChain(loadPub(*root)); err != nil {
			fmt.Printf("[FAIL] 证书链: %v\n", err)
			os.Exit(1)
		}
		if l.Cert.VendorID != l.VendorID {
			fmt.Printf("[FAIL] 证书 vendorID(%s) 与授权 vendorID(%s) 不一致\n", l.Cert.VendorID, l.VendorID)
			os.Exit(1)
		}
		fmt.Printf("[OK  ] 整链通过：授权 <- %s（链深 %d） <- 厂商根\n", l.Cert.VendorID, certDepth(l.Cert))
	}
	if *product != "" {
		ok, why := l.allows(*product, now)
		fmt.Printf("[授权判定] %s -> %v（%s）\n", *product, ok, why)
		if !ok {
			os.Exit(1)
		}
	}
}

// allows 是运行期判定的 Go 参照实现（blob 侧要写成同一套语义）：
// vendorID 匹配由调用方保证（产物里烘的 vendorID）；这里判 productID 与到期。
func (l *license) allows(productID string, now time.Time) (bool, string) {
	for _, it := range l.Items {
		if it.ProductID != productID {
			continue
		}
		if it.Expiry == "perpetual" {
			return true, "永久授权"
		}
		t, err := time.Parse(time.RFC3339, it.Expiry)
		if err != nil {
			return false, "到期时间无法解析"
		}
		if now.After(t) {
			return false, "已过期（" + it.Expiry + "）"
		}
		return true, "有效至 " + it.Expiry
	}
	return false, "授权列表里没有这个产品"
}

type multiString []string

func (m *multiString) String() string     { return strings.Join(*m, ",") }
func (m *multiString) Set(v string) error { *m = append(*m, v); return nil }

package main

// 两级 PKI：厂商根密钥 -> 一级客户「身份证书」-> 下游授权。
//
// 为什么需要这一层（回答“客户能无限生成密钥不就不乱了吗”）：
//   * 生成密钥对在密码学上人人可为（keygen 不是安全边界，堵不住也不该堵）；
//   * 真正的边界是“**谁的公钥被烘进产物**”：产物只认那把公钥签出的授权；
//   * 但如果不引入“身份”这一层，一级客户可以随便编一个 vendorID 自立门户 ✗。
//   => 于是：厂商用**根私钥**给每个一级客户签一张证书（绑定 vendorID + 客户公钥 + 有效期），
//      产物里只烘**根公钥**；运行期验链：授权签名 by 客户公钥，客户公钥 by 根公钥，
//      且 cert.vendorID == 产物里的 vendorID。这样：
//        · 客户仍可自由生成/轮换自己的密钥（业务不受影响）；
//        · 但“身份”只能由厂商签发，客户**无法自立门户**，厂商可**设有效期/吊销**。
//
// 命令：
//   vmpepoch cert-issue --root <root.priv> --subject <customer.pub> --vendor <id> --out <cert.json> [--until 2028-12-31] [--note ...]
//   vmpepoch cert-show  --cert <cert.json> [--root <root.pub>]

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type vendorCert struct {
	V          int    `json:"v"`
	VendorID   string `json:"vendorID"`
	SubjectPub string `json:"subjectPub"` // 一级客户的 Ed25519 公钥（hex），其私钥由该客户自己保管
	Issued     string `json:"issued"`
	ValidUntil string `json:"validUntil,omitempty"` // 空 = 永久
	Note       string `json:"note,omitempty"`
	Sig        string `json:"sig,omitempty"` // 由厂商根私钥签
}

func (c *vendorCert) canonical() []byte {
	d := *c
	d.Sig = ""
	b, err := json.Marshal(d)
	must(err)
	return b
}

func (c *vendorCert) sign(root ed25519.PrivateKey) {
	c.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(root, c.canonical()))
}

func (c *vendorCert) verifyRoot(root ed25519.PublicKey) error {
	if c.Sig == "" {
		return fmt.Errorf("证书没有签名")
	}
	sig, err := base64.StdEncoding.DecodeString(c.Sig)
	if err != nil {
		return fmt.Errorf("证书签名不是 base64: %w", err)
	}
	if !ed25519.Verify(root, c.canonical(), sig) {
		return fmt.Errorf("证书签名验证失败（不是这把厂商根密钥签的）")
	}
	if c.ValidUntil != "" {
		t, err := time.Parse(time.RFC3339, c.ValidUntil)
		if err == nil && time.Now().UTC().After(t) {
			return fmt.Errorf("证书已过期（%s）", c.ValidUntil)
		}
	}
	return nil
}

func (c *vendorCert) subjectKey() (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(c.SubjectPub))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("证书里的 subjectPub 不是 %d 字节 hex", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func loadCert(path string) *vendorCert {
	b, err := os.ReadFile(path)
	must(err)
	c := &vendorCert{}
	must(json.Unmarshal(b, c))
	if c.V != 1 {
		must(fmt.Errorf("不认识的证书版本 v=%d", c.V))
	}
	return c
}

func cmdCertIssue(args []string) {
	fs := flag.NewFlagSet("cert-issue", flag.ExitOnError)
	root := fs.String("root", "", "厂商根私钥（.priv，只有厂商持有）")
	subject := fs.String("subject", "", "一级客户的公钥文件（.pub）")
	vendor := fs.String("vendor", "", "签发的 vendorID，如 ACME-0001")
	out := fs.String("out", "", "输出证书（.cert.json）")
	until := fs.String("until", "", "有效期（2028-12-31 或 RFC3339；留空 = 永久）")
	note := fs.String("note", "", "备注（客户名/合同号…）")
	fs.Parse(args)
	if *root == "" || *subject == "" || *vendor == "" || *out == "" {
		fmt.Println("[!] 需要 --root --subject --vendor --out")
		os.Exit(2)
	}
	pub := loadPub(*subject)
	vu := ""
	if *until != "" {
		e, err := parseExpiry(*until)
		must(err)
		if e == "perpetual" {
			vu = ""
		} else {
			vu = e
		}
	}
	c := &vendorCert{V: 1, VendorID: *vendor, SubjectPub: hex.EncodeToString(pub),
		Issued: time.Now().UTC().Format(time.RFC3339), ValidUntil: vu, Note: *note}
	c.sign(loadPriv(*root))
	b, err := json.MarshalIndent(c, "", "  ")
	must(err)
	must(os.WriteFile(*out, append(b, 0x0A), 0o644))
	fmt.Printf("[+] 已签发身份证书: %s（vendorID=%s 有效期=%s）\n", *out, c.VendorID, orDash(vu))
}

func orDash(s string) string {
	if s == "" {
		return "永久"
	}
	return s
}

func cmdCertShow(args []string) {
	fs := flag.NewFlagSet("cert-show", flag.ExitOnError)
	certPath := fs.String("cert", "", "证书文件")
	root := fs.String("root", "", "厂商根公钥（.pub）；给了就验签")
	fs.Parse(args)
	if *certPath == "" {
		fmt.Println("[!] 需要 --cert")
		os.Exit(2)
	}
	c := loadCert(*certPath)
	fmt.Printf("vendorID   : %s\nsubjectPub : %s\nissued     : %s\nvalidUntil : %s\nnote       : %s\n",
		c.VendorID, c.SubjectPub, c.Issued, orDash(c.ValidUntil), c.Note)
	if *root != "" {
		if err := c.verifyRoot(loadPub(*root)); err != nil {
			fmt.Printf("[FAIL] %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[OK  ] 证书由该厂商根密钥签发且未过期")
	}
}

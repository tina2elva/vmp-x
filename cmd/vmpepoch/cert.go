package main

// 两级 PKI：厂商根密钥 -> 一级客户「身份证书」-> 下游授权。
//
// 密钥由谁生成（关键）：
//   * 厂商根密钥对：**厂商自己生成**，根私钥永不外发，根公钥公开分发（要烘进产物做验链）；
//   * 一级客户密钥对：**一级客户自己生成**，私钥留在客户手里（建议 DPAPI/软狗包住），
//     **只把公钥交给厂商**；厂商据此签一张证书（绑定 vendorID + 公钥 + 有效期）；
//   * 为什么不能反过来（厂商替客户生成私钥）：谁持有私钥谁就能签该 vendorID 下的所有授权，
//     厂商持有时就等于“厂商能伪造客户给下游的授权” ✗，商业上讲不清。
//
// 为避免“厂商签错人/被顶替”，签发支持**持有证明**（self-signed request）：
//   客户: vmpepoch cert-req  --key custA.priv --vendor ACME-0001 --out custA.req.json
//   厂商: vmpepoch cert-issue --root vendor-root.priv --req custA.req.json --vendor ACME-0001 --out custA.cert.json
//   （cert-issue 会先验请求里的自签名，确认对方确实持有与公钥配对的私钥；也接受旧写法 --subject <pub>，跳过证明）
//
// 命令：
//   vmpepoch cert-req   --key <cust.priv> --vendor <id> --out <req.json> [--note ...]
//   vmpepoch cert-issue --root <root.priv> (--req <req.json> | --subject <cust.pub>) --vendor <id> --out <cert.json> [--until ...] [--note ...]
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

type certReq struct {
	V          int    `json:"v"`
	VendorID   string `json:"vendorID"`
	SubjectPub string `json:"subjectPub"`
	Note       string `json:"note,omitempty"`
	SelfSig    string `json:"selfSig"` // 用被申请的那把私钥签，证明“申请者确实持有它”
}

func (r *certReq) msg() []byte {
	return []byte("vmpx-cert-req:v1:" + r.VendorID + ":" + strings.ToLower(r.SubjectPub))
}

func (r *certReq) checkSelfSig() error {
	pub, err := hex.DecodeString(strings.TrimSpace(r.SubjectPub))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("请求里的 subjectPub 不是 %d 字节 hex", ed25519.PublicKeySize)
	}
	sig, err := base64.StdEncoding.DecodeString(r.SelfSig)
	if err != nil {
		return fmt.Errorf("请求自签名不是 base64: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), r.msg(), sig) {
		return fmt.Errorf("请求自签名验证失败：申请者并没有与 subjectPub 配对的私钥（或请求被改动）")
	}
	return nil
}

type vendorCert struct {
	V          int    `json:"v"`
	VendorID   string `json:"vendorID"`
	SubjectPub string `json:"subjectPub"`
	Issued     string `json:"issued"`
	ValidUntil string `json:"validUntil,omitempty"`
	Note       string `json:"note,omitempty"`
	Sig        string `json:"sig,omitempty"` // 厂商根私钥签
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
		t, perr := time.Parse(time.RFC3339, c.ValidUntil)
		if perr == nil && time.Now().UTC().After(t) {
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

func cmdCertReq(args []string) {
	fs := flag.NewFlagSet("cert-req", flag.ExitOnError)
	key := fs.String("key", "", "一级客户自己的私钥（.priv，由客户生成并保管）")
	vendor := fs.String("vendor", "", "申请的 vendorID")
	out := fs.String("out", "", "输出的请求文件（.req.json，发给厂商）")
	note := fs.String("note", "", "备注（公司名/合同号）")
	fs.Parse(args)
	if *key == "" || *vendor == "" || *out == "" {
		fmt.Println("[!] 需要 --key --vendor --out")
		os.Exit(2)
	}
	priv := loadPriv(*key)
	r := &certReq{V: 1, VendorID: *vendor, Note: *note,
		SubjectPub: hex.EncodeToString(priv.Public().(ed25519.PublicKey))}
	r.SelfSig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, r.msg()))
	b, err := json.MarshalIndent(r, "", "  ")
	must(err)
	must(os.WriteFile(*out, append(b, 0x0A), 0o644))
	fmt.Printf("[+] 证书申请已生成: %s（vendorID=%s，含持有证明自签名）\n    把该文件发给厂商；私钥不要外发。\n", *out, r.VendorID)
}

func cmdCertIssue(args []string) {
	fs := flag.NewFlagSet("cert-issue", flag.ExitOnError)
	root := fs.String("root", "", "厂商根私钥（.priv，只有厂商持有）")
	reqIn := fs.String("req", "", "客户发来的证书申请（.req.json，含持有证明）")
	subject := fs.String("subject", "", "或直接给客户公钥文件（.pub；跳过持有证明，仅兼容旧流程）")
	vendor := fs.String("vendor", "", "签发的 vendorID")
	out := fs.String("out", "", "输出证书（.cert.json）")
	until := fs.String("until", "", "有效期（2028-12-31 或 RFC3339；留空 = 永久）")
	note := fs.String("note", "", "备注（客户名/合同号…）")
	fs.Parse(args)
	if *root == "" || *vendor == "" || *out == "" || (*reqIn == "" && *subject == "") {
		fmt.Println("[!] 需要 --root --vendor --out，以及 --req 或 --subject 之一")
		os.Exit(2)
	}
	var pubHex string
	if *reqIn != "" {
		rb, err := os.ReadFile(*reqIn)
		must(err)
		r := &certReq{}
		must(json.Unmarshal(rb, r))
		if r.V != 1 {
			must(fmt.Errorf("不认识的请求版本 v=%d", r.V))
		}
		if r.VendorID != *vendor {
			must(fmt.Errorf("请求里的 vendorID（%s）与 --vendor（%s）不一致", r.VendorID, *vendor))
		}
		must(r.checkSelfSig())
		pubHex = strings.ToLower(strings.TrimSpace(r.SubjectPub))
		if *note == "" {
			*note = r.Note
		}
		fmt.Println("[*] 请求持有证明校验通过（申请者确实持有与公钥配对的私钥）")
	} else {
		pubHex = hex.EncodeToString(loadPub(*subject))
	}
	vu := ""
	if *until != "" {
		e, err := parseExpiry(*until)
		must(err)
		if e != "perpetual" {
			vu = e
		}
	}
	c := &vendorCert{V: 1, VendorID: *vendor, SubjectPub: pubHex,
		Issued: time.Now().UTC().Format(time.RFC3339), ValidUntil: vu, Note: *note}
	c.sign(loadPriv(*root))
	b, err := json.MarshalIndent(c, "", "  ")
	must(err)
	must(os.WriteFile(*out, append(b, 0x0A), 0o644))
	fmt.Printf("[+] 已签发身份证书: %s（vendorID=%s 有效期=%s）\n    发给该客户；客户签下游授权时用 --cert 带上它。\n", *out, c.VendorID, orDash(vu))
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

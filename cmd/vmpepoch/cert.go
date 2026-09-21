package main

// 两级/三级 PKI：厂商根 -> （可选）部门/销售（canIssue）-> 一级客户 -> 下游授权。
//
// 密钥由谁生成：
//   * 厂商根密钥对：厂商自己生成，根私钥永不外发，根公钥公开分发（烘进产物做验链）；
//   * 各级中间/客户密钥对：由该级自己生成，私钥自留，只把公钥（通过带持有证明的请求）交给上级签发。
//
// 为什么要 canIssue（等价于 Sentinel EMS 的「角色」）：
//   销售/部门需要**签发授权**，但不该拿到根私钥（拿到根 = 能伪造整棵树）✗。
//   做法：根签一张 canIssue=true 的证书给该部门；部门用自己的私钥给下游签**子证书**与**授权**；
//   验链时逐级回溯到根（每级用父级公钥验签），并检查中间证书确实带 canIssue。
//   可吊销性：证书有有效期，不续签即失效（黑名单/在线吊销未做，如实登记）。
//
// 命令：
//   vmpepoch cert-req   --key <priv> --vendor <id> --out <req.json> [--note ...]
//   vmpepoch cert-issue --root <root.priv> --req <req> --vendor <id> --out <cert> [--until ...] [--can-issue]
//   vmpepoch cert-issue --issuer <cert.json> --issuer-key <issuer.priv> --root-pub <root.pub> \
//                       --req <req> --vendor <id> --out <cert> [--until ...] [--can-issue]
//   vmpepoch cert-show  --cert <cert> [--root <root.pub>]

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

const certChainMax = 8

type certReq struct {
	V          int    `json:"v"`
	VendorID   string `json:"vendorID"`
	SubjectPub string `json:"subjectPub"`
	Note       string `json:"note,omitempty"`
	SelfSig    string `json:"selfSig"`
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
	V          int         `json:"v"`
	VendorID   string      `json:"vendorID"`
	SubjectPub string      `json:"subjectPub"`
	Issued     string      `json:"issued"`
	ValidUntil string      `json:"validUntil,omitempty"`
	Note       string      `json:"note,omitempty"`
	CanIssue   bool        `json:"canIssue,omitempty"` // 允许用它去给下级签子证书与授权（EMS 角色）
	Issuer     *vendorCert `json:"issuer,omitempty"`   // 上一级证书；为 nil 表示直接由厂商根签发
	Sig        string      `json:"sig,omitempty"`      // 由 Issuer 的公钥（无 Issuer 时由厂商根）签
}

func (c *vendorCert) canonical() []byte {
	d := *c
	d.Sig = ""
	b, err := json.Marshal(d)
	must(err)
	return b
}

func (c *vendorCert) signWith(priv ed25519.PrivateKey) {
	c.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, c.canonical()))
}

func (c *vendorCert) pub() (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(c.SubjectPub))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("证书里的 subjectPub 不是 %d 字节 hex", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// verifySelf 用给定公钥验本级签名（不回溯链）。
func (c *vendorCert) verifySelf(parent ed25519.PublicKey) error {
	if c.Sig == "" {
		return fmt.Errorf("证书没有签名")
	}
	sig, err := base64.StdEncoding.DecodeString(c.Sig)
	if err != nil {
		return fmt.Errorf("证书签名不是 base64: %w", err)
	}
	if !ed25519.Verify(parent, c.canonical(), sig) {
		return fmt.Errorf("证书签名验证失败（vendorID=%s 不是由上一级签的）", c.VendorID)
	}
	if c.ValidUntil != "" {
		t, perr := time.Parse(time.RFC3339, c.ValidUntil)
		if perr == nil && time.Now().UTC().After(t) {
			return fmt.Errorf("证书已过期（%s）", c.ValidUntil)
		}
	}
	return nil
}

// verifyChain 逐级回溯到厂商根：本级由 Issuer 签、Issuer 由它的 Issuer 签…… 顶层由 root 签。
// 同时校验整条链的 vendorID 一致（防止把别的 vendorID 的证书拼进来）。
func (c *vendorCert) verifyChain(root ed25519.PublicKey) error {
	cur := c
	for depth := 0; depth < certChainMax; depth++ {
		if cur.Issuer == nil {
			return cur.verifySelf(root)
		}
		parentPub, err := cur.Issuer.pub()
		if err != nil {
			return err
		}
		if err := cur.verifySelf(parentPub); err != nil {
			return err
		}
		if cur.Issuer.VendorID != cur.VendorID {
			return fmt.Errorf("证书链里 vendorID 不一致（%s vs %s）", cur.Issuer.VendorID, cur.VendorID)
		}
		if !cur.Issuer.CanIssue {
			return fmt.Errorf("中间证书（vendorID=%s）没有 canIssue 权限，无权签发下级", cur.Issuer.VendorID)
		}
		cur = cur.Issuer
	}
	return fmt.Errorf("证书链过深（> %d 级）", certChainMax)
}

func certDepth(c *vendorCert) int {
	d := 0
	for cur := c; cur.Issuer != nil; cur = cur.Issuer {
		d++
	}
	return d
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

func loadReq(path string) *certReq {
	b, err := os.ReadFile(path)
	must(err)
	r := &certReq{}
	must(json.Unmarshal(b, r))
	if r.V != 1 {
		must(fmt.Errorf("不认识的请求版本 v=%d", r.V))
	}
	return r
}

func cmdCertReq(args []string) {
	fs := flag.NewFlagSet("cert-req", flag.ExitOnError)
	key := fs.String("key", "", "本级自己的私钥（.priv，自己生成并保管）")
	vendor := fs.String("vendor", "", "申请的 vendorID")
	out := fs.String("out", "", "输出的请求文件（.req.json）")
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
	fmt.Printf("[+] 证书申请已生成: %s（vendorID=%s，含持有证明自签名）\n", *out, r.VendorID)
}

func cmdCertIssue(args []string) {
	fs := flag.NewFlagSet("cert-issue", flag.ExitOnError)
	root := fs.String("root", "", "厂商根私钥（顶层签发用）")
	issuer := fs.String("issuer", "", "本级作为「签发者」的证书（部门/销售；须 canIssue）")
	issuerKey := fs.String("issuer-key", "", "签发者自己的私钥（.priv）")
	rootPub := fs.String("root-pub", "", "厂商根公钥（用 --issuer 时必填，用于回溯验链）")
	reqIn := fs.String("req", "", "下级发来的证书申请（.req.json，含持有证明）")
	subject := fs.String("subject", "", "或直接给下级公钥文件（.pub；跳过持有证明，兼容旧流程）")
	vendor := fs.String("vendor", "", "签发的 vendorID")
	out := fs.String("out", "", "输出证书（.cert.json）")
	until := fs.String("until", "", "有效期（2028-12-31 或 RFC3339；留空 = 永久）")
	note := fs.String("note", "", "备注")
	canIssue := fs.Bool("can-issue", false, "授予「可继续签发下级证书/授权」的权限（EMS 角色）")
	fs.Parse(args)
	topMode := *root != ""
	midMode := *issuer != "" || *issuerKey != ""
	if *vendor == "" || *out == "" || (*reqIn == "" && *subject == "") || (topMode == midMode) {
		fmt.Println("[!] 需要 --vendor --out 与 (--req 或 --subject)，并且 --root 与 --issuer/--issuer-key 二选一")
		os.Exit(2)
	}
	var pubHex string
	if *reqIn != "" {
		r := loadReq(*reqIn)
		if r.VendorID != *vendor {
			must(fmt.Errorf("请求里的 vendorID（%s）与 --vendor（%s）不一致", r.VendorID, *vendor))
		}
		must(r.checkSelfSig())
		pubHex = strings.ToLower(strings.TrimSpace(r.SubjectPub))
		if *note == "" {
			*note = r.Note
		}
		fmt.Println("[*] 请求持有证明校验通过")
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
		Issued: time.Now().UTC().Format(time.RFC3339), ValidUntil: vu, Note: *note, CanIssue: *canIssue}
	if midMode {
		if *issuerKey == "" || *rootPub == "" {
			fmt.Println("[!] 用 --issuer 时还需要 --issuer-key 与 --root-pub")
			os.Exit(2)
		}
		ic := loadCert(*issuer)
		if !ic.CanIssue {
			must(fmt.Errorf("该签发者证书（vendorID=%s）没有 canIssue 权限，不能签发下级", ic.VendorID))
		}
		must(ic.verifyChain(loadPub(*rootPub)))
		if ic.VendorID != *vendor {
			must(fmt.Errorf("签发者证书 vendorID（%s）与要签的 vendorID（%s）不一致", ic.VendorID, *vendor))
		}
		c.Issuer = ic
		c.signWith(loadPriv(*issuerKey))
		fmt.Printf("[*] 由中间签发者签发（链深 %d）\n", certDepth(c))
	} else {
		c.signWith(loadPriv(*root))
	}
	b, err := json.MarshalIndent(c, "", "  ")
	must(err)
	must(os.WriteFile(*out, append(b, 0x0A), 0o644))
	fmt.Printf("[+] 已签发证书: %s（vendorID=%s 有效期=%s canIssue=%v 链深=%d）\n", *out, c.VendorID, orDash(vu), c.CanIssue, certDepth(c))
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
	root := fs.String("root", "", "厂商根公钥（.pub）；给了就验整条链")
	fs.Parse(args)
	if *certPath == "" {
		fmt.Println("[!] 需要 --cert")
		os.Exit(2)
	}
	c := loadCert(*certPath)
	fmt.Printf("vendorID   : %s\nsubjectPub : %s\nissued     : %s\nvalidUntil : %s\ncanIssue   : %v\n链深       : %d\nnote       : %s\n",
		c.VendorID, c.SubjectPub, c.Issued, orDash(c.ValidUntil), c.CanIssue, certDepth(c), c.Note)
	for cur := c.Issuer; cur != nil; cur = cur.Issuer {
		fmt.Printf("  └ 上级: vendorID=%s canIssue=%v validUntil=%s\n", cur.VendorID, cur.CanIssue, orDash(cur.ValidUntil))
	}
	if *root != "" {
		if err := c.verifyChain(loadPub(*root)); err != nil {
			fmt.Printf("[FAIL] %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[OK  ] 整条证书链回溯到厂商根，且中间证书均带 canIssue")
	}
}

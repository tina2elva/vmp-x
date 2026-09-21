package main

// 构建凭据（工具授权）的签发与查看 —— 对应 docs/STRENGTH.md 4.4 第 1 条：
// 把「使用工具的权利」绑到你签发的身份上，而不是指望工具二进制不可复制。
//
//   vmpepoch cred-issue --root <root.priv> (--req <req.json> | --subject <pub>) \
//                       --vendor <id> [--until 2028-12-31] [--machine <fp>] --out vmpx.cred
//   vmpepoch cred-show  --cred vmpx.cred --root <root.pub>
//
// 客户侧： vmpepoch keygen --out vmpx      （自己生成工具安装密钥对，私钥留着）
//          vmpepoch cert-req --key vmpx.priv --vendor <id> --out vmpx.req.json  （申请，含持有证明）
// 工具侧： 把 vmpx.cred 放在 vmpbuild/vmpack 同目录，私钥命名为 vmpx.key 放同目录。

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vmpx/vmp-x/internal/cred"
)

func cmdCredIssue(args []string) {
	fs := flag.NewFlagSet("cred-issue", flag.ExitOnError)
	root := fs.String("root", "", "厂商根私钥（.priv，只有厂商持有）")
	reqIn := fs.String("req", "", "客户发来的申请（.req.json，含持有证明）")
	subject := fs.String("subject", "", "或直接给客户工具安装公钥（.pub；跳过持有证明）")
	vendor := fs.String("vendor", "", "授权给客户的 vendorID")
	until := fs.String("until", "", "有效期（2028-12-31 或 RFC3339；留空 = 永久）")
	machine := fs.String("machine", "", "可选：绑定机器指纹（预留）")
	note := fs.String("note", "", "备注（客户名/合同号）")
	out := fs.String("out", "vmpx.cred", "输出凭据")
	fs.Parse(args)
	if *root == "" || *vendor == "" || (*reqIn == "" && *subject == "") {
		fmt.Println("[!] 需要 --root --vendor，以及 --req 或 --subject 之一")
		os.Exit(2)
	}
	var pubStr string
	if *reqIn != "" {
		r := loadReq(*reqIn)
		if r.VendorID != *vendor {
			must(fmt.Errorf("请求里的 vendorID（%s）与 --vendor（%s）不一致", r.VendorID, *vendor))
		}
		must(r.checkSelfSig())
		pubStr = strings.ToLower(strings.TrimSpace(r.SubjectPub))
		if *note == "" {
			*note = r.Note
		}
		fmt.Println("[*] 申请持有证明校验通过")
	} else {
		pubStr = pubHexOf(loadPub(*subject))
	}
	vu := ""
	if *until != "" {
		e, err := parseExpiry(*until)
		must(err)
		if e != "perpetual" {
			vu = e
		}
	}
	c := &cred.Cred{V: 1, VendorID: *vendor, SubjectPub: pubStr, CanBuild: true,
		ValidUntil: vu, Machine: *machine, Note: *note}
	c.Sig = signDetached(loadPriv(*root), c.Canonical())
	b, err := json.MarshalIndent(c, "", "  ")
	must(err)
	must(os.WriteFile(*out, append(b, 0x0A), 0o600))
	fmt.Printf("[+] 已签发构建凭据: %s（vendorID=%s 有效期=%s）\n", *out, c.VendorID, orDash(vu))
	fmt.Println("    部署：把该文件放到 vmpbuild/vmpack 同目录（或设 VMPX_CRED），私钥命名为 vmpx.key 放同目录")
}

func cmdCredShow(args []string) {
	fs := flag.NewFlagSet("cred-show", flag.ExitOnError)
	credPath := fs.String("cred", "", "凭据文件")
	root := fs.String("root", "", "厂商根公钥（.pub）；给了就验签")
	fs.Parse(args)
	if *credPath == "" {
		fmt.Println("[!] 需要 --cred")
		os.Exit(2)
	}
	b, err := os.ReadFile(*credPath)
	must(err)
	c := &cred.Cred{}
	must(json.Unmarshal(b, c))
	fmt.Printf("vendorID   : %s\nsubjectPub : %s\ncanBuild   : %v\nvalidUntil : %s\nmachine    : %s\nnote       : %s\n",
		c.VendorID, c.SubjectPub, c.CanBuild, orDash(c.ValidUntil), c.Machine, c.Note)
	if *root != "" {
		rootPub := loadPub(*root)
		if err := c.Verify(rootPub, time.Now().UTC()); err != nil {
			fmt.Printf("[FAIL] %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[OK  ] 凭据由该厂商根签发、未过期、且带 canBuild 权限")
	}
}

var _ = hex.EncodeToString

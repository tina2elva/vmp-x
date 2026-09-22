// Package cred 实现「工具授权」：vmpbuild / vmpack 启动时校验一份由厂商根密钥签发的
// **构建凭据**（build credential）。
//
// 设计（对应 docs/STRENGTH.md 4.4 的第 1 条）：
//   - 厂商根公钥**烘进工具二进制**（-ldflags -X .../internal/cred.RootPubHex=...）；
//     开发构建不设它 => 校验关闭（现有 CI/gates 不受影响），发布构建设它 => 强制校验；
//   - 凭据文件（JSON，ECDSA P-256 签名）里除了 vendorID/到期，还绑定一把**工具安装公钥**；
//     工具旁边必须有配对的私钥文件 vmpx.key —— 只拷 .cred 拷不走权限（配合 TPM/DPAPI 更硬）；
//   - 工具只允许用凭据里的 vendorID 去构建（转卖者拿不到你签的凭据，也建不出你的身份）。
//
// 查找顺序：--cred <file> > 环境变量 VMPX_CRED > <工具可执行文件同目录>/vmpx.cred
package cred

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RootPubHex：厂商根公钥（64 字节 X||Y 的 hex）。发布构建用
//
//	go build -ldflags "-X github.com/vmpx/vmp-x/internal/cred.RootPubHex=<hex>"
//
// 烘进工具；留空 = 开发构建，工具授权校验**关闭**。
var RootPubHex string

// KeyFileName：与凭据配套的工具安装私钥文件名（放在凭据同目录）。
const KeyFileName = "vmpx.key"

// KeyFileNameDPAPI：**受保护**的私钥文件名（DPAPI，绑本机+本用户）。存在时优先用它。
const KeyFileNameDPAPI = "vmpx.key.dpapi"

// LoadToolKey 取本机的工具私钥：优先受保护形式，其次明文（并把风险喊出来）。
func LoadToolKey(dir string) (raw []byte, note string, err error) {
	dp := filepath.Join(dir, KeyFileNameDPAPI)
	if b, rerr := os.ReadFile(dp); rerr == nil {
		plain, uerr := Unprotect(b)
		if uerr != nil {
			return nil, "", fmt.Errorf("受保护的私钥 %s 解不开：%w", dp, uerr)
		}
		if len(plain) != 32 {
			return nil, "", fmt.Errorf("%s 解出来不是 32 字节私钥", dp)
		}
		return plain, "DPAPI 保护的私钥", nil
	}
	kp := filepath.Join(dir, KeyFileName)
	kb, rerr := os.ReadFile(kp)
	if rerr != nil {
		return nil, "", fmt.Errorf("找不到与凭据配套的私钥（%s 或 %s）: %w", kp, dp, rerr)
	}
	raw, herr := hex.DecodeString(strings.TrimSpace(string(kb)))
	if herr != nil || len(raw) != 32 {
		return nil, "", fmt.Errorf("%s 不是 32 字节的 ECDSA P-256 私钥标量（hex）", kp)
	}
	fmt.Fprintln(os.Stderr, "[!] 当前用的是**明文**私钥文件 "+kp+" —— 拷走它即可绕过工具授权。建议改用受保护形式：vmpepoch keygen --out <前缀> --dpapi")
	return raw, "明文私钥（建议换成 DPAPI 保护的）", nil
}

type Cred struct {
	V          int    `json:"v"`
	VendorID   string `json:"vendorID"`
	SubjectPub string `json:"subjectPub"`
	CanBuild   bool   `json:"canBuild"`
	ValidUntil string `json:"validUntil,omitempty"`
	Machine    string `json:"machine,omitempty"`
	Note       string `json:"note,omitempty"`
	Sig        string `json:"sig,omitempty"`
}

func (c *Cred) Canonical() []byte {
	d := *c
	d.Sig = ""
	b, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	return b
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// PubFromHex 解析 64 字节 X||Y（hex）。
func PubFromHex(s string) (*ecdsa.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != 64 {
		return nil, fmt.Errorf("公钥不是 64 字节 X||Y 的 hex")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(),
		X: new(big.Int).SetBytes(raw[0:32]),
		Y: new(big.Int).SetBytes(raw[32:64])}, nil
}

// PubHex: 64 字节 X||Y 的 hex。
func PubHex(pub *ecdsa.PublicKey) string {
	out := make([]byte, 64)
	pub.X.FillBytes(out[0:32])
	pub.Y.FillBytes(out[32:64])
	return hex.EncodeToString(out)
}

func VerifySig(pub *ecdsa.PublicKey, msg []byte, sigB64 string) error {
	if sigB64 == "" {
		return fmt.Errorf("没有签名")
	}
	raw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("签名不是 base64: %w", err)
	}
	if len(raw) != 64 {
		return fmt.Errorf("签名长度不是 64 字节（%d）", len(raw))
	}
	r := new(big.Int).SetBytes(raw[0:32])
	s := new(big.Int).SetBytes(raw[32:64])
	if !ecdsa.Verify(pub, sha256Sum(msg), r, s) {
		return fmt.Errorf("签名验证失败")
	}
	return nil
}

// Sign 给 vmpepoch 用（同一个签名格式，避免两处实现）。
func Sign(priv *ecdsa.PrivateKey, msg []byte) string {
	r, s, err := ecdsa.Sign(cryptoRandReader{}, priv, sha256Sum(msg))
	if err != nil {
		panic(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[0:32])
	s.FillBytes(raw[32:64])
	return base64.StdEncoding.EncodeToString(raw)
}

func (c *Cred) Verify(root *ecdsa.PublicKey, now time.Time) error {
	if c.V != 1 {
		return fmt.Errorf("不认识的凭据版本 v=%d", c.V)
	}
	if err := VerifySig(root, c.Canonical(), c.Sig); err != nil {
		return fmt.Errorf("凭据签名验证失败（不是这把厂商根签发的）: %w", err)
	}
	if !c.CanBuild {
		return fmt.Errorf("该凭据没有 canBuild 权限")
	}
	if c.ValidUntil != "" {
		t, err := time.Parse(time.RFC3339, c.ValidUntil)
		if err != nil {
			return fmt.Errorf("凭据的到期时间无法解析: %v", err)
		}
		if now.After(t) {
			return fmt.Errorf("凭据已过期（%s）", c.ValidUntil)
		}
	}
	return nil
}

// Locate 按 --cred / VMPX_CRED / <工具目录>/vmpx.cred 找凭据。
func Locate(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v := os.Getenv("VMPX_CRED"); v != "" {
		return v
	}
	if self, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(self), "vmpx.cred")
	}
	return "vmpx.cred"
}

// Require 是工具启动时的统一入口：校验通过返回 nil；不通过返回错误（调用方打印并退出）。
// vendorID 是本次构建声明的身份（工具会强制它与凭据里的一致）。
func Require(explicitCredPath, vendorID string) error {
	if strings.TrimSpace(RootPubHex) == "" {
		fmt.Fprintln(os.Stderr, "[!] 本工具未烘焙厂商根公钥（开发构建）→ 工具授权校验已关闭。发布版本必须用 -ldflags -X .../internal/cred.RootPubHex=<hex>")
		return nil
	}
	root, err := PubFromHex(RootPubHex)
	if err != nil {
		return fmt.Errorf("内置的厂商根公钥不合法: %w", err)
	}
	path := Locate(explicitCredPath)
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("找不到构建凭据 %s（没有授权就无法使用本工具）: %w", path, err)
	}
	c := &Cred{}
	if err := json.Unmarshal(b, c); err != nil {
		return fmt.Errorf("凭据不是合法 JSON: %w", err)
	}
	if err := c.Verify(root, time.Now().UTC()); err != nil {
		return fmt.Errorf("构建凭据无效（%s）: %w", path, err)
	}
	if vendorID != "" && c.VendorID != vendorID {
		return fmt.Errorf("凭据里的 vendorID（%s）与本次构建声明的（%s）不一致", c.VendorID, vendorID)
	}
	// 关键：凭据必须与本机那把私钥配对 —— 只拷 .cred 拷不走权限。
	// 私钥优先用 DPAPI 保护形式（vmpx.key.dpapi）：那样连"拷走文件"都不成立。
	raw, _, kerr := LoadToolKey(filepath.Dir(path))
	if kerr != nil {
		return kerr
	}
	priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}}
	priv.D = new(big.Int).SetBytes(raw)
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(raw)
	if PubHex(&priv.PublicKey) != strings.ToLower(strings.TrimSpace(c.SubjectPub)) {
		return fmt.Errorf("本机的私钥与凭据里绑定的公钥不匹配（凭据不能挪到别的安装上用）")
	}
	if c.Machine != "" && c.Machine != machineID() {
		return fmt.Errorf("凭据绑定的机器（%s）与本机不符", c.Machine)
	}
	return nil
}

// machineID：预留的机器绑定（现在返回空串 = 不校验；接 TPM/机器指纹时在这里实现）。
func machineID() string { return "" }

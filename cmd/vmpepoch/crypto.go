package main

// 签名原语（ECDSA P-256 + SHA-256）。
//
// 为什么不用 Ed25519：运行期要在**产物里**验签，而 Windows 的 CNG（bcrypt.dll）只提供
// ECDSA/RSA —— 没有 Ed25519。换成 ECDSA 之后，blob 侧只需要调 BCryptVerifySignature，
// 不用往 blob 里塞上千行第三方密码学实现（更大、更难审计、还会把 blob 撑大）。
//
// 文件格式（都便于和 CNG 的 BCRYPT_ECCKEY_BLOB 互转）：
//   *.priv : 32 字节标量 d（hex）
//   *.pub  : 64 字节 X||Y（hex，各 32 字节大端）
//   签名    : 64 字节 r||s（base64），**不是** ASN.1 —— CNG 只认 r||s。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/vmpx/vmp-x/internal/cred"
)

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func genKeypair() (*ecdsa.PrivateKey, string, string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	privHex := hex.EncodeToString(priv.D.FillBytes(make([]byte, 32)))
	pubHex := hex.EncodeToString(pubBytes(&priv.PublicKey))
	return priv, privHex, pubHex
}

// pubBytes: 64 字节 X||Y（各 32 字节大端）
func pubBytes(pub *ecdsa.PublicKey) []byte {
	out := make([]byte, 64)
	pub.X.FillBytes(out[0:32])
	pub.Y.FillBytes(out[32:64])
	return out
}

func loadPriv(path string) *ecdsa.PrivateKey {
	b, err := os.ReadFile(path)
	must(err)
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	must(err)
	if len(raw) != 32 {
		must(fmt.Errorf("%s 不是 32 字节的 ECDSA P-256 私钥标量（hex）", path))
	}
	d := new(big.Int).SetBytes(raw)
	priv := new(ecdsa.PrivateKey)
	priv.D = d
	priv.Curve = elliptic.P256()
	priv.PublicKey.Curve = elliptic.P256()
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(raw)
	if priv.PublicKey.X == nil {
		must(fmt.Errorf("%s 不是合法的 P-256 私钥", path))
	}
	return priv
}

func loadPub(path string) *ecdsa.PublicKey {
	b, err := os.ReadFile(path)
	must(err)
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	must(err)
	if len(raw) != 64 {
		must(fmt.Errorf("%s 不是 64 字节的 ECDSA P-256 公钥（hex，X||Y）", path))
	}
	return pubFromBytes(raw)
}

func pubFromBytes(raw []byte) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{Curve: elliptic.P256(),
		X: new(big.Int).SetBytes(raw[0:32]),
		Y: new(big.Int).SetBytes(raw[32:64])}
}

// pubHexOf 走 internal/cred 的同一实现（签名/验签/公钥编码都只有一份）。
func pubHexOf(pub *ecdsa.PublicKey) string {
	return cred.PubHex(pub)
}

// signDetached: base64(r||s)，r/s 各 32 字节大端（CNG 的格式）。
func signDetached(priv *ecdsa.PrivateKey, msg []byte) string {
	return cred.Sign(priv, msg)
}

func verifyDetached(pub *ecdsa.PublicKey, msg []byte, sigB64 string) error {
	return cred.VerifySig(pub, msg, sigB64)
}

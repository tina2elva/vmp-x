package cred

import (
	"crypto/rand"
)

// cryptoRandReader 只是给 Sign 用的随机源包装（保持 cred 包对外只暴露 Sign）。
type cryptoRandReader struct{}

func (cryptoRandReader) Read(p []byte) (int, error) { return rand.Read(p) }

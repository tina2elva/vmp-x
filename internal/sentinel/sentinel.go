// Package sentinel 把 Sentinel LDK（HASP）的加密狗能力收成一个接口，
// 让 vmp-x 的两处接缝可以「换成狗」而不动其它代码：
//
//  1. **取主密钥**：blob 需要一把主密钥（现在是 <产物>.vmpkey 文件）。上了狗之后，
//     主密钥可以放在**狗的内存**里（hasp_read），或者干脆让狗做解密（hasp_decrypt），
//     于是密钥永远不以文件形式存在。
//  2. **运行期授权判定**：现在是 <产物>.vmplic.bin + ECDSA 验签；上狗之后改成问狗
//     「这个 productID 有没有、到什么时候」。
//
// 为什么先做接口层：你们已经有母狗/子狗，但**现在不一定要上**。把接缝定下来之后：
// 今天用假后端（本地文件模拟）跑通流程与测试；将来换真 DLL 只改一个实现，不动业务代码。
//
// 真后端只依赖 Sentinel 运行时 DLL（hasp_windows_<vendorid>.dll，随 Sentinel LDK 分发），
// 用 syscall 动态加载 —— 没有狗/没有 DLL 时**明确报错**，不会静默退回文件。
package sentinel

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Status 是 HASP 的状态码（0 = 成功）。
type Status int32

const (
	StatusOK Status = 0
)

func (s Status) Error() string { return fmt.Sprintf("hasp 状态码 0x%X", int32(s)) }

// Product 是从狗上读到的一项授权。
type Product struct {
	ID     uint32
	Expiry time.Time // 零值 = 永久
}

func (p Product) String() string {
	if p.Expiry.IsZero() {
		return fmt.Sprintf("%d@perpetual", p.ID)
	}
	return fmt.Sprintf("%d@%s", p.ID, p.Expiry.Format("2006-01-02"))
}

// Backend 是我们需要狗提供的最小能力集。
type Backend interface {
	Name() string
	Login(vendorCode string, feature uint32) error
	Logout() error
	ReadMemory(fileID, offset, length uint32) ([]byte, error)
	Decrypt(fileID uint32, data []byte) ([]byte, error)
	Products() ([]Product, error)
}

// Options 是打开后端时的参数。
type Options struct {
	VendorCode   string
	Feature      uint32
	DLLPath      string // 真后端：显式指定 hasp_*.dll
	FakeMemory   string // 假后端：模拟狗内存的文件（用于测试/演示）
	FakeProducts string // 假后端：模拟授权列表，形如 "1@2030-01-01,2@perpetual"
}

// Open 按环境与参数挑选实现：显式假后端 > 真 DLL > 失败。绝不静默降级。
func Open(o Options) (Backend, error) {
	if o.FakeMemory != "" {
		return openFake(o.FakeMemory, o.FakeProducts)
	}
	if p := os.Getenv("VMPX_SENTINEL_FAKE"); p != "" {
		return openFake(p, os.Getenv("VMPX_SENTINEL_FAKE_PRODUCTS"))
	}
	return openReal(o)
}

// ---- 假后端：用本地文件模拟狗内存储，便于在没有狗的机器上跑通流程与测试 ----

type fakeBackend struct {
	mem      []byte
	path     string
	products []Product
	logged   bool
}

func openFake(path, prods string) (Backend, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("假后端读不到模拟狗内存 %s: %w", path, err)
	}
	f := &fakeBackend{mem: b, path: path}
	if prods != "" {
		ps, perr := ParseProducts(prods)
		if perr != nil {
			return nil, perr
		}
		f.products = ps
	}
	return f, nil
}

func (f *fakeBackend) Name() string { return "假后端（模拟狗内存 " + f.path + "）" }

func (f *fakeBackend) Login(vendorCode string, feature uint32) error {
	if vendorCode == "" {
		return fmt.Errorf("假后端也需要 vendor code（用于检查流程）")
	}
	f.logged = true
	return nil
}

func (f *fakeBackend) Logout() error { f.logged = false; return nil }

func (f *fakeBackend) ReadMemory(fileID, offset, length uint32) ([]byte, error) {
	if !f.logged {
		return nil, fmt.Errorf("还没 Login")
	}
	if fileID != 1 {
		return nil, fmt.Errorf("假后端只模拟 fileID=1（收到 %d）", fileID)
	}
	end := uint64(offset) + uint64(length)
	if end > uint64(len(f.mem)) {
		return nil, fmt.Errorf("读越界：offset=%d length=%d 而模拟内存只有 %d 字节", offset, length, len(f.mem))
	}
	out := make([]byte, length)
	copy(out, f.mem[offset:end])
	return out, nil
}

// Decrypt 假后端做一次可逆变换（异或 0x5A），只为把流程跑通 —— 真后端是狗内 AES。
func (f *fakeBackend) Decrypt(fileID uint32, data []byte) ([]byte, error) {
	if !f.logged {
		return nil, fmt.Errorf("还没 Login")
	}
	out := make([]byte, len(data))
	for i, c := range data {
		out[i] = c ^ 0x5A
	}
	return out, nil
}

func (f *fakeBackend) Products() ([]Product, error) { return f.products, nil }

// ParseProducts 解析 "1@2030-01-01,2@perpetual" 这样的授权列表。
func ParseProducts(s string) ([]Product, error) {
	var out []Product
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "@", 2)
		id64, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("产品 ID 不是数字: %q", parts[0])
		}
		p := Product{ID: uint32(id64)}
		if len(parts) == 2 && !isPerpetual(parts[1]) {
			t, terr := time.Parse("2006-01-02", strings.TrimSpace(parts[1]))
			if terr != nil {
				return nil, fmt.Errorf("到期时间格式应为 YYYY-MM-DD: %q", parts[1])
			}
			p.Expiry = t.Add(24*time.Hour - time.Second)
		}
		out = append(out, p)
	}
	return out, nil
}

func isPerpetual(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "perpetual" || s == "永久" || s == ""
}

// Allows 是给调用方用的判定：某个 productID 现在有没有。
func Allows(ps []Product, id uint32, now time.Time) (bool, time.Time) {
	for _, p := range ps {
		if p.ID != id {
			continue
		}
		if p.Expiry.IsZero() {
			return true, time.Time{}
		}
		if now.Before(p.Expiry) {
			return true, p.Expiry
		}
		return false, p.Expiry
	}
	return false, time.Time{}
}

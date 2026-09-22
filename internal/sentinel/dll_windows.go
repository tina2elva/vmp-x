//go:build windows

package sentinel

// 真后端：动态加载 Sentinel LDK 的运行时 DLL，直接调 HASP API。
//
// 为什么用 syscall 动态加载而不是链接导入库：
//   1) 没有狗的机器上不该因为缺少 hasp_*.dll 就连编译都过不去；
//   2) Sentinel 的运行时 DLL 名字带 vendorid（hasp_windows_<vendorid>.dll），构建期不可能固定；
//   3) 找不到 DLL 时我们要能给出**明确错误**，而不是让程序在加载期就崩。
//
// 只用四个最基础的入口：hasp_login / hasp_logout / hasp_read / hasp_decrypt。
// 更丰富的授权查询（hasp_get_info / hasp_get_size）留作下一步 —— 接口已经预留 Products()。

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

type haspHandle uint32

type realBackend struct {
	dll     *syscall.LazyDLL
	name    string
	handle  haspHandle
	logged  bool
	login   *syscall.LazyProc
	logout  *syscall.LazyProc
	read    *syscall.LazyProc
	decrypt *syscall.LazyProc
}

// candidateDLLs 给几个常见命名：显式路径、环境变量、以及程序目录/当前目录里的 hasp*.dll。
func candidateDLLs(explicit string) []string {
	if explicit != "" {
		return []string{explicit}
	}
	var out []string
	if d := os.Getenv("VMPX_SENTINEL_DLL"); d != "" {
		out = append(out, d)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if m, _ := filepath.Glob(filepath.Join(dir, "hasp*.dll")); len(m) > 0 {
			out = append(out, m...)
		}
	}
	if m, _ := filepath.Glob("hasp*.dll"); len(m) > 0 {
		out = append(out, m...)
	}
	return out
}

func openReal(o Options) (Backend, error) {
	cands := candidateDLLs(o.DLLPath)
	if len(cands) == 0 {
		return nil, fmt.Errorf("找不到 Sentinel 运行时 DLL（hasp*.dll）。请把 Sentinel LDK 的运行时 DLL 放到程序目录，或用 -dll / VMPX_SENTINEL_DLL 指定；没有狗时可用假后端：VMPX_SENTINEL_FAKE=<模拟狗内存文件>")
	}
	var lastErr error
	for _, c := range cands {
		dll := syscall.NewLazyDLL(c)
		if err := dll.Load(); err != nil {
			lastErr = fmt.Errorf("加载 %s 失败: %w", c, err)
			continue
		}
		r := &realBackend{dll: dll, name: c}
		r.login = dll.NewProc("hasp_login")
		r.logout = dll.NewProc("hasp_logout")
		r.read = dll.NewProc("hasp_read")
		r.decrypt = dll.NewProc("hasp_decrypt")
		ok := true
		for _, p := range []*syscall.LazyProc{r.login, r.logout, r.read, r.decrypt} {
			if err := p.Find(); err != nil {
				lastErr = fmt.Errorf("%s 里没有 %s: %w", c, p.Name, err)
				ok = false
				break
			}
		}
		if ok {
			return r, nil
		}
	}
	return nil, fmt.Errorf("没有可用的 Sentinel 运行时 DLL: %v", lastErr)
}

func (r *realBackend) Name() string { return "Sentinel 真后端（" + r.name + "）" }

func (r *realBackend) Login(vendorCode string, feature uint32) error {
	vc, err := syscall.BytePtrFromString(vendorCode)
	if err != nil {
		return err
	}
	var h haspHandle
	st, _, _ := r.login.Call(uintptr(feature), uintptr(unsafe.Pointer(vc)), uintptr(unsafe.Pointer(&h)))
	if Status(int32(st)) != StatusOK {
		return fmt.Errorf("hasp_login 失败: %w", Status(int32(st)))
	}
	r.handle = h
	r.logged = true
	return nil
}

func (r *realBackend) Logout() error {
	if !r.logged {
		return nil
	}
	st, _, _ := r.logout.Call(uintptr(r.handle))
	r.logged = false
	if Status(int32(st)) != StatusOK {
		return fmt.Errorf("hasp_logout 失败: %w", Status(int32(st)))
	}
	return nil
}

func (r *realBackend) ReadMemory(fileID, offset, length uint32) ([]byte, error) {
	if !r.logged {
		return nil, fmt.Errorf("还没 Login")
	}
	if length == 0 {
		return nil, fmt.Errorf("length 不能为 0")
	}
	buf := make([]byte, length)
	st, _, _ := r.read.Call(uintptr(r.handle), uintptr(fileID), uintptr(offset), uintptr(length), uintptr(unsafe.Pointer(&buf[0])))
	if Status(int32(st)) != StatusOK {
		return nil, fmt.Errorf("hasp_read(fileid=%d off=%d len=%d) 失败: %w", fileID, offset, length, Status(int32(st)))
	}
	return buf, nil
}

func (r *realBackend) Decrypt(fileID uint32, data []byte) ([]byte, error) {
	if !r.logged {
		return nil, fmt.Errorf("还没 Login")
	}
	_ = fileID // hasp_decrypt 用会话里已登录的 feature，不需要显式 fileID
	buf := make([]byte, len(data))
	copy(buf, data)
	st, _, _ := r.decrypt.Call(uintptr(r.handle), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if Status(int32(st)) != StatusOK {
		return nil, fmt.Errorf("hasp_decrypt 失败: %w", Status(int32(st)))
	}
	return buf, nil
}

func (r *realBackend) Products() ([]Product, error) {
	return nil, fmt.Errorf("真后端的授权查询（hasp_get_info/hasp_get_size）尚未实现 —— 这是下一步；当前请继续用 <产物>.vmplic.bin 那条路做运行期判定")
}

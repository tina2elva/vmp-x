package main

// dongle-probe：探一下 Sentinel 后端可用不可用，并把狗上的授权读出来。
//
//   vmpepoch dongle-probe [--vendor-code <code>] [--feature <n>] [--dll <hasp_*.dll>]
//   vmpepoch dongle-probe --fake <模拟狗内存文件> [--fake-products "1@2030-01-01,2@perpetual"]
//
// 没有狗也能跑：--fake 用本地文件模拟狗内存储（流程/测试用）。

import (
	"flag"
	"fmt"
	"os"

	"github.com/vmpx/vmp-x/internal/sentinel"
)

func cmdDongleProbe(args []string) {
	fs := flag.NewFlagSet("dongle-probe", flag.ExitOnError)
	vc := fs.String("vendor-code", os.Getenv("VMPX_SENTINEL_VENDOR_CODE"), "Sentinel vendor code")
	feat := fs.Uint("feature", 0, "feature id（hasp_login 用）")
	dll := fs.String("dll", "", "显式指定 hasp_*.dll（默认扫程序目录）")
	fake := fs.String("fake", os.Getenv("VMPX_SENTINEL_FAKE"), "假后端：模拟狗内存文件")
	fakeProds := fs.String("fake-products", os.Getenv("VMPX_SENTINEL_FAKE_PRODUCTS"), "假后端的授权列表")
	readOff := fs.Uint("read-offset", 0, "演示 hasp_read：偏移")
	readLen := fs.Uint("read-len", 16, "演示 hasp_read：长度")
	fs.Parse(args)

	be, err := sentinel.Open(sentinel.Options{VendorCode: *vc, Feature: uint32(*feat), DLLPath: *dll, FakeMemory: *fake, FakeProducts: *fakeProds})
	must(err)
	fmt.Printf("[*] 后端: %s\n", be.Name())
	if err := be.Login(*vc, uint32(*feat)); err != nil {
		must(fmt.Errorf("登录失败: %w", err))
	}
	defer func() { _ = be.Logout() }()
	fmt.Println("[+] 已登录")

	if buf, rerr := be.ReadMemory(1, uint32(*readOff), uint32(*readLen)); rerr == nil {
		// 只打印摘要，不打印完整密钥材料：这里演示的是"能读"，不是"把密钥打出来"
		fmt.Printf("[+] hasp_read(fileID=1 off=%d len=%d) 成功，前 4 字节 = %02X %02X %02X %02X\n", *readOff, *readLen, buf[0], buf[1], buf[2], buf[3])
	} else {
		fmt.Printf("[!] hasp_read 失败: %v\n", rerr)
	}

	if ps, perr := be.Products(); perr == nil {
		if len(ps) == 0 {
			fmt.Println("[*] 狗上没有登记授权项（假后端需要 --fake-products）")
		}
		for _, p := range ps {
			fmt.Printf("[*] 授权: %s\n", p)
		}
	} else {
		fmt.Printf("[!] 读授权列表失败: %v\n", perr)
	}
}

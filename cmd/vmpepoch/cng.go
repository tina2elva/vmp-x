package main

// CNG/TPM 密钥相关命令（Windows 上用 ncrypt.dll；其他平台会明确报错）。
//
//   vmpepoch cng-gen   --name <密钥名> --out <前缀>   # 生成不可导出的 P-256 密钥，写出 <前缀>.pub 与 <前缀>.cng
//   vmpepoch cng-probe --name <密钥名>                 # 探针：尝试导出私钥，应当被拒绝（证明不可导出）
//
// 部署给工具的形态：把 <前缀>.cng（只有密钥名）与 vmpx.cred 放到工具目录即可；
// 私钥永远不会以文件形式存在。

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/vmpx/vmp-x/internal/cred"
)

func cmdCngGen(args []string) {
	fs := flag.NewFlagSet("cng-gen", flag.ExitOnError)
	name := fs.String("name", "", "持久化密钥名（例如 vmpx-cng-ACME）")
	out := fs.String("out", "vmpx", "输出前缀：写 <前缀>.pub 与 <前缀>.cng")
	fs.Parse(args)
	if *name == "" {
		fmt.Println("[!] 需要 --name")
		os.Exit(2)
	}
	pub, prov, err := cred.CNGCreate(*name)
	must(err)
	must(os.WriteFile(*out+".pub", []byte(hex.EncodeToString(pub)+"\n"), 0o644))
	must(os.WriteFile(*out+".cng", []byte(*name+"\n"), 0o644))
	fmt.Printf("[+] 已生成不可导出密钥 %q（提供程序: %s）\n", *name, prov)
	fmt.Printf("    公钥: %s.pub   <- 交给厂商签构建凭据\n", *out)
	fmt.Printf("    密钥引用: %s.cng <- 部署到工具目录（里面只有密钥名，没有私钥）\n", *out)
	if e := cred.CNGTryExportPrivate(*name); e != nil {
		fmt.Printf("    自证: %v\n", e)
	}
}

func cmdCngProbe(args []string) {
	fs := flag.NewFlagSet("cng-probe", flag.ExitOnError)
	name := fs.String("name", "", "持久化密钥名")
	fs.Parse(args)
	if *name == "" {
		fmt.Println("[!] 需要 --name")
		os.Exit(2)
	}
	if e := cred.CNGTryExportPrivate(*name); e != nil {
		fmt.Printf("[*] %v\n", e)
		return
	}
	fmt.Println("[!] 这把密钥可以被导出 —— 不是不可导出密钥")
}

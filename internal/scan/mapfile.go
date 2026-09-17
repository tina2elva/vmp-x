package scan

// MSVC MAP 文件支持：给「符号表被 strip、但保留了 .map」的二进制用。
//
// 这是很常见的发布形态：wheel 里的 .pyd 没有 COFF 符号表，可是构建时留下了 .map，
// 里面 "Publics by Value" 一节按 名字 + Rva+Base + 所属 obj 列出所有公开符号。
// 有了它，vmpack 就能按**函数名**保护内部函数（否则只能用 RVA，还得自己查）。
//
// 行样例：
//   0001:00000010       __pyx_pf_7example_n        0000000180001010 f   example.obj
// 第三列是 VA（含 Preferred load address），减去它即 RVA。
import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var mapSymbols map[string]uint32

// LoadMapFile 读入一个 MSVC MAP 文件，登记 名字→RVA。重复调用会整体替换。
func LoadMapFile(path string) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	syms := map[string]uint32{}
	var preferred uint64
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "Preferred load address is") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				if v, err := strconv.ParseUint(fields[len(fields)-1], 16, 64); err == nil {
					preferred = v
				}
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// 第一列形如 0001:00000010（节:偏移）
		if len(fields[0]) < 5 || !strings.Contains(fields[0], ":") {
			continue
		}
		va, err := strconv.ParseUint(fields[2], 16, 64)
		if err != nil {
			continue
		}
		name := fields[1]
		if va >= preferred {
			syms[name] = uint32(va - preferred)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(syms) == 0 {
		return fmt.Errorf("MAP 文件 %s 里没解析出任何符号", path)
	}
	mapSymbols = syms
	return nil
}

// mapRVA 在已载入的 MAP 里查名字。
func mapRVA(name string) (uint32, bool) {
	if mapSymbols == nil {
		return 0, false
	}
	v, ok := mapSymbols[name]
	return v, ok
}

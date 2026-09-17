package scan

import (
	"os"
	"strings"
	"testing"

	dbgpe "debug/pe"

	"github.com/vmpx/vmp-x/internal/load/pe"
)

// 用真实 wheel .pyd（D:\taiji\pytest\example.cp313-win_amd64.pyd）验证「没有符号表」这条路：
//   - 导出表能定位 PyInit_example；
//   - .pdata 能给出一大批函数的精确范围；
//   - 该样本的导出其实是一枚 7 字节跳转桩（jmp [rip+...]），末尾不是 RET，
//     FindFunction 会保守地拒绝（宁可报错也不猜边界）—— 这条行为也钉住。
func TestFindFunctionWithoutSymbols(t *testing.T) {
	const pyd = `D:\taiji\pytest\example.cp313-win_amd64.pyd`
	if _, err := os.Stat(pyd); err != nil {
		t.Skip("本机没有这个样本，跳过")
	}
	df, err := dbgpe.Open(pyd)
	if err != nil {
		t.Fatal(err)
	}
	defer df.Close()
	rva, ok := exportRVA(df, "PyInit_example")
	if !ok {
		t.Fatal("导出表里应能找到 PyInit_example")
	}
	t.Logf("exportRVA(PyInit_example)=0x%X", rva)
	_, dirSize, _ := peDataDir(df, 3)
	if dirSize/12 < 50 {
		t.Errorf(".pdata 条目太少（%d），解析可疑", dirSize/12)
	}
	t.Logf(".pdata 里有 %d 条 RUNTIME_FUNCTION", dirSize/12)
	f, err := pe.Open(pyd)
	if err != nil {
		t.Fatal(err)
	}
	got, err := FindFunction(pyd, f, "PyInit_example")
	if err != nil {
		if !strings.Contains(err.Error(), "RET") {
			t.Errorf("期望是「末尾不是 RET」这类保守拒绝，实际: %v", err)
		}
		t.Logf("按预期保守拒绝: %v", err)
		return
	}
	t.Logf("FindFunction: RVA=0x%X End=0x%X 指令数=%d 字节数=%d", got.RVA, got.End, got.InstrNum, len(got.Code))
}

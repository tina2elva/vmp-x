package inject

import (
	"bytes"
	"testing"
)

// 抹除的语义边界：入口跳板必须原样保留（运行期要用它进 VM），
// 函数体必须被改掉，函数以外的字节一个都不能动。
func TestWipeNativeErasesBodyButKeepsEntryPatch(t *testing.T) {
	orig := make([]byte, 64)
	for i := range orig {
		orig[i] = byte(i + 1)
	}
	data := append([]byte(nil), orig...)
	pl := &Payload{Placements: []Placement{{Name: "f", FuncRVA: 0x100, NativeSize: 20}}}
	rvaToOff := func(rva uint32) (int, error) { return int(rva - 0x100), nil }
	n, err := wipeNative(data, [8]byte{1, 2, 3}, 0x2000, pl, 5, rvaToOff)
	if err != nil {
		t.Fatalf("wipeNative: %v", err)
	}
	if n != 15 {
		t.Fatalf("抹除字节数 = %d，期望 15（NativeSize 20 - patchLen 5）", n)
	}
	if !bytes.Equal(data[:5], orig[:5]) {
		t.Fatalf("入口跳板被改动了: % X", data[:5])
	}
	if bytes.Equal(data[5:20], orig[5:20]) {
		t.Fatalf("函数体没有被抹除: % X", data[5:20])
	}
	if !bytes.Equal(data[20:], orig[20:]) {
		t.Fatalf("抹除越界，改到了函数以外的字节")
	}
	if pl.Placements[0].WipedBytes != 15 {
		t.Fatalf("WipedBytes = %d，期望 15", pl.Placements[0].WipedBytes)
	}
}

// NativeSize <= patchLen 的函数（比跳板还短）不能被当成"有函数体可抹"。
func TestWipeNativeSkipsTinyFunctions(t *testing.T) {
	data := make([]byte, 16)
	pl := &Payload{Placements: []Placement{{Name: "t", FuncRVA: 0x100, NativeSize: 8}}}
	rvaToOff := func(rva uint32) (int, error) { return int(rva - 0x100), nil }
	n, err := wipeNative(data, [8]byte{}, 0x2000, pl, 8, rvaToOff)
	if err != nil {
		t.Fatalf("wipeNative: %v", err)
	}
	if n != 0 {
		t.Fatalf("抹除字节数 = %d，期望 0", n)
	}
	for i, b := range data {
		if b != 0 {
			t.Fatalf("data[%d] 被改动", i)
		}
	}
}

// 填充必须是「构建密钥 + 函数位置」的函数：同一次构建里不同函数不共享同一段填充，
// 不同构建（密钥不同）也不共享 —— 否则填充本身就成了一种可批量匹配的特征。
func TestWipeSeedVariesWithKeyAndFunc(t *testing.T) {
	a := wipeSeed([8]byte{1}, 0x1000, 0x2000)
	if a == wipeSeed([8]byte{1}, 0x1010, 0x2000) {
		t.Fatalf("不同函数的种子相同")
	}
	if a == wipeSeed([8]byte{2}, 0x1000, 0x2000) {
		t.Fatalf("不同构建密钥的种子相同")
	}
	buf1, buf2 := make([]byte, 32), make([]byte, 32)
	wipeResidue(buf1, 0, 32, a)
	wipeResidue(buf2, 0, 32, a)
	if !bytes.Equal(buf1, buf2) {
		t.Fatalf("同一粒种子的填充不稳定")
	}
	wipeResidue(buf2, 0, 32, wipeSeed([8]byte{1}, 0x1010, 0x2000))
	if bytes.Equal(buf1, buf2) {
		t.Fatalf("不同函数的填充相同")
	}
}

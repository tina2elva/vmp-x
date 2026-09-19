#!/usr/bin/env bash
# e2e_elf_image.sh - ELF 整体加密（-enc-image-elf）的**真机**端到端检查。
#
# 为什么单独成脚本：常跑门禁 tools/gates.ps1 是 Windows 侧的；ELF 的"入口自解密"
# 只有在 Linux 上真正加载执行才能验证（本机没有 Linux 真机/qemu，所以这一段长期未验证）。
#
# 用法（Linux/amd64）:
#   bash tools/e2e_elf_image.sh            # 报告模式：比对失败只打印 MISMATCH，退出码仍为 0
#   bash tools/e2e_elf_image.sh --strict   # 严格模式：比对失败即退出 1（确认过之后再用）
set -u
cd "$(dirname "$0")/.."
STRICT=0
if [ $# -gt 0 ] && [ "$1" = "--strict" ]; then STRICT=1; fi
fail() {
    echo "[FAIL] $*"
    if [ "$STRICT" = "1" ]; then exit 1; else exit 0; fi
}

mkdir -p build
go build -o build/vmpbuild ./cmd/vmpbuild || fail "build vmpbuild"
go build -o build/vmpack ./cmd/vmpack || fail "build vmpack"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/elf_target ./testdata/linux || fail "build elf_target"
./build/vmpbuild -src stub/linux/amd64 -out build/vm_interp_linux.bin -manifest build/vm_interp_linux.json -entry vm_entry >/dev/null || fail "build linux blob"

./build/vmpack -exe build/elf_target -func main.checkKey -func main.sumTo \
    -blob build/vm_interp_linux.bin -manifest build/vm_interp_linux.json \
    -out build/elf_target.enc -report build/elf_enc.json -enc-image-elf || fail "pack -enc-image-elf"

echo "[*] 结构：e_entry 必须落在 payload 新段里"
python3 -c '
import json, struct, sys
rep = json.load(open("build/elf_enc.json"))
d = open("build/elf_target.enc","rb").read()
entry = struct.unpack_from("<Q", d, 0x18)[0]
phoff = struct.unpack_from("<Q", d, 0x20)[0]
phentsize = struct.unpack_from("<H", d, 0x36)[0]
phnum = struct.unpack_from("<H", d, 0x38)[0]
base = None
for i in range(phnum):
    o = phoff + i * phentsize
    t, _fl = struct.unpack_from("<II", d, o)
    _off, va = struct.unpack_from("<QQ", d, o + 8)
    if t == 1:
        base = va if base is None else min(base, va)
if base is None:
    base = 0
rva = entry - base
lo, hi = rep["sectionRVA"], rep["sectionRVA"] + rep["sectionSize"]
print("    e_entry=0x%X 基址=0x%X -> RVA=0x%X，payload=[0x%X,0x%X)" % (entry, base, rva, lo, hi))
sys.exit(0 if lo <= rva < hi else 1)
' || fail "e_entry 没有指到 payload"

echo "[*] 文件级：原执行段在打包文件里应 0 残留（非零 64B 块）"
python3 tools/image_residue_elf.py build/elf_target build/elf_target.enc || fail "ELF 代码仍可从打包文件里读到"

echo "[*] 运行期：原生 vs 加密后逐字节比对"
NATIVE_OUT="$(./build/elf_target 2>&1)"
PACKED_OUT="$(./build/elf_target.enc 2>&1)"
if [ "$NATIVE_OUT" = "$PACKED_OUT" ]; then
    echo "[OK  ] ELF 整体加密：输出一致"
else
    echo "[MISMATCH] 原生与加密后输出不同"
    echo "--- native ---"; echo "$NATIVE_OUT" | head -5
    echo "--- packed ---"; echo "$PACKED_OUT" | head -5
    fail "ELF 入口自解密后行为不一致"
fi
echo "[+] e2e_elf_image: OK"

#!/usr/bin/env bash
# e2e_elf_image.sh - ELF 整体加密（-enc-image-elf）的真机端到端检查。
#
# 默认 x86-64（linux-amd64 作业）；切 aarch64 + qemu：
#   BLOB_SRC=stub/linux/arm64 BLOB_CC=aarch64-linux-gnu-gcc GOARCH_TARGET=arm64 QEMU=qemu-aarch64 TAG=a64 #     bash tools/e2e_elf_image.sh --strict
set -u
cd "$(dirname "$0")/.."

STRICT=0
if [ $# -gt 0 ] && [ "$1" = "--strict" ]; then STRICT=1; fi
fail() {
    echo "[FAIL] $*"
    if [ "$STRICT" = "1" ]; then exit 1; else exit 0; fi
}

BLOB_SRC=${BLOB_SRC:-stub/linux/amd64}
BLOB_CC=${BLOB_CC:-}
GOARCH_TARGET=${GOARCH_TARGET:-amd64}
QEMU=${QEMU:-}
TAG=${TAG:-x64}
BLOB_GUEST=${BLOB_GUEST:-}
BLOB_EXTRA=${BLOB_EXTRA:-}
VMP_FUNCS=${VMP_FUNCS:--func main.checkKey -func main.sumTo}

mkdir -p build
go build -o build/vmpbuild ./cmd/vmpbuild || fail "build vmpbuild"
go build -o build/vmpack ./cmd/vmpack || fail "build vmpack"
GOOS=linux GOARCH=$GOARCH_TARGET CGO_ENABLED=0 go build -o build/elf_target ./testdata/linux || fail "build elf_target"

CCARG=""
if [ -n "$BLOB_CC" ]; then CCARG="-cc $BLOB_CC"; fi
GUESTARG=""
if [ -n "$BLOB_GUEST" ]; then GUESTARG="-guest $BLOB_GUEST"; fi
./build/vmpbuild -src "$BLOB_SRC" $CCARG $GUESTARG $BLOB_EXTRA -out build/vm_interp_elf.bin -manifest build/vm_interp_elf.json -entry vm_entry >/dev/null || fail "build blob"

./build/vmpack -exe build/elf_target $VMP_FUNCS \
    -blob build/vm_interp_elf.bin -manifest build/vm_interp_elf.json \
    -out build/elf_target_$TAG.enc -report build/elf_enc_$TAG.json || fail "pack (default -enc-image-elf)"

echo "[*] 结构：e_entry 必须落在 payload 新段里"
ELF_REPORT=build/elf_enc_$TAG.json ELF_PACKED=build/elf_target_$TAG.enc python3 -c '
import json, os, struct, sys
rep = json.load(open(os.environ["ELF_REPORT"]))
d = open(os.environ["ELF_PACKED"], "rb").read()
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
print("    e_entry=0x%X base=0x%X -> RVA=0x%X payload=[0x%X,0x%X)" % (entry, base, rva, lo, hi))
sys.exit(0 if lo <= rva < hi else 1)
' || fail "e_entry not inside payload"

echo "[*] 文件级：原执行段在打包文件里应 0 残留（非零 64B 块）"
python3 tools/image_residue_elf.py build/elf_target build/elf_target_$TAG.enc || fail "ELF code still readable"

echo "[*] 语义级：打包后不应再有成串的可读字符串（.text/.rodata/.gopclntab）"
python3 tools/expose_report.py --img build/elf_target --compare build/elf_target_$TAG.enc \\
    --sections .text,.rodata,.gopclntab --max-ratio 0.05 || fail "packed image still exposes readable strings"

echo "[*] 运行期：原生 vs 加密后逐字节比对"
NATIVE_OUT="$($QEMU ./build/elf_target 2>&1)"
PACKED_OUT="$($QEMU ./build/elf_target_$TAG.enc 2>&1)"
if [ "$NATIVE_OUT" = "$PACKED_OUT" ]; then
    echo "[OK  ] ELF 整体加密：输出一致"
else
    echo "[MISMATCH] 原生与加密后输出不同"
    echo "--- native ---"; echo "$NATIVE_OUT" | head -5
    echo "--- packed ---"; echo "$PACKED_OUT" | head -5
    fail "ELF entry self-decrypt mismatch"
fi
echo "[+] e2e_elf_image: OK"

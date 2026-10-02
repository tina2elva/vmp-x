#!/usr/bin/env bash
# e2e_elf_image.sh - ELF 整体加密（-enc-image-elf）的真机端到端检查。
#
# 默认 x86-64（linux-amd64 作业）；切 aarch64 + qemu：
#   BLOB_SRC=stub/linux/arm64 BLOB_CC=aarch64-linux-gnu-gcc GOARCH_TARGET=arm64 QEMU=qemu-aarch64 TAG=a64 #     bash tools/e2e_elf_image.sh --strict
#
# 三个模式（同一套断言，差别在目标与 vmpack 开关；都由 tools/wsl_linux.sh 驱动）：
#   (默认)          ET_EXEC 的 Go 目标：默认就整体加密。
#   PIE=1           ET_DYN(PIE) 的 Go 目标（go build -buildmode=pie）+ -enc-image-elf-pie。
#                   PIE 的加密范围里只要有一条相对重定位，就必须有运行期应用器
#                   （ld.so 在入口点之前会写那些槽位，密文的 AEAD tag 覆盖整个范围）。
#                   这个目标加密范围里**没有**重定位，所以现在就能跑通，且必须与原生一致。
#   PIE_RELOCS=1    ET_DYN(PIE) 的 **C** 目标（gcc -fPIE），.rodata 里故意放两条
#                   R_X86_64_RELATIVE：默认必须**拒绝**加密那个范围（fail-closed），
#                   产物照旧跑通；打开 -enc-image-elf-pie-relocs 才加密它并把重定位应用表
#                   落进 payload/报告（运行期应用器是另一个任务 ⇒ 那一份只做结构断言、不运行）。
#
# 校准（改之前必须能红）：PIE 模式下"原执行段 0 残留"这条断言在改动前直接失败 ——
# 打包器会打印 "跳过（只支持 ET_EXEC；PIE 会被重定位破坏密文）"，密文根本没做，
# 于是 image_residue_elf.py 报 NON-ZERO FOUND=10121；输出比对却仍然通过（没加密 != 跑不对），
# 所以**必须**有这条结构断言才抓得住。任何 reviewer 都能复现这条校准：
#
#   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildmode=pie -o build/elf_target_pie ./testdata/linux
#   ./build/vmpack -exe build/elf_target_pie -func main.checkKey -func main.sumTo \
#       -blob build/vm_interp_elf.bin -manifest build/vm_interp_elf.json \
#       -enc-image-elf-pie -no-enc-image-elf -out build/cal_pie.enc -report build/cal_pie.json
#   python3 tools/image_residue_elf.py build/elf_target_pie build/cal_pie.enc   # NON-ZERO FOUND=10121, rc=2
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
EXPOSE_SECTIONS=${EXPOSE_SECTIONS:-.text,.rodata,.gopclntab}
BLOB_EXTRA=${BLOB_EXTRA:-}
VMP_FUNCS=${VMP_FUNCS:--func main.checkKey -func main.sumTo}
PIE=${PIE:-0}
PIE_RELOCS=${PIE_RELOCS:-0}

mkdir -p build
go build -o build/vmpbuild ./cmd/vmpbuild || fail "build vmpbuild"
go build -o build/vmpack ./cmd/vmpack || fail "build vmpack"

TARGET=build/elf_target
PACK_EXTRA=""
if [ "$PIE_RELOCS" = "1" ]; then
    # C 目标的夹具（gcc 的 PIE 布局：第一个 PT_LOAD 的 p_vaddr = 0，可执行段从文件偏移 0x1000 开始，
    # 而 .rodata 里有一条指向 .data 的相对重定位）。main 里那句 tbl 自检是**运行期**断言：
    # 只要那两个槽位在运行期不是正确地址，输出/返回码就与原生不同 ⇒ 用例直接抓住。
    TARGET=build/elf_target_pie_reloc
    cat > build/pie_reloc_target.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* See tools/e2e_elf_image.sh: this fixture exists so the packer's
 * "-enc-image-elf-pie refuses ranges that contain relative relocations" rule
 * has a REAL target to be calibrated on.  The pointer array below lands in
 * .rodata with two R_X86_64_RELATIVE entries whose r_offset is inside it. */
static int g_a = 7;
static int g_b = 9;
__attribute__((used, section(".rodata"))) const int *const tbl[2] = {&g_a, &g_b};

__attribute__((noinline)) unsigned long checkKey(unsigned long x) { return ((x * 7) + 42) ^ 0xFF; }

__attribute__((noinline)) long sumTo(long n) {
    long s = 0;
    for (long i = 1; i <= n; i++) s += i;
    return s;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: pie_reloc_target <check-key|sum-to> <arg>\n");
        return 2;
    }
    /* runtime self-check: ld.so must have written both RELATIVE slots correctly,
     * otherwise the encrypted range's relocations were destroyed. */
    if (tbl[0] != &g_a || tbl[1] != &g_b) {
        fprintf(stderr, "reloc slots corrupted\n");
        return 3;
    }
    unsigned long v = strtoul(argv[2], 0, 0);
    if (strcmp(argv[1], "check-key") == 0) {
        printf("%lu\n", checkKey(v));
    } else if (strcmp(argv[1], "sum-to") == 0) {
        printf("%ld\n", sumTo((long)v));
    } else {
        fprintf(stderr, "unknown function\n");
        return 2;
    }
    return 0;
}
EOF
    gcc -fPIE -pie -O1 -o "$TARGET" build/pie_reloc_target.c || fail "build C PIE fixture"
    PACK_EXTRA="-enc-image-elf-pie"
    VMP_FUNCS=${VMP_FUNCS_C:--func checkKey -func sumTo}
    # .rodata 里的两条重定位按设计保持明文（要等运行期应用器），所以只对 .text 断言暴露面。
    EXPOSE_SECTIONS=".text"
elif [ "$PIE" = "1" ]; then
    TARGET=build/elf_target_pie
    GOOS=linux GOARCH=$GOARCH_TARGET CGO_ENABLED=0 go build -buildmode=pie -o "$TARGET" ./testdata/linux || fail "build PIE target"
    PACK_EXTRA="-enc-image-elf-pie"
else
    GOOS=linux GOARCH=$GOARCH_TARGET CGO_ENABLED=0 go build -o "$TARGET" ./testdata/linux || fail "build elf_target"
fi

CCARG=""
if [ -n "$BLOB_CC" ]; then CCARG="-cc $BLOB_CC"; fi
GUESTARG=""
if [ -n "$BLOB_GUEST" ]; then GUESTARG="-guest $BLOB_GUEST"; fi
./build/vmpbuild -src "$BLOB_SRC" $CCARG $GUESTARG $BLOB_EXTRA -out build/vm_interp_elf.bin -manifest build/vm_interp_elf.json -entry vm_entry >/dev/null || fail "build blob"

./build/vmpack -exe "$TARGET" $VMP_FUNCS $PACK_EXTRA \
    -blob build/vm_interp_elf.bin -manifest build/vm_interp_elf.json \
    -out build/elf_target_$TAG.enc -report build/elf_enc_$TAG.json || fail "pack (default -enc-image-elf)"

if [ "$PIE" = "1" ] || [ "$PIE_RELOCS" = "1" ]; then
    echo "[*] PIE: target must be ET_DYN and the report must carry the relocation bookkeeping"
    ELF_TARGET="$TARGET" ELF_REPORT=build/elf_enc_$TAG.json ELF_MODE=$([ "$PIE_RELOCS" = "1" ] && echo relocs || echo pie) \
    python3 - <<'PY' || fail "PIE report assertions"
import json, os, struct

rep = json.load(open(os.environ["ELF_REPORT"]))
d = open(os.environ["ELF_TARGET"], "rb").read()
mode = os.environ["ELF_MODE"]
etype = struct.unpack_from("<H", d, 16)[0]
assert etype == 3, "target is not ET_DYN (e_type=%d)" % etype
assert int(rep["imgEType"]) == 3, "report.imgEType=%s (2=ET_EXEC, 3=ET_DYN)" % rep.get("imgEType")
secs = rep.get("imgSections") or []
assert secs, "no encrypted range at all -- did the packer silently skip the image encryption?"
rv = [int(s["rva"]) for s in secs]
assert int(rep["imgRelocCount"]) == 0, "default must not encrypt reloc-bearing ranges: imgRelocCount=%s" % rep["imgRelocCount"]
assert int(rep["imgRelocTableRVA"]) == 0 and int(rep["imgRelocLen"]) == 0, "no relocations => no reloc table"
print("    e_type=3 imgEType=%s prefBase=0x%X imgSections=%s imgRelocCount=%d"
      % (rep["imgEType"], int(rep["imgPrefBase"]), [(hex(r), s["size"]) for r, s in zip(rv, secs)], int(rep["imgRelocCount"])))
if mode == "relocs":
    assert 0x2000 not in rv, "the .rodata range carries relative relocations but got encrypted anyway: %s" % rv
    print("    .rodata (rva 0x2000, 2 relative relocs) was refused as expected")
else:
    assert int(rep["imgPrefBase"]) == 0x400000, "Go PIE preferred base should be 0x400000, got 0x%X" % int(rep["imgPrefBase"])
PY
fi

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
python3 tools/image_residue_elf.py "$TARGET" build/elf_target_$TAG.enc || fail "ELF code still readable"

# 语义级断言的接线先撤下：ELF 数据节加密在 CI 上暴露了 aarch64 SIGSEGV（docs/STATUS.md 374），
# 等那条查清、并且暴露面数字在 CI 上也解释得通之后再接回来。

echo "[*] 语义级：打包后 >=12 字节的可读串应降到原始的 5% 以内"
python3 tools/expose_report.py --img "$TARGET" --compare build/elf_target_$TAG.enc --sections $EXPOSE_SECTIONS --max-ratio 0.05 || fail "packed image still exposes readable strings"

echo "[*] 运行期：原生 vs 加密后逐字节比对（check-key 与 sum-to 两条路径）"
NATIVE_OUT="$($QEMU ./$TARGET check-key 10 2>&1)"
PACKED_OUT="$($QEMU ./build/elf_target_$TAG.enc check-key 10 2>&1)"
if [ "$NATIVE_OUT" != "$PACKED_OUT" ]; then
    echo "[MISMATCH] 原生与加密后输出不同"
    echo "--- native ---"; echo "$NATIVE_OUT" | head -5
    echo "--- packed ---"; echo "$PACKED_OUT" | head -5
    fail "ELF entry self-decrypt mismatch (check-key)"
fi
NATIVE_SUM="$($QEMU ./$TARGET sum-to 100 2>&1)"
PACKED_SUM="$($QEMU ./build/elf_target_$TAG.enc sum-to 100 2>&1)"
if [ "$NATIVE_SUM" != "$PACKED_SUM" ]; then
    echo "[MISMATCH] sum-to: native=$NATIVE_SUM packed=$PACKED_SUM"
    fail "ELF entry self-decrypt mismatch (sum-to)"
fi
echo "[OK  ] ELF 整体加密：check-key 10 -> $NATIVE_OUT ; sum-to 100 -> $NATIVE_SUM（两次都与原生一致）"

if [ "$PIE_RELOCS" = "1" ]; then
    echo "[*] PIE: with -enc-image-elf-pie-relocs the reloc-bearing range MUST be encrypted and recorded"
    ./build/vmpack -exe "$TARGET" $VMP_FUNCS -enc-image-elf-pie -enc-image-elf-pie-relocs \
        -blob build/vm_interp_elf.bin -manifest build/vm_interp_elf.json \
        -out build/elf_target_${TAG}_relocs.enc -report build/elf_enc_${TAG}_relocs.json >/dev/null || fail "pack (relocs opt-in)"
    ELF_REPORT=build/elf_enc_${TAG}_relocs.json python3 - <<'PY' || fail "reloc-apply table bookkeeping"
import json, os
rep = json.load(open(os.environ["ELF_REPORT"]))
rv = [int(s["rva"]) for s in rep["imgSections"]]
assert 0x2000 in rv, "the .rodata range must be encrypted with -enc-image-elf-pie-relocs: %s" % rv
assert int(rep["imgRelocCount"]) == 2, "expected the 2 .rodata relocs to be recorded, got %s" % rep["imgRelocCount"]
assert int(rep["imgRelocTableRVA"]) != 0, "a relocation table must be emitted into the payload"
assert int(rep["imgRelocLen"]) == 32 + 2 * 8, "table length must be header(32) + 2*8, got %s" % rep["imgRelocLen"]
print("    imgRelocTableRVA=0x%X imgRelocLen=%d imgRelocCount=%d" % (int(rep["imgRelocTableRVA"]), int(rep["imgRelocLen"]), int(rep["imgRelocCount"])))
PY
    # 这一份**现在只能失败**：运行期应用器（先减 delta / 验签 / 解密 / 再加回 delta）是下一个任务。
    # 但它必须**fail-closed**（ld.so 已经写过那两个槽位 ⇒ AEAD 验签失败 ⇒ ud2），
    # 而不是带着错的重定位值往下跑 —— 后者才是真正危险的那种"能跑但算错"。
    echo "[*] PIE: the relocs product must fail CLOSED until the runtime applier lands"
    OPT_RC=0
    OPT_OUT="$(./build/elf_target_${TAG}_relocs.enc check-key 10 2>&1)" || OPT_RC=$?
    if [ "$OPT_RC" -eq 0 ] && [ "$OPT_OUT" = "$NATIVE_OUT" ]; then
        echo "[NOTE] the relocs product now runs correctly -- the runtime applier has landed;"
        echo "       replace this fail-closed expectation with a plain native-vs-packed check."
    elif printf '%s' "$OPT_OUT" | grep -q "verifyfail"; then
        echo "[OK  ] fail-closed as expected: rc=$OPT_RC, out=[$OPT_OUT]"
    else
        fail "relocs product neither ran correctly nor failed closed (rc=$OPT_RC, out=[$OPT_OUT])"
    fi
fi

echo "[+] e2e_elf_image: OK"

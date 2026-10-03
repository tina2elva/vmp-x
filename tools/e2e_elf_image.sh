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
#                   R_X86_64_RELATIVE：默认必须**拒绝**加密那个范围（fail-closed），产物照旧跑通；
#                   打开 -enc-image-elf-pie-relocs 才加密它并把重定位应用表落进 payload/报告。
#                   这一份**必须与原生逐字节一致**（check-key 10 → 143、sum-to 100 → 5050）：
#                   它是运行期应用器（vm_reloc_fix）唯一的端到端验收点。
#
# 校准 1（改之前必须能红）：PIE 模式下"原执行段 0 残留"这条断言在 t3 之前直接失败 ——
# 打包器会打印 "跳过（只支持 ET_EXEC；PIE 会被重定位破坏密文）"，密文根本没做，
# 于是 image_residue_elf.py 报 NON-ZERO FOUND=10121；输出比对却仍然通过（没加密 != 跑不对），
# 所以**必须**有这条结构断言才抓得住。任何 reviewer 都能复现这条校准：
#
#   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildmode=pie -o build/elf_target_pie ./testdata/linux
#   ./build/vmpack -exe build/elf_target_pie -func main.checkKey -func main.sumTo \
#       -blob build/vm_interp_elf.bin -manifest build/vm_interp_elf.json \
#       -enc-image-elf-pie -no-enc-image-elf -out build/cal_pie.enc -report build/cal_pie.json
#   python3 tools/image_residue_elf.py build/elf_target_pie build/cal_pie.enc   # NON-ZERO FOUND=10121, rc=2
#
# 校准 2（PIE_RELOCS=1 的"与原生一致"断言必须能红）：把运行期应用器短路掉再跑同一个用例。
# **只在本地做，不要提交 stub/**（本任务的 in-scope 只有 tools/）：
#
#   python3 - <<'PY'
#   p = "stub/win/x64/vm_interp.c"
#   s = open(p).read()
#   s = s.replace("    const u8 *eh = (const u8 *)base;\n    u64 phoff",
#                 "    return 0; /* CAL: short-circuit the applier */\n    const u8 *eh = (const u8 *)base;\n    u64 phoff", 1)
#   open(p, "w").write(s)
#   PY
#   PIE_RELOCS=1 TAG=cal bash tools/e2e_elf_image.sh --strict   # 必须 [MISMATCH] + exit 1
#   git checkout -- stub/win/x64/vm_interp.c                     # 恢复（git status 必须干净）
#   # 实测输出（t10，短路后跑 --strict）：
#   #   [*] PIE: the reloc-bearing product must answer exactly what native answers
#   #   [MISMATCH] reloc-bearing product check-key: native=[143] (rc=0) packed=[VMPELF verifyfail rva=8192
#   #   VMPELF verifyfail size=128] (rc=132)
#   #   [FAIL] reloc-bearing PIE product is not byte-identical to native (check-key)   -> exit 1
#
# 校准 3（fail-closed `code=8`：重定位表地址既不在运行期窗口、也不在链接期窗口）：运行期应用器
# 读的是**目标自己的** PT_DYNAMIC（DT_RELA/DT_RELASZ），**不是** payload 里那张 VMPR 应用表 ——
# 把那张表整张清零，产物照样与原生一致（实测，本用例构造时顺手验过）。所以想构造 code=8 只能改动态段，
# 而"直接改坏动态段"会被 ld.so 先拦。本轮实测的四条死路（都在 PIE_RELOCS=1 的产物上）：
#   * DT_RELA -> 未映射地址(0x900000)：ld.so 读表即 SIGSEGV，rc=139，根本进不到入口蹦床；
#   * DT_RELAENT = 16：ld.so 断言 get-dynamic-info.h:123（DT_RELAENT == sizeof(Rela)）失败，rc=127；
#   * DT_RELA -> 窗口外但已映射的零页、RELASZ=24、**RELACOUNT 保持 5**：glibc 走"前 RELACOUNT 条
#     都是 RELATIVE"的快路径，断言 dl-machine.h:498（r_info == R_X86_64_RELATIVE）失败，rc=127；
#   * payload 里那张 VMPR 表（selfRVA/flags/条目）怎么改都没用：运行期不读它。
# 可构造的一版（本脚本末尾那段）：DT_RELA 指向"镜像窗口之外、但仍在最后一个 PT_LOAD 映射页里的
# 零字节尾巴"，RELASZ=24，并把 RELACOUNT 改成 0 —— 于是 ld.so 读到的那一条是全零
# （R_X86_64_NONE，无操作），它照常把控制权交给入口蹦床，应用器这才按"两个窗口都不含该地址"判硬门。
# 实测：exit 7 + stderr "VMPELF relocfail code=8"（未构造的同一份产物：exit 0 / 143 / 无 relocfail）。
# 顺带登记一条**文档**缺陷（本轮只读核对，未改该文件）：internal/inject/payload.go 的
# RelocTableHeaderSize 注释把运行期算法写成"每个条目就地 -= delta"，而 vm_reloc_fix 实际是
# "槽位 := r_addend ^ 密码流字节（还原原始密文）→ 验签/解密 → += delta" —— 减 delta 会得到链接期
# 明文、验签仍然不过（这正是"直接改动态表会被 ld.so 先拦"之外的另一个误读来源）。
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
    # 这一份必须**与原生逐字节一致**：含相对重定位的加密范围要靠运行期应用器
    # （stub/win/x64/vm_interp.c 的 vm_reloc_fix：先按 r_addend ^ 密码流还原密文 → 验签 → 解密
    #  → 再把槽位写成 l_addr + r_addend）才能跑起来。应用器缺失/被短路/写错，这里就红。
    # 原来这里是一条"必须 fail-closed"的期望（应用器未落地时的占位），t10 起换成真检查。
    echo "[*] PIE: the reloc-bearing product must answer exactly what native answers"
    OPT_RC=0
    OPT_OUT="$(./build/elf_target_${TAG}_relocs.enc check-key 10 2>&1)" || OPT_RC=$?
    if [ "$OPT_RC" -ne 0 ] || [ "$OPT_OUT" != "$NATIVE_OUT" ]; then
        echo "[MISMATCH] reloc-bearing product check-key: native=[$NATIVE_OUT] (rc=0) packed=[$OPT_OUT] (rc=$OPT_RC)"
        fail "reloc-bearing PIE product is not byte-identical to native (check-key)"
    fi
    OPT_SUM_RC=0
    OPT_SUM="$(./build/elf_target_${TAG}_relocs.enc sum-to 100 2>&1)" || OPT_SUM_RC=$?
    if [ "$OPT_SUM_RC" -ne 0 ] || [ "$OPT_SUM" != "$NATIVE_SUM" ]; then
        echo "[MISMATCH] reloc-bearing product sum-to: native=[$NATIVE_SUM] (rc=0) packed=[$OPT_SUM] (rc=$OPT_SUM_RC)"
        fail "reloc-bearing PIE product is not byte-identical to native (sum-to)"
    fi
    echo "[OK  ] 带重定位的 PIE 产物：check-key 10 -> $OPT_OUT ; sum-to 100 -> $OPT_SUM（与原生一致）"

    # ---- fail-closed code=8：重定位表地址**既不在运行期窗口、也不在链接期窗口** ----
    # 运行期应用器（vm_interp.c 的 vm_reloc_fix）读的是**目标自己的** PT_DYNAMIC：DT_RELA/DT_RELASZ
    # 在运行期已经被 ld.so 就地改成运行期地址，应用器必须在"运行期窗口 [base, base+imgSize)"和
    # "链接期窗口 [prefBase, linkEnd)"里认出它；两边都不在就走硬门（code=8，exit 7）。
    # payload 里那张 VMPR 应用表**运行期不被读**，所以构造点只能在动态段（改那张表 = 无效，实测见头部校准 3）。
    #
    # 构造（对产物**副本**做字节级改写；运行期一行不动、格式也不变）：
    #   DT_RELA      := 镜像窗口之外、但仍在最后一个 PT_LOAD 映射页里的零字节尾巴
    #                   （= page_up(linkEnd) - 32：读它得到全零，不会 SIGSEGV）
    #   DT_RELASZ    := 24（正好一条）
    #   DT_RELACOUNT := 0（否则 glibc 按"前 RELACOUNT 条都是 RELATIVE"的快路径读那张表，
    #                     会在 ld.so 里先断言死掉 —— 这就是"直接改动态表会被 ld.so 先拦"的真身）
    # 于是 ld.so 从那张"表"里读到的唯一一条是全零 ⇒ R_X86_64_NONE（无操作），它照常跳入口蹦床；
    # 蹦床里的应用器按"两个窗口都不含该地址"判定 ⇒ 硬门 code=8 ⇒ exit 7。
    #
    # 校准（本块自带两条断言，防止"空转"）：
    #   ① 未构造的同一份产物：exit 0、输出与原生一致、stderr 里没有 relocfail；
    #   ② 构造后：exit 7 且 stderr 含 "relocfail code=8"。
    echo "[*] PIE: fail-closed code=8 (reloc table address in NEITHER window) must be constructible"
    C8_PRISTINE="build/elf_target_${TAG}_relocs.enc"
    C8_COPY="build/elf_target_${TAG}_c8.enc"
    rm -f "$C8_COPY"
    python3 - "$C8_PRISTINE" "$C8_COPY" <<'PY' || fail "construct the code=8 artifact"
import os, struct, sys
src, dst = sys.argv[1], sys.argv[2]
d = bytearray(open(src, "rb").read())
def u16(o): return struct.unpack_from("<H", d, o)[0]
def u32(o): return struct.unpack_from("<I", d, o)[0]
def u64(o): return struct.unpack_from("<Q", d, o)[0]
phoff, phentsize, phnum = u64(0x20), u16(0x36), u16(0x38)
loads, dynamic = [], None
for i in range(phnum):
    o = phoff + i * phentsize
    t = u32(o)
    if t == 1:
        loads.append((u64(o + 16), u64(o + 40), u64(o + 8), o))  # p_vaddr, p_memsz, p_offset, phdr off
    elif t == 2:
        dynamic = (u64(o + 16), u64(o + 32))  # p_vaddr, p_filesz
assert loads and dynamic, "packed product has no PT_LOAD/PT_DYNAMIC"
def va2off(va):
    for (va0, msz, off0, _pho) in loads:
        if va0 <= va < va0 + msz:
            return off0 + (va - va0)
    return None
PAGE = 0x1000
va0, msz, off0, pho = max(loads, key=lambda l: l[0] + l[1])
link_end = va0 + msz
# The table must live in a mapped page but outside [prefBase, linkEnd).  Keep >=32 bytes of
# zero tail in that last page; if the segment ends too close to the page boundary, grow its
# p_memsz by 64 bytes (plain .bss semantics -- nobody uses those bytes).
if ((link_end + PAGE - 1) & ~(PAGE - 1)) - link_end < 32:
    msz += 64
    struct.pack_into("<Q", d, pho + 40, msz)
    link_end = va0 + msz
target = ((link_end + PAGE - 1) & ~(PAGE - 1)) - 32
dynoff = va2off(dynamic[0])
assert dynoff is not None, "PT_DYNAMIC is not covered by any PT_LOAD"
want = {7: ("DT_RELA", target), 8: ("DT_RELASZ", 24), 0x6FFFFFF9: ("DT_RELACOUNT", 0)}
hit = []
for j in range(dynamic[1] // 16):
    o = dynoff + j * 16
    tag = u64(o)
    if tag == 0:
        break
    if tag in want:
        struct.pack_into("<Q", d, o + 8, want[tag][1])
        hit.append(want[tag][0])
assert sorted(hit) == sorted(["DT_RELA", "DT_RELASZ", "DT_RELACOUNT"]), \
    "dynamic section lacks the expected tags (hit=%r)" % (hit,)
open(dst, "wb").write(d)
os.chmod(dst, 0o755)
print("    dynamic @file 0x%X ; linkEnd=0x%X ; out-of-window table VA=0x%X ; patched=%s"
      % (dynoff, link_end, target, ",".join(sorted(hit))))
PY
    c8_run() {  # $1 = binary -> C8_RC / C8_OUT / C8_ERR
        local errf
        errf="$(mktemp)"
        C8_OUT="$("$1" check-key 10 2>"$errf")"
        C8_RC=$?
        C8_ERR="$(cat "$errf")"
        rm -f "$errf"
    }
    c8_run "./$C8_PRISTINE"
    if [ "$C8_RC" -ne 0 ] || [ "$C8_OUT" != "$NATIVE_OUT" ] || printf '%s' "$C8_ERR" | grep -q relocfail; then
        echo "[MISMATCH] calibration (unpatched): rc=$C8_RC out=[$C8_OUT] err=[$C8_ERR]"
        fail "code=8 case would be spinning: the unpatched product must not report relocfail"
    fi
    C8_BASE_OUT="$C8_OUT"
    c8_run "./$C8_COPY"
    if [ "$C8_RC" -ne 7 ] || ! printf '%s' "$C8_ERR" | grep -q 'relocfail code=8'; then
        echo "[MISMATCH] code=8 artifact: rc=$C8_RC out=[$C8_OUT]"
        printf '%s\n' "$C8_ERR" | head -n 5 | sed 's/^/    /'
        fail "the patched product must exit 7 with 'relocfail code=8' on stderr"
    fi
    echo "[OK  ] code=8: unpatched -> $C8_BASE_OUT (rc=0, no relocfail) ; patched -> rc=7 + $(printf '%s' "$C8_ERR" | head -n 1)"
fi

# ---- 静态 PIE：显式请求 -enc-image-elf-pie 但打包端拒绝加密时，必须**醒目告警**，且产物仍可用 ----
# 背景（TODO #772）：曾登记"静态 PIE + 该开关 ⇒ 产物 rc=139(SIGSEGV)"。2026-10-02 实测**复现不出来**：
# 跳过分支产出的产物与原生逐字节一致。所以这条用例钉住的是两件**真的**要求：
#   ① 告警必须显眼（[!]，不是 [*]）—— 否则会造成"以为加了密、其实没有"；
#   ② 既然只是跳过（没加密），产物就必须**可用**（与原生一致），不能借跳过之名产出坏产物。
# 只在**本机架构**（无 QEMU 的 x86-64 宿主）跑：夹具是 `gcc -static-pie` 出来的**宿主**可执行文件，
# 而 arm64 那次调用同样满足 PIE=0 —— 若不守这一条，就会把"x86-64 夹具"和"arm64 blob"打在一起，
# 产物必然 SIGSEGV(rc=139)。**这正是历史上"静态 PIE ⇒ rc=139"那条记录的真身：架构不匹配的伪缺陷**
# （2026-10-02 实测：同一块在 amd64 调用里通过、在 a64 调用里 rc=139）。
if [ "$PIE" = "0" ] && [ "$PIE_RELOCS" = "0" ] && [ -z "$QEMU" ] && [ "$GOARCH_TARGET" = "amd64" ]; then
    echo "[*] static-PIE: -enc-image-elf-pie must be refused LOUDLY (and the product must still work)"
    cat > build/static_pie_target.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int g_a = 7; static int g_b = 9;
__attribute__((used, section(".rodata"))) const int *const tbl[2] = {&g_a, &g_b};
__attribute__((noinline)) unsigned long checkKey(unsigned long x) { return ((x * 7) + 42) ^ 0xFF; }
__attribute__((noinline)) long sumTo(long n) { long s = 0; for (long i = 1; i <= n; i++) s += i; return s; }
int main(int argc, char **argv) {
    if (argc < 3) { return 2; }
    unsigned long v = strtoul(argv[2], 0, 0);
    if (strcmp(argv[1], "check-key") == 0) printf("%lu\n", checkKey(v));
    else if (strcmp(argv[1], "sum-to") == 0) printf("%ld\n", sumTo((long)v));
    else return 2;
    return 0;
}
EOF
    gcc -static-pie -O1 -o build/elf_target_staticpie build/static_pie_target.c || fail "build static-PIE fixture"
    # 校准之一：夹具必须**真的**没有 PT_INTERP，否则本条根本没走到目标分支。
    if readelf -lW build/elf_target_staticpie | grep -q INTERP; then
        fail "static-PIE fixture has PT_INTERP; this case would not exercise the skip branch"
    fi
    SP_OUT="$(./build/vmpack -exe build/elf_target_staticpie -func checkKey -func sumTo -enc-image-elf-pie \
        -blob build/vm_interp_elf.bin -manifest build/vm_interp_elf.json \
        -out build/elf_target_staticpie.enc -report build/elf_enc_staticpie.json 2>&1)" || fail "pack static PIE"
    if ! printf '%s' "$SP_OUT" | grep -q '^\[!\] ELF 整体加密：跳过'; then
        printf '%s\n' "$SP_OUT" | tail -n 4
        fail "static PIE skip must be a LOUD [!] warning (no such line) -- see TODO #772"
    fi
    SP_NATIVE_RC=0; SP_NATIVE="$(./build/elf_target_staticpie check-key 10 2>&1)" || SP_NATIVE_RC=$?
    SP_PACKED_RC=0; SP_PACKED="$(./build/elf_target_staticpie.enc check-key 10 2>&1)" || SP_PACKED_RC=$?
    if [ "$SP_PACKED_RC" -ne 0 ] || [ "$SP_PACKED" != "$SP_NATIVE" ]; then
        echo "[MISMATCH] static PIE product: native=[$SP_NATIVE] (rc=$SP_NATIVE_RC) packed=[$SP_PACKED] (rc=$SP_PACKED_RC)"
        fail "a skipped-over static PIE product must still behave like native"
    fi
    echo "[OK  ] 静态 PIE：打包端醒目告警且产物与原生一致（check-key 10 -> $SP_PACKED）"
fi

# ---- aarch64：加密范围内重定位 —— 打包侧可断言，运行期侧如实登记为"无可跑用例" ----
# #376/#377 把 aarch64 的只读数据节加密默认关掉（根因未定，AGENTS.md 禁止打开），所以
# "加密范围里带 R_AARCH64_RELATIVE" 这条运行期路径一直没有可跑用例。本块做两件**能跑**的事，
# 并把跑不了的那半用实测数字打进日志（不做断言）：
#   ① 打包侧契约：造一个 aarch64 PIE 夹具（.rodata 里两条相对重定位），用
#      -enc-image-elf-pie -enc-image-elf-pie-relocs 打包，然后让**布局门禁**从产物自己的
#      PT_DYNAMIC 重新推导"范围内重定位条数/应用表 RVA/类型"（E5(b)），并顺带把 E1..E4 与
#      全部校准跑在**aarch64 产物**上（此前门禁只吃过 amd64 产物）。
#   ② 运行期侧：今天不可达 —— 数据节加密被 #376/#377 禁；把重定位放进**可执行**范围则产物在
#      amd64 上也会 SIGSEGV（DT_TEXTREL 类夹具，plain 打包同样崩）。所以这里只**记录**实测
#      运行结果，不写成断言：把一个"当前崩"的状态钉成期望值，等于给未来的修复埋一颗假红，
#      而这部分的结论写在 tools/check_elf_layout.py 的 "E5 coverage gap on aarch64" 一节里。
if [ "${GOARCH_TARGET}" = "arm64" ] && [ -n "${BLOB_CC}" ]; then
    echo "[*] aarch64: reloc-in-encrypted-range -- packing half asserted, runtime half registered as unverified (#376/#377)"
    A64_CC=${A64_CC:-aarch64-linux-gnu-gcc}
    cat > build/a64_pie_reloc.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int g_a = 7;
static int g_b = 9;
__attribute__((used, section(".rodata"))) const int *const tbl[2] = {&g_a, &g_b};
__attribute__((noinline)) unsigned long checkKey(unsigned long x) { return ((x * 7) + 42) ^ 0xFF; }
__attribute__((noinline)) long sumTo(long n) { long s = 0; for (long i = 1; i <= n; i++) s += i; return s; }
int main(int argc, char **argv) {
    if (argc < 3) { return 2; }
    if (tbl[0] != &g_a || tbl[1] != &g_b) { fprintf(stderr, "reloc slots corrupted\n"); return 3; }
    unsigned long v = strtoul(argv[2], 0, 0);
    if (strcmp(argv[1], "check-key") == 0) printf("%lu\n", checkKey(v));
    else if (strcmp(argv[1], "sum-to") == 0) printf("%ld\n", sumTo((long)v));
    else return 2;
    return 0;
}
EOF
    "$A64_CC" -fPIE -pie -O1 -o build/elf_target_a64reloc build/a64_pie_reloc.c || fail "build aarch64 PIE fixture"
    ./build/vmpack -exe build/elf_target_a64reloc -func checkKey -func sumTo \
        -enc-image-elf-pie -enc-image-elf-pie-relocs \
        -blob build/vm_interp_elf.bin -manifest build/vm_interp_elf.json \
        -out build/elf_target_a64reloc.enc -report build/elf_enc_a64reloc.json || fail "pack aarch64 reloc case"
    python3 tools/check_elf_layout.py --packed build/elf_target_a64reloc.enc \
        --manifest build/vm_interp_elf.json --blob build/vm_interp_elf.bin \
        --report build/elf_enc_a64reloc.json --selftest || fail "aarch64 layout gate (packing half of the reloc contract)"
    # qemu 的 -L 是**前缀**：guest 里的 /lib/ld-linux-aarch64.so.1 会被解析成 <前缀>/lib/... ，
    # 所以前缀要取"loader 所在目录的上一级"（例如 /usr/aarch64-linux-gnu/lib -> /usr/aarch64-linux-gnu）。
    A64_LDFILE="$("$A64_CC" -print-file-name=ld-linux-aarch64.so.1 2>/dev/null)"
    A64_LD="$(dirname "$(dirname "$A64_LDFILE")")"
    if [ -f "$A64_LDFILE" ]; then
        A64_NAT_RC=0; A64_NAT="$($QEMU -L "$A64_LD" ./build/elf_target_a64reloc check-key 10 2>&1)" || A64_NAT_RC=$?
        A64_RC=0; A64_OUT="$($QEMU -L "$A64_LD" ./build/elf_target_a64reloc.enc check-key 10 2>&1)" || A64_RC=$?
        echo "[INFO] aarch64 reloc product runtime (NOT asserted): native rc=$A64_NAT_RC -> [$A64_NAT] ; packed rc=$A64_RC -> [$(printf '%s' "$A64_OUT" | head -n 2 | tr '\n' ' ')]"
        echo "[INFO]   today the packed one cannot answer like native: read-only-data encryption is off on aarch64 (#376/#377) and a reloc slot inside an encrypted executable range SIGSEGVs on amd64 too"
    else
        echo "[INFO] aarch64 reloc product runtime: no aarch64 loader next to $A64_CC (looked for [$A64_LDFILE]) -- runtime half left unverified (#376/#377)"
    fi
fi

echo "[+] e2e_elf_image: OK"

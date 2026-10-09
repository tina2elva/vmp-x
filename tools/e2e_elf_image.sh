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
# run_target：执行一个产物（qemu 下要带上 -L 前缀）。参数化的执行器（$1 可省略 = 本机直接跑），
# 这样同一段断言在"本机原生"和"经 qemu 跑另一种架构"两种驱动下都能用。
run_target() {
    local runner="$1"; shift
    if [ -n "$runner" ]; then "$runner" "$@"; else "$@"; fi
}
TARGET_RUN="$QEMU"
if [ -n "$QEMU" ] && [ "$GOARCH_TARGET" = "arm64" ]; then
    A64_RT_CC="${A64_CC:-aarch64-linux-gnu-gcc}"
    A64_RT_LDFILE="$("$A64_RT_CC" -print-file-name=ld-linux-aarch64.so.1 2>/dev/null)"
    if [ -f "$A64_RT_LDFILE" ]; then
        A64_RT_LD="$(dirname "$(dirname "$A64_RT_LDFILE")")"
        TARGET_RUN="$QEMU -L $A64_RT_LD"
    fi
fi

# ---- 载荷形状的两把尺子（t8/G2）：槽位数 + 实测档位 ----
#
# payload_slots()：在**源目标**上复刻 internal/load/elf.File.SparePhdrSlots 的槽位计数
#   （类型优先 + 取最低空闲索引；PT_NOTE → PT_GNU_RELRO → 无 PT_INTERP 时的 PT_PHDR/PT_NULL）。
# payload_tier()：从**产物**程序头 + report + manifest 读出它实际落在哪一档
#   (1) 三段相邻 / (2) 前缀只读 + 一段 W+X 窗口+尾部 / (3) 整段 W+X / (0) 无窗口 / (DEFECT) 老重叠形状。
# assert_tier_matches_slots()：把两者对起来 —— 这才是"槽位足够的目标不得走回退"的**真断言**。
#   只对"报告 ↔ 程序头一致"（payloadWXFallback 那条）做不出这个结论：打包端整体回归到 (2)/(3) 时
#   flag 会一起变 true、形状仍合法 ⇒ 全绿。这里按源目标的槽位数算出**应有的档位**再比对。
payload_slots() {  # $1 = 源目标 ELF -> 可复用程序头槽位数
    python3 - "$1" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
PT_NOTE, PT_INTERP, PT_PHDR, PT_NULL, PT_GNU_RELRO = 4, 3, 6, 0, 0x6474E552
phoff, pes, phn = struct.unpack_from("<Q", d, 0x20)[0], struct.unpack_from("<H", d, 0x36)[0], struct.unpack_from("<H", d, 0x38)[0]
types = [struct.unpack_from("<I", d, phoff + i * pes)[0] for i in range(phn)]
used = [False] * len(types)
n = 0
def take(pred):
    global n
    for i, t in enumerate(types):
        if not used[i] and pred(t):
            used[i] = True
            n += 1
            return True
    return False
def drain(pred):
    while take(pred):
        pass
drain(lambda t: t == PT_NOTE)
drain(lambda t: t == PT_GNU_RELRO)
if PT_INTERP not in types:          # canDropPHDR()
    drain(lambda t: t in (PT_PHDR, PT_NULL))
print(n)
PY
}

payload_tier() {  # $1 packed, $2 report, $3 manifest
    ELF_PACKED="$1" ELF_REPORT="$2" ELF_MANIFEST="$3" python3 - <<'PY'
import json, os, struct
d = open(os.environ["ELF_PACKED"], "rb").read()
rep = json.load(open(os.environ["ELF_REPORT"]))
man = json.load(open(os.environ["ELF_MANIFEST"]))
phoff, pes, phn = struct.unpack_from("<Q", d, 0x20)[0], struct.unpack_from("<H", d, 0x36)[0], struct.unpack_from("<H", d, 0x38)[0]
loads = []
for i in range(phn):
    o = phoff + i * pes
    t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", d, o)
    if t == 1:
        loads.append(dict(flags=fl, off=off, vaddr=va, filesz=fsz, memsz=msz))
base = min((l["vaddr"] & ~0xFFF for l in loads), default=0)
sec_va = base + int(rep["sectionRVA"])
sec_size = int(rep["sectionSize"])
bss_off, bss_size = int(man["bssOff"]), int(man["bssSize"])
bss_va, bss_end = sec_va + bss_off, sec_va + bss_off + bss_size
tail = sec_size - bss_off - bss_size
PF_W, PF_X = 2, 1

def at(va):
    return next((l for l in loads if l["vaddr"] == va), None)

def fs(f):
    return ("R" if f & 4 else "-") + ("W" if f & PF_W else "-") + ("X" if f & PF_X else "-")

pl = at(sec_va)
win = at(bss_va) if bss_size > 0 else None
if (pl is not None and not (pl["flags"] & PF_W) and bss_size > 0
        and pl["memsz"] >= bss_off + bss_size and win is not None and (win["flags"] & PF_W)):
    print("(DEFECT) old overlay shape: non-writable payload LOAD @0x%X (flags=%s memsz=0x%X) covers the "
          "window [0x%X,0x%X) and an RW segment @0x%X is nested inside it"
          % (pl["vaddr"], fs(pl["flags"]), pl["memsz"], bss_va, bss_end, win["vaddr"]))
elif pl is None:
    print("(none) no payload LOAD at sectionRVA (0x%X)" % sec_va)
elif bss_size == 0:
    if pl["flags"] & PF_W:
        print("(none) manifest bssSize=0 but the payload LOAD is writable (flags=%s)" % fs(pl["flags"]))
    else:
        print("(0) one %s payload LOAD @0x%X (0x%X), no writable window (manifest bssSize=0)"
              % (fs(pl["flags"]), pl["vaddr"], pl["filesz"]))
elif pl["filesz"] == sec_size:
    if (pl["flags"] & PF_W) and (pl["flags"] & PF_X):
        print("(3) ONE W+X payload segment @0x%X (flags=%s filesz=0x%X memsz=0x%X), window [0x%X,0x%X) "
              "file-backed inside it" % (pl["vaddr"], fs(pl["flags"]), pl["filesz"], pl["memsz"], bss_va, bss_end))
    else:
        print("(none) the payload LOAD maps the whole payload but is not W+X (flags=%s)" % fs(pl["flags"]))
elif pl["filesz"] == bss_off and not (pl["flags"] & PF_W):
    prefix = "RX prefix @0x%X (flags=%s filesz=0x%X)" % (pl["vaddr"], fs(pl["flags"]), pl["filesz"])
    if win is None:
        print("(none) %s but no segment at the writable window start 0x%X" % (prefix, bss_va))
    elif not (win["flags"] & PF_W):
        print("(none) %s and the window segment @0x%X is not writable (flags=%s)"
              % (prefix, bss_va, fs(win["flags"])))
    elif (win["flags"] & PF_X) and win["filesz"] == bss_size + tail and win["memsz"] == win["filesz"]:
        print("(2) %s + **W+X window+tail** segment [0x%X,0x%X) (flags=%s filesz=0x%X) -- code page stays "
              "read-only, that one span is writable" % (prefix, bss_va, bss_end + tail, fs(win["flags"]), win["filesz"]))
    elif win["filesz"] == bss_size and win["memsz"] == bss_size:
        window = "RW window [0x%X,0x%X) (flags=%s filesz=0x%X)" % (bss_va, bss_end, fs(win["flags"]), win["filesz"])
        tl = at(bss_end) if tail > 0 else None
        if tail == 0:
            print("(1) %s + %s -- payload ends at the window edge, no tail" % (prefix, window))
        elif tl is not None and (tl["flags"] & PF_X) and not (tl["flags"] & PF_W) and tl["filesz"] == tail:
            print("(1) THREE adjacent segments: %s + %s + R+X tail @0x%X (flags=%s filesz=0x%X)"
                  % (prefix, window, bss_end, fs(tl["flags"]), tl["filesz"]))
        else:
            print("(none) %s + %s but the payload tail @0x%X (0x%X bytes) is missing or not R+X"
                  % (prefix, window, bss_end, tail))
    else:
        print("(none) window segment @0x%X is flags=%s 0x%X/0x%X, expected 0x%X (or window+tail 0x%X)"
              % (bss_va, fs(win["flags"]), win["filesz"], win["memsz"], bss_size, bss_size + tail))
else:
    print("(none) payload LOAD @0x%X is flags=%s filesz=0x%X memsz=0x%X -- not a legal M5 shape"
          % (pl["vaddr"], fs(pl["flags"]), pl["filesz"], pl["memsz"]))
PY
}

assert_tier_matches_slots() {  # $1 tier line, $2 源目标, $3 report, $4 manifest
    local tier="$1" src="$2" rep="$3" man="$4" slots expected label
    label="${tier%% *}"     # 只取档位标签，例如 "(2)"
    case "$label" in "(1)"|"(2)"|"(3)"|"(0)") ;; *) fail "no legal payload tier to compare: $tier" ;; esac
    slots="$(payload_slots "$src")"
    expected="$(ELF_REPORT="$rep" ELF_MANIFEST="$man" ELF_SLOTS="$slots" python3 - <<'PY'
import json, os
rep = json.load(open(os.environ["ELF_REPORT"]))
man = json.load(open(os.environ["ELF_MANIFEST"]))
slots = int(os.environ["ELF_SLOTS"])
sec_size, bss_off, bss_size = int(rep["sectionSize"]), int(man["bssOff"]), int(man["bssSize"])
page = 0x1000
if bss_size > 0 and 0 < bss_off < sec_size and bss_off % page == 0 and bss_size % page == 0:
    segments = 2 + (1 if sec_size > bss_off + bss_size else 0)
else:
    segments = 1
if segments == 1:
    print("(0)" if bss_size == 0 else "(3)")
elif slots >= segments:
    print("(1)")
elif segments == 3 and slots == 2:
    print("(2)")
else:
    print("(3)")
PY
)"
    if [ "$label" != "$expected" ]; then
        fail "payload tier does not follow from the source's reusable program-header slots: measured $tier but slots=$slots with this sectionSize/bssOff/bssSize implies $expected"
    fi
    echo "    payload tier follows from the source's reusable program-header slots (slots=$slots): $tier"
}

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

# 形状账（t6/F6 + t8/G2）：两层断言，别混为一谈。
#   ① 一致性：report.payloadWXFallback 必须等于产物程序头里"有没有 W+X 载荷段"。它只证
#      "报告说的形状 == 产物形状"，**证不出**"槽位足够的目标不得走回退"（打包端整体回归到
#      (2)/(3) 时 flag 会一起变 true、形状仍合法 ⇒ 这条照样全绿）。
#   ② 真断言：在**源目标**上复刻 sparePhdrSlot 数出可复用槽位，按 sectionSize/bssOff/bssSize
#      算出应有的档位，再与产物实测档位比对 ⇒ 整体回归到 (2)/(3) 会被这条抓住。
# 两条都对**三种模式**（默认 / PIE / PIE_RELOCS）跑。
echo "[*] 形状账 ①：report.payloadWXFallback 必须与产物程序头里的载荷形状一致"
ELF_PACKED=build/elf_target_$TAG.enc ELF_REPORT=build/elf_enc_$TAG.json \
ELF_MANIFEST=build/vm_interp_elf.json python3 - <<'PY' || fail "payloadWXFallback disagrees with the product"
import json, os, struct
d = open(os.environ["ELF_PACKED"], "rb").read()
rep = json.load(open(os.environ["ELF_REPORT"]))
man = json.load(open(os.environ["ELF_MANIFEST"]))
phoff, pes, phn = struct.unpack_from("<Q", d, 0x20)[0], struct.unpack_from("<H", d, 0x36)[0], struct.unpack_from("<H", d, 0x38)[0]
loads = []
for i in range(phn):
    o = phoff + i * pes
    t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", d, o)
    if t == 1:
        loads.append(dict(flags=fl, vaddr=va, filesz=fsz, memsz=msz))
base = min((l["vaddr"] & ~0xFFF for l in loads), default=0)
sec_va = base + int(rep["sectionRVA"])
sec_end = sec_va + int(rep["sectionSize"])
payload_wx = any((l["flags"] & 2) and (l["flags"] & 1)
                 for l in loads if l["vaddr"] < sec_end and sec_va < l["vaddr"] + l["memsz"])
got = rep.get("payloadWXFallback")
assert isinstance(got, bool), "report.payloadWXFallback is %r (want a JSON bool)" % (got,)
assert got == payload_wx, ("report.payloadWXFallback=%s but the product's payload W+X segment presence "
                           "is %s -- declared shape contradicts the program headers" % (got, payload_wx))
print("    payloadWXFallback=%s matches the product (payload W+X segment present: %s)" % (got, payload_wx))
PY

echo "[*] 形状账 ②：产物的档位必须由**源目标的槽位数**决定（tier == f(slots)；'槽位够的目标不得走回退'）"
PAYLOAD_TIER="$(payload_tier build/elf_target_$TAG.enc build/elf_enc_$TAG.json build/vm_interp_elf.json)"
echo "    measured payload tier: $PAYLOAD_TIER"
assert_tier_matches_slots "$PAYLOAD_TIER" "$TARGET" build/elf_enc_$TAG.json build/vm_interp_elf.json

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
# DT_RELA/DT_RELASZ are required for this construction; DT_RELACOUNT is only glibc's RELATIVE
# fast-path hint and NOT every linker emits it -- requiring it would false-red on those toolchains
# (the construction still works without it: glibc then takes the generic relocation path).
required = {7: ("DT_RELA", target), 8: ("DT_RELASZ", 24)}
optional = {0x6FFFFFF9: ("DT_RELACOUNT", 0)}
hit = []
for j in range(dynamic[1] // 16):
    o = dynoff + j * 16
    tag = u64(o)
    if tag == 0:
        break
    src = required if tag in required else (optional if tag in optional else None)
    if src is not None:
        struct.pack_into("<Q", d, o + 8, src[tag][1])
        hit.append(src[tag][0])
missing = sorted(v[0] for v in required.values() if v[0] not in hit)
assert not missing, "dynamic section lacks %r (hit=%r)" % (missing, hit)
open(dst, "wb").write(d)
os.chmod(dst, 0o755)
print("    dynamic @file 0x%X ; linkEnd=0x%X ; out-of-window table VA=0x%X ; patched=%s%s"
      % (dynoff, link_end, target, ",".join(sorted(hit)),
         "" if "DT_RELACOUNT" in hit else " (no DT_RELACOUNT on this toolchain: glibc takes the generic path)"))
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

# ---- #597：可执行段内的重定位（DT_TEXTREL 类）---- 打包端决策的 committed 见证 ----
#
# 背景与实测（本轮，M5 三段布局之后）：
#   * **amd64 已经修好**：#597 正文里那句"plain 打包也 rc=139"是 M5 的几何缺陷（载荷 RX 段盖住可写窗口），
#     已被 #598 的三段布局修掉 —— 自造 DT_TEXTREL 夹具（.text 内两个指针槽 + -Wl,-z,notext）现在
#     plain / -enc-image-elf-pie / -enc-image-elf-pie-relocs 三种打包**都与原生一致**。
#   * 但"可执行段内的重定位"本身仍需要打包端把账做平：默认（不带 -relocs）必须**跳过**含相对重定位的
#     范围并说清；带 -relocs 则是打包端记表 + 运行期应用器（vm_interp.c 的 vm_reloc_fix）端到端可用。
#     下面这条用例就是这两半的 committed 见证。
#   * 同族的两条 fail-closed 守卫（#597 守卫 1/2，见 cmd/vmpack/main.go）：装载器在入口点前要读的
#     PT_DYNAMIC **不加密**（该范围从候选里排除，报告如实反映），且加密范围里出现非 R_*_RELATIVE 的
#     动重定位就**拒绝打包**。aarch64 的 C PIE 正是靠守卫 1 才不再产出 SIGSEGV 产物（见本文件末尾的真断言）。
#
# 校准 A（"含相对重定位的范围默认跳过"必须承重）：把 cmd/vmpack/main.go 里
#   `if !encImageELFPIERelocs {` 那个跳过分支临时去掉 ⇒ 下面的 pie 子例必须变红
#   （该范围被加密但**没有应用表** ⇒ 目标自检打印 BADSLOTS 或直接崩，与原生不同）。
# 校准 B（运行期应用器必须承重）：把 stub/win/x64/vm_interp.c 的 vm_reloc_fix 短路掉（**只在本地做、
#   不要提交 stub/**）⇒ relocs 子例必须变红（verifyfail / rc≠0）。
if [ -z "$QEMU" ] && [ "$GOARCH_TARGET" = "amd64" ]; then
    echo "[*] #597: relocations INSIDE the executable segment (DT_TEXTREL) -- skipped by default, applied with -enc-image-elf-pie-relocs"
    # 本块用**自己的** blob：后面 PIE/静态 PIE 那几步会重建 build/vm_interp_elf.bin，而"打包用的 blob 与
    # 运行时不一致"正是这条用例最容易踩的坑（本轮实测：拿旧 blob 打包 ⇒ 产物 rc=139，看起来像产品缺陷）。
    TRBLOB=build/vm_interp_elf_textrel
    ./build/vmpbuild -src "$BLOB_SRC" $([ -n "$BLOB_CC" ] && echo "-cc $BLOB_CC") $([ -n "$BLOB_GUEST" ] && echo "-guest $BLOB_GUEST") $BLOB_EXTRA \
        -out "$TRBLOB.bin" -manifest "$TRBLOB.json" -entry vm_entry >/dev/null || fail "build the DT_TEXTREL block's own blob"
    cat > build/textrel_target.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_a = 7;
static int g_b = 9;

/* Two absolute pointer slots placed in the EXECUTABLE section: the linker must emit
 * R_X86_64_RELATIVE entries whose r_offset is inside .text, i.e. DT_TEXTREL. */
__asm__(".section .text\n"
        ".globl textrel_tbl\n"
        "textrel_tbl:\n"
        ".quad g_a\n"
        ".quad g_b\n"
        ".previous\n");
extern int *const textrel_tbl[2];

__attribute__((noinline)) unsigned long checkKey(unsigned long x) { return ((x * 7) + 42) ^ 0xFF; }
__attribute__((noinline)) long sumTo(long n) { long s = 0; for (long i = 1; i <= n; i++) s += i; return s; }

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: textrel_target <check-key|sum-to> <arg>\n"); return 2; }
    /* a slot the loader never applied reads as a WRONG VALUE (or faults): print the
     * difference so the failure is a distinct output, not just a crash. */
    long da = (long)textrel_tbl[0] - (long)&g_a;
    long db = (long)textrel_tbl[1] - (long)&g_b;
    if (da != 0 || db != 0) { printf("BADSLOTS %ld %ld\n", da, db); return 4; }
    unsigned long v = strtoul(argv[2], 0, 0);
    if (strcmp(argv[1], "check-key") == 0) printf("%lu\n", checkKey(v));
    else if (strcmp(argv[1], "sum-to") == 0) printf("%ld\n", sumTo((long)v));
    else return 2;
    return 0;
}
EOF
    gcc -fPIE -pie -O1 -Wl,-z,notext -o build/elf_target_textrel build/textrel_target.c || fail "build the DT_TEXTREL fixture"
    # 校准 0：夹具必须真的把相对重定位放进**可执行**范围（否则这条用例是空转）。
    readelf -dW build/elf_target_textrel | grep -q 'TEXTREL' || fail "the DT_TEXTREL fixture has no TEXTREL dynamic tag"
    python3 - <<'PY' || fail "the fixture has no R_X86_64_RELATIVE slot inside an executable range"
import struct
d = open("build/elf_target_textrel", "rb").read()
phoff, pes, phn = struct.unpack_from("<Q", d, 0x20)[0], struct.unpack_from("<H", d, 0x36)[0], struct.unpack_from("<H", d, 0x38)[0]
loads, dyn = [], None
for i in range(phn):
    o = phoff + i * pes
    t, fl, off, va, _pa, fsz, msz, _al = struct.unpack_from("<IIQQQQQQ", d, o)
    if t == 1:
        loads.append((va, msz, fl))
    elif t == 2:
        dyn = va
def off_of(va):
    for i in range(phn):
        o = phoff + i * pes
        t, fl, off, v, _pa, fsz, msz, _al = struct.unpack_from("<IIQQQQQQ", d, o)
        if t == 1 and v <= va < v + msz:
            return off + (va - v)
    return None
do = off_of(dyn)
rela = sz = ent = 0
for j in range(0x400 // 16):
    tag, val = struct.unpack_from("<QQ", d, do + j * 16)
    if tag == 0:
        break
    if tag == 7: rela = val
    if tag == 8: sz = val
    if tag == 9: ent = val
ro = off_of(rela)
hits = []
for k in range(sz // (ent or 24)):
    off, info, _add = struct.unpack_from("<QQq", d, ro + k * 24)
    if (info & 0xFFFFFFFF) != 8:
        continue
    for va, msz, fl in loads:
        if (fl & 1) and va <= off < va + msz:
            hits.append(off)
            break
assert hits, "no R_X86_64_RELATIVE r_offset inside an executable PT_LOAD"
print("    fixture: %d R_X86_64_RELATIVE slot(s) inside an executable range (e.g. 0x%X)" % (len(hits), hits[0]))
PY
    TR_NATIVE_RC=0
    TR_NATIVE="$($TARGET_RUN ./build/elf_target_textrel check-key 10 2>&1)" || TR_NATIVE_RC=$?
    TR_NATIVE_SUM_RC=0
    TR_NATIVE_SUM="$($TARGET_RUN ./build/elf_target_textrel sum-to 100 2>&1)" || TR_NATIVE_SUM_RC=$?
    if [ "$TR_NATIVE_RC" -ne 0 ] || [ "$TR_NATIVE" != "143" ]; then
        echo "[MISMATCH] DT_TEXTREL fixture native: rc=$TR_NATIVE_RC out=[$TR_NATIVE] (want 143)"
        fail "the DT_TEXTREL fixture does not run natively"
    fi
    for trmode in plain pie relocs; do
        case "$trmode" in
            plain)  TR_EXTRA="" ;;
            pie)    TR_EXTRA="-enc-image-elf-pie" ;;
            relocs) TR_EXTRA="-enc-image-elf-pie -enc-image-elf-pie-relocs" ;;
        esac
        TR_OUT="build/elf_textrel_${TAG}_${trmode}.enc"
        TR_REP="build/elf_textrel_${TAG}_${trmode}.json"
        rm -f "$TR_OUT" "$TR_REP"
        # shellcheck disable=SC2086
        TR_PACK="$($TARGET_RUN ./build/vmpack -exe build/elf_target_textrel -func checkKey -func sumTo $TR_EXTRA \
            -blob "$TRBLOB.bin" -manifest "$TRBLOB.json" \
            -out "$TR_OUT" -report "$TR_REP" 2>&1)" || fail "pack the DT_TEXTREL fixture ($trmode)"
        [ -f "$TR_OUT" ] || fail "packing the DT_TEXTREL fixture ($trmode) produced no artifact"
        TR_RC=0; TR_GOT="$($TARGET_RUN "./$TR_OUT" check-key 10 2>&1)" || TR_RC=$?
        TR_SUM_RC=0; TR_GOT_SUM="$($TARGET_RUN "./$TR_OUT" sum-to 100 2>&1)" || TR_SUM_RC=$?
        if [ "$TR_RC" -ne 0 ] || [ "$TR_GOT" != "$TR_NATIVE" ] || [ "$TR_SUM_RC" -ne 0 ] || [ "$TR_GOT_SUM" != "$TR_NATIVE_SUM" ]; then
            echo "[MISMATCH] DT_TEXTREL product ($trmode): check-key native=[$TR_NATIVE](rc=$TR_NATIVE_RC) packed=[$TR_GOT](rc=$TR_RC); sum-to native=[$TR_NATIVE_SUM](rc=$TR_NATIVE_SUM_RC) packed=[$TR_GOT_SUM](rc=$TR_SUM_RC)"
            printf '%s\n' "$TR_GOT" | head -n 3 | sed 's/^/    /'
            fail "DT_TEXTREL product ($trmode) is not identical to native"
        fi
        ELF_REPORT="$TR_REP" TR_MODE="$trmode" python3 - <<'PY' || fail "DT_TEXTREL report contract ($trmode)"
import json, os, struct
rep = json.load(open(os.environ["ELF_REPORT"]))
mode = os.environ["TR_MODE"]
secs = rep.get("imgSections") or []
d = open("build/elf_target_textrel", "rb").read()
phoff, pes, phn = struct.unpack_from("<Q", d, 0x20)[0], struct.unpack_from("<H", d, 0x36)[0], struct.unpack_from("<H", d, 0x38)[0]
# DERIVE the executable range carrying the R_X86_64_RELATIVE slots from the TARGET itself
loads, dyn, base = [], None, None
for i in range(phn):
    o = phoff + i * pes
    t, fl, off, va, _pa, fsz, msz, _al = struct.unpack_from("<IIQQQQQQ", d, o)
    if t == 1:
        loads.append((va, msz, fl))
        base = va if base is None else min(base, va)
    elif t == 2:
        dyn = va
def off_of(va):
    for i in range(phn):
        o = phoff + i * pes
        t, fl, off, v, _pa, fsz, msz, _al = struct.unpack_from("<IIQQQQQQ", d, o)
        if t == 1 and v <= va < v + msz:
            return off + (va - v)
    return None
do = off_of(dyn)
rela = sz = ent = 0
for j in range(0x400 // 16):
    tag, val = struct.unpack_from("<QQ", d, do + j * 16)
    if tag == 0:
        break
    if tag == 7: rela = val
    if tag == 8: sz = val
    if tag == 9: ent = val
ro = off_of(rela)
need = None
for k in range(sz // (ent or 24)):
    off, info, _add = struct.unpack_from("<QQq", d, ro + k * 24)
    if (info & 0xFFFFFFFF) != 8:
        continue
    for va, msz, fl in loads:
        if (fl & 1) and va <= off < va + msz and off + 8 <= va + msz:
            need = (va - base, va + msz - base)
            break
    if need:
        break
assert need, "could not derive the executable reloc range"
lo, hi = need
covered = any(int(s["rva"]) <= lo and hi <= int(s["rva"]) + int(s["size"]) for s in secs)
if mode == "relocs":
    assert covered, "with -enc-image-elf-pie-relocs the executable reloc range [%#x,%#x) MUST be encrypted; imgSections=%s" % (lo, hi, secs)
    nn = int(rep["imgRelocCount"] or 0)
    assert nn >= 1, "the encrypted executable range carries relocations but imgRelocCount=%s" % rep.get("imgRelocCount")
    assert int(rep["imgRelocTableRVA"] or 0) != 0, "an apply table must be emitted (imgRelocTableRVA=0)"
    print("    relocs: executable range [%#x,%#x) encrypted, %d relative reloc(s) recorded, apply table RVA=%#x" % (lo, hi, nn, int(rep["imgRelocTableRVA"])))
else:
    assert not covered, "the executable reloc range MUST NOT be encrypted without -enc-image-elf-pie-relocs; imgSections=%s" % (secs,)
    assert int(rep["imgRelocCount"] or 0) == 0, "no reloc-bearing range is encrypted => imgRelocCount must be 0, got %s" % rep.get("imgRelocCount")
    assert int(rep["imgRelocTableRVA"] or 0) == 0, "no relocations => no apply table"
    print("    %s: executable reloc range [%#x,%#x) deliberately NOT encrypted (report says so)" % (mode, lo, hi))
PY
        case "$trmode" in
            pie)
                # ASCII anchor only: the packer's skip line is the only place that prints this switch's
                # name while reporting a skipped range. (Chinese literals in this harness come back
                # mangled through the CI/WSL text pipeline -- see the same trap the aarch64 block hit.)
                printf '%s' "$TR_PACK" | grep -aq -- '-enc-image-elf-pie-relocs' || fail "the default -enc-image-elf-pie must SAY how to encrypt the skipped reloc-bearing range"
                ;;
            relocs)
                printf '%s' "$TR_PACK" | grep -aq 'imgRelocTableRVA\|RVA=0x' || fail "with -enc-image-elf-pie-relocs the packer must SAY the relocations were recorded"
                ;;
        esac
        echo "[OK  ] DT_TEXTREL ($trmode): the packed artifact answers 143/5050 exactly like native"
    done

    # ---- negative case: a non-R_*_RELATIVE dynamic relocation inside a range that WOULD be encrypted
    #      => the packer must refuse (non-zero exit + loud message + NO artifact) ----
    # Why this must be fail-closed: ld.so UNCONDITIONALLY writes those slots before the entry point, while
    # the runtime applier (vm_reloc_fix) only understands R_*_RELATIVE and the stub hard-fails on anything
    # else -- the product can therefore never be correct. Construction: patch the ONE R_X86_64_RELATIVE
    # (type 8) that sits inside the executable range into R_X86_64_64 (type 1) -- same table, same slot,
    # different type. Calibration: turn the guard off in cmd/vmpack/main.go ("if !inside || r.Type ==
    # relType" -> "if !inside || true") => the pack SUCCEEDS and leaves an artifact => this block goes red.
    echo "[*] #597: a non-R_*_RELATIVE dynamic relocation inside an encryptable range must refuse the pack"
    python3 - build/elf_target_textrel build/elf_target_textrel_abs <<'PY' || fail "build the non-RELATIVE-in-executable fixture"
import os, struct, sys
src, dst = sys.argv[1], sys.argv[2]
d = bytearray(open(src, "rb").read())
phoff, pes, phn = struct.unpack_from("<Q", d, 0x20)[0], struct.unpack_from("<H", d, 0x36)[0], struct.unpack_from("<H", d, 0x38)[0]
loads, dyn = [], None
for i in range(phn):
    o = phoff + i * pes
    t, fl, off, va, _pa, fsz, msz, _al = struct.unpack_from("<IIQQQQQQ", d, o)
    if t == 1:
        loads.append((va, msz, fl))
    elif t == 2:
        dyn = va
def off_of(va):
    for i in range(phn):
        o = phoff + i * pes
        t, fl, off, v, _pa, fsz, msz, _al = struct.unpack_from("<IIQQQQQQ", d, o)
        if t == 1 and v <= va < v + msz:
            return off + (va - v)
    return None
do = off_of(dyn)
rela = sz = 0
for j in range(0x400 // 16):
    tag, val = struct.unpack_from("<QQ", d, do + j * 16)
    if tag == 0:
        break
    if tag == 7: rela = val
    if tag == 8: sz = val
ro = off_of(rela)
hit = 0
for k in range(sz // 24):
    o = ro + k * 24
    r_off, info, _add = struct.unpack_from("<QQq", d, o)
    if (info & 0xFFFFFFFF) != 8:
        continue
    for va, msz, fl in loads:
        if (fl & 1) and va <= r_off < va + msz:
            struct.pack_into("<Q", d, o + 8, (info & ~0xFFFFFFFF) | 1)  # R_X86_64_RELATIVE -> R_X86_64_64
            print("    patched the in-executable RELATIVE at 0x%X into R_X86_64_64" % r_off)
            hit += 1
            break
assert hit, "no R_X86_64_RELATIVE slot inside an executable range to patch"
open(dst, "wb").write(d)
os.chmod(dst, 0o755)
PY
    G2_OUT="build/elf_textrel_${TAG}_nonrelative.enc"
    G2_REP="build/elf_textrel_${TAG}_nonrelative.json"
    rm -f "$G2_OUT" "$G2_REP"
    G2_RC=0
    G2_MSG="$(./build/vmpack -exe build/elf_target_textrel_abs -func checkKey -func sumTo \
        -enc-image-elf-pie -enc-image-elf-pie-relocs \
        -blob "$TRBLOB.bin" -manifest "$TRBLOB.json" \
        -out "$G2_OUT" -report "$G2_REP" 2>&1)" || G2_RC=$?
    if [ "$G2_RC" -eq 0 ]; then
        echo "[MISMATCH] the packer ACCEPTED a non-R_*_RELATIVE relocation inside a range it would encrypt"
        printf '%s\n' "$G2_MSG" | tail -n 3 | sed 's/^/    /'
        fail "a non-RELATIVE relocation inside an encrypted range must be refused (fail-closed)"
    fi
    # loud message: ASCII keyword only (Chinese literals do not survive this harness pipe)
    printf '%s' "$G2_MSG" | grep -aqF 'R_*_RELATIVE' || fail "the refusal must say which relocation kinds the runtime applier understands"
    # and no artifact / no report may be left behind
    if [ -f "$G2_OUT" ] || [ -f "$G2_REP" ]; then
        fail "a refused pack must not leave an artifact or a report behind"
    fi
    echo "[OK  ] #597 fail-closed: non-relative reloc inside an encryptable range -> rc=$G2_RC, no artifact, refusal names the R_*_RELATIVE kernel the applier implements"
fi

# ---- RELR（DT_RELR 压缩相对重定位）---- 打包端 fail-closed 决策的 committed 见证 ----
#
# 取向（docs/STATUS.md #603）：**RELR 已支持**。运行期应用器（stub/win/x64/vm_interp.c 的
# vm_relr_entry + vm_reloc_fix 的 RELR 段）按隐式 addend 语义还原：打包端加密的是槽位**原本的字节**，
# 产物里躺着的是**密文 C**，而 ld.so 在入口点之前做的是 C += l_addr ⇒ 减回去就得到 C。
# **这里不是 XOR 密码流**（显式表那条路是从表里的 r_addend 重算密文，RELR 没有 addend 可重算）。
# 本块从 #600 的"断言拒绝"翻转为"断言产物与原生逐字节一致"，并新增 C 侧契约 KAT。
#
# 本条用例做三件事（全是真断言，不是复述策略）：
#   1. **夹具校准**：readelf 必须真的解出 DT_RELR 与 .relr.dyn，且用"已与 readelf 对齐的解码器"
#      独立解出的**条目数**必须等于 readelf 印的 "contains N entries"（所有 binutils 版本都印）；
#      较新 binutils 还会印 "which relocate N locations"，有就一并硬断言，没有就大声登记（见下面）；
#   2. **主断言**：带 DT_RELR 的目标 + 要加密范围 ⇒ 打包成功，且产物与原生逐字节一致（143/5050）；
#   3. **单变量对照**：同一份源码、同样开关，只把 -z pack-relative-relocs 去掉 ⇒ 必须打包成功
#      且与原生逐字节一致（⇒ 触发拒绝的确实是 DT_RELR，不是别的）。
#
# 解码算法（本轮用独立 python 与 readelf **逐项对齐**；将来做真支持时按这个来）：
#   偶数条目 = 槽位地址，base = 条目 + 8；
#   奇数条目 = 位图，bit i (1..63) ⇒ 槽位 base + (i-1)*8，之后 base += 63*8。
#   夹具实测：条目 [0x3d78, 0x3, 0x80001] ⇒ 槽位 {0x3d78, 0x3d80, 0x4008}，与 readelf -rW 完全一致。
#   旧解码器的三个已知缺陷（bitmap 之后缺 base += 63*8、首个 bitmap 的 base 应为 addr+8、
#   裸地址条目本身也是一条重定位却被丢掉）—— 本条用例就是钉住这类回归的最小样本。
#
# 校准（改之前必须能红）：
#   A. 去掉夹具的 -Wl,-z,pack-relative-relocs ⇒ 第 1 步的 readelf 断言直接 FAIL（用例不空转）；
#   B.（#600 时期）注释掉 cmd/vmpack 的 hasRelr 分支 ⇒ 当时"必须拒绝"那条断言会红。#603 之后这条
#      校准改成：把 RELR 还原写回 XOR 密码流的老写法（*slot = (*slot - delta) ^ ks）⇒ 产物验签失败、
#      第 2 步变红（实测 VMPELF verifyfail rva=4096，rc=132）。
if [ -z "$QEMU" ] && [ "$GOARCH_TARGET" = "amd64" ]; then
    echo "[*] RELR: a DT_RELR target must PACK and match native; the same source without RELR stays the control"
    # 本块用**自己的** blob（同 #597 块的理由：后续步骤会重建 build/vm_interp_elf.bin）。
    RLRBLOB=build/vm_interp_elf_relr
    ./build/vmpbuild -src "$BLOB_SRC" $([ -n "$BLOB_CC" ] && echo "-cc $BLOB_CC") $([ -n "$BLOB_GUEST" ] && echo "-guest $BLOB_GUEST") $BLOB_EXTRA \
        -out "$RLRBLOB.bin" -manifest "$RLRBLOB.json" -entry vm_entry >/dev/null || fail "build the RELR block's own blob"
    cat > build/relr_target.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_a = 7;
static int g_b = 9;

/* 两个指向本镜像的指针槽，放在**只读数据节**里（不是 .text）：
 *   · 链接器为它们发 R_X86_64_RELATIVE；带 -z pack-relative-relocs 时进 .relr.dyn（DT_RELR）；
 *   · .rodata 会被打包端整体加密，而它里面**没有**显式 RELA 相对重定位（全被 RELR 打包了）
 *     ⇒ 不会被 -enc-image-elf-pie-relocs 的"范围含重定位就跳过"逻辑排除
 *     ⇒ RELR 槽位**必然落在加密范围内**，运行期 RELR 还原段必然被走到。
 * 为什么不用 .text（第一版就是那么写的，在 CI 上会空转）：较老的 ld 把 .text 里的相对重定位
 * 留在 .rela.dyn（不打包进 RELR），于是加密范围里根本没有 RELR 槽位，用例静默变成空转
 * —— 这正是 STATUS #604.3 记录的那次"红得正确"。 */
__attribute__((used, section(".rodata"))) const int *const relr_tbl[2] = { &g_a, &g_b };

__attribute__((noinline)) unsigned long checkKey(unsigned long x) { return ((x * 7) + 42) ^ 0xFF; }
__attribute__((noinline)) long sumTo(long n) { long s = 0; for (long i = 1; i <= n; i++) s += i; return s; }

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: relr_target <check-key|sum-to> <arg>\n"); return 2; }
    /* a slot the loader never applied reads as a WRONG VALUE: print the difference so the
     * failure is a distinct output, not just a crash. */
    long da = (long)relr_tbl[0] - (long)&g_a;
    long db = (long)relr_tbl[1] - (long)&g_b;
    if (da != 0 || db != 0) { printf("BADSLOTS %ld %ld\n", da, db); return 4; }
    unsigned long v = strtoul(argv[2], 0, 0);
    if (strcmp(argv[1], "check-key") == 0) printf("%lu\n", checkKey(v));
    else if (strcmp(argv[1], "sum-to") == 0) printf("%ld\n", sumTo((long)v));
    else return 2;
    return 0;
}
EOF
    for rlrmode in relr norel; do
        if [ "$rlrmode" = relr ]; then RLR_FLAGS="-Wl,-z,notext -Wl,-z,pack-relative-relocs"; else RLR_FLAGS="-Wl,-z,notext"; fi
        # shellcheck disable=SC2086
        gcc -fPIE -pie -O1 $RLR_FLAGS -o "build/elf_target_$rlrmode" build/relr_target.c || fail "build the RELR fixture ($rlrmode)"
    done
    # ---- 1. 夹具校准：relr 变体必须真的带 DT_RELR + .relr.dyn；norel 变体必须一条都没有 ----
    readelf -dW build/elf_target_relr | grep -q 'RELR' || fail "the RELR fixture has no DT_RELR dynamic tag (the case would be vacuous)"
    readelf -rW build/elf_target_relr | grep -q '.relr.dyn' || fail "the RELR fixture has no .relr.dyn relocation section"
    if readelf -dW build/elf_target_norel | grep -q 'RELR'; then
        fail "the single-variable control unexpectedly carries DT_RELR (the control would be vacuous)"
    fi
    # 版本差异（本轮 CI 实测踩到）：**条目数**在所有 binutils 上都印（"contains N entries"）；
    # 而 "which relocate N locations" 是较新 binutils 才有的措辞 —— ubuntu-latest 的 binutils 没有它，
    # 条用例因此在 linux-amd64 作业上误红过一次。所以：条目数**硬断言**；位置数有则一并硬断言，
    # 没有就大声登记（并把原始块打给 reviewer 看），不静默放过。
    RLR_ENTRIES_READELF="$(readelf -rW build/elf_target_relr | sed -n 's/.*relr\.dyn.*contains \([0-9][0-9]*\) entr.*/\1/p' | head -n 1)"
    [ -n "$RLR_ENTRIES_READELF" ] || fail "readelf did not report how many entries the RELR table has"
    RLR_LOCS_READELF="$(readelf -rW build/elf_target_relr | sed -n 's/.*which relocate \([0-9][0-9]*\) locations.*/\1/p' | head -n 1)"
    RLR_DECODED="$(RLR_ART=build/elf_target_relr python3 - <<'PY'
import os, struct
d = open(os.environ["RLR_ART"], "rb").read()
phoff, pes, phn = struct.unpack_from("<Q", d, 0x20)[0], struct.unpack_from("<H", d, 0x36)[0], struct.unpack_from("<H", d, 0x38)[0]
loads, dyn = [], None
for i in range(phn):
    o = phoff + i * pes
    t, fl, off, va, _pa, fsz, msz, _al = struct.unpack_from("<IIQQQQQQ", d, o)
    if t == 1:
        loads.append((va, msz, off))
    elif t == 2:
        dyn = va
def off_of(va):
    for v, msz, off in loads:
        if v <= va < v + msz:
            return off + (va - v)
    return None
do = off_of(dyn)
relr = rsz = 0
for j in range(0x400 // 16):
    tag, val = struct.unpack_from("<QQ", d, do + j * 16)
    if tag == 0:
        break
    if tag == 36: relr = val
    if tag == 35: rsz = val
ro = off_of(relr)
ents = [struct.unpack_from("<Q", d, ro + 8 * k)[0] for k in range(rsz // 8)]
# calibrated algorithm (must agree with readelf)
addrs, base = [], 0
for e in ents:
    if (e & 1) == 0:
        addrs.append(e)
        base = e + 8
    else:
        for i in range(1, 64):
            if e & (1 << i):
                addrs.append(base + (i - 1) * 8)
        base += 63 * 8
print("%d %d" % (len(ents), len(addrs)))
PY
)"
    RLR_ENTRIES_FILE="${RLR_DECODED%% *}"
    RLR_LOCS_FILE="${RLR_DECODED##* }"
    if [ "$RLR_ENTRIES_READELF" != "$RLR_ENTRIES_FILE" ]; then
        echo "[MISMATCH] RELR entries: readelf says [$RLR_ENTRIES_READELF], the file/decode says [$RLR_ENTRIES_FILE]"
        fail "the calibrated RELR decoder reads a different number of entries than readelf"
    fi
    if [ -n "$RLR_LOCS_READELF" ]; then
        if [ "$RLR_LOCS_READELF" != "$RLR_LOCS_FILE" ]; then
            echo "[MISMATCH] RELR locations: readelf says [$RLR_LOCS_READELF], the calibrated decoder says [$RLR_LOCS_FILE]"
            fail "the calibrated RELR decoder disagrees with readelf on the fixture"
        fi
        echo "[OK  ] RELR decode calibrated against readelf: $RLR_LOCS_READELF location(s) over $RLR_ENTRIES_READELF entry/entries"
    else
        echo "[NOTE] this readelf does not print 'which relocate N locations' (older binutils wording)"
        echo "[NOTE]   entries are still calibrated against readelf ($RLR_ENTRIES_READELF); locations = $RLR_LOCS_FILE (binutils 2.46 cross-check recorded in STATUS #601)"
        readelf -rW build/elf_target_relr | sed -n '/relr\.dyn/,$p' | sed 's/^/    | /'
    fi
    # ---- 2. 主断言：带 DT_RELR + 要加密范围 ⇒ **打包成功，且产物与原生逐字节一致** ----
    # （#600 时这里是"必须拒绝"；STATUS #603 落地了运行期 RELR 还原路径之后翻转为"必须一致"。）
    RLR_N_RC=0; RLR_N="$(run_target "$TARGET_RUN" ./build/elf_target_relr check-key 10 2>&1)" || RLR_N_RC=$?
    RLR_N_SUM_RC=0; RLR_N_SUM="$(run_target "$TARGET_RUN" ./build/elf_target_relr sum-to 100 2>&1)" || RLR_N_SUM_RC=$?
    if [ "$RLR_N_RC" -ne 0 ] || [ "$RLR_N" != "143" ] || [ "$RLR_N_SUM_RC" -ne 0 ] || [ "$RLR_N_SUM" != "5050" ]; then
        echo "[MISMATCH] RELR fixture native: check-key rc=$RLR_N_RC out=[$RLR_N] (want 143); sum-to rc=$RLR_N_SUM_RC out=[$RLR_N_SUM] (want 5050)"
        fail "the RELR fixture does not run natively"
    fi
    # ---- 1b. C 侧契约断言：同一组向量喂 C 侧展开器（vm_interp.c 的 vm_relr_entry）----
    # 两侧算法错开一格，产物就是"验签失败"或更糟的静默错值 ⇒ 这条必须与上面的 Go/readelf 对账一起跑。
    gcc -O1 -w -DVM_BLOB_TARGET_LINUX=1 -I stub/win/x64 -o build/relr_kat \
        stub/win/x64/relr_kat.c stub/win/x64/vm_crypto.c stub/win/x64/vm_kdf.c stub/linux/amd64/vm_entry_asm.S \
        || fail "build the C-side RELR KAT"
    RLR_KAT_RC=0
    RLR_KAT_OUT="$(./build/relr_kat 2>&1)" || RLR_KAT_RC=$?
    if [ "$RLR_KAT_RC" -ne 0 ]; then
        printf '%s\n' "$RLR_KAT_OUT" | tail -n 5 | sed 's/^/    /'
        fail "the C-side RELR KAT failed (Go and C disagree on the slot expansion)"
    fi
    printf '%s' "$RLR_KAT_OUT" | grep -q 'PASS: 0 failure' || fail "the C-side RELR KAT did not report PASS"
    echo "[OK  ] RELR contract KAT: the C-side expansion agrees with the Go/readelf vectors"

    RLR_OUT="build/elf_relr_${TAG}_product.enc"
    RLR_REP="build/elf_relr_${TAG}_product.json"
    rm -f "$RLR_OUT" "$RLR_REP"
    RLR_RC=0
    RLR_MSG="$("./build/vmpack" -exe build/elf_target_relr -func checkKey -func sumTo \
        -enc-image-elf-pie -enc-image-elf-pie-relocs \
        -blob "$RLRBLOB.bin" -manifest "$RLRBLOB.json" \
        -out "$RLR_OUT" -report "$RLR_REP" 2>&1)" || RLR_RC=$?
    if [ "$RLR_RC" -ne 0 ]; then
        echo "[MISMATCH] the packer REFUSED a DT_RELR target (rc=$RLR_RC) although the runtime has a RELR restore path"
        printf '%s\n' "$RLR_MSG" | tail -n 3 | sed 's/^/    /'
        fail "a DT_RELR target must pack now (STATUS #603 made it supported)"
    fi
    [ -f "$RLR_OUT" ] || fail "packing the DT_RELR fixture produced no artifact"
    # 打包端必须如实记账（报告里点名 DT_RELR 槽位数；ASCII keyword only）
    # 空转防线（本轮实测踩到）：只查 "DT_RELR" 字样是不够的 —— 汇总行里也有这个词，而真正证明
    # "这条用例没空转"的是**槽位记账**：必须解出槽位，且**至少一个落在加密范围内**（否则运行期
    # 的 RELR 还原段根本没被走到）。打包端为此打了一段 ASCII 关键字 [DT_RELR slots=N in_range=M]。
    RLR_ACC="$(printf '%s' "$RLR_MSG" | sed -n 's/.*\[DT_RELR slots=\([0-9][0-9]*\) in_range=\([0-9][0-9]*\)\].*/\1 \2/p' | head -n 1)"
    if [ -z "$RLR_ACC" ]; then
        printf '%s\n' "$RLR_MSG" | tail -n 4 | sed 's/^/    /'
        fail "the packer printed no DT_RELR slot accounting (no slots decoded = the case would be vacuous)"
    fi
    RLR_SLOTS="${RLR_ACC%% *}"; RLR_INRANGE="${RLR_ACC##* }"
    # 夹具放在 .rodata 之后这条是**硬断言**（#604.6）：两种工具链上都必然有 RELR 槽位落在加密范围内，
    # 所以"in_range==0"只可能是真的出问题（而非工具链布局差异），必须是红的。
    if [ "$RLR_INRANGE" -eq 0 ]; then
        printf '%s\n' "$RLR_MSG" | tail -n 3 | sed 's/^/    /'
        fail "no DT_RELR slot fell inside an encrypted range ($RLR_SLOTS decoded) -- the case would be vacuous"
    fi
    echo "[OK  ] RELR accounting: $RLR_SLOTS slot(s) decoded, $RLR_INRANGE inside encrypted range(s)"
    RLR_P_RC=0; RLR_GOT="$(run_target "$TARGET_RUN" "./$RLR_OUT" check-key 10 2>&1)" || RLR_P_RC=$?
    RLR_PS_RC=0; RLR_GOT_SUM="$(run_target "$TARGET_RUN" "./$RLR_OUT" sum-to 100 2>&1)" || RLR_PS_RC=$?
    if [ "$RLR_P_RC" -ne 0 ] || [ "$RLR_GOT" != "$RLR_N" ] || [ "$RLR_PS_RC" -ne 0 ] || [ "$RLR_GOT_SUM" != "$RLR_N_SUM" ]; then
        echo "[MISMATCH] DT_RELR product: check-key native=[$RLR_N](rc=$RLR_N_RC) packed=[$RLR_GOT](rc=$RLR_P_RC); sum-to native=[$RLR_N_SUM](rc=$RLR_N_SUM_RC) packed=[$RLR_GOT_SUM](rc=$RLR_PS_RC)"
        printf '%s\n' "$RLR_GOT" | head -n 3 | sed 's/^/    /'
        fail "the DT_RELR product is not byte-identical to native (the runtime RELR restore is the only thing between the ciphertext and the addend)"
    fi
    echo "[OK  ] #603 RELR: DT_RELR target + encryptable ranges -> packs, and the product answers exactly like native (143/5050)"
    # ---- 2b. 守卫负例（`#604.7`）：**DT_RELR 表自身落在被加密的范围里 ⇒ 拒绝打包** ----
    # 造法：把正例夹具复制一份，用 python 把 DT_RELR 指向 .rodata 里的 `relr_tbl`（.rodata 会被加密）、
    # DT_RELRSZ 改成 16。守卫是**结构性判据**（已挪到解码之前），所以表内容如何都不影响它触发。
    RLR_G_IN=build/elf_target_relr_guardin
    python3 - build/elf_target_relr "$RLR_G_IN" <<'PY' || fail "build the guard negative fixture"
import struct, subprocess, sys
src, dst = sys.argv[1], sys.argv[2]
d = bytearray(open(src, "rb").read())
out = subprocess.run(["readelf", "-sW", src], capture_output=True, text=True).stdout
addr = None
for ln in out.splitlines():
    p = ln.split()
    if len(p) >= 8 and p[-1] == "relr_tbl":
        addr = int(p[1], 16)
        break
assert addr is not None, "relr_tbl symbol not found"
phoff, pes, phn = struct.unpack_from("<Q", d, 0x20)[0], struct.unpack_from("<H", d, 0x36)[0], struct.unpack_from("<H", d, 0x38)[0]
dyn = None
for i in range(phn):
    o = phoff + i * pes
    if struct.unpack_from("<I", d, o)[0] == 2:
        dyn = struct.unpack_from("<Q", d, o + 8)[0]
        break
assert dyn is not None, "no PT_DYNAMIC"
doff = None
for i in range(phn):
    o = phoff + i * pes
    t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", d, o)
    if t == 1 and va <= dyn < va + msz:
        doff = off + (dyn - va)
        break
assert doff is not None, "cannot map PT_DYNAMIC"
hits = 0
for j in range(0x400 // 16):
    o = doff + j * 16
    tag = struct.unpack_from("<Q", d, o)[0]
    if tag == 0:
        break
    if tag == 36:    # DT_RELR
        struct.pack_into("<Q", d, o + 8, addr); hits += 1
    elif tag == 35:  # DT_RELRSZ
        struct.pack_into("<Q", d, o + 8, 16); hits += 1
assert hits == 2, "expected exactly DT_RELR + DT_RELRSZ, patched %d" % hits
# 让这张"假表"**能干净解码** —— 这样"关掉守卫 ⇒ 打包成功（产出坏产物）"才是真的校准。
#   条目 0 = addr（8 字节对齐、在某个 PT_LOAD 内）；条目 1 = 0（VA 0 在 PIE 里也在第一个 PT_LOAD 内）。
toff = None
for i in range(phn):
    o = phoff + i * pes
    t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", d, o)
    if t == 1 and va <= addr < va + msz:
        toff = off + (addr - va)
        break
assert toff is not None, "cannot map relr_tbl in the file"
struct.pack_into("<QQ", d, toff, addr, 0)
open(dst, "wb").write(bytes(d))
import os
os.chmod(dst, 0o755)
print("    guard fixture: DT_RELR -> 0x%X (.rodata), DT_RELRSZ=16" % addr)
PY
    RLR_G_OUT="build/elf_relr_${TAG}_guard.enc"
    RLR_G_REP="build/elf_relr_${TAG}_guard.json"
    rm -f "$RLR_G_OUT" "$RLR_G_REP"
    RLR_G_RC=0
    RLR_G_MSG="$("./build/vmpack" -exe "$RLR_G_IN" -func checkKey -func sumTo \
        -enc-image-elf-pie -enc-image-elf-pie-relocs \
        -blob "$RLRBLOB.bin" -manifest "$RLRBLOB.json" \
        -out "$RLR_G_OUT" -report "$RLR_G_REP" 2>&1)" || RLR_G_RC=$?
    if [ "$RLR_G_RC" -eq 0 ]; then
        echo "[MISMATCH] the packer ACCEPTED a DT_RELR table sitting inside a range it encrypts"
        printf '%s\n' "$RLR_G_MSG" | tail -n 3 | sed 's/^/    /'
        fail "a DT_RELR table inside an encrypted range must be refused (the applier reads it BEFORE decrypt)"
    fi
    printf '%s' "$RLR_G_MSG" | grep -aqF 'DT_RELR_TABLE_IN_ENCRYPTED_RANGE' || fail "the refusal must carry the ASCII keyword [DT_RELR_TABLE_IN_ENCRYPTED_RANGE]"
    if [ -f "$RLR_G_OUT" ] || [ -f "$RLR_G_REP" ]; then
        fail "a refused pack must not leave an artifact or a report behind"
    fi
    echo "[OK  ] #604.7 RELR guard: DT_RELR table inside an encrypted range -> refused (rc=$RLR_G_RC), no artifact, ASCII keyword present"
    # ---- 3. 单变量对照：同一份源码去掉 -z pack-relative-relocs ⇒ 必须能打包且与原生一致 ----
    RLR_C_OUT="build/elf_relr_${TAG}_control.enc"
    RLR_C_REP="build/elf_relr_${TAG}_control.json"
    rm -f "$RLR_C_OUT" "$RLR_C_REP"
    RLR_C_RC=0
    RLR_C_MSG="$("./build/vmpack" -exe build/elf_target_norel -func checkKey -func sumTo \
        -enc-image-elf-pie -enc-image-elf-pie-relocs \
        -blob "$RLRBLOB.bin" -manifest "$RLRBLOB.json" \
        -out "$RLR_C_OUT" -report "$RLR_C_REP" 2>&1)" || RLR_C_RC=$?
    if [ "$RLR_C_RC" -ne 0 ]; then
        echo "[MISMATCH] the DT_RELR-free control was refused too (rc=$RLR_C_RC) -- the refusal is not specific to DT_RELR"
        printf '%s\n' "$RLR_C_MSG" | tail -n 3 | sed 's/^/    /'
        fail "the DT_RELR-free control must still pack"
    fi
    [ -f "$RLR_C_OUT" ] || fail "the DT_RELR-free control produced no artifact"
    RLR_C_GRC=0; RLR_C_GOT="$(run_target "$TARGET_RUN" "./$RLR_C_OUT" check-key 10 2>&1)" || RLR_C_GRC=$?
    RLR_C_SUM_RC=0; RLR_C_SUM="$(run_target "$TARGET_RUN" "./$RLR_C_OUT" sum-to 100 2>&1)" || RLR_C_SUM_RC=$?
    if [ "$RLR_C_GRC" -ne 0 ] || [ "$RLR_C_GOT" != "$RLR_N" ] || [ "$RLR_C_SUM_RC" -ne 0 ] || [ "$RLR_C_SUM" != "$RLR_N_SUM" ]; then
        echo "[MISMATCH] DT_RELR-free control product: check-key native=[$RLR_N](rc=$RLR_N_RC) packed=[$RLR_C_GOT](rc=$RLR_C_GRC); sum-to native=[$RLR_N_SUM](rc=$RLR_N_SUM_RC) packed=[$RLR_C_SUM](rc=$RLR_C_SUM_RC)"
        fail "the DT_RELR-free control product is not identical to native"
    fi
    echo "[OK  ] #600 RELR control: the same source without DT_RELR packs and answers exactly like native (143/5050)"
fi


# ---- RELR（DT_RELR）在 aarch64 上的端到端 ----（STATUS #603.5 登记的唯一缺口）
# 与 amd64 那块**同一套断言**，只是夹具用交叉 gcc、产物经 qemu 跑：
#   夹具必须真的带 DT_RELR；带 DT_RELR + 要加密范围 ⇒ 打包成功，且产物与原生逐字节一致。
# 为什么值得单列：RELR 的解码/还原代码是 arch 无关的（vm_relr_entry 纯算术、类型号按架构取
# R_*_RELATIVE），但 aarch64 从没跑过这条路径 —— "代码看起来 arch 无关"不是证据。
if [ -n "$QEMU" ] && [ "${GOARCH_TARGET}" = "arm64" ] && [ -n "${BLOB_CC}" ]; then
    echo "[*] RELR (aarch64): a DT_RELR target must PACK and match native under qemu"
    A64RLR_CC=${A64_CC:-aarch64-linux-gnu-gcc}
    A64RLRBLOB=build/vm_interp_elf_relr_a64
    ./build/vmpbuild -src "$BLOB_SRC" $([ -n "$BLOB_CC" ] && echo "-cc $BLOB_CC") $([ -n "$BLOB_GUEST" ] && echo "-guest $BLOB_GUEST") $BLOB_EXTRA \
        -out "$A64RLRBLOB.bin" -manifest "$A64RLRBLOB.json" -entry vm_entry >/dev/null || fail "build the aarch64 RELR block own blob"
    cat > build/relr_a64.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_a = 7;
static int g_b = 9;

/* aarch64 上同样把两个指针槽放进 .text：链接器为它们发 R_AARCH64_RELATIVE，
 * 加上 -z pack-relative-relocs 后进 .relr.dyn（DT_RELR）。
 *
 * 前面那 16KB NOP 填充是**必须的**（本轮实测踩到）：小夹具的可执行段全落在**第一页**
 * （ELF 头 + 程序头表）里，打包端会整段跳过加密、于是这条用例空转（没有任何槽位需要还原）。
 * 填充把 .text 推过第一页，同时也让 PT_DYNAMIC 落到后面 —— aarch64 的守卫 1 只加密
 * "PT_DYNAMIC 之前"的那一段，所以槽位必须在这段里才真的被加密。 */
__asm__(".section .text\n"
        ".globl relr_a64_pad\n"
        "relr_a64_pad:\n"
        ".space 16384, 0x90\n"
        ".balign 8\n"
        ".globl relr_tbl\n"
        "relr_tbl:\n"
        ".quad g_a\n"
        ".quad g_b\n"
        ".previous\n");
extern int *const relr_tbl[2];

__attribute__((noinline)) unsigned long checkKey(unsigned long x) { return ((x * 7) + 42) ^ 0xFF; }
__attribute__((noinline)) long sumTo(long n) { long s = 0; for (long i = 1; i <= n; i++) s += i; return s; }

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: relr_a64 <check-key|sum-to> <arg>\n"); return 2; }
    long da = (long)relr_tbl[0] - (long)&g_a;
    long db = (long)relr_tbl[1] - (long)&g_b;
    if (da != 0 || db != 0) { printf("BADSLOTS %ld %ld\n", da, db); return 4; }
    unsigned long v = strtoul(argv[2], 0, 0);
    if (strcmp(argv[1], "check-key") == 0) printf("%lu\n", checkKey(v));
    else if (strcmp(argv[1], "sum-to") == 0) printf("%ld\n", sumTo((long)v));
    else return 2;
    return 0;
}
EOF
    "$A64RLR_CC" -fPIE -pie -O1 -Wl,-z,notext -Wl,-z,pack-relative-relocs -o build/elf_target_relr_a64 build/relr_a64.c \
        || fail "build the aarch64 RELR fixture"
    # 夹具校准：必须真的带 DT_RELR。CI 的交叉工具链**不产出** DT_RELR（-z pack-relative-relocs 没生效，
    # 实测 linux-arm64 作业上夹具里没有该 tag）⇒ 按仓库约定醒目 SKIP（缺能力，不算通过）；本机（binutils 2.46）
    # 上这条用例是真跑的。
    if ! readelf -dW build/elf_target_relr_a64 | grep -q 'RELR'; then
        echo "[SKIP] aarch64 RELR: this cross toolchain does not emit DT_RELR (needs a linker that honours -z pack-relative-relocs)"
        RLR_A64_CAP=0
    else
        RLR_A64_CAP=1
    fi
    if [ "$RLR_A64_CAP" = "1" ]; then
    readelf -rW build/elf_target_relr_a64 | grep -q '.relr.dyn' || fail "the aarch64 RELR fixture has no .relr.dyn section"
    # 注意：这里必须用**不加引号**的 $TARGET_RUN（= "qemu-aarch64 -L <ld dir>"）—— 既需要 -L 才能找到
    # aarch64 的 ld.so，又不能用 run_target（那个 helper 把 runner 当**单个命令名**执行，含空格会失败）。
    A64RLR_N_RC=0; A64RLR_N="$( $TARGET_RUN ./build/elf_target_relr_a64 check-key 10 2>&1 )" || A64RLR_N_RC=$?
    if [ "$A64RLR_N_RC" -ne 0 ] || [ "$A64RLR_N" != "143" ]; then
        echo "[MISMATCH] aarch64 RELR fixture native: rc=$A64RLR_N_RC out=[$A64RLR_N] (want 143)"
        fail "the aarch64 RELR fixture does not run natively under qemu"
    fi
    A64RLR_OUT="build/elf_relr_a64_${TAG}.enc"
    A64RLR_REP="build/elf_relr_a64_${TAG}.json"
    rm -f "$A64RLR_OUT" "$A64RLR_REP"
    A64RLR_RC=0
    A64RLR_MSG="$("./build/vmpack" -exe build/elf_target_relr_a64 -func checkKey -func sumTo \
        -enc-image-elf-pie -enc-image-elf-pie-relocs \
        -blob "$A64RLRBLOB.bin" -manifest "$A64RLRBLOB.json" \
        -out "$A64RLR_OUT" -report "$A64RLR_REP" 2>&1)" || A64RLR_RC=$?
    if [ "$A64RLR_RC" -ne 0 ]; then
        echo "[MISMATCH] the packer REFUSED an aarch64 DT_RELR target (rc=$A64RLR_RC)"
        printf '%s\n' "$A64RLR_MSG" | tail -n 3 | sed 's/^/    /'
        fail "an aarch64 DT_RELR target must pack (RELR is supported since STATUS #603)"
    fi
    # 空转防线（本轮实测踩到）：只查 "DT_RELR" 字样是不够的 —— 汇总行里也有这个词，而真正证明
    # "这条用例没空转"的是**槽位记账**：必须解出槽位，且**至少一个落在加密范围内**（否则运行期
    # 的 RELR 还原段根本没被走到）。打包端为此打了一段 ASCII 关键字 [DT_RELR slots=N in_range=M]。
    A64RLR_ACC="$(printf '%s' "$A64RLR_MSG" | sed -n 's/.*\[DT_RELR slots=\([0-9][0-9]*\) in_range=\([0-9][0-9]*\)\].*/\1 \2/p' | head -n 1)"
    if [ -z "$A64RLR_ACC" ]; then
        printf '%s\n' "$A64RLR_MSG" | tail -n 4 | sed 's/^/    /'
        fail "the packer printed no DT_RELR slot accounting (no slots decoded = the case would be vacuous)"
    fi
    A64RLR_SLOTS="${A64RLR_ACC%% *}"; A64RLR_INRANGE="${A64RLR_ACC##* }"
    [ "$A64RLR_INRANGE" -gt 0 ] || fail "no DT_RELR slot fell inside an encrypted range ($A64RLR_SLOTS decoded) -- the case would be vacuous"
    echo "[OK  ] RELR accounting: $A64RLR_SLOTS slot(s) decoded, $A64RLR_INRANGE inside encrypted range(s)"
    A64RLR_P_RC=0; A64RLR_GOT="$( $TARGET_RUN "./$A64RLR_OUT" check-key 10 2>&1 )" || A64RLR_P_RC=$?
    A64RLR_S_RC=0; A64RLR_SUM="$( $TARGET_RUN "./$A64RLR_OUT" sum-to 100 2>&1 )" || A64RLR_S_RC=$?
    if [ "$A64RLR_P_RC" -ne 0 ] || [ "$A64RLR_GOT" != "$A64RLR_N" ] || [ "$A64RLR_S_RC" -ne 0 ] || [ "$A64RLR_SUM" != "5050" ]; then
        echo "[MISMATCH] aarch64 DT_RELR product: check-key native=[$A64RLR_N](rc=$A64RLR_N_RC) packed=[$A64RLR_GOT](rc=$A64RLR_P_RC); sum-to packed=[$A64RLR_SUM](rc=$A64RLR_S_RC)"
        printf '%s\n' "$A64RLR_GOT" | head -n 3 | sed 's/^/    /'
        fail "the aarch64 DT_RELR product is not byte-identical to native (the arch-independent claim is unproven)"
    fi
    echo "[OK  ] #604 RELR (aarch64): DT_RELR target + encryptable ranges -> packs, and the product answers exactly like native under qemu (143/5050)"
    fi # RLR_A64_CAP=1（工具链真的产出了 DT_RELR）
fi

# ---- aarch64：加密范围内重定位 —— 打包侧的范围等式 + 运行期"必须与原生一致"都是真断言 ----
# #376/#377 把 aarch64 的只读数据节加密默认关掉（根因未定，AGENTS.md 禁止打开），所以
# "加密范围里带 R_AARCH64_RELATIVE" 这条运行期路径一直没有可跑用例。本块做两件**都跑**的事：
#   ① 打包侧契约：造一个 aarch64 PIE 夹具（.rodata 里两条相对重定位），用
#      -enc-image-elf-pie -enc-image-elf-pie-relocs 打包，然后让**布局门禁**从产物自己的
#      PT_DYNAMIC 重新推导"范围内重定位条数/应用表 RVA/类型"（E5(b)），并顺带把 E1..E4 与
#      全部校准跑在**aarch64 产物**上（此前门禁只吃过 amd64 产物）。
#   ② 运行期侧（#597 起**升级为真断言**）：aarch64 的链接器把 PT_DYNAMIC 放在那个 R-X 段内部，
#      所以旧行为是"整段加密 ⇒ ld.so 读到密文 ⇒ SIGSEGV(rc=139)"；#597 守卫 1 改成只加密
#      PT_DYNAMIC **之前**的那一段，产物必须与原生逐字节一致（下面 a64_guard_partial + 运行期断言）。
#      校准（必须能红）：把 cmd/vmpack/main.go 里守卫 1 的 `if dynOffHi > dynOffLo && ...` 改成
#      `if false` ⇒ 打包端整段加密 ⇒ qemu 下 rc=139 ⇒ 运行期断言变红。结论同步写在
#      tools/check_elf_layout.py 的 "E5 coverage gap on aarch64" 一节里。
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
    # 形状判定（t14/R2，t6/F2 按新三档重写）：形状是**产物程序头的事实**，不是打包端的措辞。
    # 注入器只可能发出下面几种（见 internal/inject/elf.go 的槽位梯子与 tools/check_elf_layout.py 的 E2）：
    #   (1) 三段相邻：RX 前缀 [..) + RW 窗口 [..) + R+X 尾部 [..)（槽位够；载荷无尾部时没有第三段）；
    #   (2) 前缀只读 + **一段 W+X 的"窗口+尾部"**（2 个槽位且载荷有尾部）；
    #   (3) **整段 W+X 载荷段**（槽位 <2：窗口/尾部都在这一段里）；
    #   (0) 整段 RX、没有可写窗口（manifest bssSize=0）。
    # 老的重叠形状（RX 载荷段盖住窗口 + 嵌套 RW）现在只可能是**缺陷**，单列 (DEFECT) 交给调用方判死。
    # 不能只 grep 打包端的告警文本：internal/load/elf/elf.go 的槽位优先级是
    # PT_NOTE -> PT_GNU_RELRO -> PT_PHDR(仅静态) -> PT_NULL，换一个会产出 RELRO 的 linker 时槽位数
    # 不同 ⇒ 产物可能落在 (2) 而不是 (3)，两者都合法，而**没有**任何 '退回' 文案。文案只作记录。
    a64_note_count() {  # $1 = ELF file -> PT_NOTE count on stdout
        python3 - "$1" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
phoff, pes, phn = struct.unpack_from("<Q", d, 0x20)[0], struct.unpack_from("<H", d, 0x36)[0], struct.unpack_from("<H", d, 0x38)[0]
print(sum(1 for i in range(phn) if struct.unpack_from("<I", d, phoff + i * pes)[0] == 4))
PY
    }
    A64_NOTE_ASBUILT="$(a64_note_count build/elf_target_a64reloc)"
    echo "    as-built aarch64 fixture: PT_NOTE=$A64_NOTE_ASBUILT (the injector needs 3 reusable slots for the three-segment split, 2 for prefix + W+X window+tail, 1 for the whole-payload W+X fallback)"
    A64_PACK1="$(./build/vmpack -exe build/elf_target_a64reloc -func checkKey -func sumTo \
        -enc-image-elf-pie -enc-image-elf-pie-relocs \
        -blob build/vm_interp_elf.bin -manifest build/vm_interp_elf.json \
        -out build/elf_target_a64reloc.enc -report build/elf_enc_a64reloc.json 2>&1)" || fail "pack aarch64 reloc case"
    # #597 守卫 1 在这条夹具上的**实测结论**（本轮之前这里是"记账 >= 1"的断言）：
    #   aarch64 的链接器把 PT_DYNAMIC 放在那个 R-X 段**内部**（本夹具：段文件范围 [0,0x20018)，
    #   PT_DYNAMIC 文件范围 [0x1FD90,0x1FF80)）⇒ 守卫 1 把它之前的部分加密、之后的部分**留着明文**。
    #   断言的就是这个**实测出来的**范围等式（不是"加密范围为空"，也不是"整段加密"）：
    #   加密范围 == [align_up(程序头表末尾), PT_DYNAMIC 文件偏移)。
    a64_guard_partial() {  # $1 = report path, $2 = pack output, $3 = source fixture
        ELF_REPORT="$1" A64_PACK_OUT="$2" ELF_SRC="$3" python3 - <<'PY' || fail "aarch64 PT_DYNAMIC guard did not take effect ($1)"
import json, os, struct
rep = json.load(open(os.environ["ELF_REPORT"]))
d = open(os.environ["ELF_SRC"], "rb").read()
phoff, pes, phn = struct.unpack_from("<Q", d, 0x20)[0], struct.unpack_from("<H", d, 0x36)[0], struct.unpack_from("<H", d, 0x38)[0]
head = phoff + phn * pes
inner = (head + 0xFFF) & ~0xFFF
if inner < 0x1000:
    inner = 0x1000
base = min(struct.unpack_from("<Q", d, phoff + i * pes + 16)[0] for i in range(phn)
           if struct.unpack_from("<I", d, phoff + i * pes)[0] == 1)
dyn_off = dyn_hi = None
for i in range(phn):
    o = phoff + i * pes
    if struct.unpack_from("<I", d, o)[0] == 2:  # PT_DYNAMIC
        dyn_off = struct.unpack_from("<Q", d, o + 8)[0]
        dyn_hi = dyn_off + struct.unpack_from("<Q", d, o + 32)[0]
        break
assert dyn_off is not None, "the fixture has no PT_DYNAMIC"
exec_los = [struct.unpack_from("<Q", d, phoff + i * pes + 8)[0] for i in range(phn)
            if struct.unpack_from("<I", d, phoff + i * pes)[0] == 1 and (struct.unpack_from("<I", d, phoff + i * pes + 4)[0] & 1)]
assert exec_los, "no executable PT_LOAD"
exec_lo, exec_hi = min(exec_los), None
for i in range(phn):
    o = phoff + i * pes
    if struct.unpack_from("<I", d, o)[0] == 1:
        off, sz = struct.unpack_from("<Q", d, o + 8)[0], struct.unpack_from("<Q", d, o + 32)[0]
        if off <= dyn_off < off + sz:
            exec_hi = off + sz
assert exec_lo < dyn_off < exec_hi, "PT_DYNAMIC is not inside the executable segment on this fixture"
want = [(inner - base, dyn_off - inner)] if dyn_off > inner else []
got = [(int(x["rva"]), int(x["size"])) for x in (rep.get("imgSections") or [])]
assert got == want, ("guard 1 must encrypt exactly the part BEFORE PT_DYNAMIC -- want %s, got %s" % ([hex(a) for a in want], got))
assert int(rep.get("imgRelocCount") or 0) >= 1, ("the encrypted part still carries relocations, so they must be recorded: %s" % rep.get("imgRelocCount"))
assert int(rep.get("imgRelocTableRVA") or 0) != 0, "an apply table must be emitted for the recorded relocations"
print("    guard 1 active: encrypted [0x%X,0x%X), PT_DYNAMIC [0x%X,0x%X) left plaintext, %d reloc(s) recorded"
      % (want[0][0], want[0][0] + want[0][1], dyn_off - base, dyn_hi - base, int(rep["imgRelocCount"])))
PY
        # ASCII anchor: this exact string appears ONLY in the guard-1 message (the source prints
        # "载着 PT_DYNAMIC" and nothing else mentions PT_DYNAMIC in that line).
        printf '%s' "$2" | grep -aq 'PT_DYNAMIC' || fail "the packer must LOUDLY say that the range carrying PT_DYNAMIC is not fully encrypted ($1)"
    }
    a64_guard_partial build/elf_enc_a64reloc.json "$A64_PACK1" build/elf_target_a64reloc
    python3 tools/check_elf_layout.py --packed build/elf_target_a64reloc.enc \
        --manifest build/vm_interp_elf.json --blob build/vm_interp_elf.bin \
        --report build/elf_enc_a64reloc.json --selftest || fail "aarch64 layout gate (packing half of the reloc contract)"
    A64_SHAPE1="$(payload_tier build/elf_target_a64reloc.enc build/elf_enc_a64reloc.json build/vm_interp_elf.json)"
    echo "[OK  ] aarch64: product 1 (as-built fixture, PT_NOTE=$A64_NOTE_ASBUILT) payload shape $A64_SHAPE1"
    # 真断言：product 1 的档位必须由它**自己的源目标**的槽位数决定（不是只看报告 ↔ 程序头一致）
    assert_tier_matches_slots "$A64_SHAPE1" build/elf_target_a64reloc build/elf_enc_a64reloc.json build/vm_interp_elf.json
    # 第二种**合法**形状（槽位更少那一档）：只留 1 个可复用的 PT_NOTE，注入器就拿不到"三段相邻"或
    # "前缀 + W+X 窗口+尾部"所需的 2~3 个槽位，只能退回**整段 W+X 载荷段**（窗口/尾部都在那一段里，
    # 由该段自己的文件镜像承载）。CI 的 gcc/ld 13 夹具只有 1 个 PT_NOTE，走的正是这条；本机 ld 15 的
    # 夹具有 2 个（于是落在 (1)/(2) 档），所以 2026-10-03 的 CI run 37128895442 在本机复现不出来。
    # 这里把多余的 PT_NOTE 抹掉，把 CI 那种形状**在本机也造出来**（门禁与校准必须接受它）。
    python3 - build/elf_target_a64reloc build/elf_target_a64reloc_rwx <<'PY' || fail "build the one-NOTE (RWX fallback) fixture"
import os, struct, sys
src, dst = sys.argv[1], sys.argv[2]
d = bytearray(open(src, "rb").read())
phoff, phentsize, phnum = struct.unpack_from("<Q", d, 0x20)[0], struct.unpack_from("<H", d, 0x36)[0], struct.unpack_from("<H", d, 0x38)[0]
notes = [i for i in range(phnum) if struct.unpack_from("<I", d, phoff + i * phentsize)[0] == 4]
for i in notes[1:]:
    struct.pack_into("<I", d, phoff + i * phentsize, 0)   # p_type = PT_NULL: leave exactly one NOTE slot
open(dst, "wb").write(d)
os.chmod(dst, 0o755)
print("    fixture has %d PT_NOTE; kept 1 so the injector cannot take the split shapes ((1)/(2))" % len(notes))
PY
    RWX_OUT="$(./build/vmpack -exe build/elf_target_a64reloc_rwx -func checkKey -func sumTo \
        -enc-image-elf-pie -enc-image-elf-pie-relocs \
        -blob build/vm_interp_elf.bin -manifest build/vm_interp_elf.json \
        -out build/elf_target_a64reloc_rwx.enc -report build/elf_enc_a64reloc_rwx.json 2>&1)" || fail "pack the one-RWX-segment aarch64 case"
    # (R2) 判定只认**产物形状**，不认告警文本：打包端的槽位优先级里 PT_GNU_RELRO 也是候选
    # （internal/load/elf/elf.go 的 sparePhdrSlot），换一个会产出 RELRO 的 linker 时槽位数不同 ⇒
    # 产物可能落在 (2) 而不是 (3)，两者都合法、告警文案也不同 —— 把文案当不变量就会假红。文案只作记录。
    if printf '%s' "$RWX_OUT" | grep -q '退回'; then
        echo "[INFO] aarch64: pack output announced a fallback in words (informational; the assertion below is on program headers)"
    else
        echo "[INFO] aarch64: no fallback line in this run's pack output (informational only -- the shape is asserted from the product below)"
    fi
    a64_guard_partial build/elf_enc_a64reloc_rwx.json "$RWX_OUT" build/elf_target_a64reloc_rwx
    python3 tools/check_elf_layout.py --packed build/elf_target_a64reloc_rwx.enc \
        --manifest build/vm_interp_elf.json --blob build/vm_interp_elf.bin \
        --report build/elf_enc_a64reloc_rwx.json --selftest || fail "aarch64 layout gate (one-RWX-segment shape)"
    A64_SHAPE2="$(payload_tier build/elf_target_a64reloc_rwx.enc build/elf_enc_a64reloc_rwx.json build/vm_interp_elf.json)"
    echo "[OK  ] aarch64: product 2 (one-PT_NOTE fixture, PT_NOTE=$(a64_note_count build/elf_target_a64reloc_rwx)) payload shape $A64_SHAPE2"
    assert_tier_matches_slots "$A64_SHAPE2" build/elf_target_a64reloc_rwx build/elf_enc_a64reloc_rwx.json build/vm_interp_elf.json
    # 下面这条是**一致性**：report.payloadWXFallback 必须与**实测档位**一致（档 (1) ⇒ false，
    # 档 (2)/(3) ⇒ true）。"槽位足够的目标不得走回退"由上面的 assert_tier_matches_slots 承担
    # （它数源目标的槽位、算应有档位），这条只证"报告说的档 == 产物档"。
    a64_assert_flag() {  # $1 = shape line, $2 = report path
        case "$1" in
            "(1)"*) a64_want=False;;
            "(2)"*|"(3)"*) a64_want=True;;
            *) return 0;;
        esac
        ELF_REPORT="$2" A64_WANT="$a64_want" python3 - <<'PY' || fail "payloadWXFallback disagrees with the measured shape ($1 / $2)"
import json, os
rep = json.load(open(os.environ["ELF_REPORT"]))
got = rep.get("payloadWXFallback")
want = os.environ["A64_WANT"] == "True"
assert isinstance(got, bool), "report.payloadWXFallback is %r (want a JSON bool)" % (got,)
assert got == want, "report.payloadWXFallback=%s but the measured shape needs %s" % (got, want)
print("    payloadWXFallback=%s matches the measured shape" % got)
PY
    }
    # (R1) 只宣称**本 run 实测到**的档位：CI 的夹具只有 1 个 PT_NOTE ⇒ 两个产物都落在 (3)，
    # 这时说 "三档都测过" 就是超出实测的宣称（t8 的 R1）。
    A64_SEEN_1=0; A64_SEEN_2=0; A64_SEEN_3=0
    case "$A64_SHAPE1" in "(1)"*) A64_SEEN_1=1;; "(2)"*) A64_SEEN_2=1;; "(3)"*) A64_SEEN_3=1;; *) fail "product 1 has no legal payload shape: $A64_SHAPE1";; esac
    case "$A64_SHAPE2" in "(1)"*) A64_SEEN_1=1;; "(2)"*) A64_SEEN_2=1;; "(3)"*) A64_SEEN_3=1;; *) fail "product 2 has no legal payload shape: $A64_SHAPE2";; esac
    a64_assert_flag "$A64_SHAPE1" build/elf_enc_a64reloc.json
    a64_assert_flag "$A64_SHAPE2" build/elf_enc_a64reloc_rwx.json
    A64_SEEN_LIST=""
    [ "$A64_SEEN_1" = 1 ] && A64_SEEN_LIST="(1) three adjacent segments"
    [ "$A64_SEEN_2" = 1 ] && A64_SEEN_LIST="$A64_SEEN_LIST (2) prefix + W+X window+tail"
    [ "$A64_SEEN_3" = 1 ] && A64_SEEN_LIST="$A64_SEEN_LIST (3) one W+X payload segment"
    echo "[OK  ] aarch64: measured payload shape tier(s) in this run:$A64_SEEN_LIST"
    if [ "$A64_SEEN_1" = 1 ] && [ "$A64_SEEN_2" = 1 ] && [ "$A64_SEEN_3" = 1 ]; then
        echo "[OK  ] aarch64: all three legal payload tiers verified in this run (no fallback beyond what the slot count forces)"
    else
        echo "[SKIP] aarch64: only the tier(s) actually measured are claimed -- the missing tier(s) were NOT constructed in this run"
        echo "[SKIP] aarch64:   as-built fixture PT_NOTE=$A64_NOTE_ASBUILT: fewer reusable slots force a lower tier, and the tier a product lands in is asserted from its program headers + report.payloadWXFallback"
    fi
    # qemu 的 -L 是**前缀**：guest 里的 /lib/ld-linux-aarch64.so.1 会被解析成 <前缀>/lib/... ，
    # 所以前缀要取"loader 所在目录的上一级"（例如 /usr/aarch64-linux-gnu/lib -> /usr/aarch64-linux-gnu）。
    A64_LDFILE="$("$A64_CC" -print-file-name=ld-linux-aarch64.so.1 2>/dev/null)"
    A64_LD="$(dirname "$(dirname "$A64_LDFILE")")"
    # 运行期那半**升级为真断言**（#597）：守卫 1 把载着 PT_DYNAMIC 的 R-X 范围排除之后，
    # 产物不再含密文代码段，必须与原生逐字节一致。
    # 校准（必须能红）：把 cmd/vmpack/main.go 里守卫 1 的 `if dynHi > dynLo && ...` 改成 `if false`
    #   ⇒ 打包端会把那个范围整体加密 ⇒ 产物在 qemu 下 SIGSEGV(rc=139) ⇒ 下面这条断言变红。
    #   （本轮实测：守卫关掉后 exactly 这条命令 rc=139；守卫打开后 rc=0 且输出 143。）
    if [ -f "$A64_LDFILE" ]; then
        A64_NAT_RC=0; A64_NAT="$($QEMU -L "$A64_LD" ./build/elf_target_a64reloc check-key 10 2>&1)" || A64_NAT_RC=$?
        A64_RC=0; A64_OUT="$($QEMU -L "$A64_LD" ./build/elf_target_a64reloc.enc check-key 10 2>&1)" || A64_RC=$?
        if [ "$A64_NAT_RC" -ne 0 ] || [ "$A64_NAT" != "143" ]; then
            echo "[MISMATCH] aarch64 fixture native: rc=$A64_NAT_RC out=[$A64_NAT]"
            fail "the aarch64 reloc fixture does not run natively"
        fi
        if [ "$A64_RC" -ne 0 ] || [ "$A64_OUT" != "$A64_NAT" ]; then
            echo "[MISMATCH] aarch64 guard-1 product: native=[$A64_NAT](rc=$A64_NAT_RC) packed=[$(printf '%s' "$A64_OUT" | head -n 2 | tr '\n' ' ')](rc=$A64_RC)"
            fail "the aarch64 product must answer exactly what native answers (#597 guard 1)"
        fi
        echo "[OK  ] aarch64: guard-1 product answers like native (check-key 10 -> $A64_OUT)"
    else
        echo "[INFO] aarch64 reloc product runtime: no aarch64 loader next to $A64_CC (looked for [$A64_LDFILE])"
        fail "the aarch64 loader is missing: the #597 runtime assertion cannot run (refusing to report a silent pass)"
    fi
fi

echo "[+] e2e_elf_image: OK"

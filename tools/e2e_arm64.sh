#!/usr/bin/env bash
# e2e_arm64.sh - Linux/arm64 end-to-end (CI: linux/arm64 runner + qemu-user).
#
#   1. cross-compile a freestanding aarch64 target (only liftable instructions inside
#      the protected functions: check_key / sum_to)
#   2. build the ARM64 host blob (stub/linux/arm64) with the built-in merger (-merge go)
#   3. pack check_key / sum_to with vmpack (AArch64: 4-byte BL thunk + 4-byte B entry patch)
#   4. run native and protected under qemu-aarch64 and compare the output
#
# The only thing this does NOT cover is the kernel/loader handing control to the patched
# entry point: qemu-user executes the binary through the normal loader path, so in fact
# that is covered too (the packed binary is a real ELF that goes through execve).
set -euo pipefail


# --- 失败时把日志尾部打成 GitHub 注解 -------------------------------------
# 为什么需要它：仓库的原始日志需要鉴权才能下载，而注解可以在运行页/API 上匿名读到。
# 这样我（或者任何 reviewer）不用登录就能看到"为什么红"。
mkdir -p build
exec > >(tee build/e2e_run.log) 2>&1
# 注意用 EXIT 而不是 ERR：脚本里有若干显式的 "exit 1"（例如段权限断言），
# 那些路径不会触发 ERR trap，结果注解里什么都看不到（CI 上真踩过这一脚）。
ok=0
on_exit() {
    rc=$?
    if [ "$ok" = "0" ] && [ "$rc" -ne 0 ]; then
        msg=$(tail -n 20 build/e2e_run.log 2>/dev/null | sed -e 's/%/%25/g' -e 's/\r//g' | awk '{printf "%s%%0A", $0}')
        echo "::error title=$(basename "$0") failed (exit $rc)::$msg"
    fi
}
trap on_exit EXIT

cd "$(dirname "$0")/.."
mkdir -p build

CC=${CC:-aarch64-linux-gnu-gcc}
OBJDUMP=${OBJDUMP:-aarch64-linux-gnu-objdump}
QEMU=${QEMU:-qemu-aarch64}

echo "[*] building tools..."
go build -o build/vmpbuild ./cmd/vmpbuild
go build -o build/vmpack ./cmd/vmpack
go build -o build/extractpayload ./cmd/extractpayload

echo "[*] cross-compiling the aarch64 target..."
$CC -O1 -fno-tree-vectorize -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -nostdlib -static -Wl,-e,_start -o build/arm64_target testdata/arm64/target.c

echo "[*] building the linux/arm64 blob (built-in merger)..."
./build/vmpbuild -src stub/linux/arm64 \
    -out build/vm_interp_arm64.bin -manifest build/vm_interp_arm64.json \
    -entry vm_entry -guest arm64 -merge go -random-opcodes=false \
    -cc "$CC" -objdump "$OBJDUMP"

echo "[*] packing check_key / sum_to..."
./build/vmpack -exe build/arm64_target -func check_key -func sum_to \
    -blob build/vm_interp_arm64.bin -manifest build/vm_interp_arm64.json \
    -dumpbytecode build/bcdump \
    -out build/arm64_target.vmp -report build/arm64_vmp.json

# 入口补丁检查：在打包产物里反汇编被保护函数开头，确认 8 字节补丁真的写进去了
# （期望 F0 03 1E AA = mov x16,x30，紧跟一条 B）。x86-64 侧正是靠这一步排除/确认了补丁问题。
if [ -n "$OBJDUMP" ] && command -v "$OBJDUMP" >/dev/null 2>&1; then
    echo "[*] 入口补丁检查（$OBJDUMP）:"
    for rva in $(grep -o '"funcRVA": *[0-9]*' build/arm64_vmp.json | sed 's/.*: *//' | head -n 2); do
        va=$((0x400000 + rva))
        start=$(printf '0x%x' "$va"); end=$(printf '0x%x' $((va + 8)))
        line=$($OBJDUMP -d --start-address=$start --stop-address=$end build/arm64_target.vmp 2>/dev/null | grep -E '^\s+[0-9a-f]+:' | head -n 2 | tr '\n' ';')
        echo "[*]   补丁 rva=0x$(printf '%x' $rva): $line"
    done
fi
# payload 探针：把注入段按原始 VA 映射后直接调 thunk（与入口补丁同构的尾跳）——
# 用来区分「payload 自身」与「入口/加载」。所有取数都带 || true：脚本是 set -e + pipefail，
# 任何一次 grep 落空都会直接终止脚本，把后面的关键输出（探针数值）全部吞掉 —— 那个坑我踩过。
if [ -n "$CC" ] && [ -f stub/linux/arm64/payload_probe_arm64.c ]; then
    if $CC -O1 -static -no-pie -Wl,-Ttext-segment=0x100000000 -o build/payload_probe_arm64 stub/linux/arm64/payload_probe_arm64.c 2>build/probe_cc.log; then
        sec_rva=$(grep -o '"sectionRVA": *[0-9]*' build/arm64_vmp.json | head -n1 | sed 's/.*: *//' || true)
        sec_sz=$(grep -o '"sectionSize": *[0-9]*' build/arm64_vmp.json | head -n1 | sed 's/.*: *//' || true)
        thunk_rva=$(grep -o '"thunkRVA": *[0-9]*' build/arm64_vmp.json | head -n1 | sed 's/.*: *//' || true)
        va=$((0x400000 + ${sec_rva:-0})); thunk_off=$(( ${thunk_rva:-0} - ${sec_rva:-0} ))
        echo "[*] payload 探针：payloadVA=0x$(printf %x $va) thunkOff=0x$(printf %x $thunk_off)"
        python3 - <<'PY' 2>/dev/null || true
import json, glob
m = json.load(open("build/vm_interp_arm64.json"))
inv = {v: k for k, v in m["opcodeMap"].items()}
rep = json.load(open("build/arm64_vmp.json"))
want = rep["placements"][0].get("bytecodeBytes", 0)
code = b""
for f in sorted(glob.glob("build/bcdump/bytecode_*.bin")):
    b = open(f, "rb").read()
    if len(b) == want:
        code = b
        break
names = " ".join("0x%X=%s" % (code[p], inv.get(code[p], "?")) for p in (0, 9, 0xF, 0x18, 0x23, 0x29) if p < len(code))
print("MISMATCH 解码: len=%d maxFrame=%s margin=%s %s" % (len(code), m.get("maxStubStackFrame"), m.get("margin"), names))
  # 第二个函数（sum_to，带循环）的字节码与它循环里的 op：环形缓冲显示 pc 在 0x20/0x26/0x2F 之间打转
  dumps = sorted(glob.glob("build/bcdump/bytecode_*.bin"))
  if len(dumps) > 1:
      c2 = open(dumps[1], "rb").read()
      print("MISMATCH sum_to 字节码(%d): %s" % (len(c2), c2.hex()))
      print("MISMATCH sum_to 循环 op: " + " ".join("0x%X=%s" % (c2[p], inv.get(c2[p], "?")) for p in (0x20, 0x26, 0x2F) if p < len(c2)))
PY
        ./build/extractpayload -elf build/arm64_target.vmp -rva "$sec_rva" -size "$sec_sz" -thunk "$thunk_rva" -manifest build/vm_interp_arm64.json -out build/arm64_payload.bin >build/extract.log 2>&1 || echo "[!] extractpayload 失败: $(tail -n1 build/extract.log)"
        ring_off=$(grep -o '"vm_ring_hdr": *[0-9]*' build/vm_interp_arm64.json | head -n1 | sed 's/.*: *//' || true)
        diag_off=$(grep -o '"vm_diag": *[0-9]*' build/vm_interp_arm64.json | head -n1 | sed 's/.*: *//' || true)
        probe_out=$(timeout 60 $QEMU ./build/payload_probe_arm64 build/arm64_payload.bin "$(printf 0x%x $va)" "$(printf 0x%x $thunk_off)" "${ring_off:-0}" "${diag_off:-0}" 0 1 10 255 2>&1) || true
        echo "MISMATCH 探针结果: $(printf '%s' "$probe_out" | tr '\n' '|')"
        # 再探一次第二个被保护函数 sum_to（带循环，能区分"叶子函数对"与"循环/分支也對"）
        thunk2_rva=$(grep -o '"thunkRVA": *[0-9]*' build/arm64_vmp.json | sed -n 2p | sed 's/.*: *//' || true)
        if [ -n "$thunk2_rva" ]; then
            thunk_off2=$(( thunk2_rva - ${sec_rva:-0} ))
            probe2=$(timeout 60 $QEMU ./build/payload_probe_arm64 build/arm64_payload.bin "$(printf 0x%x $va)" "$(printf 0x%x $thunk_off2)" "${ring_off:-0}" "${diag_off:-0}" 1 7 1000 2>&1) || true
            echo "MISMATCH 探针结果(sum_to): $(printf '%s' "$probe2" | tr '\n' '|')"
            # 探针超时通常意味着客户机里的循环没有终止 —— 这本身就是要查的现象
            if printf '%s' "$probe2" | grep -q '^$'; then echo "[!] sum_to 探针无输出（可能超时：客户机循环未终止）"; fi
        fi
        if printf '%s' "$probe_out" | grep -q "signal"; then
            set +e
            timeout 180 $QEMU -d in_asm,cpu -D build/qemu_probe.log ./build/payload_probe_arm64 build/arm64_payload.bin "$(printf 0x%x $va)" "$(printf 0x%x $thunk_off)" "${ring_off:-0}" "${diag_off:-0}" 0 >/dev/null 2>&1
            set -e
            ln=$(grep -n 'IN: ' build/qemu_probe.log 2>/dev/null | tail -n1 | cut -d: -f1 || true)
            if [ -n "$ln" ]; then
                from=$((ln > 14 ? ln - 14 : 1))
                echo "[!] 探针最后指令: $(sed -n "${from},$((ln + 4))p" build/qemu_probe.log 2>/dev/null | tr '\n' '|' || true)"
            fi
        fi
    else
        echo "[!] payload 探针编译失败: $(tail -n 2 build/probe_cc.log | tr '\n' '|')"
    fi
fi
echo "[*] running native vs protected under $QEMU..."
# 注意：脚本是 set -e。qemu 里客户机崩溃时命令替换会直接终止脚本（上一轮 CI 就只留下
# "qemu: uncaught target signal 11" 而没有我们的诊断输出），所以统一用 "cmd || rc=$?"。
nrc=0
native=$($QEMU ./build/arm64_target 2>&1) || nrc=$?
prc=0
protected=$($QEMU ./build/arm64_target.vmp 2>&1) || prc=$?
echo "--- native (rc=$nrc) ---"
echo "$native"
echo "--- protected (rc=$prc) ---"
echo "$protected"
if [ "$native" = "$protected" ] && [ -n "$native" ] && [ "$nrc" -eq 0 ] && [ "$prc" -eq 0 ]; then
    echo "[+] arm64 end-to-end: outputs match"
else
    echo "[!] arm64 end-to-end: MISMATCH (native rc=$nrc, protected rc=$prc)"
    # 单行输出，前缀 [!] 以便被 CI 注解抓取（多行现场容易被截断丢掉）
    echo "[!] native   = $(printf '%s' "$native" | tr '\n' '|')"
    echo "[!] protected= $(printf '%s' "$protected" | tr '\n' '|')"
    # 失败时用 qemu 的指令级日志重跑一次，打印尾部 —— 用来定位"炸在哪条 arm64 指令"
    # （对应 x86 侧用 objdump 反汇编故障偏移附近的做法）。
    set +e
    $QEMU -d in_asm,cpu -D build/qemu_arm64.log ./build/arm64_target.vmp >/dev/null 2>&1
    set -e
    echo "[*] qemu 指令日志尾部（共 $(wc -l < build/qemu_arm64.log 2>/dev/null || echo 0) 行）:"
    tail -n 70 build/qemu_arm64.log 2>/dev/null | sed 's/^/    /'
    exit 1
fi
# ---- 1b 外置主密钥（-key-external）验收：与 amd64 侧同一套三条 ----
# aarch64 没有 open/readlink，走的是 openat/readlinkat（见 vm_interp.c 的 Linux 取钥块）。
# 硬门是 exit_group(0xC0DE0007)，POSIX 只看得到低 8 位 ⇒ 断言 rc=7 且无输出。
echo "[*] 1b 外置密钥（-key-external）验收..."
KEY1B=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
./build/vmpbuild -cc "$CC" -src stub/linux/arm64 -out build/vm_interp_arm64_ext.bin \
    -manifest build/vm_interp_arm64_ext.json -entry vm_entry \
    -key-external -key-in "$KEY1B" >/dev/null
./build/vmpack -exe build/arm64_target -func check_key -func sum_to \
    -blob build/vm_interp_arm64_ext.bin -manifest build/vm_interp_arm64_ext.json \
    -out build/arm64_target_ext.vmp -report build/arm64_ext_vmp.json >/dev/null

rc_no=0
out_no=$($QEMU ./build/arm64_target_ext.vmp 2>&1) || rc_no=$?
if [ "$rc_no" -eq 7 ] && [ -z "$out_no" ]; then
    echo "[+] 1b: 无密钥 -> rc=7（硬门低 8 位）且无输出"
else
    echo "[!] 1b: 无密钥时 rc=$rc_no（期望 7），输出=[$(printf %s "$out_no" | tr "\n" "|")]"
    exit 1
fi

erc=0
eout=$(VMPX_KEY=$KEY1B $QEMU ./build/arm64_target_ext.vmp 2>&1) || erc=$?
if [ "$erc" -eq 0 ] && [ "$eout" = "$native" ]; then
    echo "[+] 1b: 有密钥(VMPX_KEY) -> 与原生一致"
else
    echo "[!] 1b: 有密钥(VMPX_KEY) rc=$erc；native=[$(printf %s "$native" | tr "\n" "|")] ext=[$(printf %s "$eout" | tr "\n" "|")]"
    exit 1
fi

ok=1

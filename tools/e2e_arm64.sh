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
    -entry vm_entry -guest arm64 -merge go \
    -cc "$CC" -objdump "$OBJDUMP"

echo "[*] packing check_key / sum_to..."
./build/vmpack -exe build/arm64_target -func check_key -func sum_to \
    -blob build/vm_interp_arm64.bin -manifest build/vm_interp_arm64.json \
    -out build/arm64_target.vmp -report build/arm64_vmp.json

# 入口补丁检查：在打包产物里反汇编被保护函数开头，确认 8 字节补丁真的写进去了
# （期望 F0 03 1E AA = mov x16,x30，紧跟一条 B）。x86-64 侧正是靠这一步排除/确认了补丁问题。
if [ -n "$OBJDUMP" ] && command -v "$OBJDUMP" >/dev/null 2>&1; then
    echo "[*] 入口补丁检查（$OBJDUMP）:"
    for rva in $(grep -o '"funcRVA": *[0-9]*' build/arm64_vmp.json | sed 's/.*: *//' | head -n 2); do
        va=$((0x400000 + rva))
        start=$(printf '0x%x' "$va"); end=$(printf '0x%x' $((va + 8)))
        line=$($OBJDUMP -d --start-address=$start --stop-address=$end build/arm64_target.vmp 2>/dev/null | grep -E '^\s+[0-9a-f]+:' | head -n 2 | tr '\n' ';')
        echo "[!]   补丁 rva=0x$(printf '%x' $rva): $line"
    done
fi
# payload 探针：把注入段按原始 VA 映射后直接调 thunk —— 用于区分「payload 自身」与「入口/加载」。
if [ -n "$CC" ] && [ -f stub/linux/arm64/payload_probe_arm64.c ]; then
    if $CC -O1 -static -no-pie -Wl,-Ttext-segment=0x100000000 -o build/payload_probe_arm64 stub/linux/arm64/payload_probe_arm64.c 2>build/probe_cc.log; then
        sec_rva=$(grep -o '"sectionRVA": *[0-9]*' build/arm64_vmp.json | head -n1 | sed 's/.*: *//')
        sec_sz=$(grep -o '"sectionSize": *[0-9]*' build/arm64_vmp.json | head -n1 | sed 's/.*: *//')
        thunk_rva=$(grep -o '"thunkRVA": *[0-9]*' build/arm64_vmp.json | head -n1 | sed 's/.*: *//')
        va=$((0x400000 + sec_rva)); thunk_off=$((thunk_rva - sec_rva))
        echo "[*] payload 探针：payloadVA=0x$(printf %x $va) thunkOff=0x$(printf %x $thunk_off)"
        extract_out=$(./build/extractpayload -elf build/arm64_target.vmp -rva "$sec_rva" -size "$sec_sz" -thunk "$thunk_rva" -out build/arm64_payload.bin 2>&1) || echo "[!] extractpayload 失败: $(printf '%s' "$extract_out" | tr '\n' '|')"
        ring_off=$(grep -o '"vm_ring_hdr": *[0-9]*' build/vm_interp_arm64.json | head -n1 | sed 's/.*: *//')
        echo "[*] vm_ring_hdr 偏移: ${ring_off:-未知}"
        python3 - <<'PY' > build/opnames.txt 2>/dev/null || true
import json
try:
    m = json.load(open("build/vm_interp_arm64.json"))
    op = m.get("opcodes") or m.get("opcodeValues") or {}
    inv = {v: k for k, v in op.items()} if isinstance(op, dict) else {}
    for v in (0x69, 0x73, 0xA3, 0xFC):
        print("0x%X=%s" % (v, inv.get(v, "?")))
except Exception as ex:
    print("decode failed: %s" % ex)
PY
        echo "[*] 操作码解码: $(tr '\n' ' ' < build/opnames.txt)"
        probe_out=$($QEMU ./build/payload_probe_arm64 build/arm64_payload.bin "$(printf 0x%x $va)" "$(printf 0x%x $thunk_off)" "${ring_off:-0}" 0 1 10 255 2>&1) || true
        echo "[!] payload 探针结果: $(printf '%s' "$probe_out" | tr '\n' '|')"
        # 探针崩了的话，用 qemu 的指令级日志再看一次，打印尾部 —— 定位炸在哪条 arm64 指令
        if printf '%s' "$probe_out" | grep -q "signal"; then
            set +e
            $QEMU -d in_asm,cpu -D build/qemu_probe.log ./build/payload_probe_arm64 build/arm64_payload.bin "$(printf 0x%x $va)" "$(printf 0x%x $thunk_off)" "${ring_off:-0}" 0 >/dev/null 2>&1
            set -e
            echo "[!] 探针现场（qemu 指令日志尾部 $(wc -l < build/qemu_probe.log 2>/dev/null || echo 0) 行）:"
            # 只打最后几条指令，并压成单行 —— 注解只保留前 12 条 [!] 行，多行会被截掉
            ln=$(grep -n 'IN: ' build/qemu_probe.log 2>/dev/null | tail -n1 | cut -d: -f1)
            from=$((ln > 14 ? ln - 14 : 1))
            echo "[!] 探针最后指令（含前几个块）: $(sed -n "${from},$((ln + 4))p" build/qemu_probe.log 2>/dev/null | tr '\n' '|')"
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
ok=1
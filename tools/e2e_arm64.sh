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
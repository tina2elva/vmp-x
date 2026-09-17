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
on_err() {
    rc=$?
    msg=$(tail -n 20 build/e2e_run.log 2>/dev/null | sed -e 's/%/%25/g' -e 's/\r//g' | awk '{printf "%s%%0A", $0}')
    echo "::error title=$(basename "$0") failed (exit $rc)::$msg"
    exit $rc
}
trap on_err ERR

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
native=$($QEMU ./build/arm64_target)
protected=$($QEMU ./build/arm64_target.vmp)
echo "--- native ---"
echo "$native"
echo "--- protected ---"
echo "$protected"
if [ "$native" = "$protected" ] && [ -n "$native" ]; then
    echo "[+] arm64 end-to-end: outputs match"
else
    echo "[!] arm64 end-to-end: MISMATCH"
    exit 1
fi
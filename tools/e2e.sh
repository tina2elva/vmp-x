#!/usr/bin/env bash
# e2e.sh - Linux/amd64 end-to-end test (runs on a Linux host / CI runner).
#
#  1. build vmpbuild + vmpack (Go)
#  2. build the VM interpreter blob for linux/amd64
#  3. build the target Go program (real Linux ELF, ET_EXEC, symbols intact)
#  4. protect checkKey/sumTo, then compare native vs protected for many inputs
#
# The stub is compiled with the HOST gcc, which produces an ELF relocatable object;
# vmpbuild reads it through the normalized object path (COFF and ELF share the blob
# builder and the PC-relative relocation logic). A mingw cross compiler is only used
# as a fallback, so a CI log always states which compiler produced the blob.
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

echo "[*] building tools..."
go build -o build/vmpbuild ./cmd/vmpbuild
go build -o build/vmpack ./cmd/vmpack

echo "[*] building target (linux/amd64)..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/linux_target ./testdata/linux

build_stub() {
    local cc="$1"
    if [ -n "$cc" ]; then
        ./build/vmpbuild -cc "$cc" -src stub/linux/amd64 -out build/vm_interp_linux.bin \
            -manifest build/vm_interp_linux.json -entry vm_entry
    else
        ./build/vmpbuild -src stub/linux/amd64 -out build/vm_interp_linux.bin \
            -manifest build/vm_interp_linux.json -entry vm_entry
    fi
}

echo "[*] building VM stub for linux/amd64 with host gcc (ELF object)..."
if ! build_stub ""; then
    if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
        echo "[warn] ELF object path failed; falling back to mingw (COFF object)"
        build_stub x86_64-w64-mingw32-gcc
    else
        echo "[!] stub build failed and no mingw fallback available"
        exit 1
    fi
fi

echo "[*] packing..."
./build/vmpack -exe build/linux_target -func main.checkKey -func main.sumTo \
    -blob build/vm_interp_linux.bin -manifest build/vm_interp_linux.json \
    -out build/linux_target.vmp -report build/linux_vmp.json

# 断言：注入后的 ELF 里**没有**同时可写又可执行的段（RWX 是安全坏味道）。
# 可写数据（解释器的明文解密缓存）应当落在单独的 R+W 覆盖段里。
if command -v readelf >/dev/null 2>&1; then
    wx=$(readelf -lW build/linux_target.vmp | awk '$1=="LOAD" && $0 ~ /W/ && $0 ~ /E/ {print}')
    if [ -n "$wx" ]; then
        echo "[!] 存在 W+X 段（RWX）:"; echo "$wx"
        exit 1
    fi
    echo "[+] 段权限检查通过：没有 W+X 段"
fi

pass=0
fail=0
run_case() {
    fn="$1"
    arg="$2"
    n=$(./build/linux_target "$fn" "$arg" 2>/dev/null || echo "<crash>")
    v=$(./build/linux_target.vmp "$fn" "$arg" 2>/dev/null || echo "<crash>")
    if [ "$n" = "$v" ] && [ -n "$n" ]; then
        pass=$((pass + 1))
        echo "  [OK  ] $fn($arg): native=$n protected=$v"
    else
        fail=$((fail + 1))
        echo "  [FAIL] $fn($arg): native=$n protected=$v"
    fi
}

echo "[*] differential test (native vs protected)..."
for a in 0 1 10 255 12345 1000000 4294967295; do
    run_case check-key "$a"
done
for a in 0 1 2 10 100 1000 9999; do
    run_case sum-to "$a"
done

echo ""
echo "e2e(linux): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
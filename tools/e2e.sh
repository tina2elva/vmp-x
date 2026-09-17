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
    # 注意：脚本是 set -e，命令替换里命令失败会直接终止脚本，所以统一用 "cmd || rc=$?"。
    nrc=0
    nout=$(./build/linux_target "$fn" "$arg" 2>&1) || nrc=$?
    vrc=0
    vout=$(./build/linux_target.vmp "$fn" "$arg" 2>&1) || vrc=$?
    n=$(printf '%s' "$nout" | head -n 1)
    v=$(printf '%s' "$vout" | head -n 1)
    if [ "$n" = "$v" ] && [ -n "$n" ] && [ "$nrc" -eq 0 ] && [ "$vrc" -eq 0 ]; then
        pass=$((pass + 1))
        echo "  [OK  ] $fn($arg): native=$n protected=$v"
    else
        fail=$((fail + 1))
        echo "  [FAIL] $fn($arg): native=$n (rc=$nrc) protected=$v (rc=$vrc)"
        # 崩溃/panic 的正文在 stderr 里：把它打印出来（Go 程序 panic 时退出码就是 2，
        # 光看 rc=2 完全不知道原因 —— 上一轮 CI 就是这样）。
        if [ "$vrc" -ne 0 ]; then
            echo "         --- protected stderr/stdout ---"
            printf '%s' "$vout" | head -n 12 | sed 's/^/         /'
        fi
    fi
}

# 运行前先确认"入口补丁真的写进文件了"：如果没写，崩溃就与解释器无关，
# 而是补丁/写回这一环；如果写了，问题才在运行期（CI 上这条路径本机跑不到）。
if command -v objdump >/dev/null 2>&1 && command -v grep >/dev/null 2>&1; then
    echo "[*] 检查入口补丁（用 objdump 反汇编被保护后的文件）..."
    for rva in $(grep -o '"funcRVA": *[0-9]*' build/linux_vmp.json | sed 's/.*: *//' | head -n 2); do
        va=$((0x400000 + rva))
        hexva=$(printf '0x%x' "$va")
        hexend=$(printf '0x%x' $((va + 16)))
        first=$(objdump -d --start-address=$hexva --stop-address=$hexend build/linux_target.vmp 2>/dev/null | grep -E '^\s+[0-9a-f]+:' | head -n 1)
        echo "    RVA=0x$(printf '%x' "$rva") -> $first"
    done
fi

# 打包后把程序头打出来：注入段是 RX，blob 的 .bss（解密缓存）靠一个**重叠的 RW** LOAD 覆盖。
# 覆盖段缺失/尺寸不对时，内核会把 .bss 留在只读 RX 映射里 → VM 第一次写缓存就 SIGSEGV，
# 而 Windows 的 PE 路径没有这种映射检查，所以这个 bug 只在 Linux 上现形。
if command -v readelf >/dev/null 2>&1; then
    echo "[*] 打包后程序头（只看 LOAD/NOTE）:"
    readelf -lW build/linux_target.vmp | grep -E "LOAD|NOTE" | sed "s/^/    /"
fi
echo "[*] differential test (native vs protected)..."
for a in 0 1 10 255 12345 1000000 4294967295; do
    run_case check-key "$a"
done
for a in 0 1 2 10 100 1000 9999; do
    run_case sum-to "$a"
done

echo ""
echo "e2e(linux): $pass passed, $fail failed"
ok=1
[ "$fail" -eq 0 ]
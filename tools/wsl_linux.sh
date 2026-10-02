#!/usr/bin/env bash
# wsl_linux.sh - run CI's linux-amd64 and linux-arm64 job commands LOCALLY (inside WSL).
#
# Why this exists: those two CI jobs exist to build and RUN the ELF payloads on a real Linux
# kernel. A WSL distro can do exactly that (gcc, aarch64 cross toolchain, qemu-user), so the
# inner loop does not have to pay a CI round trip; CI keeps the role of "a second toolchain /
# OS as the acceptance witness" (STATUS #583).
#
# Usage (inside WSL, from the repo root):
#     bash tools/wsl_linux.sh [all|amd64|arm64]
# Windows entry point: tools/wsl_linux.ps1 (syncs the repo first, then calls this).
#
# KNOWN_FAIL below: steps that are known to fail on a *newer local toolchain* for a bug that is
# registered separately (STATUS #584). Marking them is NOT loosening a check: they still run,
# they still print every failing line, and the moment one of them PASSES this script says so
# loudly ("remove the exemption") so an exemption cannot silently outlive its bug. This mirrors
# how the two windows-arm64 CI jobs are continue-on-error while that platform is deferred
# (STATUS #581).
#
# Output is ASCII only (Windows runners are not UTF-8; see AGENTS.md).
set -u
cd "$(dirname "$0")/.."
mkdir -p build
ONLY="${1:-all}"
FAIL=0
# Currently EMPTY: the two linux/amd64 ELF steps were listed here for exactly one round (they
# failed on this local kernel because the injector left the original .bss unmapped). STATUS #585
# fixed that in the packer (MakeBssFileBacked), so the exemption was removed -- i.e. the
# "stale exemption" path this mechanism forces you to notice actually fired.
KNOWN_FAIL=""

step() {
  local name="$1"; shift
  local log="build/wsl_$(echo "$name" | tr ' /.' '___').log"
  local known=0
  case ",$KNOWN_FAIL," in *",$name,"*) known=1 ;; esac
  echo "[*] $name"
  if "$@" > "$log" 2>&1; then
    echo "[OK  ] $name"
    if [ "$known" = "1" ]; then
      echo "[NOTE] '$name' is marked KNOWN-FAIL but just PASSED -- the exemption is stale, remove it"
    fi
  else
    if [ "$known" = "1" ]; then
      echo "[KNOWN-FAIL] $name -- registered bug, not counted as a gate failure (STATUS #584)"
      tail -n 6 "$log" | sed 's/^/    /'
    else
      echo "[FAIL] $name (log: $log)"
      tail -n 20 "$log" | sed 's/^/    /'
      FAIL=$((FAIL + 1))
    fi
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

echo "=== dependency check ==="
for t in gcc go make; do
  if have "$t"; then echo "  ok      $t"; else echo "  MISSING $t"; fi
done
if [ "$ONLY" = "all" ] || [ "$ONLY" = "arm64" ]; then
  for t in aarch64-linux-gnu-gcc aarch64-linux-gnu-objdump qemu-aarch64; do
    if have "$t"; then echo "  ok      $t"; else echo "  MISSING $t"; fi
  done
fi

if [ "$ONLY" = "all" ] || [ "$ONLY" = "amd64" ]; then
  echo "=== linux/amd64 (CI job linux-amd64) ==="
  step "go build ./..."       go build ./...
  # 真实 PIE 夹具：internal/load/elf 的 TestRelativeRelocsRealPIE 拿它当输入（没有就 SKIP）。
  # 它必须在 go test **之前**造出来，否则那条用例在 CI 上永远是"跳过的死代码"。
  step "pie target fixture"   env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildmode=pie -o build/pie_target ./testdata/linux
  # TestARM64PayloadUnderQEMU 以前按"build/ 里恰好有什么"决定跑还是跳（残留产物会让它拿错配的
  # blob/manifest）。STATUS #588 把它改成**只认 VMP_ARM64_DIR**：没给就确定性 SKIP。
  # 所以这里不再需要"先删残留"那种补丁 —— 残留不会再影响它。
  step "go test ./..."        go test ./...
  step "payload probe"        bash tools/verify_linux_payload.sh
  step "elf end-to-end"       bash tools/e2e.sh
  # ELF 侧的布局门禁（PE 侧对应 tools/check_symmap.py）：程序头/载荷映射/逐字节一致/
  # **bss 覆盖**（#585 那条）/重定位覆盖，且自带校准（--selftest）。
  # 用 e2e.sh 刚留下的产物，所以必须排在它后面。
  step "elf layout gate"      python3 tools/check_elf_layout.py \
    --packed build/linux_target.vmp --manifest build/vm_interp_linux.json \
    --blob build/vm_interp_linux.bin --report build/linux_vmp.json --selftest
  # Linux 侧反调试（/proc/self/status 的 TracerPid，#389 登记的那条缺口）：两个方向都要验 ——
  # 没有 tracer 时**行为必须完全不变**，有 tracer 时必须**静默延后**（给错值但正常退出，不 trap）。
  # gdb 只是"制造一个 tracer"的手段（实测它会把 TracerPid 置成自己的 pid）。
  antidebug_probe() {
    local p="build/linux_target.vmp"
    [ -x "$p" ] || { echo "no $p"; return 1; }
    local plain traced
    plain=$("./$p" check-key 10 2>/dev/null | head -1)
    if [ "$plain" != "143" ]; then echo "no-tracer run returned '$plain' (expected 143) -> false positive?"; return 1; fi
    traced=$(gdb -batch -ex run --args "./$p" check-key 10 2>/dev/null | grep -E '^[0-9]+$' | head -1)
    if [ -z "$traced" ] || [ "$traced" = "143" ]; then
      echo "under a tracer the result was '$traced' (expected != 143)"; return 1
    fi
    echo "no tracer -> 143 ; under gdb -> $traced (wrong value, normal exit: silent deferral)"
  }
  if command -v gdb >/dev/null 2>&1; then
    step "linux anti-debug (TracerPid)" antidebug_probe
  else
    echo "[SKIP] linux anti-debug: no gdb on this machine to create a tracer"
  fi
  step "elf image encryption" bash tools/e2e_elf_image.sh --strict
  # ET_DYN(PIE)：镜像加密 + **载荷里不能有未重定位的绝对 VA**（E5 对 ET_DYN 才是真检查；
  # 对 ET_EXEC 它只是一条 INFO）。这里必须**紧挨着**跑布局门禁：e2e_elf_image.sh 会重建
  # vm_interp_elf.bin/json，而 blob 构建带随机性，隔一次跑就对不上（E3 会红）。
  # 校准：改动前 PIE 这条用例直接红（打包器跳过加密 → 原执行段 0 残留那条断言失败）。
  step "elf pie image"        env PIE=1 TAG=pie bash tools/e2e_elf_image.sh --strict
  step "elf layout gate (PIE)" python3 tools/check_elf_layout.py \
    --packed build/elf_target_pie.enc --manifest build/vm_interp_elf.json \
    --blob build/vm_interp_elf.bin --report build/elf_enc_pie.json --selftest
  # 加密范围里**真的有**相对重定位的目标（gcc 的 PIE，.rodata 里两条 R_X86_64_RELATIVE）：
  # 默认必须拒绝加密那个范围（fail-closed），产物照旧与原生一致。
  step "elf pie relocs"       env PIE_RELOCS=1 TAG=pierel bash tools/e2e_elf_image.sh --strict
  # 这一份的门禁验的是"账目"：声明的加密范围里那 2 条重定位必须被记录（imgRelocCount），
  # 且 payload 里必须真有应用表（imgRelocTableRVA）。
  step "elf layout gate (PIE + relocs)" python3 tools/check_elf_layout.py \
    --packed build/elf_target_pierel_relocs.enc --manifest build/vm_interp_elf.json \
    --blob build/vm_interp_elf.bin --report build/elf_enc_pierel_relocs.json --selftest
fi

if [ "$ONLY" = "all" ] || [ "$ONLY" = "arm64" ]; then
  echo "=== linux/arm64 under qemu-user (CI job linux-arm64) ==="
  step "arm64 end-to-end" env CC=aarch64-linux-gnu-gcc OBJDUMP=aarch64-linux-gnu-objdump QEMU=qemu-aarch64 \
    bash tools/e2e_arm64.sh
  # Same environment variables as CI: vmpbuild's ASSEMBLY step uses CC from the environment;
  # passing only -cc would assemble the .S with the host toolchain (CI hit exactly that).
  step "arm64 elf image" env CC=aarch64-linux-gnu-gcc OBJDUMP=aarch64-linux-gnu-objdump \
    BLOB_SRC=stub/linux/arm64 BLOB_CC=aarch64-linux-gnu-gcc BLOB_GUEST=arm64 \
    BLOB_EXTRA="-merge go -random-opcodes=false -objdump aarch64-linux-gnu-objdump" \
    GOARCH_TARGET=arm64 QEMU=qemu-aarch64 TAG=a64 EXPOSE_SECTIONS=".text" \
    bash tools/e2e_elf_image.sh --strict
fi

echo ""
if [ "$FAIL" -gt 0 ]; then
  echo "[FAIL] wsl_linux: $FAIL step(s) failed"
  exit 1
fi
if [ -n "$KNOWN_FAIL" ]; then
  echo "[OK  ] wsl_linux: no unexpected failures (known-failing steps are marked above)"
else
  echo "[OK  ] wsl_linux: every step passed"
fi
exit 0

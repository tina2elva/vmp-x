# e2e_arm64guest.ps1 - ARM64 GUEST semantics, executed by the x86-64 host interpreter.
#
#   powershell -NoProfile -File tools/e2e_arm64guest.ps1
#
# 为什么单独成脚本：它需要先构建两个产物（a64g blob 与 harness），
# 而且 harness 必须与 blob 用同一套 ctx 布局（-DVM_GUEST_ARM64=1 -DVM_REG_COUNT=35）——
# 少传 -DVM_REG_COUNT=35 的症状是解释器 rc=1，非常难查（这个坑真踩过，见 docs/STATUS.md 第 76 轮）。
# 单独成脚本还可以让 gates.ps1 用子进程调用，退出码语义干净。
Set-Location (Join-Path $PSScriptRoot "..")
$ErrorActionPreference = "Continue"

Write-Host "[*] building arm64-guest blob (identity opcodes, so the Go-side test bytecode matches)"
& .\build\vmpbuild.exe -src stub/win/x64 -out build/vm_interp_a64g.bin -manifest build/vm_interp_a64g.json -entry vm_entry -guest arm64 -random-opcodes=false
if ($LASTEXITCODE -ne 0) { Write-Host "[!] blob build failed"; exit 1 }

Write-Host "[*] building harness (same ctx layout as the blob)"
& gcc -O1 -Wall -DVM_GUEST_ARM64=1 -DVM_REG_COUNT=35 -I stub/win/x64 -o build/runbc_a64g.exe stub/win/x64/blob_probe.c
if ($LASTEXITCODE -ne 0) { Write-Host "[!] harness build failed"; exit 1 }

Write-Host "[*] ARM64 guest differential vs Go reference (C interpreter)"
& go test ./internal/lift/arm64/ -run TestArm64GuestInCInterpreter
if ($LASTEXITCODE -ne 0) { Write-Host "[!] differential failed"; exit 1 }

Write-Host "[*] ARM64 guest borrow/condition-code semantics"
& go test ./internal/vm/ -run TestGuestSemantics
if ($LASTEXITCODE -ne 0) { Write-Host "[!] semantics test failed"; exit 1 }

Write-Host "[+] arm64 guest e2e: OK"
exit 0

# gates.ps1 - run every local (Windows/amd64) gate in one shot.
#
#   powershell -NoProfile -File tools/gates.ps1
#
# NOTE: this file is deliberately ASCII-only. Windows PowerShell 5.1 reads .ps1 as ANSI
# unless it has a BOM, so non-ASCII bytes (e.g. Chinese comments) can swallow a following
# line and turn a Step call into part of a comment -- a gate that silently never runs.
# That is exactly what happened here before (the linux-payload step disappeared).
param(
    # -NoWsl: skip the WSL Linux suite (tools/wsl_linux.ps1) while iterating on the Windows side.
    [switch]$NoWsl
)
Set-Location (Join-Path $PSScriptRoot "..")
$script:results = @()

# 步骤的三种结局：通过(0) / 失败(非0) / **跳过(77)**。77 是约定值：e2e_32bit.ps1 与 wsl_linux.ps1
# 在缺工具链/缺 WSL 时用它，gates 于是能**单独记账**。以前它们 exit 0，gates 就报成 "[OK  ]" 并把
# 未跑的步骤留在 "15" 里 —— 换台机器同一个 "15/0" 就含未验证项（与已修的"skip 计入 passed"同族）。
function Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host "[*] $Name"
    $script:stepCode = 0
    & $Body
    if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { $script:stepCode = $LASTEXITCODE }
    $skipped = ($script:stepCode -eq 77)
    if ($skipped) { $script:stepCode = 0 }
    $script:results += [pscustomobject]@{ Name = $Name; Exit = $script:stepCode; Skipped = $skipped }
    if ($skipped) { Write-Host "[SKIP] $Name -- NOT verified by this run" }
    elseif ($script:stepCode -ne 0) { Write-Host "[!] $Name FAILED (exit $script:stepCode)" }
    $global:LASTEXITCODE = 0
}

Step "gofmt -l ."        { $out = (gofmt -l . | Out-String).Trim(); if ($out -ne "") { Write-Host $out; $script:stepCode = 1 } }
Step "go vet ./..."      { go vet ./... }
# 32-bit (i686/PE32) path. Before this gate existed, NOTHING built a 32-bit blob or packed a
# 32-bit exe, which is how the i686 thunk defects (32-bit stores leaving the high half of each
# u64 ctx slot as stack garbage, and a simulated ESP 4 bytes too low) stayed invisible so long.
# It SKIPs with a loud line (exit 0) when the i686 toolchain is absent; set VMP_REQUIRE_I686=1
# on any runner that is supposed to have it. Runs before go test so the artifacts it leaves
# behind cannot confuse the C probes that go test uses.
Step "32-bit payload (i686 blob + PE32 pack vs native)" { & powershell -NoProfile -File (Join-Path $PSScriptRoot "e2e_32bit.ps1") }
# The Linux halves (ELF payload on amd64 + arm64 under qemu-user) used to be CI-only. A WSL
# distro with gcc + the aarch64 cross toolchain + qemu-user runs EXACTLY the commands those
# two CI jobs run, so this brings them into the local loop (STATUS #583). It syncs the tree
# into the WSL filesystem first, so the Linux build/ cannot collide with the Windows one.
# SKIPs loudly (exit 0) when WSL is absent -- set VMP_REQUIRE_WSL=1 to make that a hard failure.
Step "linux payloads via WSL (CI's linux-amd64/arm64 command set)" {
    if ($NoWsl) { Write-Host "[SKIP] skipped with -NoWsl"; $script:stepCode = 77 }
    else { & powershell -NoProfile -File (Join-Path $PSScriptRoot "wsl_linux.ps1") }
}
Step "go test ./..."     { go test ./... }
# Blob must build: the Go gates never compile C, which once let a broken source stay green.
# vmpbuild wants -src relative to the repo root, so run it from there.
Step "vmpbuild (blob builds)" {
    Push-Location (Join-Path $PSScriptRoot "..")
    & ".\build\vmpbuild.exe" -src "stub/win/x64" -out "build/gates_blob.bin" -manifest "build/gates_blob.json" -entry vm_entry 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "[!] blob build failed (stub/win/x64 has compile errors)"; $script:stepCode = 1 }
    & ".\build\vmpbuild.exe" -src "stub/win/x64" -out "build/gates_blob_rel.bin" -manifest "build/gates_blob_rel.json" -entry vm_entry -release 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "[!] release blob build failed"; $script:stepCode = 1 }
    # Blob-level KDF KAT: load the BUILT blob into executable memory and call the functions
    # inside it. The single-file KAT (stub/win/x64/kdf_kat.c) cannot see "layout inside the
    # merged blob" defects -- once a string in vm_kdf.c was resolved to the START of .rdata
    # instead of its real offset, so the salt was wrong. Only calling the blob's own code
    # catches that class of bug.
    & gcc -O2 -o "build\kdf_blob_kat.exe" stub\win\x64\kdf_blob_kat.c 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "[!] kdf_blob_kat.exe build failed"; $script:stepCode = 1 }
    else {
        foreach ($pair in @(@("build\gates_blob.json", "build\gates_blob.bin"), @("build\gates_blob_rel.json", "build\gates_blob_rel.bin"))) {
            $mj = Get-Content $pair[0] -Raw | ConvertFrom-Json
            & ".\build\kdf_blob_kat.exe" $pair[1] $mj.symbols.vm_kdf_salt $mj.symbols.vm_kdf_entry $mj.symbols.vm_patch_mac
            if ($LASTEXITCODE -ne 0) { Write-Host ("[!] blob KDF KAT failed for " + $pair[1] + " (vmpbuild relocation/layout bug?)"); $script:stepCode = 1 }
        }
    }
    Pop-Location
}
Step "e2e.ps1 (x86-64)"  { & powershell -NoProfile -File (Join-Path $PSScriptRoot "e2e.ps1") }
# The packed image must not carry the native machine code of a protected function:
# not on disk, and not in memory either (PE maps the file, so a file-level leak IS a
# memory-level leak). Uses the artifacts e2e.ps1 just left behind.
Step "residue probe (no native code in image/memory)" {
    python tools/residue_probe.py --pe build/target.exe --report build/target_vmp.json --run "build/target_vmp.exe bench check_key 10000000000" --func check_key,sum_to --delay 1.5 --fail-on-native
    if ($LASTEXITCODE -ne 0) { Write-Host "[!] native residue found in image/memory (is -wipe off?)"; $script:stepCode = 1 }
}
# The bytecode must stay ENCRYPTED in memory too: the interpreter streams the ChaCha20
# keystream and XORs one byte at a time, so no plaintext buffer ever exists. We use
# vmpack's own -dumpbytecode output as the "must not appear" pattern.
Step "bytecode plaintext scan (no plaintext in memory)" {
    if (Test-Path "build\_bcdump") { Remove-Item -Recurse -Force "build\_bcdump" }
    & ".\build\vmpack.exe" -exe "build\target.exe" -func check_key -out "build\target_bcscan.exe" -blob "build\vm_interp.bin" -manifest "build\vm_interp.json" -report "build\target_bcscan.json" -dumpbytecode "build\_bcdump" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "[!] packing for the bytecode scan failed"; $script:stepCode = 1 }
    else {
        python tools/residue_probe.py --pe build/target.exe --report build/target_bcscan.json --run "build/target_bcscan.exe bench check_key 10000000000" --func check_key --bytecode-dir build/_bcdump --delay 1.5 --fail-on-bytecode
        if ($LASTEXITCODE -ne 0) { Write-Host "[!] plaintext bytecode found in memory (streaming fetch broken?)"; $script:stepCode = 1 }
    }
}
# The whole-image encryption (-enc-image, default on for x86-64 EXEs) must leave NOTHING of the
# original .text readable in the packed file. e2e.ps1 packs with that default, so its artifact is
# the sample under test. All-zero chunks are excluded (plain padding matches padding).
Step "image residue (original .text not readable in the packed file)" {
    python tools/image_residue.py --src build/target.exe --packed build/target_vmp.exe --section .text,.rdata,.data
    if ($LASTEXITCODE -ne 0) { Write-Host "[!] original code still readable in the packed image"; $script:stepCode = 1 }
}
# The packed image must keep the blob's internal layout, because the interpreter derives every
# address from "payload base + blob offset"; and every preferred-base absolute VA the packer
# writes into the payload must be registered in .reloc, or the product breaks as soon as ASLR
# actually moves it (STATUS #507/#508/#520; #580 reduced the win/arm64 failure to exactly this
# "section mapping vs blob-internal address derivation" class). check_symmap.py re-derives the
# mapping from the PRODUCT's own section table and self-calibrates on mutated copies, so this
# gate cannot silently turn into a no-op. It runs on the artifacts e2e.ps1 just built.
# The packed image must keep the blob's internal layout, because the interpreter derives every
# address from "payload base + blob offset"; and every preferred-base absolute VA the packer writes
# into the payload must be registered in .reloc, or the product breaks as soon as ASLR actually
# moves it (STATUS #507/#508/#520; #580 reduced the win/arm64 failure to exactly this "section
# mapping vs blob-internal address derivation" class). The check self-calibrates on mutated copies,
# so it cannot silently degrade into a no-op. Both steps live in tools/check_layout.ps1 so CI runs
# the very same code as this local run.
Step "packed layout (symbol mapping / payload identity / reloc coverage)" {
    & powershell -NoProfile -File (Join-Path $PSScriptRoot "check_layout.ps1") -Layout
}
# The diagnostic scaffolding (markers + VEH post-mortem) used to be compiled into every "external
# key + Windows + ARM64" blob unconditionally -- which contradicted -release ("drop all
# diagnostics") and cost ~8 KB. It is opt-in now (-diag), and its file sink goes through ntdll only:
# kernel32's CreateFileA/WriteFile can be FORWARDER exports, and calling a forwarder's RVA as code
# is exactly how #385 died on the CI runner. -diag also builds the scaffolding for win/x64, so this
# gate compiles AND runs it instead of leaving code that nothing ever exercises.
Step "diagnostics are opt-in and land through ntdll" {
    & powershell -NoProfile -File (Join-Path $PSScriptRoot "check_layout.ps1") -Diag
}
Step "e2e_dll.ps1"       { & powershell -NoProfile -File (Join-Path $PSScriptRoot "e2e_dll.ps1") }
Step "guest differential (arm64 + x86-32)" { & powershell -NoProfile -File (Join-Path $PSScriptRoot "e2e_arm64guest.ps1") }
Step "linux payload (executed on Windows)" { & powershell -NoProfile -File (Join-Path $PSScriptRoot "verify_linux_payload.ps1") }

Write-Host ""
Write-Host "==== local gates ===="
foreach ($r in $script:results) {
    $tag = if ($r.Skipped) { "[SKIP]" } elseif ($r.Exit -eq 0) { "[OK  ]" } else { "[FAIL]" }
    Write-Host ("{0} {1} (exit {2})" -f $tag, $r.Name, $r.Exit)
}
$bad = @($script:results | Where-Object { $_.Exit -ne 0 }).Count
$skipN = @($script:results | Where-Object { $_.Skipped }).Count
Write-Host ("total {0} gates, {1} failed, {2} skipped" -f $script:results.Count, $bad, $skipN)
if ($skipN -gt 0) { Write-Host ("[!] " + $skipN + " gate(s) were SKIPPED: those steps were NOT verified by this run (see the [SKIP] lines above)") }
if ($bad -gt 0) { exit 1 }
exit 0
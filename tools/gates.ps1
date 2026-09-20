# gates.ps1 - run every local (Windows/amd64) gate in one shot.
#
#   powershell -NoProfile -File tools/gates.ps1
#
# NOTE: this file is deliberately ASCII-only. Windows PowerShell 5.1 reads .ps1 as ANSI
# unless it has a BOM, so non-ASCII bytes (e.g. Chinese comments) can swallow a following
# line and turn a Step call into part of a comment -- a gate that silently never runs.
# That is exactly what happened here before (the linux-payload step disappeared).
Set-Location (Join-Path $PSScriptRoot "..")
$script:results = @()

function Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host "[*] $Name"
    $script:stepCode = 0
    & $Body
    if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { $script:stepCode = $LASTEXITCODE }
    $script:results += [pscustomobject]@{ Name = $Name; Exit = $script:stepCode }
    if ($script:stepCode -ne 0) { Write-Host "[!] $Name FAILED (exit $script:stepCode)" }
    $global:LASTEXITCODE = 0
}

Step "gofmt -l ."        { $out = (gofmt -l . | Out-String).Trim(); if ($out -ne "") { Write-Host $out; $script:stepCode = 1 } }
Step "go vet ./..."      { go vet ./... }
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
Step "e2e_dll.ps1"       { & powershell -NoProfile -File (Join-Path $PSScriptRoot "e2e_dll.ps1") }
Step "arm64-guest differential" { & powershell -NoProfile -File (Join-Path $PSScriptRoot "e2e_arm64guest.ps1") }
Step "linux payload (executed on Windows)" { & powershell -NoProfile -File (Join-Path $PSScriptRoot "verify_linux_payload.ps1") }

Write-Host ""
Write-Host "==== local gates ===="
foreach ($r in $script:results) {
    $tag = if ($r.Exit -eq 0) { "[OK  ]" } else { "[FAIL]" }
    Write-Host ("{0} {1} (exit {2})" -f $tag, $r.Name, $r.Exit)
}
$bad = @($script:results | Where-Object { $_.Exit -ne 0 }).Count
Write-Host ("total {0} gates, {1} failed" -f $script:results.Count, $bad)
if ($bad -gt 0) { exit 1 }
exit 0
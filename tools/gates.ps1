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
    Pop-Location
}
Step "e2e.ps1 (x86-64)"  { & powershell -NoProfile -File (Join-Path $PSScriptRoot "e2e.ps1") }
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
# preflight.ps1 - fast sanity checks before any real work (AGENTS.md acceptance item 1).
#
# Contract: prints "[+] preflight: OK" and exits 0 when everything checks out;
# otherwise prints one "[!] ..." line per problem and exits 1.
#
# ASCII-only output on purpose: this runs on Windows CI runners whose console code page
# is not UTF-8 (see AGENTS.md).
#
# This is NOT a replacement for tools/gates.ps1 (the 11 real gates) - it is the cheap
# subset you can run in a few seconds before touching anything.
param(
  [switch]$Quiet
)
$ErrorActionPreference = "Continue"
Set-Location (Join-Path $PSScriptRoot "..")
$problems = New-Object System.Collections.ArrayList

function Step([string]$name, [scriptblock]$body) {
  if (-not $Quiet) { Write-Host ("[*] " + $name) }
  try {
    $ok = & $body
    if (-not $ok) { [void]$problems.Add($name) }
  } catch {
    if (-not $Quiet) { Write-Host ("    " + $_.Exception.Message) }
    [void]$problems.Add($name)
  }
}

# 1) formatting / vet / build
Step "gofmt -l . is empty" {
  $out = (& gofmt -l . 2>&1 | Out-String).Trim()
  if ($out -ne "") { Write-Host ("    unformatted: " + ($out -replace "`r?`n", " ")); return $false }
  return $true
}
Step "go vet ./... " {
  $out = (& go vet ./... 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) { Write-Host ("    " + ($out -split "`r?`n" | Select-Object -First 3)); return $false }
  return $true
}
Step "go build ./..." {
  $out = (& go build ./... 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) { Write-Host ("    " + ($out -split "`r?`n" | Select-Object -First 3)); return $false }
  return $true
}

# 2) the tools we are about to drive must exist
Step "tool binaries and scripts exist" {
  $need = @("build/vmpack.exe", "build/vmpbuild.exe", "build/vmpepoch.exe",
            "tools/gates.ps1", "tools/e2e.ps1", "tools/diffcheck.ps1")
  $missing = @($need | Where-Object { -not (Test-Path $_) })
  if ($missing.Count -gt 0) { Write-Host ("    missing: " + ($missing -join ", ")); return $false }
  return $true
}

# 3) the stale-artifact trap that has bitten this repo twice:
#    build/runbc*.exe are prebuilt C interpreters; if a header changed after they were built,
#    go test fails with a confusing 0xC0000005 instead of telling you to rebuild them.
Step "C probe binaries are newer than stub headers" {
  $headers = @(Get-ChildItem "stub" -Recurse -Include *.h,*.c -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 1)
  if ($headers.Count -eq 0) { return $true }
  $newest = $headers[0].LastWriteTime
  $probes = @("build/runbc.exe", "build/runbc_a64g.exe")
  $stale = @()
  foreach ($p in $probes) {
    if (Test-Path $p) {
      if ((Get-Item $p).LastWriteTime -lt $newest) { $stale += $p }
    }
  }
  if ($stale.Count -gt 0) {
    Write-Host ("    stale: " + ($stale -join ", ") + " (rebuild: gcc -O2 -I stub/win/x64 -o build/runbc.exe stub/win/x64/blob_probe.c)")
    return $false
  }
  return $true
}

# 4) the blob the packer will embed must actually build
Step "blob builds (vmpbuild)" {
  $out = (& .\build\vmpbuild.exe -src "stub/win/x64" -out build/preflight_blob.bin -manifest build/preflight_blob.json -entry vm_entry 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) { Write-Host ("    " + ($out -split "`r?`n" | Select-Object -First 3)); return $false }
  if (-not (Test-Path "build/preflight_blob.bin")) { Write-Host "    no blob produced"; return $false }
  Remove-Item build/preflight_blob.bin, build/preflight_blob.json -ErrorAction SilentlyContinue
  return $true
}

if ($problems.Count -gt 0) {
  Write-Host ""
  foreach ($p in $problems) { Write-Host ("[!] " + $p) }
  Write-Host ("[!] preflight: " + $problems.Count + " problem(s)")
  exit 1
}
Write-Host "[+] preflight: OK"
exit 0

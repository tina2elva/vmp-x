# preflight.ps1 - fast sanity checks before any real work (AGENTS.md acceptance item 1).
#
# Contract: prints "[+] preflight: OK" and exits 0 when everything checks out;
# otherwise prints one "[!] ..." line per problem and exits 1.
#
# ASCII-only output on purpose: this runs on Windows CI runners whose console code page
# is not UTF-8 (see AGENTS.md).
#
# This is NOT a replacement for tools/gates.ps1 (the 15 real gates) - it is the cheap
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

# 5) 含非 ASCII 的 .ps1 必须带 UTF-8 BOM：PowerShell 5.1 在**没有 BOM** 时按 ANSI 读文件，
#    中文注释/字符串会变成乱码，**而且可能直接造成语法错误**。本仓库真踩过：用编辑工具改 e2e.ps1 时
#    把开头的 BOM 吃掉了，[]::ParseFile 当场报 10 个解析错误（错误位置还指向无关的行，很难查）。
Step "ps1 encoding (BOM)" {
  $bad = @()
  foreach ($f in Get-ChildItem -Path tools -Filter *.ps1 -Recurse) {
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $nonAscii = $false
    for ($i = 0; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -gt 0x7F) { $nonAscii = $true; break } }
    if ($nonAscii -and -not $hasBom) { $bad += $f.Name }
  }
  if ($bad.Count -gt 0) {
    Write-Host ("    no UTF-8 BOM (PowerShell 5.1 reads these as ANSI -> mojibake/syntax errors): " + ($bad -join ", "))
    return $false
  }
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

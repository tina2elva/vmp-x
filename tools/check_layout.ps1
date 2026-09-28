# check_layout.ps1 - artifact-level gates shared by tools/gates.ps1 and CI.
#
#   -Layout : the packed image must preserve the blob's internal layout, and every
#             preferred-base absolute VA it stores must be registered in .reloc.
#             (tools/check_symmap.py, which self-calibrates on mutated copies, so it
#              cannot silently degrade into a no-op.)
#   -Diag   : the diagnostic scaffolding must be OPT-IN (no markers in a default blob),
#             must not resolve kernel32's forwarder-prone file APIs, and -- when switched
#             on -- must actually write vmpdiag.txt through ntdll.
#
# Both gates are about the PRODUCT, not about tests: they read the artifact a user would
# ship. Kept in their own script so CI runs exactly the same code as the local gate run.
#
# ASCII-only output on purpose (Windows runners are not UTF-8; see AGENTS.md).
param(
  [switch]$Layout,
  [switch]$Diag
)
$ErrorActionPreference = "Continue"
Set-Location (Join-Path $PSScriptRoot "..")
$script:bad = 0
function Fail([string]$m) { Write-Host ("[!] " + $m); $script:bad++ }

function BlobHas([string]$path, [string]$needle) {
  # calibrate-by-construction: the needle must be non-empty, otherwise "not found" is meaningless
  if ([string]::IsNullOrEmpty($needle)) { throw "BlobHas: empty needle" }
  $d = [System.IO.File]::ReadAllBytes((Resolve-Path $path).Path)
  $n = [System.Text.Encoding]::ASCII.GetBytes($needle)
  for ($i = 0; $i -le $d.Length - $n.Length; $i++) {
    if ($d[$i] -ne $n[0]) { continue }
    $hit = $true
    for ($j = 1; $j -lt $n.Length; $j++) { if ($d[$i + $j] -ne $n[$j]) { $hit = $false; break } }
    if ($hit) { return $true }
  }
  return $false
}

if (-not $Layout -and -not $Diag) { $Layout = $true; $Diag = $true }

if ($Layout) {
  # Needs the artifacts e2e.ps1 leaves behind: build/target.exe + build/vm_interp.{bin,json}
  & ".\build\vmpack.exe" -exe "build\target.exe" -func check_key -func sum_to -blob "build\vm_interp.bin" -manifest "build\vm_interp.json" -out "build\symmap_vmp.exe" -report "build\symmap_vmp.json" 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "packing for the layout gate failed" }
  else {
    python tools/check_symmap.py --packed build/symmap_vmp.exe --manifest build/vm_interp.json --blob build/vm_interp.bin --report build/symmap_vmp.json --require-aslr --selftest
    if ($LASTEXITCODE -ne 0) { Fail "packed layout is inconsistent (details in the check_symmap output above)" }
    else { Write-Host "[OK  ] layout: symbol mapping, payload identity and reloc coverage consistent" }
  }
}

if ($Diag) {
  # (1) default: no diagnostic scaffolding in the blob at all
  & ".\build\vmpbuild.exe" -src "stub/win/x64" -out "build\diag_off.bin" -manifest "build\diag_off.json" -entry vm_entry -key-external 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "default (no -diag) blob build failed" }
  elseif (BlobHas "build\diag_off.bin" "veh:install-begin") {
    Fail "diagnostics are compiled into the blob by DEFAULT (they must be opt-in via -diag)"
  } else { Write-Host "[OK  ] diag: default blob carries no diagnostic scaffolding" }

  # (2) -diag: compiles, and the sink must not use kernel32's forwarder-prone file APIs
  & ".\build\vmpbuild.exe" -src "stub/win/x64" -out "build\diag_on.bin" -manifest "build\diag_on.json" -entry vm_entry -key-external -diag 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "-diag blob build failed (the scaffolding does not compile)" }
  elseif (-not (BlobHas "build\diag_on.bin" "veh:install-begin")) { Fail "-diag did not compile the diagnostics in" }
  elseif (BlobHas "build\diag_on.bin" "CreateFileA") { Fail "the diagnostic sink still resolves a kernel32 (forwarder-prone) API" }
  elseif (-not (BlobHas "build\diag_on.bin" "NtWriteFile")) { Fail "the diagnostic sink does not go through ntdll" }
  else {
    Write-Host "[OK  ] diag: -diag compiles the scaffolding in and the sink is ntdll-only"
    & ".\build\vmpack.exe" -exe "build\target.exe" -func check_key -func sum_to -blob "build\diag_on.bin" -manifest "build\diag_on.json" -out "build\diag_prod.exe" -report "build\diag_prod.json" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "packing the -diag product failed" }
    else {
      # calibrate the needle first (AGENTS.md): a wrong/empty key must be loud, not a silent pass
      $raw = Get-Content "build\diag_on.json" -Raw
      $hex = ""
      if ($raw -match '"key"\s*:\s*"([0-9a-fA-F]{64})"') { $hex = $Matches[1] }
      if ($hex.Length -ne 64) { Fail ("manifest key hex is not 64 chars (got " + $hex.Length + ")") }
      else {
        Remove-Item -Recurse -Force "build\diagrun" -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force "build\diagrun" | Out-Null
        $env:VMPX_KEY = $hex
        Push-Location "build\diagrun"
        & "..\..\build\diag_prod.exe" check_key 10 | Out-Null
        $rc = $LASTEXITCODE
        Pop-Location
        $env:VMPX_KEY = $null
        if ($rc -ne 0) { Fail ("the -diag product did not run (rc=" + $rc + ")") }
        elseif (-not (Test-Path "build\diagrun\vmpdiag.txt")) { Fail "-diag product wrote no vmpdiag.txt (ntdll sink broken?)" }
        elseif (-not ((Get-Content "build\diagrun\vmpdiag.txt" -Raw) -match "1b:enter")) { Fail "vmpdiag.txt has no stage markers" }
        else { Write-Host "[OK  ] diag: the -diag product wrote vmpdiag.txt through ntdll" }
      }
    }
  }
}

if ($script:bad -gt 0) { Write-Host ("[!] check_layout: " + $script:bad + " problem(s)"); exit 1 }
exit 0

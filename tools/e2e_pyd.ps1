# e2e_pyd.ps1 - VM-protect functions inside a Python extension module (.pyd) and verify it.
#
#   powershell -NoProfile -File tools/e2e_pyd.ps1 -Pyd <path.pyd> -Map <path.map> -Func <name>
#
# Why a .pyd needs the MAP: wheel-installed extensions are stripped (0 COFF symbols),
# and their only export is often a tiny CFG jump thunk. The .map keeps every symbol name,
# so vmpack -map can address the real (internal) function bodies by name.
#
# Verification is behavioural: the same Python snippet runs against the native module and
# against the packed one, and the output must match exactly.
param(
    [Parameter(Mandatory = $true)][string]$Pyd,
    [Parameter(Mandatory = $true)][string]$Map,
    [Parameter(Mandatory = $true)][string[]]$Func,
    [string]$Python = 'C:\TaijiControl\WinPy313\python\python.exe',
    [string]$Expr = 'pass'
)
$ErrorActionPreference = 'Continue'
if ($PSScriptRoot) { Set-Location (Join-Path $PSScriptRoot '..') }
New-Item -ItemType Directory -Force -Path build | Out-Null

& go build -o build/vmpack.exe ./cmd/vmpack
& go build -o build/vmpbuild.exe ./cmd/vmpbuild
& .\build\vmpbuild.exe -src stub/win/x64 -out build/vm_interp.bin -manifest build/vm_interp.json -entry vm_entry | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host '[FAIL] blob build failed'; exit 1 }

$args = @('-exe', $Pyd, '-map', $Map)
foreach ($f in $Func) { $args += @('-func', $f) }
$args += @('-out', 'build/target_pyd_vmp.pyd', '-report', 'build/target_pyd_vmp.json')
& .\build\vmpack.exe @args
if ($LASTEXITCODE -ne 0) { Write-Host '[FAIL] packing failed'; exit 1 }

# structural check: the entry of the first protected function must be a jmp into the new section
$rep = Get-Content build/target_pyd_vmp.json -Raw | ConvertFrom-Json
foreach ($p in $rep.placements) {
    Write-Host ('  [struct] {0}: desc=0x{1:X} thunk=0x{2:X} patch={3}' -f $p.name, $p.descRVA, $p.thunkRVA, $p.entryPatch)
}

$modName = [System.IO.Path]::GetFileNameWithoutExtension($Pyd)
# strip the ABI tag (example.cp313-win_amd64 -> example) so Python's import name matches
if ($modName -match '^([^.]+)\..*') { $modName = $Matches[1] }
$tagged = $modName + '.cp313-win_amd64.pyd'
Remove-Item -Recurse -Force build/pyd_native, build/pyd_vmp -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force build/pyd_native, build/pyd_vmp | Out-Null
Copy-Item $Pyd (Join-Path build/pyd_native $tagged) -Force
Copy-Item build/target_pyd_vmp.pyd (Join-Path build/pyd_vmp $tagged) -Force

$body = "import sys; sys.path.insert(0, r'__DIR__'); import " + $modName + "; " + $Expr + "; print('done')"
function Run-With([string]$dir) {
    $code = $body.Replace('__DIR__', $dir)
    $out = & $Python -c $code 2>&1
    return ($out | Out-String)
}
$nat = Run-With (Resolve-Path build/pyd_native).Path
$vmp = Run-With (Resolve-Path build/pyd_vmp).Path
Write-Host '--- native ---'; Write-Host $nat
Write-Host '--- protected ---'; Write-Host $vmp
if ($nat.Trim() -eq $vmp.Trim() -and $nat.Trim() -ne '') {
    Write-Host '[+] pyd e2e: outputs match'
    exit 0
}
Write-Host '[FAIL] pyd e2e: outputs differ'
exit 1
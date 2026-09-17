# difftest.ps1 - Differential test: same function, native execution vs VM bytecode execution.
#
# Steps:
#   1. build the target program, the lifter, the blob builder and the blob runner
#   2. for each (function, input) pair, compare the native result with the VM result
#
# Usage: pwsh -File tools/difftest.ps1

$ErrorActionPreference = "Continue"
if ($PSScriptRoot) { Set-Location (Join-Path $PSScriptRoot "..") }
New-Item -ItemType Directory -Force -Path build | Out-Null

Write-Host "[*] building target and tools..."
& gcc -O2 -o build/target.exe testdata/target.c
& go build -o build/vmp-lift.exe ./cmd/lift
& go build -o build/vmpbuild.exe ./cmd/vmpbuild
& gcc -O2 -Wall -I stub/win/x64 -o build/runbc.exe stub/win/x64/blob_probe.c
& .\build\vmpbuild.exe -src stub\win\x64 -out build\vm_interp.bin -manifest build\vm_interp.json -entry vm_run | Out-Null

$manifest = Get-Content build/vm_interp.json | ConvertFrom-Json
$entryOff = $manifest.entryOff
Write-Host ("[*] blob: {0} bytes, vm_run @ +0x{1:X}" -f $manifest.blobSize, $entryOff)

$cases = @(
    @{ func = "check_key"; args = @(0, 1, 10, 12345, 255, 1000000) },
    @{ func = "sum_to";    args = @(0, 1, 2, 10, 100, 1000, 9999) }
)

$pass = 0
$fail = 0
foreach ($c in $cases) {
    $vmb = "build/$($c.func).vmb"
    & .\build\vmp-lift.exe -exe build\target.exe -func $c.func -out $vmb
    foreach ($a in $c.args) {
        $native = (& .\build\target.exe $c.func $a 2>&1 | Out-String).Trim()
        $vmOut = (& .\build\runbc.exe build\vm_interp.bin $entryOff $vmb $a 2>&1 | Out-String).Trim()
        $vmRax = "?"
        if ($vmOut -match "rax=(\d+)") { $vmRax = $Matches[1] }
        $ok = ($native -eq $vmRax)
        if ($ok) { $pass++ } else { $fail++ }
        $tag = if ($ok) { "OK  " } else { "FAIL" }
        Write-Host ("  [{0}] {1}({2}): native={3} vm={4}" -f $tag, $c.func, $a, $native, $vmRax)
    }
}

Write-Host ""
Write-Host ("differential test: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -ne 0) { exit 1 }

# e2e_dll.ps1 - protect a Windows DLL and verify it through a host process.
#
# Difference from an EXE: a DLL has no entry point, but the injection is identical
# (add the payload section, patch the exported function entries with a thunk).
# The host is a separate process that LoadLibrary()s the DLL and calls exports.

$ErrorActionPreference = "Continue"
if ($PSScriptRoot) { Set-Location (Join-Path $PSScriptRoot "..") }
New-Item -ItemType Directory -Force -Path build | Out-Null

& go build -o build/vmpack.exe ./cmd/vmpack
& go build -o build/vmpbuild.exe ./cmd/vmpbuild
& gcc -O2 -shared -o build/testlib.dll testdata/dll.c
& gcc -O2 -o build/dlhost.exe testdata/dlhost.c
& .\build\vmpbuild.exe -src stub/win/x64 -out build/vm_interp.bin -manifest build/vm_interp.json -entry vm_entry | Out-Null

& .\build\vmpack.exe -exe build/testlib.dll -func dll_check_key -func dll_sum_to -func dll_mix -out build/testlib_vmp.dll -report build/testlib_vmp.json | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "[FAIL] packing the DLL failed"; exit 1 }

$pass = 0; $fail = 0
$cases = @(
    @{ sel = "check_key"; args = @("0", "10", "12345", "255", "1000000", "18446744073709551615") },
    @{ sel = "sum_to";    args = @("0", "1", "10", "100", "1000") },
    @{ sel = "mix";       args = @("7", "9", "12345", "6789", "-5", "3") }
)
foreach ($c in $cases) {
    $n = & .\build\dlhost.exe build/testlib.dll $c.sel @($c.args)
    $v = & .\build\dlhost.exe build/testlib_vmp.dll $c.sel @($c.args)
    $ns = ($n -join ","); $vs = ($v -join ",")
    if ($ns -eq $vs -and $ns -ne "") { $pass++ } else { $fail++; Write-Host "  [FAIL] $($c.sel): native=$ns protected=$vs" }
    Write-Host ("  [{0}] {1}({2}) -> {3}" -f $(if ($ns -eq $vs) { "OK  " } else { "FAIL" }), $c.sel, ($c.args -join " "), $ns)
}
Write-Host "dll e2e: $pass passed, $fail failed"
if ($fail -ne 0) { exit 1 }

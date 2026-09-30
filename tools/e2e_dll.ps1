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

# Reads a child process exit code + captured stdout/stderr (a hard gate kills the *host*,
# so we need the code, not $LASTEXITCODE which is signed int32 here).
function Get-ExitCode([string]$exe, [string[]]$a) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Resolve-Path $exe).Path
    $psi.Arguments = ($a -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    return @{ Code = $p.ExitCode; Out = $out; Err = $err }
}

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
# ---- 1b: external master key + DLL (the combination registered as missing in STATUS #385) ----
# The runtime must look for **<the DLL's own path>.vmpkey**. The old code used
# PEB->ProcessParameters->ImagePathName, which inside a DLL is the **host EXE** path, so a key file
# placed next to the DLL was never found (the DLL always took the hard gate). The host here is
# dlhost.exe, so this case can only pass if the "our own module" lookup works -- it is the
# acceptance for that change.
& .\build\vmpbuild.exe -src stub/win/x64 -out build\dll_ext_blob.bin -manifest build\dll_ext_blob.json -entry vm_entry -key-external -key-out build\dll_ext_key.vmpkey | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "[FAIL] vmpbuild -key-external (dll) failed"; exit 1 }
& .\build\vmpack.exe -exe build/testlib.dll -func dll_check_key -func dll_sum_to -func dll_mix -blob build\dll_ext_blob.bin -manifest build\dll_ext_blob.json -out build/testlib_ext.dll -report build/testlib_ext_vmp.json | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "[FAIL] packing the external-key DLL failed"; exit 1 }
$extDllHex = ""
if ((Get-Content build\dll_ext_blob.json -Raw) -match '"key"\s*:\s*"([0-9a-fA-F]{64})"') { $extDllHex = $Matches[1] }
if ($extDllHex.Length -ne 64) { Write-Host "[FAIL] the external DLL manifest carries no 64-hex key"; exit 1 }
$keyBeside = Join-Path (Get-Location) "build/testlib_ext.dll.vmpkey"

# (a) no key file => hard gate: the *host* process dies with 0xC0DE0007 and prints nothing
Remove-Item Env:\VMPX_KEY -ErrorAction SilentlyContinue
Remove-Item $keyBeside -ErrorAction SilentlyContinue
$rGate = Get-ExitCode "build/dlhost.exe" @("build/testlib_ext.dll", "check_key", "10")
if ((($rGate.Code -band 0xFFFFFFFF) -eq 0xC0DE0007) -and ($rGate.Out -eq "")) {
    $pass++; Write-Host "  [OK  ] 1b/dll: no key -> rc=0xC0DE0007, no output"
} else {
    $fail++; Write-Host ("  [FAIL] 1b/dll: no key rc=0x{0:X8} out=[{1}] (expect 0xC0DE0007)" -f ($rGate.Code -band 0xFFFFFFFF), $rGate.Out.Trim())
}

# (b) key file **next to the DLL** (name = DLL full name + .vmpkey; the deployment default form)
[System.IO.File]::WriteAllText($keyBeside, $extDllHex.ToUpper())
foreach ($c in $cases) {
    $n = & .\build\dlhost.exe build/testlib.dll $c.sel @($c.args)
    $e = & .\build\dlhost.exe build/testlib_ext.dll $c.sel @($c.args)
    $ns = ($n -join ","); $es = ($e -join ",")
    if ($ns -eq $es -and $ns -ne "") { $pass++; Write-Host "  [OK  ] 1b/dll: $($c.sel) -> $ns" }
    else { $fail++; Write-Host "  [FAIL] 1b/dll: $($c.sel) native=$ns ext=$es" }
}
Remove-Item $keyBeside -ErrorAction SilentlyContinue

Write-Host "dll e2e: $pass passed, $fail failed"
if ($fail -ne 0) { exit 1 }

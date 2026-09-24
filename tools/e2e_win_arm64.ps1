# e2e_win_arm64.ps1 - 1b external-master-key acceptance for Windows/ARM64, run NATIVELY.
#
# This is the only environment that can execute the Windows/ARM64 blob: the other two arm64
# CI jobs run on x86-64 hosts and only execute arm64 GUEST bytecode, while the blob itself is
# ARM64 machine code. So this script is the runtime proof for platform (c).
#
# ASCII only: PS 5.1 reads .ps1 as ANSI, and a non-ASCII byte swallows the following line.

$ErrorActionPreference = "Continue"

# File-based trace: CI kept showing NO output from this script's later stages even though the
# deployed copy demonstrably contained the lines (see STATUS #504). Writing to a FILE is immune to
# whatever swallows the output stream, and the CI step prints this file no matter how we exit.
$PROBE = "build/probe.txt"
Remove-Item $PROBE -ErrorAction SilentlyContinue
function Mark([string]$m) { Add-Content -Path $PROBE -Value ($m) -ErrorAction SilentlyContinue }
Mark "stage:start"
if ($PSScriptRoot) { Set-Location (Join-Path $PSScriptRoot "..") }
New-Item -ItemType Directory -Force -Path build | Out-Null

# ---- locate clang (LLVM) ----
$clang = (Get-Command clang -ErrorAction SilentlyContinue).Source
if (-not $clang) {
    foreach ($c in @("C:\Program Files\LLVM\bin\clang.exe", "C:\Program Files (x86)\LLVM\bin\clang.exe")) {
        if (Test-Path $c) { $clang = $c; break }
    }
}
if (-not $clang) { Write-Host "[!] clang not found (install LLVM first)"; exit 1 }
$objdump = (Get-Command llvm-objdump -ErrorAction SilentlyContinue).Source
if (-not $objdump) { $objdump = "llvm-objdump" }
Write-Host ("[*] clang   : " + $clang)
Write-Host ("[*] objdump : " + $objdump)
Mark ("stage:clang-ok clang=" + $clang)

# IMPORTANT: pass clang exactly the way the (green) windows-arm64-run job does - plain "clang",
# no --target wrapper. On this native ARM64 runner clang already targets Windows/ARM64 with the
# ABI vmpbuild expects; forcing --target=aarch64-w64-windows-gnu produced a blob that crashed on
# entry with 0xC0000005 *before any blob code ran* (and even in non-external mode).
$ccArg = "clang"
$wrap = ""  # kept for reference; not used anymore
$wrap = Join-Path $PWD "build/clang-a64w.cmd"
# Build the wrapper without backtick escapes or embedded quotes - that line used to be
# written as ("@echo off`r`n`"" + $clang + ...) and pwsh rejected it with a ParserError on CI.
$nl = [string][char]13 + [string][char]10
$q = [string][char]34
Set-Content -Path $wrap -Value ("@echo off" + $nl + $q + $clang + $q + " --target=aarch64-w64-windows-gnu %*") -Encoding Ascii

& go build -o build/vmpbuild.exe ./cmd/vmpbuild
& go build -o build/vmpack.exe ./cmd/vmpack
if (-not (Test-Path build/vmpbuild.exe) -or -not (Test-Path build/vmpack.exe)) { Write-Host "[!] go build failed"; exit 1 }

# ---- the freestanding ARM64 PE test target (no Windows SDK needed) ----
Write-Host "[*] building the arm64 PE test target..."
# Arguments go through an array: a bare -Wl,-e,entry argument is a ParserError under pwsh 7
# (the comma is the array operator in argument position). Keep every comma-bearing flag quoted.
$tgtArgs = @(
    "--target=aarch64-w64-windows-gnu", "-O1", "-fno-tree-vectorize", "-nostdlib", "-fuse-ld=lld",
    "-Wl,-e,entry", "-Wl,-subsystem=console", "-o", "build/target_arm64.exe", "testdata/arm64/target_win.c"
)
& $clang @tgtArgs 2>&1 | Select-Object -Last 8
if (-not (Test-Path build/target_arm64.exe)) { Write-Host "[!] arm64 PE target build failed"; exit 1 }

# ---- the Windows/ARM64 blob in EXTERNAL key mode ----
$keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
Remove-Item build/vm_interp_win_arm64_ext.bin, build/vm_interp_win_arm64_ext.json -ErrorAction SilentlyContinue
Write-Host "[*] building the Windows/arm64 external-key blob..."
& .\build\vmpbuild.exe -src stub/win/arm64 -out build/vm_interp_win_arm64_ext.bin -manifest build/vm_interp_win_arm64_ext.json -entry vm_entry -guest arm64 -merge go -cc $ccArg -objdump $objdump -key-external -key-in $keyHex 2>&1 | Select-Object -Last 60
if (-not (Test-Path build/vm_interp_win_arm64_ext.bin)) { Write-Host "[!] Windows/arm64 external blob build FAILED"; exit 1 }

# ---- pack check_key / sum_to ----
Write-Host "[*] packing..."
& .\build\vmpack.exe -exe build/target_arm64.exe -func check_key -func sum_to -blob build/vm_interp_win_arm64_ext.bin -manifest build/vm_interp_win_arm64_ext.json -out build/target_arm64_ext.exe -report build/target_arm64_ext_vmp.json 2>&1 | Select-Object -Last 8
if (-not (Test-Path build/target_arm64_ext.exe)) { Write-Host "[!] packing failed"; exit 1 }

# ---- PROBE: re-run the product the (green) job built earlier in this same job ----
# Discriminates two very different causes for the 0xC0DE0002 seen below:
#   works here  => my construction differs from the green job;
#   fails here  => the failure is order/state dependent, not about how I build.
# Unconditional and dependency-free: an earlier version referenced $natRc (defined later) and was
# guarded by Test-Path, and it produced NO line at all in CI - so make it impossible to miss.
Mark ("stage:ext-packed exists=" + (Test-Path "build/target_arm64_ext.exe"))
$green = Join-Path $PWD "build/target_arm64.vmp"
Mark ("probe:start exists=" + (Test-Path $green))
if (Test-Path $green) {
    # PowerShell refuses to run a .vmp document ("Cannot run a document in the middle of a pipeline",
    # found via the file trace). Start-Process goes through CreateProcess, which runs any PE file.
    $so = Join-Path $PWD "build/probe_green.out"
    $se = Join-Path $PWD "build/probe_green.err"
    Remove-Item $so, $se -ErrorAction SilentlyContinue
    $grc = -999
    try {
        $p = Start-Process -FilePath $green -Wait -PassThru -RedirectStandardOutput $so -RedirectStandardError $se
        $grc = $p.ExitCode
    } catch {
        Mark ("probe:green-product EXCEPTION " + $_.Exception.Message)
    }
    $gout = ""
    if (Test-Path $so) { $gout = (Get-Content $so -Raw) }; if (Test-Path $se) { $gout = $gout + (Get-Content $se -Raw) }
    if ($gout -eq $null) { $gout = "" }
    $gout = $gout.Trim()
    Write-Host ("[*] PROBE green-job product re-run: rc=" + $grc + " out=[" + $gout + "]")
    Mark ("probe:green-product rc=" + $grc + " out=" + $gout)
    # 0xC0DE0002 = vm_img_fail(2) "needs relocation but the table is gone" -> smells like ASLR:
    # the same file succeeded in the previous step of the same job. Run it 10 times and count.
    $hist = @{}
    for ($i = 1; $i -le 10; $i++) {
        $ri = -999
        try {
            $pi = Start-Process -FilePath $green -Wait -PassThru -RedirectStandardOutput $so -RedirectStandardError $se
            $ri = $pi.ExitCode
        } catch { $ri = -998 }
        if ($hist.ContainsKey($ri)) { $hist[$ri]++ } else { $hist[$ri] = 1 }
    }
    $line = "probe:green-product 10runs"
    foreach ($k in $hist.Keys) { $line = $line + " rc=" + $k + "x" + $hist[$k] }
    Mark $line
} else {
    Write-Host "[*] PROBE green-job product not present"
    Mark "probe:green-product MISSING"
}

# ---- CALIBRATION: the same flow, but with a NON-external blob ----
# Without this, "the external build crashes" could just mean "my pack invocation differs from the
# one the (green) windows-arm64-run job uses". AGENTS.md discipline: calibrate the probe first.
Remove-Item build/vm_interp_win_arm64_cal.bin, build/vm_interp_win_arm64_cal.json -ErrorAction SilentlyContinue
& .\build\vmpbuild.exe -src stub/win/arm64 -out build/vm_interp_win_arm64_cal.bin -manifest build/vm_interp_win_arm64_cal.json -entry vm_entry -guest arm64 -merge go -cc $ccArg -objdump $objdump 2>&1 | Select-Object -Last 6
if (-not (Test-Path build/vm_interp_win_arm64_cal.bin)) { Write-Host "[!] CALIBRATION: non-external blob build failed"; exit 1 }
& .\build\vmpack.exe -exe build/target_arm64.exe -func check_key -func sum_to -blob build/vm_interp_win_arm64_cal.bin -manifest build/vm_interp_win_arm64_cal.json -out build/target_arm64_cal.exe -report build/target_arm64_cal_vmp.json 2>&1 | Select-Object -Last 6
if (-not (Test-Path build/target_arm64_cal.exe)) { Write-Host "[!] CALIBRATION: packing failed"; exit 1 }
$calRc = 0; $calOut = (& (Join-Path $PWD "build/target_arm64_cal.exe") 2>&1) -join "|"; $calRc = $LASTEXITCODE
Write-Host ("[*] CALIBRATION (non-external blob): rc=" + $calRc + " out=[" + $calOut + "]  native rc=" + $natRc)
if ($calRc -ne $natRc) { Write-Host "[!] CALIBRATION FAILED: my own default-mode product does not match native => this harness differs from the green job, so any external-mode conclusion is confounded" }
else { Write-Host "[+] CALIBRATION OK: default-mode product built by this harness matches native" }

# ---- three cases: no key / VMPX_KEY env / <product>.vmpkey file ----
$bad = 0
function Fail([string]$m) { Write-Host ("[!] " + $m); $script:bad++ }

& build/target_arm64.exe | Out-Null; $natRc = $LASTEXITCODE
$natOut = (& build/target_arm64.exe 2>&1) -join "|"
Write-Host ("[*] native rc=" + $natRc + " out=" + $natOut)

$pk = Join-Path $PWD "build/target_arm64_ext.exe"
$keyFile = $pk + ".vmpkey"
Remove-Item $keyFile -ErrorAction SilentlyContinue
$env:VMPX_KEY = $null
$o1 = (& $pk 2>&1) -join "|"; $r1 = $LASTEXITCODE
if ($r1 -ne [int]0xC0DE0007) { Fail ("no key: rc=" + $r1 + " expected " + [int]0xC0DE0007 + " out=[" + $o1 + "]") }
else { Write-Host "  [OK  ] 1b: no key -> 0xC0DE0007 (hard gate)" }

$env:VMPX_KEY = $keyHex
$o2 = (& $pk 2>&1) -join "|"; $r2 = $LASTEXITCODE
$env:VMPX_KEY = $null
if ($r2 -ne $natRc -or $o2 -ne $natOut) { Fail ("VMPX_KEY: rc=" + $r2 + " native=" + $natRc + " out=[" + $o2 + "]") }
else { Write-Host "  [OK  ] 1b: VMPX_KEY -> matches native" }

Set-Content -Path $keyFile -Value $keyHex -NoNewline -Encoding Ascii
$o3 = (& $pk 2>&1) -join "|"; $r3 = $LASTEXITCODE
Remove-Item $keyFile -ErrorAction SilentlyContinue
if ($r3 -ne $natRc -or $o3 -ne $natOut) { Fail (".vmpkey file: rc=" + $r3 + " native=" + $natRc + " out=[" + $o3 + "]") }
else { Write-Host "  [OK  ] 1b: .vmpkey file -> matches native" }

if ($bad -eq 0) { Write-Host "[OK] win/arm64 1b external key: 3/3" } else { Write-Host ("[!] win/arm64 1b: " + $bad + " case(s) failed") }
Mark ("stage:done bad=" + $bad + " calRc=" + $calRc)
exit $bad

# e2e_32bit.ps1 - gate for the 32-bit (i686/PE32) path.
#
#   powershell -NoProfile -File tools/e2e_32bit.ps1
#
# Why this gate exists: the i686 entry thunk used to fill vm_ctx_t.regs[] (u64 slots) with
# 32-bit `movl` stores, leaving the upper half of every slot as stale stack garbage. The
# interpreter reads the full u64 (notably the UNSIGNED stack guard), so protected functions
# that touch the stack returned wrong values (rc=99) - and NOTHING in the gate set noticed,
# because no gate ever built a 32-bit blob or packed a 32-bit exe. This gate does exactly
# that: build the i686 blob, pack one function per run, and compare the packed exe exit code
# with the unpacked one (the subject returns small distinct values; see testdata/e2e32.c).
#
# Toolchain: needs i686-w64-mingw32-gcc. It is NOT installed on every machine/runner, so a
# missing toolchain prints a loud SKIPPED line and exits 0. Set VMP_REQUIRE_I686=1 to make a
# missing toolchain a hard failure (use that on any runner that is supposed to have it).
#
# ASCII-only on purpose (see AGENTS.md): Windows PowerShell 5.1 reads .ps1 as ANSI.
#
# NOT WIRED INTO gates.ps1 YET. Reason: this gate currently fails on the cdecl
# multi-argument case (e32_args). Five of six cases pass; e32_args reads the wrong
# stack slot, so the gate is red on purpose until that is fixed. Wiring it in while it
# is red would make the trunk red, and dropping the case would be lowering the bar -
# neither is allowed. Run it standalone; wire it into gates.ps1 once it prints 6/6.
$ErrorActionPreference = "Continue"
Set-Location (Join-Path $PSScriptRoot "..")

$script:bad = 0
function Fail([string]$m) { Write-Host ("[!] " + $m); $script:bad++ }

# ---- locate the i686 toolchain: PATH first, then the usual install dirs ----
$ccName = "i686-w64-mingw32-gcc.exe"
$cc = $null
$cmd = Get-Command $ccName -ErrorAction SilentlyContinue
if ($cmd) { $cc = $cmd.Source }
if (-not $cc) {
    foreach ($d in @("C:\msys64\mingw32\bin", "C:\mingw32\bin", "C:\msys64\ucrt64\bin")) {
        $p = Join-Path $d $ccName
        if (Test-Path $p) { $cc = $p; $env:PATH = $d + ";" + $env:PATH; break }
    }
}
if (-not $cc) {
    Write-Host "[!] SKIPPED: 32-bit toolchain ($ccName) not found on PATH or in the usual dirs."
    Write-Host "[!] SKIPPED: the 32-bit path is therefore NOT being verified by this run."
    if ($env:VMP_REQUIRE_I686 -eq "1") {
        Write-Host "[!] VMP_REQUIRE_I686=1 was set, so this skip is a failure."
        exit 1
    }
    exit 0
}
Write-Host ("[*] i686 toolchain: " + $cc)

foreach ($t in @("build/vmpack.exe", "build/vmpbuild.exe")) {
    if (-not (Test-Path $t)) { Write-Host ("[!] missing " + $t + " (build it first)"); exit 1 }
}

# ---- the subject: a real 32-bit PE32 exe ----
& $cc -O0 -Wall -o build/target32.exe testdata/e2e32.c 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path "build/target32.exe")) { Write-Host "[!] could not build build/target32.exe"; exit 1 }

# ---- the 32-bit blob (VM_HOST_X86_32 + x86-32 guest are injected by vmpbuild from -guest) ----
& ".\build\vmpbuild.exe" -cc $ccName -src "stub/win/x86" -out "build/gates_blob32.bin" -manifest "build/gates_blob32.json" -entry vm_entry -guest x86-32 -merge go -random-opcodes=false 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "[!] i686 blob build failed (stub/win/x86 has compile errors?)"; exit 1 }

# ---- pack each function on its own and compare exit codes ----
$cases = @(
    @("e32_const", 100),   # no locals: push/mov/pop/ret
    @("e32_local",  35),   # two locals via [ebp-N] STORE/LOAD
    @("e32_loop",   55),   # loop with a stack-resident counter
    @("e32_args",  123),   # cdecl multi-argument, read from the caller frame
    @("e32_big",    36),   # many locals: longer bytecode
    @("e32_call",   42)    # guest calls a native function and uses the result
)
$pass = 0
foreach ($c in $cases) {
    $fn = $c[0]; $want = $c[1]
    $outExe = "build/target32_" + $fn + ".exe"
    if (Test-Path $outExe) { Remove-Item $outExe -Force }
    & ".\build\vmpack.exe" -exe "build/target32.exe" -func $fn -out $outExe -blob "build/gates_blob32.bin" -manifest "build/gates_blob32.json" -strip-relocs 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $outExe)) { Fail ("packing " + $fn + " failed"); continue }
    & ".\build\target32.exe" $fn | Out-Null; $nat = $LASTEXITCODE
    & $outExe $fn | Out-Null; $pac = $LASTEXITCODE
    if ($nat -ne $want) { Fail ($fn + ": native=" + $nat + " but the case expects " + $want + " (test subject changed?)"); continue }
    if ($pac -ne $nat) { Fail ($fn + ": packed=" + $pac + " native=" + $nat + " (32-bit guest behaves differently)") }
    else { $pass++ }
}

if ($script:bad -eq 0) { Write-Host ("[OK] 32-bit e2e: " + $pass + "/" + $cases.Count + " packed functions match native") }
exit $script:bad

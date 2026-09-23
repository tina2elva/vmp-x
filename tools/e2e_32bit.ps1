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
# WIRED INTO gates.ps1 (right before "go test ./..."). It prints 12/12 as of STATUS #481.
# The paragraph below is kept only as the history of why this took a while to get there.
#
# HISTORICAL NOTE (no longer true): this gate used to fail on the cdecl
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
# -msse2 -mfpmath=sse: i686 defaults to x87, whose FLD/FSTP the lifter rejects ("unsupported
# instruction"). Any protected function that touches floating point therefore needs SSE codegen
# on this target. Keeping the flags here documents that constraint and covers the FP path.
# -mno-stackrealign: some GCC versions (observed on the CI runner) emit an SSE stack-realignment
# prologue (`and esp,-16`) for a function with double locals. The lifter refuses to guess about a
# modified RSP ("RSP modified in an untrackable way"), so the pack fails. Forbid that prologue.
& $cc -O0 -Wall -msse2 -mfpmath=sse -mno-stackrealign -o build/target32.exe testdata/e2e32.c 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path "build/target32.exe")) { Write-Host "[!] could not build build/target32.exe"; exit 1 }

# A SECOND subject at -O1, used only for the floating-point cases.
# Why: at -O0 some GCC versions (observed on the CI runner) address the double locals as
# [ESP+Reg(0)] (indexed stack addressing). The lifter refuses that form by design ("symbol of
# rsp+idx*scale+disp depends on a runtime index"), so the pack fails there while it passes with
# the locally installed GCC. At -O1 the doubles stay in XMM registers and the form disappears.
& $cc -O1 -Wall -msse2 -mfpmath=sse -mno-stackrealign -o build/target32_o1.exe testdata/e2e32.c 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path "build/target32_o1.exe")) { Write-Host "[!] could not build build/target32_o1.exe"; exit 1 }

# ---- the 32-bit blob (VM_HOST_X86_32 + x86-32 guest are injected by vmpbuild from -guest) ----
& ".\build\vmpbuild.exe" -cc $ccName -src "stub/win/x86" -out "build/gates_blob32.bin" -manifest "build/gates_blob32.json" -entry vm_entry -guest x86-32 -merge go -random-opcodes=false 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "[!] i686 blob build failed (stub/win/x86 has compile errors?)"; exit 1 }

# ---- pack each function on its own and compare exit codes ----
$cases = @(
    @("e32_const", 100, 0),   # no locals: push/mov/pop/ret
    @("e32_local",  35, 0),   # two locals via [ebp-N] STORE/LOAD
    @("e32_loop",   55, 0),   # loop with a stack-resident counter
    @("e32_args",  123, 0),   # cdecl multi-argument, read from the caller frame
    @("e32_big",    36, 0),   # many locals: longer bytecode
    @("e32_call",   42, 0),   # guest calls a native function and uses the result
    @("e32_shl_imm", 8, 0),   # CONSTANT-local shift: no argument read at all
    @("e32_shr_imm", 16, 0),  # same, right shift
    @("e32_shl",     8, 0),   # pure shift left (isolates shift-class ALU_RI)
    @("e32_shr",    16, 0),   # pure shift right
    @("e32_dbl",     4, 1),   # floating point, no args (needs the -O1 subject)
    @("e32_dblarg",  3, 1)    # floating point, two doubles on the stack (cdecl)
)
$pass = 0
foreach ($c in $cases) {
    $fn = $c[0]; $want = $c[1]
    $subj = "build/target32.exe"
    if ($c[2] -eq 1) { $subj = "build/target32_o1.exe" }
    $outExe = "build/target32_" + $fn + ".exe"
    if (Test-Path $outExe) { Remove-Item $outExe -Force }
    & ".\build\vmpack.exe" -exe $subj -func $fn -out $outExe -blob "build/gates_blob32.bin" -manifest "build/gates_blob32.json" -strip-relocs 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $outExe)) { Fail ("packing " + $fn + " failed"); continue }
    & $subj $fn | Out-Null; $nat = $LASTEXITCODE
    & $outExe $fn | Out-Null; $pac = $LASTEXITCODE
    if ($nat -ne $want) { Fail ($fn + ": native=" + $nat + " but the case expects " + $want + " (test subject changed?)"); continue }
    if ($pac -ne $nat) { Fail ($fn + ": packed=" + $pac + " native=" + $nat + " (32-bit guest behaves differently)") }
    else { $pass++ }
}

# Second pass: the same cases WITHOUT -strip-relocs, i.e. with the relocation table kept.
# That configuration used to fail outright (the old .reloc had no raw slack left):
# vmpack can now move the whole relocation table into a new carrier section.
# relocation table into a new carrier section (.vreloc) when the old .reloc has no raw slack.
# It exercises the loader-relocation path, so it is worth a pass of its own.
$pass2 = 0
foreach ($c in $cases) {
    $fn = $c[0]; $want = $c[1]
    $subj = "build/target32.exe"
    if ($c[2] -eq 1) { $subj = "build/target32_o1.exe" }
    $outExe = "build/target32_rel_" + $fn + ".exe"
    if (Test-Path $outExe) { Remove-Item $outExe -Force }
    $pk = & ".\build\vmpack.exe" -exe $subj -func $fn -out $outExe -blob "build/gates_blob32.bin" -manifest "build/gates_blob32.json" 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $outExe)) {
# Do not swallow the real reason from vmpack: it is the only diagnostic on this path.
        # Print the tail VERBATIM (no filter): an earlier filter dropped the real reason because it
# did not contain any of the words I guessed at.
($pk -split "`r?`n") | Where-Object { $_.Trim() -ne "" } | Select-Object -Last 6 | ForEach-Object { Write-Host ("      vmpack| " + $_.Trim()) }
        Fail ("packing " + $fn + " with relocations kept failed")
        continue
    }
    & $subj $fn | Out-Null; $nat = $LASTEXITCODE
    & $outExe $fn | Out-Null; $pac = $LASTEXITCODE
    if ($nat -ne $want) { Fail ($fn + " (relocs kept): native=" + $nat + " but the case expects " + $want); continue }
    if ($pac -ne $nat) { Fail ($fn + " (relocs kept): packed=" + $pac + " native=" + $nat) }
    else { $pass2++ }
}

if ($script:bad -eq 0) {
    Write-Host ("[OK] 32-bit e2e: " + $pass + "/" + $cases.Count + " match native (-strip-relocs)")
    Write-Host ("[OK] 32-bit e2e: " + $pass2 + "/" + $cases.Count + " match native (relocations kept)")
}
exit $script:bad

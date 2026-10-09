# harness.ps1 - interpreter semantics harness (stub/win/x64/test_harness.c).
#
#   powershell -NoProfile -File tools/harness.ps1
#
# WHY THIS GATE EXISTS: test_harness.c includes the REAL stub/win/x64/vm_interp.c (not a copy)
# and drives vm_run() with hand-written bytecode, so interpreter semantics bugs -- real NZCV
# flags, 32-bit zero extension, 8/16-bit partial register writes, LEA addressing, LOAD/STORE
# widths, TEST/CMP + Jcc -- go red in about two seconds instead of waiting for the minute-scale
# end-to-end suites.
#
# It was written long ago but NO script ever ran it, so it had rotted: its emit_load/emit_store
# encodings were missing the index+scale bytes that vm_opcodes.h has documented for a while, and
# case 8 died with an access violation (STATUS #602). A test nobody runs is not a test.
#
# ASCII-only on purpose (see AGENTS.md): Windows PowerShell 5.1 reads a .ps1 as ANSI unless it
# has a UTF-8 BOM, so non-ASCII bytes can swallow a following line.
Set-Location (Join-Path $PSScriptRoot "..")

$requireGcc = ($env:VMP_REQUIRE_GCC -eq "1")
if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    if ($requireGcc) { Write-Host "[!] harness: gcc is required (VMP_REQUIRE_GCC=1) but not found"; exit 1 }
    Write-Host "[SKIP] harness: no gcc on this machine (set VMP_REQUIRE_GCC=1 to make that a hard failure)"
    exit 77
}

# Same include/define shape as stub/win/x64/keyname_probe.c: test_harness.c pulls in the real
# vm_interp.c and satisfies the build-time generated constants with the placeholder key header.
& gcc -O1 -w -I stub/win/x64 -o build/harness.exe `
    stub/win/x64/test_harness.c stub/win/x64/vm_crypto.c stub/win/x64/vm_kdf.c stub/win/x64/vm_entry_asm.S
if ($LASTEXITCODE -ne 0) { Write-Host "[!] harness: build failed (stub/win/x64 does not compile)"; exit 1 }

$out = (& .\build\harness.exe 2>&1 | Out-String)
$rc = $LASTEXITCODE
Write-Host ($out.Trim())
if ($rc -ne 0 -or $out -notmatch "PASS: 0 failure") {
    Write-Host ("[!] harness: interpreter semantics FAILED (rc=" + $rc + ")")
    exit 1
}
Write-Host "[OK  ] harness: interpreter semantics (real vm_interp.c, hand-written bytecode)"

# ---- guest-stack guard (rc=97): minimal repro + control (STATUS #607) ----
# Why: after wiring random bytecode programs into the C-vs-Go-reference-VM differential, the very
# first run had one program make the C interpreter take a hard gate while the Go reference VM ran
# it fine. Diagnosed as DELIBERATE fail-closed behaviour, not a bug:
#     vm_interp.c:  if (rsp_start - vm->regs[VRSP] > VM_MARGIN) return 99;  // stack below its floor
#                   if (vm->regs[VRSP] > rsp_start)             return 97;  // SP above entry
# Measured (STATUS #607.2): with SP above entry the UNDERFLOWED first check used to fire first, so the
# code was 99 and the 97 branch was unreachable (dead). STATUS #608 fixed the ORDER (97 first), so 97
# is reachable again. This Windows probe can only assert "abnormal exit + no output" (ud2 carries no
# code); the exact-code assertion (rc=97) lives in tools/e2e_elf_image.sh, where the Linux hard gate
# encodes the code in the exit status.
# mode 0: write the guest SP ABOVE its entry value -> expect an abnormal exit (0xC000001D) and
#         NO output at all (the program must not reach its own printf).
# mode 1: write the SP EQUAL to the entry value -> expect a clean run printing rc=0 (this proves
#         the guard keys on the VALUE, not on "the program wrote SP at all").
# This is also one instance of "every hard-gate branch needs a test that really reaches it"
# (STATUS #602.5): remove that guard and mode 0 stops trapping, so this check turns red.
& gcc -O1 -w -I stub/win/x64 -o build/rsp_guard_probe.exe `
    stub/win/x64/rsp_guard_probe.c stub/win/x64/vm_crypto.c stub/win/x64/vm_kdf.c stub/win/x64/vm_entry_asm.S
if ($LASTEXITCODE -ne 0) { Write-Host "[!] harness: rsp_guard_probe build failed"; exit 1 }
$g1 = [string](& .\build\rsp_guard_probe.exe 1 2>&1 | Out-String)
$rc1 = $LASTEXITCODE
$g0 = [string](& .\build\rsp_guard_probe.exe 0 2>&1 | Out-String)
$rc0 = $LASTEXITCODE
# PowerShell 5.1 parses a literal like 0xC000001D as a NEGATIVE Int32, so compare with a DECIMAL
# constant (AGENTS.md records this trap). Also: with no output the captured value can be $null, and
# $null -ne "" is TRUE in PowerShell -- cast to [string] before judging emptiness.
$trapCode = -1073741795
if ($rc1 -ne 0 -or $g1 -notmatch "rc=0") {
    Write-Host ("[!] harness: rsp guard control (mode 1) failed: rc=" + $rc1 + " out=" + $g1)
    exit 1
}
if ($rc0 -ne $trapCode -or $g0.Trim().Length -ne 0) {
    Write-Host ("[!] harness: rsp guard (mode 0) did NOT trap as expected: rc=" + $rc0 + " out=" + $g0)
    exit 1
}
Write-Host "[OK  ] harness: guest-stack guard (SP above entry -> hard gate/ud2; SP == entry -> runs)"
exit 0

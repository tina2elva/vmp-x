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
exit 0

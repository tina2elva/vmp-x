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
# ---- EARLY A/B probe: run the green product BEFORE this script rebuilds anything ----
# The 10-run histogram showed the SAME file fails 10/10 in this step, while it succeeded in the
# previous step of the same job => not ASLR, but something this step does deterministically.
# Prime suspect: we recompile build/target_arm64.exe (the file the green .vmp was built from).
$greenE = Join-Path $PWD "build/target_arm64.vmp"
Mark ("probe-early:exists=" + (Test-Path $greenE))
if (Test-Path $greenE) {
    $soE = Join-Path $PWD "build/probe_early.out"
    $seE = Join-Path $PWD "build/probe_early.err"
    $hE = @{}
    for ($i = 1; $i -le 5; $i++) {
        $rE = -999
        try {
            $pE = Start-Process -FilePath $greenE -Wait -PassThru -RedirectStandardOutput $soE -RedirectStandardError $seE
            $rE = $pE.ExitCode
        } catch { $rE = -998 }
        if ($hE.ContainsKey($rE)) { $hE[$rE]++ } else { $hE[$rE] = 1 }
    }
    $lE = "probe-early:5runs"
    foreach ($k in $hE.Keys) { $lE = $lE + " rc=" + $k + "x" + $hE[$k] }
    Mark $lE
}

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

# ---- RELOCATION DIAGNOSIS (STATUS #507): does the target even HAVE a relocation table? ----
# If the freestanding lld-linked ARM64 target has no .reloc, then nothing can be carried into the
# product, and with ASLR active (Start-Process / double-click) the entry self-decrypt cannot undo
# the loader delta => vm_img_fail(2) => 0xC0DE0002. The green job never sees it because a plain
# call loads at the preferred base (delta = 0).
$od2 = (Get-Command llvm-objdump -ErrorAction SilentlyContinue).Source
if (-not $od2) { $od2 = "llvm-objdump" }
$hdr = (& $od2 -h build/target_arm64.exe 2>&1 | Out-String)
$relSeen = ($hdr -split "`n" | Where-Object { $_ -match "reloc" }) -join " ; "
Mark ("reloc:target-sections has-reloc=" + [bool]($hdr -match "reloc"))
Mark ("reloc:target-line " + $relSeen.Trim())
$prodHdr = (& $od2 -h build/target_arm64.vmp 2>&1 | Out-String)
$prodRel = ($prodHdr -split "`n" | Where-Object { $_ -match "reloc" }) -join " ; "
Mark ("reloc:product has-reloc=" + [bool]($prodHdr -match "reloc"))
Mark ("reloc:product-line " + $prodRel.Trim())
# ---- BASE BOOKKEEPING (STATUS #517 follow-up) ----
# The product DOES run (.vmp.exe) and returns 0xC0DE0002 = "delta != 0 but no reloc table".
# But an image without a reloc table cannot be moved by the loader at all - so delta != 0 is
# itself suspicious: maybe the recorded wantBase disagrees with the image s real ImageBase.
$imgo = (& $od2 -p build/target_arm64.exe 2>&1 | Out-String)
$imgLine = ($imgo -split "`n" | Where-Object { $_ -match "ImageBase|image base" } | Select-Object -First 2) -join " ; "
Mark ("base:target-exe " + $imgLine.Trim())
$imgp = (& $od2 -p build/target_arm64.vmp 2>&1 | Out-String)
$imgLineP = ($imgp -split "`n" | Where-Object { $_ -match "ImageBase|image base" } | Select-Object -First 2) -join " ; "
Mark ("base:product " + $imgLineP.Trim())
# ---- ENTRY BYTES (STATUS #530 follow-up) ----
# The crash is 0xC000001D (illegal instruction) inside the entry trampoline, after the image
# decrypt succeeded. Read the ACTUAL bytes at AddressOfEntryPoint and dump the first few
# instructions, so we can compare them with stub/win/arm64/vm_entry_asm.S line by line.
$ph = (& $od2 -p build/target_arm64.vmp 2>&1 | Out-String)
$ent = ($ph -split "`n" | Where-Object { $_ -match "AddressOfEntryPoint|entry point" } | Select-Object -First 1)
Mark ("entry:header " + ("" + $ent).Trim())
$erva = 0
if ("" -ne ("" + $ent)) {
  $tok = (("" + $ent).Trim() -split "\s+")[-1]
  try { $erva = [Convert]::ToUInt32($tok, 16) } catch { $erva = 0 }
}
Mark ("entry:rva=0x" + $erva.ToString("X"))
if (($erva -ne 0) -and (Test-Path build/target_arm64.vmp)) {
  $st1 = 0x140000000 + $erva
  $en1 = $st1 + 0x180
  $dd = (& $od2 -d ("--start-address=0x" + $st1.ToString("X")) ("--stop-address=0x" + $en1.ToString("X")) build/target_arm64.vmp 2>&1 | Out-String)
  $lines = ($dd -split "`n") | Select-Object -First 30
  foreach ($ln in $lines) { if ("" -ne $ln.Trim()) { Mark ("entry:bytes " + $ln.Trim()) } }
  # The entry does: save args / adrp+add (x0 = pointer) / bl 0x14000d6c8 / cbz / brk #0.
  # Dump the CALLEE (0x14000d6c8) - it lives in the payload section, which is NOT encrypted, so
  # these are the real instructions of whatever check the entry trampoline calls.
  $tva = 0x14000d6c8
  $dd3 = (& $od2 -d ("--start-address=0x" + $tva.ToString("X")) ("--stop-address=0x" + ($tva + 0x70).ToString("X")) build/target_arm64.vmp 2>&1 | Out-String)
  foreach ($ln in (($dd3 -split "`n") | Select-Object -First 22)) { if ("" -ne $ln.Trim()) { Mark ("target:code " + $ln.Trim()) } }
  # The first 8 instructions decode as: mov/mov/mov / adrp+add (x0 = a message pointer) /
  # bl (a check) / cbz / brk #0. So the crash is a DELIBERATE assertion trap, not corrupt code.
  # Dump the bytes at that pointer (0x140011670 in the run above) to learn WHICH check failed.
  $msgVA = 0x140011670
  $dd2 = (& $od2 -s ("--start-address=0x" + $msgVA.ToString("X")) ("--stop-address=0x" + ($msgVA + 0x60).ToString("X")) build/target_arm64.vmp 2>&1 | Out-String)
  foreach ($ln in (($dd2 -split "`n") | Select-Object -First 8)) { if ("" -ne $ln.Trim()) { Mark ("entry:msg " + $ln.Trim()) } }
} else { Mark "entry:bytes (no entry rva or no product)" }
$manTxt = ""
if (Test-Path build/vm_interp_win_arm64.json) { $manTxt = Get-Content build/vm_interp_win_arm64.json -Raw }
$mb = ""
if ($manTxt -match '"imageBase"\s*:\s*([0-9]+)') { $mb = $Matches[1] }
Mark ("base:manifest-imageBase-decimal=" + $mb)
if ($mb -ne "") { Mark ("base:manifest-imageBase-hex=0x" + ([int64]$mb).ToString("X")) }
# A/B: pack the same funcs with -strip-relocs (clears DYNAMIC_BASE) and run it under Start-Process.
& .\build\vmpack.exe -exe build/target_arm64.exe -func check_key -func sum_to -blob build/vm_interp_win_arm64.bin -manifest build/vm_interp_win_arm64.json -out build/target_arm64_strip.vmp -strip-relocs 2>&1 | Out-Null
if (Test-Path build/target_arm64_strip.vmp) {
    $soS = Join-Path $PWD "build/strip_sp.out"
    $seS = Join-Path $PWD "build/strip_sp.err"
    $rsS = -999
    try { $ps2 = Start-Process -FilePath (Join-Path $PWD "build/target_arm64_strip.vmp") -Wait -PassThru -RedirectStandardOutput $soS -RedirectStandardError $seS; $rsS = $ps2.ExitCode } catch { $rsS = -998 }
    Mark ("strip-relocs via Start-Process: rc=" + $rsS)
    $rp = -999
    & build/target_arm64_strip.vmp; $rp = $LASTEXITCODE
    Mark ("strip-relocs via plain call: rc=" + $rp)
} else { Mark "strip-relocs: pack failed" }

# ---- CALIBRATION: the same flow, but with a NON-external blob ----
# Without this, "the external build crashes" could just mean "my pack invocation differs from the
# one the (green) windows-arm64-run job uses". AGENTS.md discipline: calibrate the probe first.
Remove-Item build/vm_interp_win_arm64_cal.bin, build/vm_interp_win_arm64_cal.json -ErrorAction SilentlyContinue
& .\build\vmpbuild.exe -src stub/win/arm64 -out build/vm_interp_win_arm64_cal.bin -manifest build/vm_interp_win_arm64_cal.json -entry vm_entry -guest arm64 -merge go -cc $ccArg -objdump $objdump 2>&1 | Select-Object -Last 6
if (-not (Test-Path build/vm_interp_win_arm64_cal.bin)) { Write-Host "[!] CALIBRATION: non-external blob build failed"; exit 1 }
& .\build\vmpack.exe -exe build/target_arm64.exe -func check_key -func sum_to -blob build/vm_interp_win_arm64_cal.bin -manifest build/vm_interp_win_arm64_cal.json -out build/target_arm64_cal.exe -report build/target_arm64_cal_vmp.json 2>&1 | Select-Object -Last 6
if (-not (Test-Path build/target_arm64_cal.exe)) { Write-Host "[!] CALIBRATION: packing failed"; exit 1 }
# A/B on the LAUNCHER: the green step runs the product with a plain call (no pipeline, no shell),
# and it succeeds there. Everything I ran so far went through a pipeline or Start-Process and
# failed with a real-looking 0xC0DE0002. So compare both ways on the SAME exe.
$calPlain = Join-Path $PWD "build/cal_plain.txt"
Remove-Item $calPlain -ErrorAction SilentlyContinue
$calRc2 = -999
& (Join-Path $PWD "build/target_arm64_cal.exe") *> $calPlain; $calRc2 = $LASTEXITCODE
$calOut2 = ""
if (Test-Path $calPlain) { $calOut2 = ((Get-Content $calPlain -Raw) + "").Trim() }
Mark ("cal-plain: rc=" + $calRc2 + " out=" + $calOut2)
$soC = Join-Path $PWD "build/cal_sp.out"
$seC = Join-Path $PWD "build/cal_sp.err"
$calRc3 = -999
try { $pc = Start-Process -FilePath (Join-Path $PWD "build/target_arm64_cal.exe") -Wait -PassThru -RedirectStandardOutput $soC -RedirectStandardError $seC; $calRc3 = $pc.ExitCode } catch { $calRc3 = -998 }
Mark ("cal-startprocess: rc=" + $calRc3)
# ---- A/B: pack with the GREEN STEP's own blob/manifest (same funcs) ----
# Isolates "my blob build differs" from "my pack invocation differs": the previous step in this
# same job built build/vm_interp_win_arm64.bin + .json and packed a product that MATCHES native.
$gBlob = "build/vm_interp_win_arm64.bin"
$gMan = "build/vm_interp_win_arm64.json"
if ((Test-Path $gBlob) -and (Test-Path $gMan)) {
    & .\build\vmpack.exe -exe build/target_arm64.exe -func check_key -func sum_to -blob $gBlob -manifest $gMan -out build/target_arm64_greenblob.exe -report build/target_arm64_greenblob.json 2>&1 | Out-Null
    if (Test-Path build/target_arm64_greenblob.exe) {
        $rg = 0; & build/target_arm64_greenblob.exe; $rg = $LASTEXITCODE
        Mark ("greenblob-pack: rc=" + $rg)
    } else { Mark "greenblob-pack: pack failed" }
} else { Mark "greenblob-pack: green blob/manifest not present" }
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

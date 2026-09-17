# verify_linux_payload.ps1 - verify (on Windows) that the protected Linux/amd64 payload executes.
#
# The injected machine code is position-independent x86-64 and independent of the host kernel.
# Mapping it at the ELF's original VA and calling the thunk with the guest calling convention
# verifies: payload bytes + descriptor + thunk + System V entry + bytecode.
# The only unverified step left is "the Linux loader maps that segment and transfers control
# to the patched function entry" - which is what tools/e2e.sh checks on a real Linux runner.
#
# Usage: pwsh -File tools/verify_linux_payload.ps1

$ErrorActionPreference = "Continue"
if ($PSScriptRoot) { Set-Location (Join-Path $PSScriptRoot "..") }
New-Item -ItemType Directory -Force -Path build | Out-Null

& go build -o build/vmpbuild.exe ./cmd/vmpbuild
& go build -o build/vmpack.exe ./cmd/vmpack
& go build -o build/extractpayload.exe ./cmd/extractpayload
& gcc -O2 -o build/payload_probe.exe stub/linux/amd64/payload_probe.c

# Target must be a real Linux ELF: build with GOOS/GOARCH set.
$env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
& go build -o build/linux_target.exe ./testdata/linux
Move-Item -Force build/linux_target.exe build/linux_target
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue

# On Windows the Linux blob is built by mingw (Win64 internal ABI); vmpbuild defines
# VM_BLOB_USES_WIN64 automatically so the entry calls vm_run with RCX + shadow space.
& .\build\vmpbuild.exe -src stub/linux/amd64 -out build/vm_interp_linux.bin -manifest build/vm_interp_linux.json -entry vm_entry | Out-Null
& .\build\vmpack.exe -exe build/linux_target -func main.checkKey -func main.sumTo -blob build/vm_interp_linux.bin -manifest build/vm_interp_linux.json -out build/linux_target.vmp -report build/linux_vmp.json | Out-Null

$m = Get-Content build/linux_vmp.json | ConvertFrom-Json
$p = $m.placements | Where-Object { $_.name -eq "main.checkKey" }
$thunkOff = '{0:X}' -f ($p.thunkRVA - $m.sectionRVA)
$meta = & .\build\extractpayload.exe -elf build/linux_target.vmp -rva $m.sectionRVA -size $m.sectionSize -thunk $p.thunkRVA -out build/linux_payload.bin
$meta | ForEach-Object { Write-Host "    $_" }
$va = ($meta | Select-String -Pattern 'payloadVA=(0x[0-9A-Fa-f]+)').Matches[0].Groups[1].Value

Write-Host "[*] executing the protected payload (guest arg register = RAX for Go binaries)..."
$out = & .\build\payload_probe.exe build/linux_payload.bin $va 0x$thunkOff 10 0 1 255 12345 1000000
$out | ForEach-Object { Write-Host $_ }

$expected = @{ 10 = 143; 0 = 213; 1 = 206; 255 = 2012; 12345 = 86342; 1000000 = 6999829 }
$fail = 0
foreach ($kv in $expected.GetEnumerator()) {
    $want = "  checkKey($($kv.Key)) = $($kv.Value)"
    if ($out -notcontains $want) { Write-Host "  [FAIL] missing/mismatch: $want"; $fail++ }
}
if ($fail -eq 0) { Write-Host "payload execution: all values match" } else { Write-Host "payload execution: $fail mismatch(es)"; exit 1 }

# ---------------------------------------------------------------------------
# Phase 2: PIE (ET_DYN) target.
#
# A PIE's whole point is that the image can be loaded anywhere: the payload
# segment, the thunk (E8 rel32) and the descriptor selfRVA are all relative, and
# the entry stub derives the base from "descriptor address - selfRVA". So besides
# packing, we deliberately run the payload at a SECOND load address and require
# identical results - that is the real evidence for PIE support.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] PIE (ET_DYN) target: pack, then execute at two different load addresses"
$env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
& go build -buildmode=pie -o build/linux_target_pie ./testdata/linux
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue

& .\build\vmpack.exe -exe build/linux_target_pie -func main.checkKey -func main.sumTo -blob build/vm_interp_linux.bin -manifest build/vm_interp_linux.json -out build/linux_pie.vmp -report build/linux_pie.json | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "[FAIL] PIE packing failed"; exit 1 }

$mp = Get-Content build/linux_pie.json | ConvertFrom-Json
$pp = $mp.placements | Where-Object { $_.name -eq "main.checkKey" }
$pthunkOff = '{0:X}' -f ($pp.thunkRVA - $mp.sectionRVA)
$pmeta = & .\build\extractpayload.exe -elf build/linux_pie.vmp -rva $mp.sectionRVA -size $mp.sectionSize -thunk $pp.thunkRVA -out build/linux_pie_payload.bin
$pmeta | ForEach-Object { Write-Host "    $_" }
$pva = ($pmeta | Select-String -Pattern 'payloadVA=(0x[0-9A-Fa-f]+)').Matches[0].Groups[1].Value

$a1 = @("build/linux_pie_payload.bin", $pva, "0x$pthunkOff", "10", "0", "1", "255", "12345", "1000000")
$run1 = & .\build\payload_probe.exe @a1
$biased = "0x" + ('{0:X}' -f ([Convert]::ToInt64($pva, 16) + 0x100000))
$a2 = @("build/linux_pie_payload.bin", $biased, "0x$pthunkOff", "10", "0", "1", "255", "12345", "1000000")
$run2 = & .\build\payload_probe.exe @a2
Write-Host "    load address 1 (original VA): $pva"
Write-Host "    load address 2 (+0x100000)  : $biased"

$pfail = 0
foreach ($kv in $expected.GetEnumerator()) {
    $want = "  checkKey($($kv.Key)) = $($kv.Value)"
    if ($run1 -notcontains $want) { Write-Host "  [FAIL] PIE@$pva missing/mismatch: $want"; $pfail++ }
    if ($run2 -notcontains $want) { Write-Host "  [FAIL] PIE@$biased missing/mismatch: $want"; $pfail++ }
}
if ($pfail -eq 0) {
    Write-Host "PIE payload: identical to native at BOTH load addresses"
} else {
    Write-Host "PIE payload: $pfail mismatch(es)"; exit 1
}

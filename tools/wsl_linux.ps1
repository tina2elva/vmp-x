# wsl_linux.ps1 - run CI's Linux jobs LOCALLY, through WSL.
#
#   powershell -NoProfile -File tools/wsl_linux.ps1            # all steps
#   powershell -NoProfile -File tools/wsl_linux.ps1 -Only arm64
#   powershell -NoProfile -File tools/wsl_linux.ps1 -NoSync    # reuse the existing WSL copy
#
# It syncs this working tree into the WSL filesystem (~/vmp-x) and runs tools/wsl_linux.sh
# there. Syncing into ext4 (instead of building on /mnt/d) keeps the Linux build fast and,
# more importantly, keeps the Linux artifacts in a SEPARATE build/ directory: several of
# these scripts write build/vm_interp.bin, which is also the packer's default blob, so
# sharing build/ with the Windows gates would silently corrupt them.
#
# Missing WSL is a LOUD SKIP (exit 0) so tools/gates.ps1 still works on machines without it;
# set VMP_REQUIRE_WSL=1 to turn that into a hard failure (mirrors VMP_REQUIRE_I686).
#
# ASCII-only output on purpose (see AGENTS.md).
param(
  [ValidateSet("all", "amd64", "arm64")]
  [string]$Only = "all",
  [switch]$NoSync
)
$ErrorActionPreference = "Continue"
Set-Location (Join-Path $PSScriptRoot "..")
$requireWsl = ($env:VMP_REQUIRE_WSL -eq "1")

$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wsl) {
    if ($requireWsl) { Write-Host "[!] wsl_linux: WSL is required (VMP_REQUIRE_WSL=1) but wsl.exe was not found"; exit 1 }
    Write-Host "[SKIP] wsl_linux: no WSL on this machine (set VMP_REQUIRE_WSL=1 to make this a hard failure)"
    exit 77   # 77 = skipped：gates.ps1 会单独记账，不再把它报成 [OK]
}

# A broken/stopped distro must be a loud SKIP too, not a confusing failure later on.
$probe = (& wsl.exe -e bash -c "echo WSL_OK" 2>&1 | Out-String)
if ($probe -notmatch "WSL_OK") {
    $why = ($probe -replace "\s+", " ").Trim()
    if ($requireWsl) { Write-Host ("[!] wsl_linux: WSL is present but not usable: " + $why); exit 1 }
    Write-Host ("[SKIP] wsl_linux: WSL is present but not usable: " + $why)
    exit 77   # 77 = skipped（同上）
}

# Windows repo path -> WSL mount path (D:\vmp-x -> /mnt/d/vmp-x)
$root = (Get-Location).Path
$mnt = "/mnt/" + $root.Substring(0, 1).ToLower() + $root.Substring(2).Replace("\", "/")

if (-not $NoSync) {
    Write-Host ("[*] syncing " + $mnt + " -> ~/vmp-x (excluding build/ and .git/)")
    & wsl.exe -e bash -c "mkdir -p ~/vmp-x && rsync -a --delete --exclude 'build/' --exclude '.git/' '$mnt/' ~/vmp-x/"
    if ($LASTEXITCODE -ne 0) { Write-Host "[!] wsl_linux: rsync into WSL failed"; exit 1 }
}

Write-Host ("[*] running the Linux CI command set inside WSL (only=" + $Only + ")")
& wsl.exe -e bash -lc "cd ~/vmp-x && bash tools/wsl_linux.sh $Only"
$rc = $LASTEXITCODE
if ($rc -ne 0) { Write-Host ("[!] wsl_linux: failed (rc=" + $rc + ")"); exit $rc }
Write-Host "[+] wsl_linux: OK"
exit 0

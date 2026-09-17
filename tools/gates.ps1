# gates.ps1 - run every local (Windows/amd64) gate in one shot.
#
#   powershell -NoProfile -File tools/gates.ps1      (Windows PowerShell 5.1)
#   pwsh        -NoProfile -File tools/gates.ps1      (PowerShell 7, if installed)
#
# This is the single command to run before claiming anything about the PoC.
# It checks exit codes everywhere on purpose: several incidents in this project
# were caused by a silently failing step being papered over by a stale artifact
# (see docs/RUNBOOK.md section 5).
#
# 注意（踩过的坑）：一开始我在步骤脚本块里写 exit 0 / exit 1，结果 exit 会**终止整个
# PowerShell 进程**——脚本跑完第一步就以 0 退出了，是典型的"假绿"。现在步骤只设置
# $script:stepCode，由 Step 统一汇总。
Set-Location (Join-Path $PSScriptRoot "..")
$script:results = @()

# 说明：E2E 步骤用**子进程**跑（powershell -NoProfile -File ...），因为脚本里的 exit
# 只有在子进程里才会变成我们可以检查的退出码；顺带避开"上一轮原生命令的 LASTEXITCODE 残留"。

function Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host "[*] $Name"
    $script:stepCode = 0
    & $Body
    if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { $script:stepCode = $LASTEXITCODE }
    $script:results += [pscustomobject]@{ Name = $Name; Exit = $script:stepCode }
    if ($script:stepCode -ne 0) { Write-Host "[!] $Name FAILED (exit $script:stepCode)" }
    $global:LASTEXITCODE = 0
}

Step "gofmt -l ."        { $out = (gofmt -l . | Out-String).Trim(); if ($out -ne "") { Write-Host $out; $script:stepCode = 1 } }
Step "go vet ./..."      { go vet ./... }
Step "go test ./..."     { go test ./... }
Step "e2e.ps1 (x86-64)"  { & powershell -NoProfile -File (Join-Path $PSScriptRoot "e2e.ps1") }
Step "e2e_dll.ps1"       { & powershell -NoProfile -File (Join-Path $PSScriptRoot "e2e_dll.ps1") }
# ARM64 客户机语义（宿主仍是 x86-64）：单独脚本 + 子进程调用，退出码语义干净
Step "arm64-guest differential" { & powershell -NoProfile -File (Join-Path $PSScriptRoot "e2e_arm64guest.ps1") }

Write-Host ""
Write-Host "==== local gates ===="
foreach ($r in $script:results) {
    $tag = if ($r.Exit -eq 0) { "[OK  ]" } else { "[FAIL]" }
    Write-Host ("{0} {1} (exit {2})" -f $tag, $r.Name, $r.Exit)
}
$bad = @($script:results | Where-Object { $_.Exit -ne 0 }).Count
Write-Host ("total {0} gates, {1} failed" -f $script:results.Count, $bad)
if ($bad -gt 0) { exit 1 }
exit 0
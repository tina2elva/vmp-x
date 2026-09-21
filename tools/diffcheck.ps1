# diffcheck.ps1 - 保护前逐函数差分自检（目标项 4/5）
#
# 对候选函数**逐个**单独保护，然后跑原生 vs 受保护，比较输出：
#   - 打包就被拒（lifter 说缺哪条指令）      -> REFUSED（并打印原因）
#   - 打包成功但输出不一致（静默算错）        -> WRONG（点名函数）
#   - 输出一致                                -> OK
#
# 为什么这么做：工具以前会**静默产出算错的受保护程序**（比拒绝保护危险得多）。
# 这个脚本把"静默"变成"点名"，也是给客户看的可保护性清单。
#
# 用法：
#   powershell -NoProfile -File tools/diffcheck.ps1 -Exe build\a.exe -Map build\a.map \
#            -FuncList '?A@@YAXXZ,?B@@YAXXZ' [-Args 'x y'] [-Filter '^\[demo'] [-Blob ... -Manifest ...]
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$Map,
  [Parameter(Mandatory=$true)][string]$FuncList,
  [string]$Args = '',
  [string]$Filter = '',
  [string]$Blob = '',
  [string]$Manifest = '',
  [int]$TimeoutSec = 30,
  [string]$Work = 'build\diffcheck'
)
$ErrorActionPreference = 'Continue'
if ($PSScriptRoot) { Set-Location (Join-Path $PSScriptRoot '..') }
New-Item -ItemType Directory -Force -Path $Work | Out-Null

function RunCapture([string]$exe, [string]$argstr) {
  $tmp = Join-Path $Work 'out.txt'
  Remove-Item $tmp -ErrorAction SilentlyContinue
  # 注意：**不能**把空数组传给 -ArgumentList —— PS 会直接报参数校验失败，
  # 于是原生与被保护两边都拿到空输出，比较结果就是假的 OK（实测踩过）。
  $sp = @{ FilePath = $exe; NoNewWindow = $true; PassThru = $true; RedirectStandardOutput = $tmp;
          RedirectStandardError = (Join-Path $Work 'err.txt') }
  if ($argstr) { $sp['ArgumentList'] = $argstr.Split(' ') }
  $p = Start-Process @sp
  if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch {} ; return @{ Out = '<TIMEOUT>'; Code = -999 } }
  $out = ''
  if (Test-Path $tmp) { $out = (Get-Content $tmp -Raw) }
  if (-not $out) { $out = '' }
  if ($Filter) {
    $lines = $out -split "`n" | Where-Object { $_ -notmatch $Filter }
    $out = ($lines -join "`n")
  }
  return @{ Out = $out.Trim(); Code = $p.ExitCode }
}

$native = RunCapture $Exe $Args
Write-Host ('原生: exit=' + $native.Code)
$funcs = $FuncList.Split(',') | Where-Object { $_ -ne '' }
$ok = 0; $wrong = 0; $refused = 0
$report = New-Object System.Collections.ArrayList
foreach ($f in $funcs) {
  $out = Join-Path $Work 'one.exe'
  Remove-Item $out -ErrorAction SilentlyContinue
  $pa = @('-exe', $Exe, '-map', $Map, '-func', $f, '-out', $out)
  if ($Blob) { $pa += @('-blob', $Blob) }
  if ($Manifest) { $pa += @('-manifest', $Manifest) }
  $packOut = (& .\build\vmpack.exe @pa 2>&1 | Out-String)
  if (-not (Test-Path $out)) {
    $refused++
    $reason = ($packOut -split "`n" | Where-Object { $_ -match '无法翻译|\[!\]' } | Select-Object -First 1)
    if (-not $reason) { $reason = '打包失败' }
    [void]$report.Add([pscustomobject]@{ Func = $f; Verdict = 'REFUSED'; Detail = $reason.Trim() })
    Write-Host ('[REFUSED] ' + $f + '  ' + $reason.Trim())
    continue
  }
  $prot = RunCapture $out $Args
  if ($prot.Out -eq $native.Out) {
    $ok++
    [void]$report.Add([pscustomobject]@{ Func = $f; Verdict = 'OK'; Detail = '' })
    Write-Host ('[OK     ] ' + $f)
  } else {
    $wrong++
    $nl = @($native.Out -split "`n")
    $pl = @($prot.Out -split "`n")
    $nd = 0; $n1 = ''; $p1 = ''
    for ($i = 0; $i -lt [Math]::Max($nl.Count, $pl.Count); $i++) {
      $x = if ($i -lt $nl.Count) { $nl[$i] } else { '<缺>' }
      $y = if ($i -lt $pl.Count) { $pl[$i] } else { '<缺>' }
      if ($x -ne $y) { $nd++; if ($n1 -eq '') { $n1 = $x; $p1 = $y } }
    }
    $detail = ('不一致 ' + $nd + ' 行；首处差异 原生=[' + $n1.Trim() + '] 受保护=[' + $p1.Trim() + ']')
    [void]$report.Add([pscustomobject]@{ Func = $f; Verdict = 'WRONG'; Detail = $detail })
    Write-Host ('[WRONG  ] ' + $f + '  ' + $detail)
  }
}

Write-Host ''
Write-Host ('==== 汇总：可保护 ' + $ok + ' / 静默算错 ' + $wrong + ' / 被拒 ' + $refused + ' ====')
$csv = Join-Path $Work 'report.csv'
$report | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
Write-Host ('明细: ' + $csv)
if ($wrong -gt 0) { exit 2 }
if ($refused -gt 0) { exit 1 }
exit 0

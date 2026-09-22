# diffcheck.ps1 - 保护前逐函数差分自检 / 可保护性清单（目标项 4+5）
#
# 对候选函数**逐个**单独保护，然后比对输出，给三档结论：
#   REFUSED : 打包就被拒（附 lifter 原话，例如缺哪条指令）
#   WRONG   : 打包成功但输出不一致 —— 点名函数 + 不一致行数 + 首处差异
#   OK      : 输出一致
#
# 期望值来源（优先级从高到低）：
#   -Expect <file> : 客户自己的 ground truth / run_*.txt（推荐：验收口径与客户一致）
#   否则           : 跑一遍原始（未受保护）可执行文件的输出
#
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [string]$Map = '', # 可选：cl 构建的 PE 用 MAP；gcc 目标 vmpack 直接读符号表
  [Parameter(Mandatory=$true)][string]$FuncList,
  [string]$Expect = '',
  [string]$Args = '',
  [string]$Filter = '',
  [string]$Blob = '',
  [string]$Manifest = '',
  [int]$TimeoutSec = 30,
  [string]$Work = 'build\diffcheck',
  [string]$Markdown = ''
)
$ErrorActionPreference = 'Continue'
if ($PSScriptRoot) { Set-Location (Join-Path $PSScriptRoot '..') }
New-Item -ItemType Directory -Force -Path $Work | Out-Null

function Filter-Text([string]$t) {
  if (-not $Filter) { return $t.Trim() }
  $lines = $t -split "`n" | Where-Object { $_ -notmatch $Filter }
  return (($lines -join "`n").Trim())
}
function RunCapture([string]$exe, [string]$argstr) {
  $tmp = Join-Path $Work 'out.txt'
  Remove-Item $tmp -ErrorAction SilentlyContinue
  $sp = @{ FilePath = $exe; NoNewWindow = $true; PassThru = $true; RedirectStandardOutput = $tmp;
          RedirectStandardError = (Join-Path $Work 'err.txt') }
  if ($argstr) { $sp['ArgumentList'] = $argstr.Split(' ') }
  $p = Start-Process @sp
  if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch {}; return @{ Out = '<TIMEOUT>'; Code = -999 } }
  $out = ''
  if (Test-Path $tmp) { $out = (Get-Content $tmp -Raw) }
  if (-not $out) { $out = '' }
  return @{ Out = (Filter-Text $out); Code = $p.ExitCode }
}

if ($Expect) {
  if (-not (Test-Path $Expect)) { Write-Host ('[!] 找不到期望值文件 ' + $Expect); exit 3 }
  $expected = @{ Out = (Filter-Text (Get-Content $Expect -Raw)); Code = 'expect' }
  Write-Host ('期望值来源: ' + $Expect)
} else {
  $expected = RunCapture $Exe $Args
  Write-Host ('期望值来源: 原始可执行文件（exit=' + $expected.Code + '）')
}

$funcs = $FuncList.Split(',') | Where-Object { $_ -ne '' }
$ok = 0; $wrong = 0; $refused = 0
$report = New-Object System.Collections.ArrayList
foreach ($f in $funcs) {
  $out = Join-Path $Work 'one.exe'
  Remove-Item $out -ErrorAction SilentlyContinue
  $pa = @('-exe', $Exe, '-func', $f, '-out', $out)
  if ($Map) { $pa += @('-map', $Map) }
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
  if ($prot.Out -eq $expected.Out) {
    $ok++
    [void]$report.Add([pscustomobject]@{ Func = $f; Verdict = 'OK'; Detail = '' })
    Write-Host ('[OK     ] ' + $f)
  } else {
    $wrong++
    $nl = @($expected.Out -split "`n")
    $pl = @($prot.Out -split "`n")
    $nd = 0; $n1 = ''; $p1 = ''
    for ($i = 0; $i -lt [Math]::Max($nl.Count, $pl.Count); $i++) {
      $x = if ($i -lt $nl.Count) { $nl[$i] } else { '<缺>' }
      $y = if ($i -lt $pl.Count) { $pl[$i] } else { '<缺>' }
      if ($x -ne $y) { $nd++; if ($n1 -eq '') { $n1 = $x; $p1 = $y } }
    }
    $detail = ('不一致 ' + $nd + ' 行；首处差异 期望=[' + $n1.Trim() + '] 受保护=[' + $p1.Trim() + ']')
    [void]$report.Add([pscustomobject]@{ Func = $f; Verdict = 'WRONG'; Detail = $detail })
    Write-Host ('[WRONG  ] ' + $f + '  ' + $detail)
  }
}

Write-Host ''
Write-Host ('==== 汇总：可保护 ' + $ok + ' / 静默算错 ' + $wrong + ' / 被拒 ' + $refused + ' ====')
$csv = Join-Path $Work 'report.csv'
$report | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
Write-Host ('明细: ' + $csv)
if ($Markdown) {
  $src = '原始可执行文件'; if ($Expect) { $src = $Expect }
  $md = @()
  $md += '# 逐函数可保护性清单'
  $md += ''
  $md += ('- 产物: ' + $Exe)
  $md += ('- 期望值来源: ' + $src)
  $md += ('- 汇总: **可保护 ' + $ok + ' / 静默算错 ' + $wrong + ' / 被拒 ' + $refused + '**')
  $md += ''
  $md += '| 函数 | 结论 | 说明 |'
  $md += '|---|---|---|'
  foreach ($r in $report) { $md += ('| ' + $r.Func + ' | ' + $r.Verdict + ' | ' + ($r.Detail -replace '\|', '/') + ' |') }
  Set-Content -Path $Markdown -Value ($md -join "`n") -Encoding UTF8
  Write-Host ('清单(markdown): ' + $Markdown)
}
if ($wrong -gt 0) { exit 2 }
if ($refused -gt 0) { exit 1 }
exit 0

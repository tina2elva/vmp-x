# diffcheck.ps1 - 保护前逐函数差分自检 / 可保护性清单
#
# 结论三档：REFUSED（打包被拒，附 lifter 原话）/ WRONG（点名 + 不一致行数 + 首处差异）/ OK
# 期望值来源：-Expect <file>（客户自己的 ground truth / run_*.txt，推荐）；否则跑原始可执行文件。
# 函数名来源：-FuncList '?A@@YAXXZ,...'；或只给 -Map，脚本自己从 MAP 里挑带 f 标志的函数。
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [string]$Map = '',
  [string]$FuncList = '',
  [string]$FuncFilter = '', # 只跑名字匹配该正则的函数（MAP 自动模式下特别有用，例如 'Demo|Math'）
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
# 控制台按 UTF-8 输出：否则中文在 GBK(936) 代码页的窗口里显示成乱码
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
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
  # 不能把空数组传给 -ArgumentList（PS 报参数校验失败 ⇒ 两边都空 ⇒ 假 OK）
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

# 从 MAP 取函数名：MSVC 的 MAP 行形如
#   0001:00000530       ?DemoAdd@@YAHHH@Z          0000000140001530 f   demo_exe.obj
# 第三个字段是地址、第四个含 f 才表示函数（字符串常量没有 f）。
function Get-FuncsFromMap([string]$path) {
  $re = '^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+[0-9A-Fa-f]{16}\s+(.+?)\s*$'
  $names = New-Object System.Collections.ArrayList
  foreach ($line in (Get-Content $path)) {
    $m = [regex]::Match($line, $re)
    if (-not $m.Success) { continue }
    if ($m.Groups[2].Value -notmatch '(^|\s)f(\s|$)') { continue }
    [void]$names.Add($m.Groups[1].Value)
  }
  return $names
}

if ($FuncList) {
  $funcs = $FuncList.Split(',') | Where-Object { $_ -ne '' }
} elseif ($Map -and (Test-Path $Map)) {
  $funcs = Get-FuncsFromMap $Map
  if ($FuncFilter) { $funcs = @($funcs) | Where-Object { $_ -match $FuncFilter } }
  Write-Host ('函数名来源: 从 MAP 自动提取（' + @($funcs).Count + ' 个' + $(if ($FuncFilter) { '，已按 ' + $FuncFilter + ' 过滤' } else { '' }) + '）')
} else {
  Write-Host '[!] 需要 -FuncList，或给出 -Map 让脚本自己取函数名'; exit 3
}
if (@($funcs).Count -eq 0) { Write-Host '[!] 没有可用的函数名'; exit 3 }

if ($Expect) {
  if (-not (Test-Path $Expect)) { Write-Host ('[!] 找不到期望值文件 ' + $Expect); exit 3 }
  $expected = @{ Out = (Filter-Text (Get-Content $Expect -Raw)); Code = 'expect' }
  Write-Host ('期望值来源: ' + $Expect)
} else {
  $expected = RunCapture $Exe $Args
  Write-Host ('期望值来源: 原始可执行文件（exit=' + $expected.Code + '）')
}

$ok = 0; $wrong = 0; $refused = 0
$report = New-Object System.Collections.ArrayList
foreach ($f in $funcs) {
  $out = Join-Path $Work 'one.exe'
  Remove-Item $out -ErrorAction SilentlyContinue
  $pa = @('-exe', $Exe, '-func', $f, '-out', $out)
  if ($Map) { $pa += @('-map', $Map) }
  if ($Blob) { $pa += @('-blob', $Blob) }
  if ($Manifest) { $pa += @('-manifest', $Manifest) }
  # vmpack 是原生程序、输出走 ANSI(GBK)：按 Default 读才不会乱码
  # 注意：stdout/stderr **不能**重定向到同一个文件（PS 会直接报错 ⇒ 每次都被当成打包失败）
  $pkOut = Join-Path $Work 'pack_out.txt'
  $pkErr = Join-Path $Work 'pack_err.txt'
  Remove-Item $pkOut, $pkErr -ErrorAction SilentlyContinue
  $sp2 = @{ FilePath = '.\build\vmpack.exe'; ArgumentList = $pa; NoNewWindow = $true; PassThru = $true;
            RedirectStandardOutput = $pkOut; RedirectStandardError = $pkErr }
  $pk = Start-Process @sp2
  $pk.WaitForExit() | Out-Null
  $packOut = ''
  # 原生程序的输出是 ANSI(GBK)：按 Default 读才不乱码
  if (Test-Path $pkOut) { $packOut += (Get-Content $pkOut -Raw -Encoding Default) }
  if (Test-Path $pkErr) { $packOut += (Get-Content $pkErr -Raw -Encoding Default) }
  if (-not (Test-Path $out)) {
    $refused++
    $lines = $packOut -split "`n" | Where-Object { $_.Trim() -ne '' }
    $reason = ($lines | Where-Object { $_ -match '无法翻译' } | Select-Object -First 1)
    if (-not $reason) { $reason = ($lines | Where-Object { $_ -notmatch '未烘焙厂商根公钥' } | Select-Object -First 1) }
    if (-not $reason) { $reason = '打包失败' }
    $reason = $reason.Trim()
    [void]$report.Add([pscustomobject]@{ Func = $f; Verdict = 'REFUSED'; Detail = $reason })
    Write-Host ('[REFUSED] ' + $f + '  ' + $reason)
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

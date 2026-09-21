# acceptance_demo.ps1 - vmp-x 商业化闭环验收（在客户自己的 demo 上端到端跑一遍）
#
# 覆盖：① 厂商根 -> 构建凭据（工具授权）  ② 客户密钥纪元  ③ 外置密钥保护客户软件
#       ④ 授权链（根 -> 销售(canIssue) -> 客户 -> 下游授权，离线、客户自签）
#       ⑤ 运行期强制（无授权 -> 0xC0DE0007；有授权 -> 与原生逐行一致）
#       ⑥ 授权更新（增删产品/到期，不动软件、不换密钥）
#
# 用法：
#   powershell -NoProfile -File tools/acceptance_demo.ps1 -BuildDemo
#   powershell -NoProfile -File tools/acceptance_demo.ps1 -DemoExe X.exe -DemoMap X.map
#
# 注意：vmpack 靠 **MAP 文件**按名字定位函数（不读 PDB）。客户自带的 demo64.exe 没有 .map，
#       所以本脚本要么用 -BuildDemo 现场用 MSVC 重编一份带 /MAP 的，要么由 -DemoMap 指定。

param(
  [string]$DemoExe = 'D:\demo_exe\demo64.exe',
  [string]$DemoMap = '',
  [string]$DemoSrc = 'D:\demo_exe\demo_exe.cpp',
  [string]$FuncList = '',
  [string]$VendorID = 'ACME-0001',
  [string]$ProductID = 'PROD-DEMO',
  [string]$Work = 'build\acceptance',
  [switch]$BuildDemo,
  [switch]$KeepWork
)
$ErrorActionPreference = 'Continue'
if ($PSScriptRoot) { Set-Location (Join-Path $PSScriptRoot '..') }
$pass = 0
$fail = 0
function Check([string]$name, [bool]$ok, [string]$detail) {
  if ($ok) { $script:pass++; Write-Host ('[OK  ] ' + $name) }
  else { $script:fail++; Write-Host ('[FAIL] ' + $name + '  ' + $detail) }
}
function RunExe([string]$exe, [string[]]$argv) {
  $o = & $exe @argv 2>&1 | Out-String
  return @{ Code = $LASTEXITCODE; Out = $o.Trim() }
}

Write-Host '==== vmp-x 商业化闭环验收 ===='
Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Work | Out-Null
New-Item -ItemType Directory -Force -Path "$Work\tool" | Out-Null

# ---------- A. 工具链 ----------
Write-Host ''
Write-Host '--- A. 工具链 ---'
& go build -o build/vmpbuild.exe ./cmd/vmpbuild
Check 'A1 vmpbuild 构建' ($LASTEXITCODE -eq 0) ('exit=' + $LASTEXITCODE)
& go build -o build/vmpack.exe ./cmd/vmpack
Check 'A2 vmpack 构建' ($LASTEXITCODE -eq 0) ('exit=' + $LASTEXITCODE)
& go build -o build/vmpepoch.exe ./cmd/vmpepoch
Check 'A3 vmpepoch 构建' ($LASTEXITCODE -eq 0) ('exit=' + $LASTEXITCODE)

# ---------- 准备 demo（需要带 MAP 的名字表）----------
Write-Host ''
Write-Host '--- 准备客户程序 ---'
$demoBin = $DemoExe
$demoMap = $DemoMap
if ($BuildDemo) {
  if (-not (Test-Path $DemoSrc)) { Write-Host ("[FAIL] 找不到 demo 源码 " + $DemoSrc); $fail++; }
  else {
    $vc = '"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"'
    $cmd = "$vc x64 >nul && cd /d " + (Resolve-Path $Work).Path + " && cl /nologo /utf-8 /O2 /Zi /MD /EHsc /W3 $DemoSrc /Fe:demo64.exe /link /DEBUG /PDB:demo64.pdb /MAP:demo64.map"
    cmd /c $cmd 2>&1 | Out-Null
    $demoBin = (Join-Path $Work 'demo64.exe')
    $demoMap = (Join-Path $Work 'demo64.map')
    Check 'B1 用 MSVC 重编客户程序（带 /MAP）' ((Test-Path $demoBin) -and (Test-Path $demoMap)) 'cl 失败或缺 map'
  }
}
if (-not (Test-Path $demoBin)) { Write-Host ('[FAIL] 找不到客户程序 ' + $demoBin); $fail++ }
if (-not (Test-Path $demoMap)) { Write-Host '[FAIL] 没有 MAP 文件：vmpack 无法按名字定位函数（用 -BuildDemo 或 -DemoMap）'; $fail++ }
if (-not $FuncList) {
  $FuncList = '?DemoAdd@@YAHHH@Z,?DemoFactorial@@YA_JH@Z,?DemoFibonacci@@YA_JH@Z,?DemoFibonacciRec@@YA_JH@Z,?DemoFingerprint@@YAIPEBHHHH@Z,?DemoFormatReport@@YAHPEADHPEBDH@Z,?DemoReverseArray@@YAXPEAHH@Z,?DemoSumArray@@YAHPEBHH@Z,?Add@Math@Demo@@QEAAHHH@Z,?Fibonacci@Math@Demo@@QEAA_JH@Z,?SumArray@Math@Demo@@QEAAHPEBHH@Z'
}
$funcs = $FuncList.Split(',') | Where-Object { $_ -ne '' }

# ---------- ① 厂商根 + 构建凭据（工具授权）----------
Write-Host ''
Write-Host '--- ① 厂商根 + 构建凭据（工具授权）---'
$root = "$Work\vendor-root"
& .\build\vmpepoch.exe keygen --out $root 2>&1 | Out-Null
Check '①-1 生成厂商根密钥对' ((Test-Path "$root.priv") -and (Test-Path "$root.pub")) ''
$custTool = "$Work\tool\custTool"
& .\build\vmpepoch.exe keygen --out $custTool 2>&1 | Out-Null
& .\build\vmpepoch.exe cert-req --key "$custTool.priv" --vendor $VendorID --note 'custTool/license' --out "$Work\tool.req.json" 2>&1 | Out-Null
Check '①-2 客户生成工具密钥并提交（含持有证明）' (Test-Path "$Work\tool.req.json") ''
& .\build\vmpepoch.exe cred-issue --root "$root.priv" --req "$Work\tool.req.json" --vendor $VendorID --until 2030-01-01 --out "$Work\tool\vmpx.cred" 2>&1 | Out-Null
Check '①-3 厂商签发构建凭据' (Test-Path "$Work\tool\vmpx.cred") ''
$rootPubHex = (Get-Content "$root.pub" -Raw).Trim()
& go build -ldflags ('-X github.com/vmpx/vmp-x/internal/cred.RootPubHex=' + $rootPubHex) -o "$Work\tool\vmpbuild_lic.exe" ./cmd/vmpbuild
Check '①-4 打一个烘了厂商根公钥的发布版 vmpbuild' (Test-Path "$Work\tool\vmpbuild_lic.exe") ''
# 先把凭据挪走：没有授权就必须拒绝工作
Move-Item "$Work\tool\vmpx.cred" "$Work\tool\_cred" -Force
$rNocred = RunExe "$Work\tool\vmpbuild_lic.exe" @('-src', 'stub/win/x64', '-out', "$Work\x.bin", '-manifest', "$Work\x.json", '-entry', 'vm_entry')
Check '①-5 没有凭据 -> 工具拒绝工作（exit 8）' ($rNocred.Code -eq 8) ('exit=' + $rNocred.Code + ' out=' + $rNocred.Out.Substring(0, [Math]::Min(60, $rNocred.Out.Length)))
Move-Item "$Work\tool\_cred" "$Work\tool\vmpx.cred" -Force
Copy-Item "$custTool.priv" "$Work\tool\vmpx.key" -Force
$rOk = RunExe "$Work\tool\vmpbuild_lic.exe" @('-src', 'stub/win/x64', '-out', "$Work\x.bin", '-manifest', "$Work\x.json", '-entry', 'vm_entry')
Check '①-6 凭据+私钥齐全 -> 工具可用' ($rOk.Code -eq 0) ('exit=' + $rOk.Code)

# ---------- ②③ 密钥纪元 + 保护客户软件 ----------
Write-Host ''
Write-Host '--- ②③ 密钥纪元 + 保护客户软件 ---'
$epoch = "$Work\epoch"
$blob = "$epoch\blob.bin"
$man = "$epoch\blob.json"
$projKey = "$epoch\project.vmpkey"
& .\build\vmpepoch.exe new --name demo-epoch --dir $epoch --src stub/win/x64 --registry "$Work\epochs.json" --note '验收用纪元' 2>&1 | Out-Null
Check '②-1 建立密钥纪元（blob+manifest+密钥）' ((Test-Path $blob) -and (Test-Path $man) -and (Test-Path $projKey)) ''
$app = "$Work\app.exe"
$packArgs = @('-exe', $demoBin, '-map', $demoMap, '-out', $app, '-blob', $blob, '-manifest', $man,
              '-license-vendor', $VendorID, '-license-product', $ProductID, '-license-pub', "$epoch\..\issuer.pub")
# 先把「客户的签发者密钥」准备好（④ 里客户给下游签授权用它）
$issuer = "$Work\issuer"
& .\build\vmpepoch.exe keygen --out $issuer 2>&1 | Out-Null
$packArgs = @('-exe', $demoBin, '-map', $demoMap, '-out', $app, '-blob', $blob, '-manifest', $man,
              '-license-vendor', $VendorID, '-license-product', $ProductID, '-license-pub', "$issuer.pub")
foreach ($f in $funcs) { $packArgs += @('-func', $f) }
& .\build\vmpack.exe @packArgs 2>&1 | Out-Null
Check '③-1 保护客户软件（外置密钥 + 运行期强制 + 多函数）' ((Test-Path $app) -and ($LASTEXITCODE -eq 0)) ('exit=' + $LASTEXITCODE)
& .\build\vmpepoch.exe which --exe $app --registry "$Work\epochs.json" 2>&1 | Out-Null
Check '②-2 产物可归属到该纪元（epochs.json）' ($LASTEXITCODE -eq 0) ''
Copy-Item $projKey "$app.vmpkey" -Force

# ---------- ④ 授权链 ----------
Write-Host ''
Write-Host '--- ④ 授权链（根 -> 销售 -> 客户 -> 下游）---'
$sales = "$Work\sales"
& .\build\vmpepoch.exe keygen --out $sales 2>&1 | Out-Null
& .\build\vmpepoch.exe cert-req --key "$sales.priv" --vendor $VendorID --note 'sales' --out "$Work\sales.req.json" 2>&1 | Out-Null
& .\build\vmpepoch.exe cert-issue --root "$root.priv" --req "$Work\sales.req.json" --vendor $VendorID --until 2030-01-01 --can-issue --out "$Work\sales.cert.json" 2>&1 | Out-Null
Check '④-1 根给销售部签「可继续签发」证书' (Test-Path "$Work\sales.cert.json") ''
& .\build\vmpepoch.exe cert-req --key "$issuer.priv" --vendor $VendorID --note 'cust issuer' --out "$Work\cust.req.json" 2>&1 | Out-Null
& .\build\vmpepoch.exe cert-issue --issuer "$Work\sales.cert.json" --issuer-key "$sales.priv" --root-pub "$root.pub" --req "$Work\cust.req.json" --vendor $VendorID --until 2029-01-01 --out "$Work\cust.cert.json" 2>&1 | Out-Null
Check '④-2 销售部给客户签发（链深 1）' (Test-Path "$Work\cust.cert.json") ''
& .\build\vmpepoch.exe cert-issue --issuer "$Work\cust.cert.json" --issuer-key "$issuer.priv" --root-pub "$root.pub" --req "$Work\sales.req.json" --vendor $VendorID --out "$Work\bad.cert.json" 2>&1 | Out-Null
Check '④-3 无 canIssue 的证书不能签发下级（拒绝）' ($LASTEXITCODE -ne 0) ('exit=' + $LASTEXITCODE)
$licJson = "$Work\lic.json"
& .\build\vmpepoch.exe lic-new --vendor $VendorID --dongle 'A-A' --key "$issuer.priv" --cert "$Work\cust.cert.json" --out $licJson --product ($ProductID + '@2027-12-31') 2>&1 | Out-Null
& .\build\vmpepoch.exe lic-export --lic $licJson --key "$issuer.priv" --root-pub "$root.pub" --out "$app.vmplic.bin" 2>&1 | Out-Null
Check '④-4 客户给下游签发授权并导出（导出前验链）' (Test-Path "$app.vmplic.bin") ('exit=' + $LASTEXITCODE)

# ---------- ⑤ 运行期强制 ----------
Write-Host ''
Write-Host '--- ⑤ 运行期强制 ---'
$native = RunExe $demoBin @() 
# 只比数值行：demo 会打印基址与函数地址（每次运行不同），那几行以 [demo.exe] 开头。
$nativeLines = ($native.Out -split "`n") | Where-Object { ($_ -match '=' -or $_ -match '->') -and ($_ -notmatch '^\[demo\.exe\]') }
# a) 没有授权文件
Move-Item "$app.vmplic.bin" "$Work\_lic" -Force
$rNo = RunExe $app @()
Check '⑤-1 无授权 -> 恰好 0xC0DE0007、无输出' ((($rNo.Code -band 0xFFFFFFFF) -eq 0xC0DE0007) -and ($rNo.Out -eq '')) ('exit=0x' + ('{0:X8}' -f ($rNo.Code -band 0xFFFFFFFF)))
Move-Item "$Work\_lic" "$app.vmplic.bin" -Force
# b) 合法授权 -> 与原生逐行一致
$prot = RunExe $app @()
$protLines = ($prot.Out -split "`n") | Where-Object { ($_ -match '=' -or $_ -match '->') -and ($_ -notmatch '^\[demo\.exe\]') }
$same = (($nativeLines -join "`n") -eq ($protLines -join "`n")) -and ($nativeLines.Count -gt 0)
Check ('⑤-2 有授权 -> 与原生逐行一致（' + $nativeLines.Count + ' 行）') $same '输出不一致'
# c) 篡改一字节
$lb = [System.IO.File]::ReadAllBytes((Resolve-Path "$app.vmplic.bin").Path)
$lb[0x20] = $lb[0x20] -bxor 0xFF
[System.IO.File]::WriteAllBytes((Resolve-Path "$app.vmplic.bin").Path, $lb)
$rT = RunExe $app @()
Check '⑤-3 篡改授权 -> 0xC0DE0007' ((($rT.Code -band 0xFFFFFFFF) -eq 0xC0DE0007) -and ($rT.Out -eq '')) ('exit=0x' + ('{0:X8}' -f ($rT.Code -band 0xFFFFFFFF)))
# d) 过期
& .\build\vmpepoch.exe lic-new --vendor $VendorID --dongle 'A-B' --key "$issuer.priv" --cert "$Work\cust.cert.json" --out "$Work\exp.json" --product ($ProductID + '@2020-01-01') 2>&1 | Out-Null
& .\build\vmpepoch.exe lic-export --lic "$Work\exp.json" --key "$issuer.priv" --out "$app.vmplic.bin" 2>&1 | Out-Null
$rE = RunExe $app @()
Check '⑤-4 过期授权 -> 0xC0DE0007' ((($rE.Code -band 0xFFFFFFFF) -eq 0xC0DE0007) -and ($rE.Out -eq '')) ('exit=0x' + ('{0:X8}' -f ($rE.Code -band 0xFFFFFFFF)))
# e) 伪造签名
$evil = "$Work\evil"
& .\build\vmpepoch.exe keygen --out $evil 2>&1 | Out-Null
& .\build\vmpepoch.exe lic-new --vendor $VendorID --dongle 'A-C' --key "$evil.priv" --out "$Work\forge.json" --product ($ProductID + '@2027-12-31') 2>&1 | Out-Null
& .\build\vmpepoch.exe lic-export --lic "$Work\forge.json" --key "$evil.priv" --out "$app.vmplic.bin" 2>&1 | Out-Null
$rF = RunExe $app @()
Check '⑤-5 伪造签名 -> 0xC0DE0007' ((($rF.Code -band 0xFFFFFFFF) -eq 0xC0DE0007) -and ($rF.Out -eq '')) ('exit=0x' + ('{0:X8}' -f ($rF.Code -band 0xFFFFFFFF)))

# ---------- ⑥ 授权更新 ----------
Write-Host ''
Write-Host '--- ⑥ 授权更新（不动软件、不换密钥）---'
& .\build\vmpepoch.exe lic-export --lic $licJson --key "$issuer.priv" --out "$app.vmplic.bin" 2>&1 | Out-Null
& .\build\vmpepoch.exe lic-edit --lic $licJson --key "$issuer.priv" --add 'PROD-EXTRA@perpetual' 2>&1 | Out-Null
$before = (Get-FileHash $app).Hash
& .\build\vmpepoch.exe lic-export --lic $licJson --key "$issuer.priv" --root-pub "$root.pub" --out "$app.vmplic.bin" 2>&1 | Out-Null
$after = (Get-FileHash $app).Hash
$rU = RunExe $app @()
$uLines = ($rU.Out -split "`n") | Where-Object { ($_ -match '=' -or $_ -match '->') -and ($_ -notmatch '^\[demo\.exe\]') }
Check '⑥-1 更新授权后：产物未变、程序照常、输出一致' (($before -eq $after) -and (($uLines -join "`n") -eq ($nativeLines -join "`n"))) '产物被改动或输出不一致'

# ---------- 汇总 ----------
Write-Host ''
Write-Host '==== 汇总 ===='
Write-Host ('通过 ' + $pass + ' 项，失败 ' + $fail + ' 项')
if (-not $KeepWork) { Write-Host ('（工作目录保留在 ' + $Work + '，便于排查）') }
if ($fail -gt 0) { exit 1 }
Write-Host '[+] vmp-x 商业化闭环验收：全部通过'

# tools/preflight.ps1 - 交接自检：把"这一项做完了"变成机械判定。
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File tools/preflight.ps1
# 覆盖: blob 重建 / Go 测试 / demo64 打包 / demo64 运行期与暴露面。
# 另需人工（耗时较长，不在本脚本内）: tools/gates.ps1 与 CI 五个作业。
$ErrorActionPreference = 'Continue'
$fail = 0
function Step($name, $ok) { if ($ok) { Write-Host "[OK  ] $name" } else { Write-Host "[FAIL] $name"; $script:fail++ } }

Write-Host '[*] 1/4 重建 blob（新增源文件必须真进编译单元）'
& .\build\vmpbuild.exe -src stub\win\x64 -out build\vm_interp.bin -manifest build\vm_interp.json -entry vm_entry *> build\preflight_blob.log
Step 'blob 重建' ($LASTEXITCODE -eq 0)

Write-Host '[*] 2/4 Go 测试'
$t = (go test ./... 2>&1 | Out-String)
Step 'go test ./...' ($LASTEXITCODE -eq 0 -and ($t -notmatch 'FAIL'))

Write-Host '[*] 3/4 demo64 打包（无 COFF 符号，走合成 MAP）'
if (-not (Test-Path build\demo64.map)) { Write-Host '[FAIL] 缺 build\demo64.map：按 docs/HANDOFF.md 第 5 节从 ground_truth_exe.txt 生成'; $fail++ }
else {
  & .\build\vmpack.exe -exe 'D:\demo_exe\demo64.exe' -map build\demo64.map -func DemoAdd -func DemoFibonacci -func DemoFactorial -func DemoGcd -blob build\vm_interp.bin -manifest build\vm_interp.json -out build\preflight_demo64.exe -report build\preflight_demo64.json *> build\preflight_pack.log
  Step 'vmpack 打包成功' ($LASTEXITCODE -eq 0 -and (Test-Path build\preflight_demo64.exe))
}

Write-Host '[*] 4/4 运行期行为与暴露面'
if (Test-Path build\preflight_demo64.exe) {
  $n = (& 'D:\demo_exe\demo64.exe' 2>&1 | Out-String); $nrc = $LASTEXITCODE
  $p = (& .\build\preflight_demo64.exe 2>&1 | Out-String); $prc = $LASTEXITCODE
  $nl = ($n.Trim() -split [char]10); $pl = ($p.Trim() -split [char]10)
  $diff = 0
  $m = [Math]::Min($nl.Count, $pl.Count)
  for ($i = 0; $i -lt $m; $i++) { if ($nl[$i] -ne $pl[$i]) { $diff++ } }
  Step '退出码一致' ($nrc -eq $prc)
  Step '输出差异 <= 2 行（打印 base/地址，属固定基址的预期）' ($diff -le 2)
  python tools\expose_report.py --img 'D:\demo_exe\demo64.exe' --compare build\preflight_demo64.exe --sections .text,.rdata,.data --max-ratio 0.05 | Out-Null
  Step '暴露面门禁（--max-ratio 0.05）' ($LASTEXITCODE -eq 0)
}
Write-Host ''
if ($fail -eq 0) { Write-Host '[+] preflight: OK（仍须另跑 tools/gates.ps1=11/0 与 CI 五作业全绿）'; exit 0 }
Write-Host ("[!] preflight: " + $fail + " 项未过"); exit 1

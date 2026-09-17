$ErrorActionPreference = "Stop"
Set-Location "D:\vmp-x"
$p = "cmd/vmpbuild/main.go"
$t = [System.IO.File]::ReadAllText($p)
$start = $t.IndexOf("func buildBlobOld(")
$end = $t.IndexOf("func isASCII(")
if ($start -lt 0) { Write-Output "no buildBlobOld; nothing to do"; exit 0 }
if ($end -le $start) { throw "locate failed" }
$t2 = $t.Substring(0, $start) + $t.Substring($end)
[System.IO.File]::WriteAllText($p, $t2)
Write-Output ("removed " + ($end - $start) + " chars of dead code")

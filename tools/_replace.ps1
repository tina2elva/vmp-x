$ErrorActionPreference = "Stop"
Set-Location "D:\vmp-x"
$p = "cmd\vmpbuild\main.go"
$t = [System.IO.File]::ReadAllText($p)
$start = $t.IndexOf("func buildBlobOld(")
$end = $t.IndexOf("func isASCII(")
if ($start -lt 0 -or $end -lt 0 -or $end -le $start) { throw ("locate failed start=" + $start + " end=" + $end) }
$new = [System.IO.File]::ReadAllText("build\newfuncs.txt")
$t2 = $t.Substring(0, $start) + $new + $t.Substring($end)
[System.IO.File]::WriteAllText($p, $t2)
Write-Output ("replaced chars: " + ($end - $start))

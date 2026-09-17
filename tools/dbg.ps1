$cwd = (Get-Location).Path
"cwd=$cwd"
"exists=" + (Test-Path build/target.exe)
function Run-T([string]$exe, [string[]]$a, [int]$sec) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Resolve-Path $exe).Path
    $psi.WorkingDirectory = $cwd
    $psi.Arguments = ($a -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEnd()
    $e = $p.StandardError.ReadToEnd()
    $exited = $p.WaitForExit($sec * 1000)
    "  fileName=" + $psi.FileName + " args=" + $psi.Arguments + " exited=" + $exited + " code=" + $p.ExitCode + " out=[" + $o.Trim() + "] err=[" + $e.Trim() + "]"
    return @{ ok = ($exited -and ($p.ExitCode -eq 0)); out = $o.Trim() }
}
"native:"
$r1 = Run-T "build/target.exe" @("check_key", "10") 20
"  ok=" + $r1.ok
"protected:"
$r2 = Run-T "build/target_vmp.exe" @("check_key", "10") 20
"  ok=" + $r2.ok

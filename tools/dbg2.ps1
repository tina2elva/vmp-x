$cwd = (Get-Location).Path
function Run-T([string]$exe, [string[]]$a, [int]$sec) {
    $path = (Resolve-Path $exe).Path
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $path
        $psi.WorkingDirectory = $cwd
        $psi.Arguments = ($a -join [char]32)
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        try {
            $p = [System.Diagnostics.Process]::Start($psi)
            $o = $p.StandardOutput.ReadToEnd()
            $e = $p.StandardError.ReadToEnd()
            if (-not $p.WaitForExit($sec * 1000)) { try { $p.Kill() } catch {}; return "TIMEOUT" }
            return "exit=" + $p.ExitCode + " out=[" + $o.Trim() + "] err=[" + $e.Trim() + "]"
        } catch { $last = $_.Exception.Message }
        Start-Sleep -Milliseconds 300
    }
    return "STARTFAIL: " + $last
}
Write-Output ("sum_to 9999 vmp      : " + (Run-T "build/target_vmp.exe" @("sum_to", "9999") 20))
Write-Output ("sum_to 100 vmp       : " + (Run-T "build/target_vmp.exe" @("sum_to", "100") 20))
Write-Output ("bench sum_to 10000   : " + (Run-T "build/target_vmp.exe" @("bench", "sum_to", "10000") 60))
Write-Output ("bench check_key 300000: " + (Run-T "build/target_vmp.exe" @("bench", "check_key", "300000") 60))
Write-Output ("bench sum_to 100000  : " + (Run-T "build/target_vmp.exe" @("bench", "sum_to", "100000") 120))

# Kit helpers for Windows test jobs. In a job:  iex (irm -useb "$CpServer/g/cpk.ps1")
# ($CpServer, $CpVm and up come from the agent's job prelude.)
$global:CpScoreReport = 'C:\aeacus\assets\ScoringReport.html'

function global:Install-Kit([string]$Config = 'cp-config.txt') {
    Set-Location C:\
    Invoke-WebRequest -UseBasicParsing "$CpServer/f/kit.zip" -OutFile C:\cpkit.zip
    if (Test-Path C:\cpkit) { Remove-Item C:\cpkit -Recurse -Force }
    Expand-Archive C:\cpkit.zip C:\cpkit -Force
    Invoke-WebRequest -UseBasicParsing "$CpServer/f/$Config" -OutFile C:\cpkit\cp-config.txt
    "kit installed: $((Get-ChildItem C:\cpkit -Recurse -File).Count) files, config $Config"
}

# One harden.ps1 run. Streams the console output (live in the heartbeat, and the job result) and
# uploads findings + log. A hang is reported, not waited out: on timeout it lists services stuck in
# a Pending state and the kit's child processes, then kills the run.
function global:Run-Kit([string]$Tag, [string[]]$KitArgs, [int]$Timeout = 900) {
    Set-Location C:\cpkit
    $t0 = Get-Date; $out = "C:\$Tag.txt"
    # The agent is SYSTEM, but the kit protects "the user running it" ($env:USERNAME). Act as the
    # signed-in team member, like a real run from their admin PowerShell.
    $saved = $env:USERNAME
    $who = [string](Get-CimInstance Win32_ComputerSystem).UserName
    if ($who) { $env:USERNAME = ($who -split '\\')[-1] }
    $argv = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', '.\windows\harden.ps1') + $KitArgs
    $p = Start-Process powershell.exe -ArgumentList $argv -PassThru -RedirectStandardOutput $out -RedirectStandardError "$out.err"
    $null = $p.Handle
    $env:USERNAME = $saved
    "### $Tag started"
    $seen = 0; $timedOut = $false
    while (-not $p.HasExited) {
        Start-Sleep 3
        $now = @(Get-Content $out -ErrorAction SilentlyContinue)
        if ($now.Count -gt $seen) { $now[$seen..($now.Count - 1)]; $seen = $now.Count }
        if (((Get-Date) - $t0).TotalSeconds -ge $Timeout) { $timedOut = $true; break }
    }
    if ($timedOut) {
        "### TIMEOUT after ${Timeout}s - services in a Pending state:"
        Get-Service | Where-Object { [string]$_.Status -match 'Pending' } | ForEach-Object { "    $($_.Name) ($($_.DisplayName)): $($_.Status)" }
        "### child processes of the kit:"
        Get-CimInstance Win32_Process -Filter "ParentProcessId=$($p.Id)" | ForEach-Object { "    $($_.ProcessId) $($_.CommandLine)" }
        & taskkill.exe /PID $p.Id /T /F 2>&1 | Out-Null
    }
    [void]$p.WaitForExit(10000)
    $now = @(Get-Content $out -ErrorAction SilentlyContinue)
    if ($now.Count -gt $seen) { $now[$seen..($now.Count - 1)] }
    if ((Test-Path "$out.err") -and (Get-Item "$out.err").Length) { '--- stderr ---'; Get-Content "$out.err" }
    $r = (Get-ChildItem C:\cpkit-runs -Directory | Sort-Object Name | Select-Object -Last 1).FullName
    up "$Tag-findings.txt" (Get-Content "$r\findings.txt" -Raw -ErrorAction SilentlyContinue)
    up "$Tag-log.txt" (Get-Content "$r\log.txt" -Raw -ErrorAction SilentlyContinue)
    up "$Tag.txt" (Get-Content $out -Raw)
    "### $Tag finished in $([int]((Get-Date) - $t0).TotalSeconds)s (timed out: $timedOut), run dir $r"
}

# Upload the scoring report; with -Wait, first wait for the scorer to rewrite it.
function global:Get-Score([string]$Tag, [int]$Wait = 0) {
    if (-not (Test-Path $CpScoreReport)) { return "no score report at $CpScoreReport" }
    $before = (Get-Item $CpScoreReport).LastWriteTime; $t0 = Get-Date
    while ($Wait -gt 0 -and (Get-Item $CpScoreReport).LastWriteTime -eq $before -and ((Get-Date) - $t0).TotalSeconds -lt $Wait) { Start-Sleep 5 }
    up "$Tag-score.html" (Get-Content $CpScoreReport -Raw)
    "score report $Tag written $((Get-Item $CpScoreReport).LastWriteTime)"
}

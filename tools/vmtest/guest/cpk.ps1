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

# One harden.ps1 run. Prints the console output (the job result) and uploads findings + log.
function global:Run-Kit([string]$Tag, [string[]]$KitArgs) {
    Set-Location C:\cpkit
    $t0 = Get-Date
    # The agent is SYSTEM, but the kit protects "the user running it" ($env:USERNAME). Act as the
    # signed-in team member, like a real run from their admin PowerShell.
    $saved = $env:USERNAME
    $who = [string](Get-CimInstance Win32_ComputerSystem).UserName
    if ($who) { $env:USERNAME = ($who -split '\\')[-1] }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\harden.ps1 @KitArgs *> "C:\$Tag.txt"
    $env:USERNAME = $saved
    $r = (Get-ChildItem C:\cpkit-runs -Directory | Sort-Object Name | Select-Object -Last 1).FullName
    up "$Tag-findings.txt" (Get-Content "$r\findings.txt" -Raw -ErrorAction SilentlyContinue)
    up "$Tag-log.txt" (Get-Content "$r\log.txt" -Raw -ErrorAction SilentlyContinue)
    up "$Tag.txt" (Get-Content "C:\$Tag.txt" -Raw)
    "### $Tag ($([int]((Get-Date) - $t0).TotalSeconds)s, run dir $r)"
    Get-Content "C:\$Tag.txt"
}

# Upload the scoring report; with -Wait, first wait for the scorer to rewrite it.
function global:Get-Score([string]$Tag, [int]$Wait = 0) {
    if (-not (Test-Path $CpScoreReport)) { return "no score report at $CpScoreReport" }
    $before = (Get-Item $CpScoreReport).LastWriteTime; $t0 = Get-Date
    while ($Wait -gt 0 -and (Get-Item $CpScoreReport).LastWriteTime -eq $before -and ((Get-Date) - $t0).TotalSeconds -lt $Wait) { Start-Sleep 5 }
    up "$Tag-score.html" (Get-Content $CpScoreReport -Raw)
    "score report $Tag written $((Get-Item $CpScoreReport).LastWriteTime)"
}

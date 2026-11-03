# Installs the cpkit test agent on a PRACTICE Windows VM (never on a competition image).
# In an ADMIN PowerShell in the VM, type:   iex(irm -useb 192.168.209.1:8765/a)
# Afterwards the agent runs as SYSTEM: lock screen, sign-out and reboots do not stop it.
# Remove later:  Unregister-ScheduledTask cpkit-test-agent -Confirm:$false; Remove-Item C:\ProgramData\cpagent -Recurse -Force
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$S = '{{SERVER}}'
$root = Join-Path $env:ProgramData 'cpagent'
$task = 'cpkit-test-agent'

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Run this in an ADMIN PowerShell (right-click Start > Windows PowerShell (Admin)).' -ForegroundColor Red; return
}
New-Item -ItemType Directory -Force $root | Out-Null
$code = [Text.Encoding]::UTF8.GetString((Invoke-WebRequest -UseBasicParsing "$S/g/win-agent.ps1").RawContentStream.ToArray()).TrimStart([char]0xFEFF)
[IO.File]::WriteAllText((Join-Path $root 'agent.ps1'), $code, (New-Object Text.UTF8Encoding $true))

if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'cpagent\\agent\.ps1' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$root\agent.ps1`""
$triggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5))   # watchdog
)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $task -Action $action -Trigger $triggers -Settings $settings -User 'NT AUTHORITY\SYSTEM' -RunLevel Highest `
    -Description 'cpkit practice-VM test agent (PRACTICE ONLY)' -Force | Out-Null
Start-ScheduledTask -TaskName $task

# A sleeping VM stops everything. Display sleep and the lock screen are harmless now (agent = SYSTEM),
# so the scored screen-saver / inactivity-lock settings are left alone.
& powercfg.exe /change standby-timeout-ac 0 2>&1 | Out-Null
& powercfg.exe /change hibernate-timeout-ac 0 2>&1 | Out-Null

Write-Host "cpkit test agent installed: task '$task' as SYSTEM, id '$($env:COMPUTERNAME.ToLower())', server $S" -ForegroundColor Green
Write-Host 'It keeps running through lock, sign-out and reboot. You can close this window.' -ForegroundColor Green

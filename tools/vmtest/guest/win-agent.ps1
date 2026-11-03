# cpkit practice-VM test agent (Windows). PRACTICE VMs ONLY - never on a competition image.
# Installed by win-bootstrap.ps1 as scheduled task 'cpkit-test-agent' running as SYSTEM, so a lock
# screen, sign-out or reboot does not stop it. Pulls jobs from the host, runs each in its own
# PowerShell process (timeout + kill), posts results and a heartbeat every 15 s.
param(
    [string]$Server = '{{SERVER}}',
    [string]$Root = (Join-Path $env:ProgramData 'cpagent'),
    [string]$Id = $env:COMPUTERNAME.ToLower(),
    [int]$IdleSeconds = 3
)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Version = 2
New-Item -ItemType Directory -Force (Join-Path $Root 'jobs'), (Join-Path $Root 'outbox') | Out-Null

$mutex = New-Object System.Threading.Mutex($false, 'Global\cpkit-test-agent')
if (-not $mutex.WaitOne(0)) { exit 0 }   # already running (the task re-launches us every 5 min)

function Write-AgentLog([string]$Text) {
    try { Add-Content -Path (Join-Path $Root 'agent.log') -Value "$(Get-Date -Format s) $Text" -Encoding ASCII } catch { }
}

function Send-Cp([string]$Name, [byte[]]$Bytes) {
    try { Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$Server/$Id/r/$Name" -Body $Bytes -TimeoutSec 60 | Out-Null; $true } catch { $false }
}

function Get-Cp([string]$Path) {
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Uri "$Server/$Path" -TimeoutSec 15
        $text = [Text.Encoding]::UTF8.GetString($r.RawContentStream.ToArray()).TrimStart([char]0xFEFF)
        [pscustomobject]@{ Status = 200; Text = $text; Job = [string]$r.Headers['X-Job'] }
    } catch {
        $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
        [pscustomobject]@{ Status = $code; Text = $null; Job = '' }
    }
}

function Get-Tail([string]$Path, [int]$Lines = 8) {
    if (-not $Path -or -not (Test-Path $Path)) { return @() }   # Test-Path '' throws
    try { @(Get-Content -Path $Path -Tail $Lines -ErrorAction Stop | ForEach-Object { [string]$_ }) } catch { @() }   # plain strings, not PSPath-decorated
}

function Send-Heartbeat($Job, [int]$JobSecs, [string]$OutFile) {
    $up = -1
    try { $up = [int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalMinutes } catch { }
    $sessions = ''
    try { $sessions = ((& quser.exe 2>$null) | Select-Object -Skip 1 | ForEach-Object { ($_ -replace '\s+', ' ').Trim() }) -join ' | ' } catch { }
    $hb = [ordered]@{
        time = (Get-Date -Format s); vm = $Id; os = 'windows'; agent = $Version; runas = [Environment]::UserName
        uptimeMin = $up; lastJob = $script:Last; job = $Job; jobSecs = $JobSecs; sessions = $sessions
        tail = @(Get-Tail $OutFile)
    }
    [void](Send-Cp 'hb.json' ([Text.Encoding]::UTF8.GetBytes(($hb | ConvertTo-Json -Depth 3))))
}

function Send-Outbox {
    foreach ($f in @(Get-ChildItem (Join-Path $Root 'outbox') -File -ErrorAction SilentlyContinue)) {
        if (Send-Cp $f.Name ([IO.File]::ReadAllBytes($f.FullName))) { Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue }
    }
}

function Save-Result([int]$N, [string]$Text) {
    $max = 8MB
    if ($Text.Length -gt $max) { $Text = "[output truncated to the last 8 MB]`r`n" + $Text.Substring($Text.Length - $max) }
    [IO.File]::WriteAllText((Join-Path $Root "outbox\out-$N.txt"), $Text, (New-Object Text.UTF8Encoding $false))
    Send-Outbox
}

function Stop-Tree([int]$ProcessId) { & taskkill.exe /PID $ProcessId /T /F 2>&1 | Out-Null }

function Invoke-Job([int]$N, [string]$Code) {
    $timeout = 3600
    if ($Code -match '(?m)^\s*#\s*timeout\s*=\s*(\d+)') { $timeout = [int]$Matches[1] }
    $jobFile = Join-Path $Root "jobs\cmd-$N.ps1"
    $outFile = Join-Path $Root "jobs\out-$N.txt"
    # Prelude: helpers every job can use. up NAME TEXT uploads an extra result file.
    $prelude = @"
`$ErrorActionPreference = 'Continue'; `$ProgressPreference = 'SilentlyContinue'
`$CpServer = '$Server'; `$CpVm = '$Id'; `$h = `$CpServer
function up([string]`$Name, `$Text) { Invoke-WebRequest -UseBasicParsing -Method Post -Uri "`$CpServer/`$CpVm/r/`$Name" -Body ([Text.Encoding]::UTF8.GetBytes([string]`$Text)) -TimeoutSec 60 | Out-Null }
"@
    $body = "$prelude`r`ntry {`r`n& {`r`n$Code`r`n} *>&1 | ForEach-Object { if (`$_ -is [System.Management.Automation.ErrorRecord]) { 'ERROR: ' + `$_.Exception.Message } else { `$_ } } | Out-String -Stream -Width 250`r`n} catch { 'ERROR: ' + `$_.Exception.Message }`r`n"
    [IO.File]::WriteAllText($jobFile, $body, (New-Object Text.UTF8Encoding $true))

    $t0 = Get-Date; $status = 'done'; $exit = -1
    $p = Start-Process -FilePath powershell.exe -PassThru -RedirectStandardOutput $outFile -RedirectStandardError "$outFile.err" `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "`"$jobFile`"")
    $null = $p.Handle   # keeps ExitCode readable after exit (PS 5.1)
    $nextHb = Get-Date
    while (-not $p.HasExited) {
        Start-Sleep -Seconds 2
        $secs = [int]((Get-Date) - $t0).TotalSeconds
        if ($secs -ge $timeout) { $status = "timeout after ${timeout}s"; Stop-Tree $p.Id; break }
        if ((Get-Date) -ge $nextHb) {
            $nextHb = (Get-Date).AddSeconds(15)
            Send-Heartbeat $N $secs $outFile
            if ((Get-Cp "$Id/kill-$N").Status -eq 200) { $status = 'killed by host'; Stop-Tree $p.Id; break }
        }
    }
    [void]$p.WaitForExit(15000)
    try { $exit = $p.ExitCode } catch { }
    $secs = [int]((Get-Date) - $t0).TotalSeconds
    $out = ''; if (Test-Path $outFile) { $out = [IO.File]::ReadAllText($outFile) }
    $err = ''; if (Test-Path "$outFile.err") { $err = [IO.File]::ReadAllText("$outFile.err") }
    if ($err.Trim()) { $out += "`r`n--- stderr ---`r`n$err" }
    Save-Result $N "#job=$N status=$status exit=$exit secs=$secs`r`n$out"
}

$lastFile = Join-Path $Root 'last.txt'
$runFile = Join-Path $Root 'running.txt'
$script:Last = 0
if (Test-Path $lastFile) { $script:Last = [int](Get-Content $lastFile -TotalCount 1) }
if (Test-Path $runFile) {
    # The VM or the agent restarted while a job ran (e.g. the job rebooted). Never re-run it.
    $n = [int](Get-Content $runFile -TotalCount 1)
    Save-Result $n "#job=$n status=interrupted (agent or VM restarted while it ran)`r`n"
    Remove-Item $runFile -Force
}
Write-AgentLog "agent v$Version start as $([Environment]::UserName) server=$Server id=$Id last=$($script:Last)"

$nextHb = Get-Date
while ($true) {
    try {
        Send-Outbox
        $r = Get-Cp "$Id/next?after=$($script:Last)"
        if ($r.Status -eq 200 -and $r.Job -match '^\d+$') {
            $n = [int]$r.Job
            Set-Content -Path $lastFile -Value $n; Set-Content -Path $runFile -Value $n
            Write-AgentLog "job $n start"
            Invoke-Job $n $r.Text
            Remove-Item $runFile -Force -ErrorAction SilentlyContinue
            $script:Last = $n
            Write-AgentLog "job $n end"
            $nextHb = Get-Date
            continue
        }
        if ((Get-Date) -ge $nextHb) { Send-Heartbeat $null 0 ''; $nextHb = (Get-Date).AddSeconds(15) }
    } catch { Write-AgentLog "loop error: $($_.Exception.Message)" }
    Start-Sleep -Seconds $IdleSeconds
}

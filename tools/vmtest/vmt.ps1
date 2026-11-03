# Host CLI for the practice-VM test harness (talks to server.py through its state folder).
#   .\vmt.ps1 status                                  every VM: heartbeat age, running job, last output lines
#   .\vmt.ps1 run -Vm d13 -Code 'Get-Date'            queue a job (PowerShell on Windows, bash on Linux) and wait
#   .\vmt.ps1 run -Vm d13 -File job.ps1 -Timeout 1800 -Wait 0     queue only (prints the job number)
#   .\vmt.ps1 result -Vm d13 -N 7                     print a job's output
#   .\vmt.ps1 kill -Vm d13 -N 7                       stop a running job (agent kills its whole process tree)
#   .\vmt.ps1 stage -Path cp-config.txt               put a file where jobs can download it ($CpServer/f/NAME)
#   .\vmt.ps1 stage-kit                               kit.zip + kit.tgz from the repo's HEAD
param(
    [Parameter(Position = 0)][ValidateSet('status', 'run', 'result', 'kill', 'stage', 'stage-kit')][string]$Cmd = 'status',
    [string]$Vm, [string]$Code, [string]$File, [int]$N, [string]$Path,
    [int]$Timeout = 3600, [int]$Wait = 900,
    [string]$State = (Join-Path $HOME 'cpvmtest')
)
$ErrorActionPreference = 'Stop'
$vms = Join-Path $State 'vms'

function Get-Hb([string]$VmId) {
    $f = Join-Path $vms "$VmId\r\hb.json"
    if (-not (Test-Path $f)) { return $null }
    $hb = Get-Content $f -Raw | ConvertFrom-Json
    $hb | Add-Member NoteProperty AgeSec ([int]((Get-Date) - (Get-Item $f).LastWriteTime).TotalSeconds) -PassThru
}

function Get-NextJob([string]$VmId) {
    $nums = @(0)
    foreach ($d in 'q', 'r') {
        $nums += @(Get-ChildItem (Join-Path $vms "$VmId\$d") -File -ErrorAction SilentlyContinue |
            Where-Object Name -match '^(cmd|out)-(\d+)\.' | ForEach-Object { [int]($_.Name -replace '^\D+-(\d+)\..*$', '$1') })
    }
    $hb = Get-Hb $VmId
    if ($hb -and $hb.lastJob) { $nums += [int]$hb.lastJob }
    ($nums | Measure-Object -Maximum).Maximum + 1
}

function Need-Vm { if (-not $Vm) { throw "-Vm is required (see: .\vmt.ps1 status)" } }

switch ($Cmd) {
    'status' {
        if (-not (Test-Path $vms)) { "no VM has checked in yet (state: $State)"; return }
        foreach ($d in Get-ChildItem $vms -Directory) {
            $hb = Get-Hb $d.Name
            if (-not $hb) { "{0,-16} no heartbeat yet" -f $d.Name; continue }
            $alive = if ($hb.AgeSec -le 45) { 'ALIVE' } else { "SILENT $([int]($hb.AgeSec / 60))m" }
            $job = if ($hb.job) { "job $($hb.job) running $($hb.jobSecs)s" } else { "idle (last job $($hb.lastJob))" }
            "{0,-16} {1,-10} {2}  os={3} as={4} up={5}m  {6}" -f $d.Name, $alive, $job, $hb.os, $hb.runas, $hb.uptimeMin, $hb.sessions
            if ($hb.job -and $hb.tail) { @($hb.tail) -split "`n" | Select-Object -Last 4 | ForEach-Object { "    | $_" } }
        }
    }
    'run' {
        Need-Vm
        if ($File) { $Code = Get-Content $File -Raw }
        if (-not $Code) { throw '-Code or -File is required' }
        $hb = Get-Hb $Vm
        if (-not $hb) { throw "no heartbeat from '$Vm' yet - is the agent installed? (.\vmt.ps1 status)" }
        $ext = if ($hb.os -eq 'linux') { 'sh' } else { 'ps1' }
        $q = Join-Path $vms "$Vm\q"; New-Item -ItemType Directory -Force $q | Out-Null
        $num = Get-NextJob $Vm
        [IO.File]::WriteAllText((Join-Path $q "cmd-$num.$ext"), "# timeout=$Timeout`n$Code`n", (New-Object Text.UTF8Encoding $false))
        if ($hb.AgeSec -gt 45) { Write-Warning "agent '$Vm' silent for $($hb.AgeSec)s - job $num queued anyway" }
        if ($Wait -le 0) { "queued job $num on $Vm"; return }
        $res = Join-Path $vms "$Vm\r\out-$num.txt"; $t0 = Get-Date
        while (-not (Test-Path $res) -and ((Get-Date) - $t0).TotalSeconds -lt $Wait) { Start-Sleep -Milliseconds 700 }
        if (Test-Path $res) { Get-Content $res -Raw }
        else { "job $num still running after $Wait s - check: .\vmt.ps1 status / result -Vm $Vm -N $num / kill -Vm $Vm -N $num" }
    }
    'result' {
        Need-Vm; $f = Join-Path $vms "$Vm\r\out-$N.txt"
        if (Test-Path $f) { Get-Content $f -Raw } else { "no result yet for job $N on $Vm" }
    }
    'kill' {
        Need-Vm; $q = Join-Path $vms "$Vm\q"; New-Item -ItemType Directory -Force $q | Out-Null
        Set-Content (Join-Path $q "kill-$N") 'kill'; "asked $Vm to kill job $N (within ~15 s)"
    }
    'stage' {
        $dest = Join-Path $State 'files'; New-Item -ItemType Directory -Force $dest | Out-Null
        Copy-Item $Path $dest -Force; "staged $(Split-Path $Path -Leaf) -> `$CpServer/f/$(Split-Path $Path -Leaf)"
    }
    'stage-kit' {
        $repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
        $dest = Join-Path $State 'files'; New-Item -ItemType Directory -Force $dest | Out-Null
        & git -C $repo archive --format=zip -o (Join-Path $dest 'kit.zip') HEAD
        & git -C $repo archive --format=tar.gz -o (Join-Path $dest 'kit.tgz') HEAD
        "staged kit.zip + kit.tgz from $(& git -C $repo log --oneline -1)"
        if (& git -C $repo status --porcelain -- windows linux) { Write-Warning 'uncommitted kit changes are NOT in the staged kit (git archive uses HEAD)' }
    }
}

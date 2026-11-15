# Shared helpers for every Windows module (Windows PowerShell 5.1, ASCII only).
# Rules this enforces for the whole kit:
#   - audit mode (default) never changes anything; it prints [WOULD] lines
#   - apply mode asks y/N per action (unless -Yes), backs things up, logs everything
#   - README users/services, the current user, built-ins and the scoring client are protected

$script:CpApply = $false
$script:CpYes   = $false
$script:CpRun   = $null
# Scoring engines: CyberPatriot (CCSClient) and Aeacus practice images (CSSClient, phocus.exe in C:\aeacus).
$script:ScoringRe = 'cyberpatriot|cpscor|scoring|aeacus|ccsclient|cssclient|phocus'
function Get-CpScoringRegex { $script:ScoringRe }

# True if a file can be created in Dir. Planted images break TEMP so DISM/installers fail.
function Test-CpWritableDir([string]$Dir) {
    if (-not $Dir -or -not (Test-Path $Dir -PathType Container)) { return $false }
    $f = Join-Path $Dir ("cpkit-" + [guid]::NewGuid().ToString('N'))
    # DISM makes a GUID *subfolder*, so test a folder too, not just a file
    try { [IO.File]::WriteAllText("$f.tmp", 'x'); Remove-Item "$f.tmp" -Force; [void][IO.Directory]::CreateDirectory($f); Remove-Item $f -Force; return $true } catch { return $false }
}
$script:BuiltinUsers = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount','defaultuser0','krbtgt')

function Set-CpContext {
    param([string]$RunDir, [switch]$Apply, [switch]$Yes)
    $script:CpApply = [bool]$Apply
    $script:CpYes   = [bool]$Yes
    $script:CpRun   = $RunDir
    if ($RunDir) {
        New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
        foreach ($f in 'log.txt','findings.txt') { $p = Join-Path $RunDir $f; if (-not (Test-Path $p)) { New-Item -ItemType File -Path $p | Out-Null } }
    }
}
function Get-CpContext { [pscustomobject]@{ Apply = $script:CpApply; Yes = $script:CpYes; RunDir = $script:CpRun } }

function Assert-CpAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'Run PowerShell as Administrator (right-click > Run as administrator).' -ForegroundColor Red
        exit 1
    }
}

function Split-CpList([string]$v) { @($v -split '[\s,]+' | Where-Object { $_ -ne '' }) }

function Import-CpConfig {
    param([Parameter(Mandatory)][string]$Path, [switch]$RequireUsers)
    if (-not (Test-Path $Path)) { throw "Config not found: $Path  (copy config\cp-config.example.txt to cp-config.txt and fill it from the README)" }
    $h = @{}
    foreach ($line in Get-Content $Path) {
        $l = $line.TrimStart([char]0xFEFF).Trim()
        if ($l -match '^#' -or $l -notmatch '=') { continue }    # whole-line comments only
        $k, $v = $l -split '=', 2
        $k = $k.Trim().ToUpper()
        # passwords may contain '#': keep exactly; other values may carry a trailing ' # note'
        if ($k -ne 'NEW_PASSWORD') { $v = $v -replace '\s+#.*$', '' }
        $h[$k] = $v.Trim()
    }
    $known = 'ADMINS','USERS','CRITICAL_SERVICES','ALLOWED_SOFTWARE','NEW_PASSWORD','KEEP_RDP','KEEP_SHARES','RESET_PASSWORDS'
    foreach ($k in $h.Keys) { if ($known -notcontains $k) { Write-Host "  (config: unknown key '$k' ignored)" -ForegroundColor Yellow } }
    $cfg = [pscustomobject]@{
        Admins      = Split-CpList $h['ADMINS']
        Users       = Split-CpList $h['USERS']
        Critical    = Split-CpList $h['CRITICAL_SERVICES']
        Allowed     = Split-CpList $h['ALLOWED_SOFTWARE']
        NewPassword = [string]$h['NEW_PASSWORD']
        KeepRdp     = ([string]$h['KEEP_RDP']) -match '^(y|yes|true|1)$'
        KeepShares  = Split-CpList $h['KEEP_SHARES']
        ResetPasswords = ([string]$h['RESET_PASSWORDS']) -match '^(y|yes|true|1)$'
    }
    if ($RequireUsers -and $cfg.Admins.Count -eq 0) { throw 'ADMINS is empty in the config - fill it from the README before running the users module.' }
    $cfg
}

function Test-CpProtectedUser {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Config)
    if (@($Config.Admins + $Config.Users) -contains $Name) { return $true }
    if ($Name -eq $env:USERNAME) { return $true }
    if ($script:BuiltinUsers -contains $Name) { return $true }
    return $false
}

function Test-CpProtectedService {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Config)
    if ($Name -match $script:ScoringRe) { return $true }
    foreach ($c in $Config.Critical) { if ($c -ieq $Name) { return $true } }
    return $false
}

# README nicknames -> real service names (people type "FTP", Windows calls it FTPSVC).
$script:CpServiceAliases = @{
    'rdp' = @('TermService','SessionEnv','UmRdpService'); 'remotedesktop' = @('TermService','SessionEnv','UmRdpService')
    'ftp' = @('FTPSVC'); 'iis' = @('W3SVC','WAS'); 'http' = @('W3SVC','WAS'); 'web' = @('W3SVC','WAS')
    'smb' = @('LanmanServer'); 'fileshare' = @('LanmanServer'); 'filesharing' = @('LanmanServer'); 'server' = @('LanmanServer')
    'ssh' = @('sshd'); 'openssh' = @('sshd'); 'print' = @('Spooler'); 'printing' = @('Spooler')
    'telnet' = @('TlntSvr'); 'snmp' = @('SNMP'); 'winrm' = @('WinRM'); 'dhcp' = @('DHCPServer')
}

# Pure. Turns README critical entries into real service names BEFORE anything is disabled.
# Order: exact service name, nickname, exact display name, then a display-name match only if it is unique.
function Resolve-CpCriticalServices {
    param([Parameter(Mandatory)]$Services, [string[]]$Critical)
    $names = New-Object System.Collections.Generic.List[string]; $missing = @(); $map = @()
    foreach ($c in @($Critical)) {
        if (-not $c) { continue }
        $hit = @($Services | Where-Object { $_.Name -ieq $c } | ForEach-Object Name)
        if (-not $hit) { $hit = @($script:CpServiceAliases[$c.ToLower()]) | Where-Object { $_ } }
        if (-not $hit) { $hit = @($Services | Where-Object { $_.DisplayName -ieq $c } | ForEach-Object Name) }
        if (-not $hit) {
            $like = @($Services | Where-Object { $_.DisplayName -like "*$c*" -or $_.Name -like "*$c*" } | ForEach-Object Name)
            if ($like.Count -eq 1) { $hit = $like }
        }
        if ($hit) { foreach ($h in $hit) { if (-not $names.Contains($h)) { $names.Add($h) } }; $map += "$c -> $($hit -join ' ')" }
        else { $missing += $c }
    }
    [pscustomobject]@{ Names = $names.ToArray(); Missing = $missing; Map = $map; NeedsRdp = $names.Contains('TermService') }
}

function Write-CpLog {
    param([string]$Module, [string]$Action, [string]$Before, [string]$After, [string]$Why)
    if (-not $script:CpRun) { return }
    $line = '{0} | {1} | {2} | {3} -> {4} | {5}' -f (Get-Date -Format 'HH:mm:ss'), $Module, $Action, $Before, $After, $Why
    Add-Content -Path (Join-Path $script:CpRun 'log.txt') -Value $line -Encoding ASCII
}

function Add-CpFinding {
    param([string]$Module, [string]$Text)
    Write-Host "  [CHECK] $Text" -ForegroundColor Yellow
    if ($script:CpRun) { Add-Content -Path (Join-Path $script:CpRun 'findings.txt') -Value "[$Module] $Text" -Encoding ASCII }
}

function Backup-CpFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not $script:CpRun -or -not (Test-Path $Path)) { return }
    $rel  = ($Path -replace '^[A-Za-z]:\\','') -replace ':',''
    $dest = Join-Path (Join-Path $script:CpRun 'backup') $rel
    if (Test-Path $dest) { return }
    New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
    Copy-Item -Path $Path -Destination $dest -Force
}

function Backup-CpRegistry {
    param([Parameter(Mandatory)][string]$Key)   # e.g. HKLM\SYSTEM\CurrentControlSet\Control\Lsa
    if (-not $script:CpRun) { return }
    # A key that doesn't exist yet (new policy keys) has nothing to back up. reg.exe would exit 1 and
    # Invoke-CpAction would log the change as FAILED although it worked (District 13 live run).
    if (-not (Test-Path "Registry::$Key")) { return }
    $dir = Join-Path $script:CpRun 'backup\registry'; New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $file = Join-Path $dir (($Key -replace '[\\:]','_') + '.reg')
    if (-not (Test-Path $file)) { & reg.exe export $Key $file /y 2>$null | Out-Null; $global:LASTEXITCODE = 0 }
}

function Confirm-Cp {
    if ($script:CpYes) { return $true }
    $a = Read-Host '  Apply? [y/N]'
    return ($a -match '^[Yy]')
}

function Invoke-CpAction {
    param([string]$Module, [string]$Description, [string]$Why, [Parameter(Mandatory)][scriptblock]$ScriptBlock)
    if (-not $script:CpApply) { Write-Host "  [WOULD] $Description  -- $Why" -ForegroundColor Cyan; return }
    Write-Host "  [DO] $Description  -- $Why" -ForegroundColor Green
    if (-not (Confirm-Cp)) { Write-Host '       skipped'; Write-CpLog $Module 'SKIP' $Description '-' $Why; return }
    try {
        # Non-terminating errors and native exit codes would otherwise look like success.
        $global:LASTEXITCODE = 0
        $errs = @(& $ScriptBlock 2>&1 | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        if ($errs.Count -gt 0) { throw $errs[0].Exception }
        if ($global:LASTEXITCODE -ne 0) { throw "command exited with code $global:LASTEXITCODE" }
        Write-CpLog $Module 'ACTION' $Description 'done' $Why
    } catch {
        Write-Host "       FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-CpLog $Module 'FAILED' $Description $_.Exception.Message $Why
    }
}

# Run a READ again when it fails. District 13: the first AD query after boot failed once with
# "A local error has occurred" and ended the whole Server module; the second try worked.
# Only for reads: a change must never be repeated blindly.
function Invoke-CpRetry {
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock, [int]$Tries = 3, [int]$DelaySec = 5)
    for ($i = 1; $i -le $Tries; $i++) {
        try { return (& $ScriptBlock) }
        catch {
            if ($i -ge $Tries) { throw }
            Write-Host "  (read failed: $($_.Exception.Message.Split("`n")[0]) - try $($i + 1) of $Tries in $DelaySec s)" -ForegroundColor Yellow
            if ($DelaySec -gt 0) { Start-Sleep -Seconds $DelaySec }
        }
    }
}

# Registry settings outside secedit's reach. Wanted = objects with Path (HKLM:\...), Name, Type, Value, Why.
# Pure: Current = @{ 'Path\Name' = value-or-$null }. Returns the items whose value differs.
function Get-CpRegistryPlan {
    param([Parameter(Mandatory)]$Wanted, [Parameter(Mandatory)][hashtable]$Current)
    $out = @()
    foreach ($w in $Wanted) {
        $cur = $Current["$($w.Path)\$($w.Name)"]
        if ($null -ne $cur -and "$cur" -eq "$($w.Value)") { continue }
        $out += $w
    }
    return ,$out
}

function Invoke-CpRegistrySettings {
    param([string]$Module, [Parameter(Mandatory)]$Wanted)
    $cur = @{}
    foreach ($w in $Wanted) { $cur["$($w.Path)\$($w.Name)"] = (Get-ItemProperty -Path $w.Path -Name $w.Name -ErrorAction SilentlyContinue).($w.Name) }
    $plan = Get-CpRegistryPlan -Wanted $Wanted -Current $cur
    foreach ($w in $Wanted) { if ($plan -notcontains $w) { Write-CpOk "$($w.Name) = $($w.Value)" } }
    foreach ($w in $plan) {
        $p = $w.Path; $n = $w.Name; $t = $w.Type; $v = $w.Value
        $now = $cur["$p\$n"]; if ($null -eq $now) { $now = '(not set)' }
        Invoke-CpAction $Module "$n -> $v (now $now)  [$($p -replace '^HKLM:\\','HKLM\')]" $w.Why {
            Backup-CpRegistry ($p -replace '^HKLM:\\','HKLM\')
            if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
            Set-ItemProperty -Path $p -Name $n -Value $v -Type $t -ErrorAction Stop }.GetNewClosure()
    }
}

# Fast recursive file search. Get-ChildItem -Recurse -Include over C:\ took 7+ minutes; this walks
# directories itself, sees hidden files, skips junctions (no loops) and unreadable folders.
function Find-CpFiles {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$NameRegex, [string]$SkipDirRegex = '^$')
    $stack = New-Object System.Collections.Generic.Stack[string]; $stack.Push($Root)
    $re = New-Object regex $NameRegex, 'IgnoreCase'; $skip = New-Object regex $SkipDirRegex, 'IgnoreCase'
    while ($stack.Count) {
        $d = $stack.Pop()
        try { foreach ($f in [IO.Directory]::EnumerateFiles($d)) { if ($re.IsMatch([IO.Path]::GetFileName($f))) { $f } } } catch { }
        try {
            foreach ($s in [IO.Directory]::EnumerateDirectories($d)) {
                if ($skip.IsMatch($s)) { continue }
                if (([IO.File]::GetAttributes($s) -band [IO.FileAttributes]::ReparsePoint)) { continue }
                $stack.Push($s)
            }
        } catch { }
    }
}

# Service control by EXACT key name, with a time limit. Never use Stop/Set/Start-Service -Name here:
#  - they also match display names and drivers. On District 13 'Browser' resolved to the bowser
#    file-system driver (display name "Browser"), -Force stopped Workstation with it, and unloading
#    bowser.sys blue-screened the machine (bugcheck 0xD4), every time.
#  - they wait forever: WinRM sat in StopPending for 4+ minutes and the module never finished.
function Wait-CpServiceState {
    param([string]$Name, [string]$State, [int]$TimeoutSec = 20, [int]$PollMs = 500,
        [scriptblock]$Probe = { param($n) [string](Get-CimInstance Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue).State })
    $end = (Get-Date).AddSeconds($TimeoutSec)
    do {
        if ((& $Probe $Name) -eq $State) { return $true }
        Start-Sleep -Milliseconds $PollMs
    } while ((Get-Date) -lt $end)
    return $false
}

# sc.exe's own exit code is ignored: "not started" and "dependents running" are normal; the state decides.
function Stop-CpService([string]$Name, [int]$TimeoutSec = 15) {
    & sc.exe stop $Name 2>&1 | Out-Null; $global:LASTEXITCODE = 0
    Wait-CpServiceState -Name $Name -State 'Stopped' -TimeoutSec $TimeoutSec
}

function Start-CpService([string]$Name, [int]$TimeoutSec = 45) {
    & sc.exe start $Name 2>&1 | Out-Null; $global:LASTEXITCODE = 0
    Wait-CpServiceState -Name $Name -State 'Running' -TimeoutSec $TimeoutSec
}

# Mode: auto | disabled | demand. A non-zero exit code stays set, so Invoke-CpAction logs FAILED.
function Set-CpServiceStart([string]$Name, [string]$Mode) { & sc.exe config $Name start= $Mode 2>&1 | Out-Null }

# Local Group Policy lives in Registry.pol and Windows re-applies it on every refresh, so a registry
# fix made by hand or by this kit silently comes back undone minutes later. District 13 planted
# DisableAntiSpyware, NoAutoUpdate and **del.AUOptions there. Format: 'PReg' + version, then
# [key;value;type;size;data] in UTF-16. Values starting **del. mean "delete this value".
function Read-CpPolString([byte[]]$Bytes, [ref]$Pos) {
    $s = $Pos.Value
    while ($Pos.Value + 1 -lt $Bytes.Length -and ($Bytes[$Pos.Value] -ne 0 -or $Bytes[$Pos.Value + 1] -ne 0)) { $Pos.Value += 2 }
    $text = [Text.Encoding]::Unicode.GetString($Bytes, $s, $Pos.Value - $s)
    $Pos.Value += 2
    $text
}

# Pure. Bytes -> entries (Key, Name, Type, Dword, Start, End). End is one past the closing bracket.
function ConvertFrom-CpRegistryPol([byte[]]$Bytes) {
    $out = New-Object System.Collections.Generic.List[object]
    if (-not $Bytes -or $Bytes.Length -lt 8 -or [Text.Encoding]::ASCII.GetString($Bytes, 0, 4) -ne 'PReg') { return }
    $i = 8
    while ($i + 1 -lt $Bytes.Length -and $Bytes[$i] -eq 0x5B) {
        $start = $i; $i += 2
        $key = Read-CpPolString $Bytes ([ref]$i); $i += 2
        $name = Read-CpPolString $Bytes ([ref]$i); $i += 2
        $type = [BitConverter]::ToInt32($Bytes, $i); $i += 6
        $size = [BitConverter]::ToInt32($Bytes, $i); $i += 6
        $dword = if ($type -eq 4 -and $size -eq 4) { [BitConverter]::ToInt32($Bytes, $i) } else { $null }
        $i += $size + 2
        $out.Add([pscustomobject]@{ Key = $key; Name = $name; Type = $type; Dword = $dword; Start = $start; End = $i })
    }
    $out.ToArray()   # callers wrap in @(): a ,$array return reaches a pipeline as ONE item
}

# Pure. Only what fights the kit; anything else stays and is listed for the team to judge.
function Test-CpBadPolEntry($Entry, $Config) {
    $k = $Entry.Key; $n = $Entry.Name
    if ($k -match 'Windows Defender' -and $n -like 'Disable*' -and $Entry.Dword -ne 0) { return $true }
    if ($k -match 'WindowsUpdate\\AU$' -and $n -eq 'NoAutoUpdate' -and $Entry.Dword -ne 0) { return $true }
    if ($k -match 'WindowsUpdate\\AU$' -and $n -eq '**del.AUOptions') { return $true }
    if ($k -match 'WindowsUpdate$' -and $n -match '^(DisableWindowsUpdateAccess|SetDisableUXWUAccess)$' -and $Entry.Dword -ne 0) { return $true }
    if ($k -match 'Terminal Services$' -and $n -eq 'fDenyTSConnections' -and $Config.KeepRdp -and $Entry.Dword -ne 0) { return $true }
    return $false
}

# Pure. The file's bytes without the given entries.
function Remove-CpPolEntries([byte[]]$Bytes, $Entries) {
    $m = New-Object IO.MemoryStream; $pos = 0
    foreach ($e in @($Entries | Sort-Object Start)) { $m.Write($Bytes, $pos, $e.Start - $pos); $pos = $e.End }
    $m.Write($Bytes, $pos, $Bytes.Length - $pos)
    , $m.ToArray()
}

# Runs before any module, or the Defender and Updates fixes are undone at the next policy refresh.
function Repair-CpLocalPolicy {
    param($Config, [string]$Path = (Join-Path $env:windir 'System32\GroupPolicy\Machine\Registry.pol'))
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $bytes = [IO.File]::ReadAllBytes($Path)
    $all = @(ConvertFrom-CpRegistryPol $bytes)
    $bad = @($all | Where-Object { Test-CpBadPolEntry $_ $Config })
    foreach ($e in $bad) { Add-CpFinding system "local Group Policy keeps undoing a fix: $($e.Key) -> $($e.Name)" }
    $rest = @($all | Where-Object { $bad -notcontains $_ -and $_.Name -notlike '**del.*' })
    if ($rest.Count) { Add-CpFinding system "local Group Policy also sets (gpedit.msc, re-applied on every refresh): $(($rest | ForEach-Object Name) -join ', ')" }
    if ($bad.Count -eq 0) { Write-CpOk 'local Group Policy does not fight the kit'; return }
    $new = Remove-CpPolEntries $bytes $bad
    Invoke-CpAction system "remove $($bad.Count) planted value(s) from local Group Policy" 'Registry.pol re-applies them over any fix' {
        Backup-CpFile -Path $Path
        [IO.File]::WriteAllBytes($Path, $new)
    }.GetNewClosure()
}

# Admin tools an image can lock or wipe. District 13 zeroed dism.exe + sfc.exe and hid a 0-byte
# System32\Dism\dism.exe with Everyone + SYSTEM Deny: the DISM API copies that whole folder to temp,
# so every DISM call (features, SMB1) failed with a misleading "temporary folder" error.
function Get-CpAdminToolPaths {
    $s = Join-Path $env:windir 'System32'
    $tools = @((Join-Path $env:windir 'regedit.exe')) + @(
        'dism.exe','cmd.exe','WindowsPowerShell\v1.0\powershell.exe','WindowsPowerShell\v1.0\powershell_ise.exe',
        'mmc.exe','Taskmgr.exe','reg.exe','sc.exe','net.exe','net1.exe','netsh.exe','icacls.exe','takeown.exe','auditpol.exe',
        'secedit.exe','gpupdate.exe','bcdedit.exe','sfc.exe','eventvwr.exe','control.exe','secpol.msc','gpedit.msc',
        'services.msc','compmgmt.msc','lusrmgr.msc','wf.msc','gpmc.msc','dsa.msc'
    ) | ForEach-Object { if ($_ -like '*:\*') { $_ } else { Join-Path $s $_ } }
    $tools + @(Get-ChildItem (Join-Path $s 'Dism') -File -Force -ErrorAction SilentlyContinue | ForEach-Object FullName)
}

# Pure. Access = ACL rules (IdentityReference, AccessControlType). Returns each denied identity once.
function Get-CpDenyIdentities($Access) {
    @($Access | Where-Object { [string]$_.AccessControlType -eq 'Deny' } | ForEach-Object { [string]$_.IdentityReference } | Select-Object -Unique)
}

# Runs before any module (DISM-based modules need it). Reports in audit, removes the Deny entries on -Apply.
function Repair-CpToolAcls {
    param([string[]]$Paths = (Get-CpAdminToolPaths))
    Write-CpHeader 'PREFLIGHT  (admin tools locked by Deny permissions)'
    $hit = 0
    foreach ($p in $Paths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        if ($p -match '\.(exe|dll)$' -and (Get-Item -LiteralPath $p -Force).Length -eq 0) {
            $hit++; Add-CpFinding system "$p is EMPTY (0 bytes): the image wiped this tool, it cannot run. Use the GUI instead (Server Manager, optionalfeatures.exe)"
        }
        $acl = try { Get-Acl -LiteralPath $p -ErrorAction Stop } catch { $null }
        if (-not $acl) { $hit++; Add-CpFinding system "cannot read the permissions of $p - check: icacls `"$p`""; continue }
        $deny = Get-CpDenyIdentities $acl.Access
        if ($deny.Count -eq 0) { continue }
        $hit++
        Add-CpFinding system "$p has Deny entries for $($deny -join ', ') (owner $($acl.Owner)) - the tool is blocked. Fix: icacls `"$p`" /remove:d <name>"
        $restoreOwner = $p -like "$env:windir\*"
        $bak = if ($script:CpRun) { Join-Path $script:CpRun ('backup\acl-' + [IO.Path]::GetFileName($p) + '.txt') }   # closures lose $script:
        Invoke-CpAction system "remove Deny entries on $p ($($deny -join ', '))" 'planted Deny ACE blocks an admin tool' {
            if ($bak) { New-Item -ItemType Directory -Force (Split-Path $bak) | Out-Null; & icacls.exe $p /save $bak 2>&1 | Out-Null }
            foreach ($i in $deny) { & icacls.exe $p /remove:d $i 2>&1 | Out-Null; if ($LASTEXITCODE) { return } }
            # System32 binaries belong to TrustedInstaller; the plant made Administrators the owner.
            if ($restoreOwner) { & icacls.exe $p /setowner 'NT SERVICE\TrustedInstaller' 2>&1 | Out-Null }
        }.GetNewClosure()
    }
    if ($hit -eq 0) { Write-CpOk 'admin tools (dism, cmd, PowerShell, mmc, regedit, ...) not locked' }
}

function New-CpReg([string]$Path, [string]$Name, $Value, [string]$Why, [string]$Type = 'DWord') {
    [pscustomobject]@{ Path = $Path; Name = $Name; Type = $Type; Value = $Value; Why = $Why }
}

function Write-CpOk([string]$Text) { Write-Host "  ok   $Text" -ForegroundColor DarkGray }
function Write-CpHeader([string]$Text) { Write-Host ''; Write-Host "===== $Text =====" -ForegroundColor White }

Export-ModuleMember -Function *-Cp*, Split-CpList

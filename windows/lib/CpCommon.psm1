# Shared helpers for every Windows module (Windows PowerShell 5.1, ASCII only).
# Rules this enforces for the whole kit:
#   - audit mode (default) never changes anything; it prints [WOULD] lines
#   - apply mode asks y/N per action (unless -Yes), backs things up, logs everything
#   - README users/services, the current user, built-ins and the scoring client are protected

$script:CpApply = $false
$script:CpYes   = $false
$script:CpRun   = $null
$script:ScoringRe = 'cyberpatriot|cpscor|scoring|aeacus'
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
        $l = ($line -replace '#.*$','').Trim()
        if ($l -notmatch '=') { continue }
        $k, $v = $l -split '=', 2
        $h[$k.Trim().ToUpper()] = $v.Trim()
    }
    $known = 'ADMINS','USERS','CRITICAL_SERVICES','ALLOWED_SOFTWARE','NEW_PASSWORD','KEEP_RDP','KEEP_SHARES'
    foreach ($k in $h.Keys) { if ($known -notcontains $k) { Write-Host "  (config: unknown key '$k' ignored)" -ForegroundColor Yellow } }
    $cfg = [pscustomobject]@{
        Admins      = Split-CpList $h['ADMINS']
        Users       = Split-CpList $h['USERS']
        Critical    = Split-CpList $h['CRITICAL_SERVICES']
        Allowed     = Split-CpList $h['ALLOWED_SOFTWARE']
        NewPassword = [string]$h['NEW_PASSWORD']
        KeepRdp     = ([string]$h['KEEP_RDP']) -match '^(y|yes|true|1)$'
        KeepShares  = Split-CpList $h['KEEP_SHARES']
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
    $dir = Join-Path $script:CpRun 'backup\registry'; New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $file = Join-Path $dir (($Key -replace '[\\:]','_') + '.reg')
    if (-not (Test-Path $file)) { & reg.exe export $Key $file /y 2>$null | Out-Null }
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
        & $ScriptBlock | Out-Null
        Write-CpLog $Module 'ACTION' $Description 'done' $Why
    } catch {
        Write-Host "       FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-CpLog $Module 'FAILED' $Description $_.Exception.Message $Why
    }
}

function Write-CpOk([string]$Text) { Write-Host "  ok   $Text" -ForegroundColor DarkGray }
function Write-CpHeader([string]$Text) { Write-Host ''; Write-Host "===== $Text =====" -ForegroundColor White }

Export-ModuleMember -Function *-Cp*, Split-CpList

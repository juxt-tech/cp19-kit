<#
CyberPatriot Windows hardening kit (Windows 10/11, Server 2019/2022).

  powershell -ExecutionPolicy Bypass -File .\harden.ps1                  # AUDIT: shows what it would change
  powershell -ExecutionPolicy Bypass -File .\harden.ps1 -Apply           # menu; asks y/N before every change
  powershell -ExecutionPolicy Bypass -File .\harden.ps1 -Apply -Module Users,Firewall

Before running: answer the forensics questions, read the README, fill cp-config.txt, take a VMware snapshot.
Run one module at a time and snapshot between them.
#>
param(
    [switch]$Apply,
    [switch]$Yes,
    [switch]$All,
    [string]$Config,
    [string[]]$Module
)

$ErrorActionPreference = 'Continue'
$kit = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $kit 'lib\CpCommon.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $kit 'lib\CpSecedit.psm1') -Force -DisableNameChecking
foreach ($m in Get-ChildItem (Join-Path $kit 'modules') -Filter *.ps1) { . $m.FullName }

Assert-CpAdmin

$os   = Get-CimInstance Win32_OperatingSystem
$isServer = $os.ProductType -ne 1
$isDC     = $os.ProductType -eq 2

if (-not $Config) {
    foreach ($c in (Join-Path (Get-Location) 'cp-config.txt'), (Join-Path $kit 'cp-config.txt'), (Join-Path (Split-Path $kit) 'cp-config.txt')) {
        if (Test-Path $c) { $Config = $c; break }
    }
}
try { $cfg = Import-CpConfig -Path $(if ($Config) { $Config } else { '.\cp-config.txt' }) } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }

# Turn README nicknames (FTP, IIS, RDP...) into real service names BEFORE any module runs,
# so a wrong name can never let the real service be disabled.
$crit = Resolve-CpCriticalServices -Services @(Get-Service | Select-Object Name, DisplayName) -Critical $cfg.Critical
$critTyped = $cfg.Critical
$cfg.Critical = $crit.Names
if ($crit.NeedsRdp -and -not $cfg.KeepRdp) { $cfg.KeepRdp = $true; $rdpForced = $true }

$run = Join-Path 'C:\cpkit-runs' (Get-Date -Format 'yyyyMMdd-HHmmss')
if (Test-Path $run) { $run = "$run-$PID" }
Set-CpContext -RunDir $run -Apply:$Apply -Yes:$Yes

$order = [ordered]@{
    Users           = @{ Fn = { Invoke-CpModUsers -Config $cfg -IsDC:$isDC };          What = 'accounts + Administrators match README; disable Guest/Administrator' }
    AccountPolicy   = @{ Fn = { Invoke-CpModAccountPolicy -Config $cfg -IsDC:$isDC };  What = 'password length/age/history/complexity; lockout 5 / 30 min' }
    AuditPolicy     = @{ Fn = { Invoke-CpModAuditPolicy -Config $cfg };                What = 'audit success + failure for every category' }
    SecurityOptions = @{ Fn = { Invoke-CpModSecurityOptions -Config $cfg };            What = 'UAC, no anonymous SAM/shares, NTLMv2, SMB signing, CTRL+ALT+DEL' }
    Firewall        = @{ Fn = { Invoke-CpModFirewall -Config $cfg };                   What = 'all profiles on, block inbound, allow outbound' }
    Defender        = @{ Fn = { Invoke-CpModDefender -Config $cfg };                   What = 'real-time on, PUA on, remove exclusions, update + quick scan' }
    Services        = @{ Fn = { Invoke-CpModServices -Config $cfg };                   What = 'disable risky services (not README-critical); Windows Update auto' }
    Remote          = @{ Fn = { Invoke-CpModRemote -Config $cfg };                     What = 'RDP off (or on + NLA if KEEP_RDP=yes); Remote Assistance off' }
    Shares          = @{ Fn = { Invoke-CpModShares -Config $cfg };                     What = 'remove non-default shares; SMBv1 off; SMB signing' }
    Features        = @{ Fn = { Invoke-CpModFeatures -Config $cfg };                   What = 'Telnet/TFTP/SMB1/PowerShell v2 features off' }
    Updates         = @{ Fn = { Invoke-CpModUpdates -Config $cfg };                    What = 'automatic updates on; list apps to update by hand' }
    Software        = @{ Fn = { Invoke-CpModSoftware -Config $cfg };                   What = 'REPORT unwanted programs (uninstall by hand)' }
    Persistence     = @{ Fn = { Invoke-CpModPersistence -Config $cfg };                What = 'REPORT run keys, tasks, startup, IFEO, hosts, listeners, nc.exe' }
    Media           = @{ Fn = { Invoke-CpModMedia -Config $cfg };                      What = 'REPORT media + prohibited files (delete by hand later)' }
}
if ($isServer) { $order['Server'] = @{ Fn = { Invoke-CpModServer -Config $cfg -IsDC:$isDC }; What = 'AD users + domain password policy (DC), DNS, IIS, FTP' } }

Write-Host '================================================================'
Write-Host (" CyberPatriot Windows kit   mode: {0}   {1}{2}" -f $(if ($Apply) {'APPLY'} else {'AUDIT'}), $os.Caption, $(if ($isDC) {' (domain controller)'} else {''}))
Write-Host " config : $Config"
Write-Host " admins : $($cfg.Admins -join ' ')"
Write-Host " users  : $($cfg.Users -join ' ')"
Write-Host " critical services: $($critTyped -join ' ')   KEEP_RDP: $($cfg.KeepRdp)   KEEP_SHARES: $($cfg.KeepShares -join ' ')"
foreach ($m in $crit.Map) { Write-Host "   protected: $m" }
foreach ($m in $crit.Missing) {
    Write-Host "   WARNING: critical service '$m' not found - use the service NAME (TermService, W3SVC, FTPSVC, LanmanServer). Fix cp-config.txt before -Apply." -ForegroundColor Yellow
    Add-CpFinding services "critical service '$m' from cp-config.txt not found on this machine - nothing protects it"
}
if ($rdpForced) { Write-Host '   NOTE: Remote Desktop is a critical service, so KEEP_RDP was treated as yes.' -ForegroundColor Yellow }
Write-Host " running as: $env:USERNAME   run dir: $run"
Write-Host '================================================================'
if ($Apply -and -not $Yes) {
    $a = Read-Host 'Forensics questions answered AND VMware snapshot taken? [y/N]'
    if ($a -notmatch '^[Yy]') { Write-Host 'Do those first. Nothing was changed.'; exit 0 }
}

function Invoke-CpNamed([string]$name) {
    $key = @($order.Keys) | Where-Object { $_ -ieq $name } | Select-Object -First 1
    if (-not $key) { Write-Host "unknown module '$name'. Choose: $(@($order.Keys) -join ', ')"; return }
    try { & $order[$key].Fn } catch { Write-Host "  module $key stopped: $($_.Exception.Message)" -ForegroundColor Red; Write-CpLog $key 'FAILED' 'module' $_.Exception.Message 'exception' }
}

if ($Module) { foreach ($m in $Module) { Invoke-CpNamed $m } }
elseif ($All) { foreach ($k in @($order.Keys)) { Invoke-CpNamed $k } }
else {
    $keys = @($order.Keys)
    while ($true) {
        Write-Host ''; Write-Host 'Modules (recommended order - snapshot between them):'
        for ($i = 0; $i -lt $keys.Count; $i++) { Write-Host ('  {0,2}) {1,-16} {2}' -f ($i + 1), $keys[$i], $order[$keys[$i]].What) }
        Write-Host '   a) all in order     q) quit'
        $c = Read-Host 'Choose'
        if ($c -match '^(q|)$') { break }
        elseif ($c -eq 'a') { foreach ($k in $keys) { Invoke-CpNamed $k } }
        elseif ($c -match '^\d+$' -and [int]$c -ge 1 -and [int]$c -le $keys.Count) { Invoke-CpNamed $keys[[int]$c - 1] }
        else { Invoke-CpNamed $c }
    }
}

$changes  = @(Select-String -Path (Join-Path $run 'log.txt') -Pattern ' \| ACTION \| ' -ErrorAction SilentlyContinue).Count
$findings = @(Get-Content (Join-Path $run 'findings.txt') -ErrorAction SilentlyContinue).Count
Write-Host ''
Write-Host '================================================================'
Write-Host " done. changes made: $changes   findings to review: $findings"
Write-Host " findings: $(Join-Path $run 'findings.txt')    backups: $(Join-Path $run 'backup')"
if (-not $Apply) { Write-Host ' This was an AUDIT. Re-run with -Apply to make changes.' }
Write-Host '================================================================'

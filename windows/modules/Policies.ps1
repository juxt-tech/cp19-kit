# Account policy, audit policy and security options (Local Security Policy).
# CP categories: Account Policies, Local Policies. Values come from a scored CP answer key
# (accepted ranges in brackets): see docs/research.md section 1.

$script:CpAccountPolicy = [ordered]@{
    MinimumPasswordLength = '10'   # [8-14]
    PasswordComplexity    = '1'
    PasswordHistorySize   = '5'    # [5-10]
    MaximumPasswordAge    = '90'   # [30-90]
    MinimumPasswordAge    = '10'   # [10-30]
    ClearTextPassword     = '0'    # reversible encryption off
    LockoutBadCount       = '5'    # [5-50]
    ResetLockoutCount     = '30'   # [30-60]
    LockoutDuration       = '30'   # [30-60]
}

$L  = 'MACHINE\System\CurrentControlSet\Control\Lsa'
$PS = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
$script:CpSecurityOptions = [ordered]@{
    "$L\LimitBlankPasswordUse"            = '4,1'  # Accounts: limit blank passwords to console logon
    "$L\RestrictAnonymousSAM"             = '4,1'  # no anonymous enumeration of SAM accounts
    "$L\RestrictAnonymous"                = '4,1'  # ... and shares
    "$L\EveryoneIncludesAnonymous"        = '4,0'
    "$L\LmCompatibilityLevel"             = '4,5'  # NTLMv2 only, refuse LM & NTLM
    "$L\NoLMHash"                         = '4,1'
    "$L\SCENoApplyLegacyAuditPolicy"      = '4,1'  # let the detailed audit policy win
    "$L\DisableDomainCreds"               = '4,1'
    'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword' = '4,0'
    'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature' = '4,1'
    'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'     = '4,1'
    'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess'       = '4,1'
    'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal'               = '4,1'
    'MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers' = '4,1'
    'MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown'      = '4,1'
    'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel'               = '4,0'
    "$PS\EnableLUA"                       = '4,1'  # UAC on
    "$PS\ConsentPromptBehaviorAdmin"      = '4,2'  # prompt for consent on the secure desktop
    "$PS\ConsentPromptBehaviorUser"       = '4,0'  # standard users: deny elevation requests
    "$PS\PromptOnSecureDesktop"           = '4,1'
    "$PS\EnableUIADesktopToggle"          = '4,0'
    "$PS\FilterAdministratorToken"        = '4,1'
    "$PS\EnableInstallerDetection"        = '4,1'
    "$PS\DisableCAD"                      = '4,0'  # require CTRL+ALT+DEL
    "$PS\DontDisplayLastUserName"         = '4,1'
    "$PS\InactivityTimeoutSecs"           = '4,900'  # Interactive logon: machine inactivity limit
    "$PS\ShutdownWithoutLogon"            = '4,0'    # no Shut down button on the logon screen
    "$L\MSV1_0\allownullsessionfallback"  = '4,0'    # no LocalSystem NULL session fallback
}

# User Rights Assignment (Local Policies). REPORT ONLY: a wrong removal here can break services or logons.
$script:CpRightNames = @{
    SeDebugPrivilege='Debug programs'; SeTcbPrivilege='Act as part of the operating system'; SeCreateTokenPrivilege='Create a token object'
    SeTakeOwnershipPrivilege='Take ownership of files or other objects'; SeLoadDriverPrivilege='Load and unload device drivers'
    SeBackupPrivilege='Back up files and directories'; SeRestorePrivilege='Restore files and directories'
    SeSecurityPrivilege='Manage auditing and security log'; SeSystemEnvironmentPrivilege='Modify firmware environment values'
    SeRemoteShutdownPrivilege='Force shutdown from a remote system'; SeTrustedCredManAccessPrivilege='Access Credential Manager as a trusted caller'
    SeEnableDelegationPrivilege='Enable accounts to be trusted for delegation'; SeImpersonatePrivilege='Impersonate a client after authentication'
    SeAssignPrimaryTokenPrivilege='Replace a process level token'
    SeNetworkLogonRight='Access this computer from the network'; SeInteractiveLogonRight='Allow log on locally'
    SeRemoteInteractiveLogonRight='Allow log on through Remote Desktop Services'; SeBatchLogonRight='Log on as a batch job'
    SeServiceLogonRight='Log on as a service'; SeDenyNetworkLogonRight='Deny access to this computer from the network'
}
$script:CpBroadSids = @{ '*S-1-1-0'='Everyone'; '*S-1-5-32-545'='Users'; '*S-1-5-32-546'='Guests'; '*S-1-5-11'='Authenticated Users'; '*S-1-5-7'='ANONYMOUS LOGON' }

# Pure. InfText = secedit export. Returns finding strings.
function Get-CpUserRightsFindings {
    param([Parameter(Mandatory)][string]$InfText)
    $rights = @{}; $in = $false
    foreach ($line in ($InfText -split "`r?`n")) {
        if ($line -match '^\s*\[(.+)\]\s*$') { $in = ($Matches[1] -eq 'Privilege Rights'); continue }
        if ($in -and $line -match '^\s*(\w+)\s*=\s*(.*?)\s*$') { $rights[$Matches[1]] = @($Matches[2] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    }
    $isGuest = { param($e) $e -ieq 'Guest' -or $e -ieq 'Guests' -or $e -match '^\*S-1-5-21-.+-501$' -or $e -eq '*S-1-5-32-546' }
    $show    = { param($e) if ($script:CpBroadSids.ContainsKey($e)) { $script:CpBroadSids[$e] } else { $e.TrimStart('*') } }
    $out = @()
    foreach ($r in @($rights.Keys | Sort-Object)) {
        $name = if ($script:CpRightNames.ContainsKey($r)) { $script:CpRightNames[$r] } else { $r }
        foreach ($e in $rights[$r]) {
            $bad = $false
            if ($r -match 'Privilege$' -and $script:CpRightNames.ContainsKey($r)) {
                # powerful privilege: nobody broad, no single user account (CP plants e.g. "hacker" in Debug programs)
                $bad = $script:CpBroadSids.ContainsKey($e) -or $e -match '^\*S-1-5-21-' -or ($e -notmatch '^\*' -and $e -ine 'Administrators')
            } elseif ($r -in 'SeNetworkLogonRight','SeInteractiveLogonRight','SeRemoteInteractiveLogonRight','SeBatchLogonRight','SeServiceLogonRight') {
                $bad = (& $isGuest $e) -or $e -eq '*S-1-5-7' -or ($r -ne 'SeNetworkLogonRight' -and $e -eq '*S-1-1-0')
            }
            if ($bad) { $out += "user right '$name' ($r) is held by $(& $show $e) - remove it in secpol.msc > User Rights Assignment unless the README needs it" }
        }
    }
    if (-not @($rights['SeDenyNetworkLogonRight'] | Where-Object { & $isGuest $_ }).Count) {
        $out += "user right 'Deny access to this computer from the network' does not include Guest - add Guest in secpol.msc > User Rights Assignment"
    }
    return $out
}

function Invoke-CpSeceditSection {
    param([string]$Module, [string]$Section, $Wanted, [string]$Why)
    $inf = Export-CpSecPolicy
    if (-not $inf) { Add-CpFinding $Module 'secedit /export returned nothing - run as Administrator?'; return }
    $ctx = Get-CpContext
    if ($ctx.RunDir) {
        $bk = Join-Path $ctx.RunDir 'backup\secpol-before.inf'
        if (-not (Test-Path $bk)) { New-Item -ItemType Directory -Force (Split-Path $bk) | Out-Null; Set-Content $bk $inf -Encoding Unicode }
    }
    $new = $inf; $changes = @()
    foreach ($k in $Wanted.Keys) {
        $cur = Get-CpInfValue -InfText $inf -Section $Section -Key $k
        if ($cur -eq $Wanted[$k]) { Write-CpOk "$(($k -split '\\')[-1]) = $cur"; continue }
        $changes += "$(($k -split '\\')[-1]): $(if ($null -eq $cur) {'(not set)'} else {$cur}) -> $($Wanted[$k])"
        $new = Set-CpInfValue -InfText $new -Section $Section -Key $k -Value $Wanted[$k]
    }
    if ($changes.Count -eq 0) { return }
    $changes | ForEach-Object { Write-Host "  -    $_" }
    Invoke-CpAction $Module "apply $($changes.Count) $Section change(s) via secedit" $Why { Import-CpSecPolicy -InfText $new }.GetNewClosure()
}

function Invoke-CpModAccountPolicy {
    param($Config, [switch]$IsDC)
    Write-CpHeader 'ACCOUNT POLICY  (password + lockout)'
    if ($IsDC) { Write-Host '  Domain controller: the domain policy wins - use the Server module.'; return }
    Invoke-CpSeceditSection -Module accountpolicy -Section 'System Access' -Wanted $script:CpAccountPolicy -Why 'scored password/lockout values'
}

function Invoke-CpModSecurityOptions {
    param($Config)
    Write-CpHeader 'SECURITY OPTIONS  (UAC, anonymous access, NTLM, SMB signing)'
    Invoke-CpSeceditSection -Module securityoptions -Section 'Registry Values' -Wanted $script:CpSecurityOptions -Why 'Local Policies > Security Options'
    $inf = Export-CpSecPolicy
    if ($inf) {
        $f = @(Get-CpUserRightsFindings -InfText $inf)
        foreach ($x in $f) { Add-CpFinding userrights $x }
        if ($f.Count) { Write-Host "  !    $($f.Count) user-rights problem(s) listed in findings.txt (fix by hand in secpol.msc)" -ForegroundColor Yellow } else { Write-CpOk 'user rights: nothing risky found' }
    }
}

# "/file:" and the path must be ONE argument; "/file:(Join-Path ...)" splits into two.
function Get-CpAuditpolBackupArg([string]$Path) { "/file:$Path" }

function Invoke-CpModAuditPolicy {
    param($Config)
    Write-CpHeader 'AUDIT POLICY  (success + failure everywhere)'
    $csv = & auditpol.exe /get /category:* /r 2>$null | ConvertFrom-Csv
    if (-not $csv) { Add-CpFinding auditpolicy 'auditpol returned nothing - run as Administrator?'; return }
    $weak = @($csv | Where-Object { $_.'Inclusion Setting' -ne 'Success and Failure' })
    if ($weak.Count -eq 0) { Write-CpOk 'all subcategories audit Success and Failure'; return }
    Write-Host "  -    $($weak.Count) of $($csv.Count) subcategories not auditing Success and Failure"
    $ctx = Get-CpContext
    Invoke-CpAction auditpolicy 'auditpol: enable success+failure for all categories' 'scored: every audit category = Success, Failure' {
        if ($ctx.RunDir) {
            New-Item -ItemType Directory -Force (Join-Path $ctx.RunDir 'backup') | Out-Null
            $bk = Join-Path $ctx.RunDir 'backup\auditpol.csv'
            if (-not (Test-Path $bk)) { & auditpol.exe /backup (Get-CpAuditpolBackupArg -Path $bk) | Out-Null }
        }
        & auditpol.exe /set /category:* /success:enable /failure:enable | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "auditpol exit $LASTEXITCODE" }
    }.GetNewClosure()
}

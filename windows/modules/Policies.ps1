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
    "$L\ForceGuest"                       = '4,0'  # Sharing and security model for local accounts = Classic
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
    # Round 4 (Baldi's Basics / Dead by Daylight answer keys + the CIS options image makers reuse)
    'MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode'                     = '4,1'  # strengthen default permissions of internal system objects
    'MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive'           = '4,1'
    "$PS\EnableVirtualization"            = '4,1'  # UAC: virtualize file and registry write failures
    "$PS\EnableSecureUIAPaths"            = '4,1'  # UAC: only elevate UIAccess apps installed in secure locations
    'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature' = '4,1'
    'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature'      = '4,1'
    'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff'           = '4,1'
    'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect'               = '4,15' # idle SMB session limit (minutes)
    'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares'            = '7,'   # no share reachable anonymously (DBD: NETLOGON)
    'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel'             = '4,1'
    'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel'             = '4,1'
    'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey'              = '4,1'
    'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange'         = '4,0'
    "$L\MSV1_0\NTLMMinClientSec"          = '4,537395200'  # NTLMv2 session security + 128-bit
    "$L\MSV1_0\NTLMMinServerSec"          = '4,537395200'
    'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity'                          = '4,1'  # LDAP client: negotiate signing
}
# Domain controllers only. Kept apart so it gets its own question: an application that binds to LDAP
# without signing or TLS (a plain "simple bind") stops working once the DC requires signing.
# Scored on both DC answer keys read (Baldi's Basics, Dead by Daylight).
function Get-CpDcSecurityOptions {
    [ordered]@{
        'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity' = '4,2'   # LDAP server signing: Require signing
        'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange' = '4,0'
    }
}

# Scored settings secedit can't set (not in its Security Options list). Seen in practice-image answer keys.
$script:CpExtraSecurityRegistry = @(
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' AllowInsecureGuestAuth 0 'Enable insecure guest logons = Disabled'
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' AllowInsecureGuestAuth 0 'no unauthenticated guest SMB access'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' EnableSmartScreen 1 'Defender SmartScreen on'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' ShellSmartScreenLevel 'Warn' 'SmartScreen configured to warn' 'String'
    New-CpReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 255 'AutoPlay off for all drives'
    New-CpReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoAutorun 1 'no autorun.inf commands'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' NoAutoplayfornonVolume 1 'AutoPlay off for phones/cameras'
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0 'no plaintext passwords in LSASS (mimikatz)'
    # Round 4: classic privilege-escalation switches + the Baldi's Basics / Dead by Daylight items
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' AlwaysInstallElevated 0 'MSI packages must not install with SYSTEM rights'
    New-CpReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' LocalAccountTokenFilterPolicy 0 'UAC also filters remote logons of local admins'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0 'LLMNR off (name-poisoning attacks, Responder)'
    New-CpReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' AllowEncryptionOracle 0 'CredSSP encryption oracle: Force Updated Clients'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' EnableScriptBlockLogging 1 'PowerShell script block logging on'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' AllowBasic 0 'WinRM service: no Basic authentication'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' AllowUnencryptedTraffic 0 'WinRM service: no unencrypted traffic'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' AllowBasic 0 'WinRM client: no Basic authentication'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' AllowUnencryptedTraffic 0 'WinRM client: no unencrypted traffic'
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' DisableWpbtExecution 1 'Windows Platform Binary Table off (programs planted in firmware)'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots' Flags 1 'users cannot add their own trusted root certificates'
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Policies' NtfsEncryptPagingFile 1 'NTFS pagefile encryption (after the next reboot)'
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' NtfsEncryptPagingFile 1 'NTFS pagefile encryption (after the next reboot)'
    # Round 5: ideas from Ripper1004/CyberPatriot-Toolkit (CIS / MSS items seen on CP answer keys)
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' RunAsPPL 1 'LSA protection: blocks mimikatz-style password dumping (full effect after reboot)'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' EnableUserControl 0 'users cannot change Windows Installer options'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' RestrictDriverInstallationToAdministrators 1 'PrintNightmare: only admins install printer drivers'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' NoWarningNoElevationOnInstall 0 'PrintNightmare: Point and Print warns + asks for elevation (install)'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' UpdatePromptSettings 0 'PrintNightmare: Point and Print warns + asks for elevation (update)'
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' SafeDllSearchMode 1 'safe DLL search order (no DLL planting from the current folder)'
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' DisableExceptionChainValidation 0 'SEHOP exploit protection on'
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DisableIPSourceRouting 2 'MSS: IPv4 source routing off'
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' DisableIPSourceRouting 2 'MSS: IPv6 source routing off'
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' EnableICMPRedirect 0 'MSS: ICMP redirects cannot change routes'
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' NoNameReleaseOnDemand 1 'MSS: ignore NetBIOS name-release requests'
    New-CpReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' DisableWpad 1 'WPAD proxy auto-discovery off (Responder-style attacks)'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' EnableModuleLogging 1 'PowerShell module logging on'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' '*' '*' 'PowerShell module logging for every module' 'String'
    New-CpReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled 1 'process-creation events include the command line'
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' fAllowFullControl 0 'Remote Assistance cannot take full control'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' fAllowUnsolicited 0 'no unsolicited Remote Assistance offers'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' fDisableCdm 1 'Remote Desktop cannot map the client drives'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' DisableRunAs 1 'WinRM service: no stored RunAs credentials'
)
# Domain controllers only (Zerologon, CVE-2020-1472). Enforcement mode is the default since Feb 2021;
# images turn it off or add a VulnerableChannelAllowList.
$script:CpDcExtraRegistry = @(
    New-CpReg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' FullSecureChannelProtection 1 'Zerologon: Netlogon secure RPC enforced for every machine'
)

# Pure. True when the LocalMachine execution policy lets any script run.
function Test-CpLooseExecutionPolicy([string]$Policy) { $Policy -in @('Unrestricted', 'Bypass') }

# Pure. BcdText = 'bcdedit /enum {current}' output. Returns the nx policy, or $null if not shown.
function Get-CpDepPolicy([string]$BcdText) {
    foreach ($line in ($BcdText -split "`r?`n")) { if ($line -match '^\s*nx\s+(\S+)') { return $Matches[1] } }
    return $null
}

function Invoke-CpDep {
    $nx = Get-CpDepPolicy ((& bcdedit.exe /enum '{current}' 2>$null) -join "`n")
    if (-not $nx) { Add-CpFinding securityoptions 'could not read DEP (bcdedit /enum {current}) - check System > Advanced > Performance > DEP by hand'; return }
    if ($nx -in 'OptOut','AlwaysOn') { Write-CpOk "DEP = $nx (all programs)"; return }
    $bl = $null   # Server has no BitLocker cmdlets unless the feature is installed
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue }
    if ($bl -and "$($bl.ProtectionStatus)" -eq 'On') {
        Add-CpFinding securityoptions "DEP is $nx. BitLocker is on, so the kit won't touch boot settings. Set DEP for all programs by hand (System > Advanced > Performance > DEP)"
        return
    }
    Invoke-CpAction securityoptions "DEP $nx -> OptOut (all programs and services; reboot later)" 'DEP enabled system wide' {
        & bcdedit.exe /set '{current}' nx OptOut | Out-Null }
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
    param([Parameter(Mandatory)][string]$InfText, [string[]]$ServiceAccounts = @())
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
            if ($bad) { $out += "user right '$name' ($r) is held by $(& $show $e) - remove it in secpol.msc > User Rights Assignment unless the README needs it"; continue }
            # a plain user with "Log on as a service/batch job" is a planted backdoor unless it's a service account
            # (District 13: svc_iis_caseportal needs it - removing it breaks the scored caseportal)
            if ($r -in 'SeServiceLogonRight','SeBatchLogonRight' -and ($e -match '^\*S-1-5-21-' -or $e -notmatch '^(\*|NT SERVICE\\|IIS APPPOOL\\)')) {
                $acct = ($e -split '\\')[-1]
                if ($acct.Contains('$')) { continue }   # groups like SQLServer2005SQLBrowserUser$HOST, gMSAs, computers
                if (@($ServiceAccounts | Where-Object { $_ -ieq $acct }).Count) { continue }
                $out += "user right '$name' ($r) is held by account $(& $show $e) - remove it unless a service or the README needs that account"
            }
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
    $isDC = (Get-CimInstance Win32_OperatingSystem).ProductType -eq 2
    if ($isDC) {
        Invoke-CpSeceditSection -Module securityoptions -Section 'Registry Values' -Wanted (Get-CpDcSecurityOptions) `
            -Why 'domain controller: LDAP server signing = Require signing. Say NO if the README names an app that logs in to LDAP with a plain simple bind'
        Invoke-CpRegistrySettings -Module securityoptions -Wanted $script:CpDcExtraRegistry
        $allow = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction SilentlyContinue).VulnerableChannelAllowList
        if ($allow) { Add-CpFinding securityoptions "Zerologon: VulnerableChannelAllowList is set ($allow) - machines in it skip secure RPC. Delete the value under HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters (and the GPO 'Domain controller: Allow vulnerable Netlogon secure channel connections')" }
        Add-CpFinding securityoptions 'DC: a domain GPO beats local policy. If a Security Option does not score, set it in gpmc.msc > Default Domain Controllers Policy too, then gpupdate /force (also: Account Policies > Kerberos Policy > Enforce user logon restrictions = Enabled)'
    }
    Invoke-CpRegistrySettings -Module securityoptions -Wanted $script:CpExtraSecurityRegistry
    Invoke-CpDep
    $ep = "$(Get-ExecutionPolicy -Scope LocalMachine)"
    if (Test-CpLooseExecutionPolicy $ep) {
        Invoke-CpAction securityoptions "PowerShell execution policy (LocalMachine) $ep -> RemoteSigned" 'any downloaded script could run' {
            Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop }
    } else { Write-CpOk "PowerShell execution policy (LocalMachine) = $ep" }
    $gpEp = "$(Get-ExecutionPolicy -Scope MachinePolicy)"
    if (Test-CpLooseExecutionPolicy $gpEp) { Add-CpFinding securityoptions "Group Policy forces PowerShell execution policy $gpEp (MachinePolicy) - set 'Turn on Script Execution' to Allow only signed / local scripts, or delete HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy" }
    $inf = Export-CpSecPolicy
    if ($inf) {
        $all  = if ($isDC) { @(Get-ADUser -Filter * -ErrorAction SilentlyContinue | ForEach-Object SamAccountName) } else { @(Get-LocalUser | ForEach-Object Name) }
        $f = @(Get-CpUserRightsFindings -InfText $inf -ServiceAccounts (Get-CpServiceAccounts -AllUsers $all -IsDC:$isDC))
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

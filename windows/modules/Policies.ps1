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
}

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
        if ($ctx.RunDir) { New-Item -ItemType Directory -Force (Join-Path $ctx.RunDir 'backup') | Out-Null; & auditpol.exe /backup /file:(Join-Path $ctx.RunDir 'backup\auditpol.csv') | Out-Null }
        & auditpol.exe /set /category:* /success:enable /failure:enable | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "auditpol exit $LASTEXITCODE" }
    }.GetNewClosure()
}

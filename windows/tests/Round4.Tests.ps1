# Round 4 (2026-11-11): gaps found in the Baldi's Basics (Server 2022 DC) and Dead by Daylight
# (Server 2019 DC) answer keys, plus the open backlog item "one failed AD read ends the Server module".
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$kit  = Split-Path -Parent $here
Import-Module (Join-Path $kit 'lib\CpCommon.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $kit 'lib\CpSecedit.psm1') -Force -DisableNameChecking
. (Join-Path $kit 'modules\Users.ps1')
. (Join-Path $kit 'modules\System.ps1')
. (Join-Path $kit 'modules\Policies.ps1')
. (Join-Path $kit 'modules\Reports.ps1')
. (Join-Path $kit 'modules\Server.ps1')

function Svc($n, $t, $s) { [pscustomobject]@{ Name = $n; StartType = $t; Status = $s } }
function Has($plan, $action, $name) { @($plan | Where-Object { $_.Action -eq $action -and $_.Name -eq $name }).Count -gt 0 }
$cfg = [pscustomobject]@{ Admins=@('boss'); Users=@('alice'); Critical=@(); Allowed=@(); NewPassword=''; KeepRdp=$false; KeepShares=@() }

Describe 'Invoke-CpRetry (District 13: first AD read failed once with "A local error has occurred")' {
    It 'returns the value once the block stops failing' {
        $script:n = 0
        $r = Invoke-CpRetry -Tries 3 -DelaySec 0 -ScriptBlock { $script:n++; if ($script:n -lt 3) { throw 'A local error has occurred' }; 'ok' }
        $r | Should Be 'ok'
        $script:n | Should Be 3
    }
    It 'does not run a working block twice' {
        $script:n = 0
        Invoke-CpRetry -Tries 3 -DelaySec 0 -ScriptBlock { $script:n++; 1 } | Out-Null
        $script:n | Should Be 1
    }
    It 'throws the last error when every try fails' {
        $script:n = 0
        { Invoke-CpRetry -Tries 2 -DelaySec 0 -ScriptBlock { $script:n++; throw 'still broken' } } | Should Throw 'still broken'
        $script:n | Should Be 2
    }
}

Describe 'Security options from the DC answer keys' {
    It 'strengthens default permissions of internal system objects (Baldi)' {
        $script:CpSecurityOptions['MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode'] | Should Be '4,1'
    }
    It 'empties the anonymous share list (Dead by Daylight: NETLOGON reachable anonymously)' {
        $script:CpSecurityOptions['MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares'] | Should Be '7,'
    }
    It 'LDAP server signing is a DC-only setting' {
        (Get-CpDcSecurityOptions)['MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'] | Should Be '4,2'
        $script:CpSecurityOptions.Contains('MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity') | Should Be $false
    }
    It 'registry extras: AlwaysInstallElevated, LLMNR, CredSSP oracle, WPBT' {
        $names = @($script:CpExtraSecurityRegistry | ForEach-Object Name)
        foreach ($n in 'AlwaysInstallElevated','EnableMulticast','AllowEncryptionOracle','DisableWpbtExecution','EnableScriptBlockLogging') { ($names -contains $n) | Should Be $true }
    }
    It 'a planted AlwaysInstallElevated=1 is planned back to 0' {
        $w = @($script:CpExtraSecurityRegistry | Where-Object Name -eq 'AlwaysInstallElevated')
        $plan = Get-CpRegistryPlan -Wanted $w -Current @{ "$($w[0].Path)\AlwaysInstallElevated" = 1 }
        $plan.Count | Should Be 1
        $plan[0].Value | Should Be 0
    }
}

Describe 'Services on a domain controller' {
    $svcs = @((Svc 'Spooler' 'Automatic' 'Running'), (Svc 'W32Time' 'Disabled' 'Stopped'))
    It 'disables the Print Spooler on a DC (PrintNightmare; Dead by Daylight)' {
        Has (Get-CpServicePlan -Services $svcs -Config $cfg -IsDC) 'Disable' 'Spooler' | Should Be $true
    }
    It 'leaves the Print Spooler alone on a workstation' {
        Has (Get-CpServicePlan -Services $svcs -Config $cfg) 'Disable' 'Spooler' | Should Be $false
    }
    It 'keeps a README-critical Spooler on a DC' {
        $c2 = [pscustomobject]@{ Admins=@('boss'); Users=@(); Critical=@('Spooler'); Allowed=@(); NewPassword=''; KeepRdp=$false; KeepShares=@() }
        Has (Get-CpServicePlan -Services $svcs -Config $c2 -IsDC) 'Disable' 'Spooler' | Should Be $false
    }
    It 'starts Windows Time on a DC (Kerberos needs it)' {
        Has (Get-CpServicePlan -Services $svcs -Config $cfg -IsDC) 'EnableAuto' 'W32Time' | Should Be $true
    }
    It 'never touches Windows Time off a DC' {
        @(Get-CpServicePlan -Services $svcs -Config $cfg | Where-Object Name -eq 'W32Time').Count | Should Be 0
    }
}

Describe 'Get-CpAdUserFindings' {
    function U($n, $h) { $o = [pscustomobject]@{ SamAccountName=$n; UseDESKeyOnly=$false; TrustedForDelegation=$false; AccountNotDelegated=$false; SIDHistory=@(); Description='' }
        foreach ($k in $h.Keys) { $o.$k = $h[$k] }; $o }
    $users = @(
        (U 'boss'  @{}),
        (U 'bully' @{ UseDESKeyOnly = $true }),
        (U 'beans' @{ SIDHistory = @('S-1-5-21-1-2-3-512') }),
        (U 'notes' @{ Description = 'temp password: Winter2026!' }),
        (U 'deleg' @{ TrustedForDelegation = $true }),
        (U 'safe'  @{ AccountNotDelegated = $true; Description = 'Head of the art department' })
    )
    $f = @(Get-CpAdUserFindings -Users $users -DomainAdmins @('boss','safe') -Config $cfg)
    It 'turns DES-only Kerberos off (Baldi)'                 { Has $f 'DesOff' 'bully' | Should Be $true }
    It 'marks README Domain Admins as not delegatable (DBD)' { Has $f 'NotDelegated' 'boss' | Should Be $true }
    It 'skips admins already marked'                         { Has $f 'NotDelegated' 'safe' | Should Be $false }
    It 'does not mark ordinary users'                        { Has $f 'NotDelegated' 'bully' | Should Be $false }
    It 'reports SID history (Baldi)'                         { Has $f 'Finding' 'beans' | Should Be $true }
    It 'reports a password in the description field'         { Has $f 'Finding' 'notes' | Should Be $true }
    It 'reports unconstrained delegation on a user'          { Has $f 'Finding' 'deleg' | Should Be $true }
    It 'a normal description is not a finding'               { Has $f 'Finding' 'safe' | Should Be $false }
}

Describe 'Anonymous access to Active Directory' {
    It 'Pre-Windows 2000 group: Anonymous and Everyone are bad members' {
        $m = @('CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=d,DC=local', 'CN=S-1-5-7,CN=ForeignSecurityPrincipals,DC=d,DC=local', 'CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=d,DC=local')
        $bad = @(Get-CpPre2000BadMembers -MemberDns $m)
        $bad.Count | Should Be 2
        ($bad -join ' ') | Should Not Match 'S-1-5-11'
    }
    It 'dSHeuristics with 7th character 2 allows anonymous LDAP' {
        Test-CpAnonymousLdap '0000002' | Should Be $true
        Test-CpAnonymousLdap '0000000' | Should Be $false
        Test-CpAnonymousLdap ''        | Should Be $false
        Test-CpAnonymousLdap '001'     | Should Be $false
    }
    It 'the fix only changes that character' {
        Get-CpFixedHeuristics '0010002001' | Should Be '0010000001'
    }
}

Describe 'Get-CpDcSyncFindings (Dead by Daylight: a user with Replicating Directory Changes All)' {
    function Ace($who, $guid, $rights = 'ExtendedRight') { [pscustomobject]@{ IdentityReference = $who; ObjectType = [guid]$guid; ActiveDirectoryRights = $rights; AccessControlType = 'Allow' } }
    $all = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    $aces = @(
        (Ace 'DWIGHT\Ada' $all),
        (Ace 'DWIGHT\Domain Controllers' $all),
        (Ace 'BUILTIN\Administrators' $all),
        (Ace 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS' '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'),
        (Ace 'DWIGHT\Ada' 'bf967aba-0de6-11d0-a285-00aa003049e2' 'ReadProperty'),
        (Ace 'DWIGHT\helpdesk' '00000000-0000-0000-0000-000000000000' 'GenericAll')
    )
    $f = @(Get-CpDcSyncFindings -Aces $aces)
    It 'names the planted user'                       { ($f -join "`n") | Should Match 'DWIGHT\\Ada' }
    It 'names an account with full control too'       { ($f -join "`n") | Should Match 'DWIGHT\\helpdesk' }
    It 'ignores domain controllers and Administrators' { ($f -join "`n") | Should Not Match 'Domain Controllers|BUILTIN' }
    It 'one line per account'                         { $f.Count | Should Be 2 }
}

Describe 'Persistence spots from the DC answer keys' {
    It 'LSA packages: a non-default DLL is reported, defaults are not' {
        $f = @(Get-CpLsaPackageFindings -Notification @('scecli','rassfm','mimilib') -Security @('kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','""') -Authentication @('msv1_0'))
        $f.Count | Should Be 1
        $f[0] | Should Match 'mimilib'
    }
    It 'hacking PowerShell modules are named (Baldi: DSInternals)' {
        $b = @(Get-CpBadPsModules -Names @('Pester','PSReadLine','DSInternals','PowerSploit','ActiveDirectory'))
        ($b -join ',') | Should Be 'DSInternals,PowerSploit'
    }
    It 'PATH folders outside Windows / Program Files are reported (Baldi: C:\temp)' {
        $p = @(Get-CpOddPathEntries -Path 'C:\Windows\system32;C:\Windows;C:\temp;C:\Program Files\Git\cmd;%SystemRoot%\System32\Wbem;C:\Users\Public\bin;')
        ($p -join ',') | Should Be 'C:\temp,C:\Users\Public\bin'
    }
}

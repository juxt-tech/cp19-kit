# Gaps found by checking the kit against public practice-image answer keys
# (District 13 / Server 2022, L'Equipe du Dictateur / Win11, Cincinnati Zoo / Win10, PPTH / Win11).
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$kit  = Split-Path -Parent $here
Import-Module (Join-Path $kit 'lib\CpCommon.psm1') -Force -DisableNameChecking
. (Join-Path $kit 'modules\Users.ps1')
. (Join-Path $kit 'modules\System.ps1')
. (Join-Path $kit 'modules\Policies.ps1')
. (Join-Path $kit 'modules\Reports.ps1')

function Svc($n, $t, $s) { [pscustomobject]@{ Name = $n; StartType = $t; Status = $s } }
function Has($plan, $action, $name) { @($plan | Where-Object { $_.Action -eq $action -and $_.Name -eq $name }).Count -gt 0 }
$cfg = [pscustomobject]@{ Admins=@('a'); Users=@(); Critical=@(); Allowed=@(); NewPassword=''; KeepRdp=$false; KeepShares=@() }

Describe 'Service accounts are kept, not deleted (District 13 penalty: svc_iis_caseportal deleted, -5)' {
    $cfgU = [pscustomobject]@{ Admins=@('me','boss'); Users=@('alice'); Critical=@(); Allowed=@(); NewPassword='P@ss'; KeepRdp=$false; KeepShares=@() }
    $plan = Get-CpUserPlan -Config $cfgU -CurrentUser 'me' -LocalUsers @('me','boss','alice','hacker','svc_iis_caseportal','sqlrunner') `
        -Admins @('me','boss','sqlrunner','hacker') -ServiceAccounts @('svc_iis_caseportal','sqlrunner')
    It 'keeps the IIS service account'           { Has $plan 'KeepServiceAccount' 'svc_iis_caseportal' | Should Be $true }
    It 'does not delete it'                      { Has $plan 'RemoveUser' 'svc_iis_caseportal' | Should Be $false }
    It 'reports instead of demoting a service-account admin' {
        Has $plan 'RemoveAdmin' 'sqlrunner' | Should Be $false
        Has $plan 'KeepServiceAdmin' 'sqlrunner' | Should Be $true
    }
    It 'still deletes the hacker'                { Has $plan 'RemoveUser' 'hacker' | Should Be $true }
    It 'still demotes the hacker'                { Has $plan 'RemoveAdmin' 'hacker' | Should Be $true }
    It 'matches service accounts case-insensitively' {
        $p = Get-CpUserPlan -Config $cfgU -CurrentUser 'me' -LocalUsers @('SVC_Web') -ServiceAccounts @('svc_web')
        Has $p 'KeepServiceAccount' 'SVC_Web' | Should Be $true
    }
}

Describe 'ConvertTo-CpSamName' {
    It 'DOMAIN\user'      { ConvertTo-CpSamName 'DISTRICT\svc_iis_caseportal' | Should Be 'svc_iis_caseportal' }
    It '.\user'           { ConvertTo-CpSamName '.\sqlrunner' | Should Be 'sqlrunner' }
    It 'UPN'              { ConvertTo-CpSamName 'svc_web@district.local' | Should Be 'svc_web' }
    It 'LocalSystem -> null'           { ConvertTo-CpSamName 'LocalSystem' | Should Be $null }
    It 'NT AUTHORITY\... -> null'      { ConvertTo-CpSamName 'NT AUTHORITY\NetworkService' | Should Be $null }
    It 'NT SERVICE\MSSQLSERVER -> null' { ConvertTo-CpSamName 'NT SERVICE\MSSQLSERVER' | Should Be $null }
    It 'gMSA (ends in $) -> null'      { ConvertTo-CpSamName 'DISTRICT\gmsa_sql$' | Should Be $null }
    It 'name pattern catches svc_ and _svc, not "service-desk-bob"' {
        ('svc_iis' -match $script:CpServiceNameRe) -and ('backup_svc' -match $script:CpServiceNameRe) -and -not ('steven' -match $script:CpServiceNameRe) | Should Be $true
    }
}

Describe 'Services: DHCP Client / Event Log / Server must run (Cincinnati, L''Equipe keys)' {
    $plan = Get-CpServicePlan -Config $cfg -Services @(
        (Svc Dhcp Disabled Stopped), (Svc EventLog Automatic Stopped), (Svc LanmanServer Manual Stopped),
        (Svc wuauserv Automatic Stopped), (Svc BFE Automatic Running), (Svc Dnscache Disabled Stopped))
    It 'enables + starts a disabled DHCP Client'       { Has $plan 'EnableAuto' 'Dhcp' | Should Be $true }
    It 'starts Event Log that is Automatic but stopped' { Has $plan 'EnableAuto' 'EventLog' | Should Be $true }
    It 'enables Server (LanmanServer)'                  { Has $plan 'EnableAuto' 'LanmanServer' | Should Be $true }
    It 'leaves an idle Automatic wuauserv alone (re-run = 0 changes)' { Has $plan 'EnableAuto' 'wuauserv' | Should Be $false }
    It 'leaves a running BFE alone'                     { Has $plan 'EnableAuto' 'BFE' | Should Be $false }
    It 'still never touches DNS Client'                 { @($plan | Where-Object Name -eq 'Dnscache').Count | Should Be 0 }
}

Describe 'Defender default threat actions (PPTH key: severe threats no longer ignored)' {
    It 'resets Allow / NoAction, keeps default and Quarantine' {
        $mp = [pscustomobject]@{ LowThreatDefaultAction=0; ModerateThreatDefaultAction=2; HighThreatDefaultAction=6; SevereThreatDefaultAction=9; UnknownThreatDefaultAction=8 }
        (Get-CpThreatActionPlan -Mp $mp) -join ',' | Should Be 'HighThreatDefaultAction,SevereThreatDefaultAction,UnknownThreatDefaultAction'
    }
    It 'removes a threat-action POLICY of Allow, keeps Quarantine' {
        $p = Get-CpDefenderPolicyPlan -Values @{ 'Threats\ThreatSeverityDefaultAction\5' = '6'; 'Threats\ThreatSeverityDefaultAction\4' = '2' }
        $p -join ',' | Should Be 'Threats\ThreatSeverityDefaultAction\5'
    }
}

Describe 'Get-CpRegistryPlan (insecure guest logons, SmartScreen, AutoPlay, WDigest)' {
    $w = @( (New-CpReg 'HKLM:\X' A 0 'a'), (New-CpReg 'HKLM:\X' B 'Warn' 'b' 'String'), (New-CpReg 'HKLM:\Y' C 1 'c') )
    $p = Get-CpRegistryPlan -Wanted $w -Current @{ 'HKLM:\X\A' = 1; 'HKLM:\X\B' = 'Warn'; 'HKLM:\Y\C' = $null }
    It 'plans a wrong value'           { @($p | Where-Object Name -eq 'A').Count | Should Be 1 }
    It 'skips a correct string value'  { @($p | Where-Object Name -eq 'B').Count | Should Be 0 }
    It 'plans a missing value'         { @($p | Where-Object Name -eq 'C').Count | Should Be 1 }
    It 'treats 0 as set, not missing'  { (Get-CpRegistryPlan -Wanted @($w[0]) -Current @{ 'HKLM:\X\A' = 0 }).Count | Should Be 0 }
    It 'covers insecure guest logons + SmartScreen' {
        $names = $script:CpExtraSecurityRegistry | ForEach-Object Name
        ($names -contains 'AllowInsecureGuestAuth') -and ($names -contains 'ShellSmartScreenLevel') | Should Be $true
    }
}

Describe 'Get-CpDepPolicy (Cincinnati key: DEP system wide)' {
    It 'reads OptIn from bcdedit' { Get-CpDepPolicy "identifier {current}`r`nnx                      OptIn`r`nbootmenupolicy Standard" | Should Be 'OptIn' }
    It 'returns null when nx is missing' { Get-CpDepPolicy 'identifier {current}' | Should Be $null }
}

Describe 'User rights: plain account with Log on as a service (Cincinnati key: removed from Rat)' {
    $inf = "[Privilege Rights]`r`nSeServiceLogonRight = *S-1-5-80-0,*S-1-5-21-1-2-3-1005`r`nSeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551`r`nSeDenyNetworkLogonRight = Guest"
    $f = @(Get-CpUserRightsFindings -InfText $inf) -join "`n"
    It 'flags the local user SID'          { $f | Should Match 'S-1-5-21-1-2-3-1005' }
    It 'does not flag NT SERVICE\ALL SERVICES' { $f | Should Not Match 'S-1-5-80-0' }
    It 'does not flag Administrators / Backup Operators batch logon' { $f | Should Not Match 'Batch' }
}

Describe 'PII scan (L''Equipe: hidden credit-card file; PPTH: unencrypted medical records)' {
    It 'Luhn accepts a real test card'   { Test-CpLuhn '4111 1111 1111 1111' | Should Be $true }
    It 'Luhn rejects a random 16 digits' { Test-CpLuhn '1234567812345678' | Should Be $false }
    It 'finds a card number'  { (Get-CpPiiKinds "name,card`nbob,4111-1111-1111-1111") -join ',' | Should Be 'credit card' }
    It 'finds an SSN'         { (Get-CpPiiKinds 'patient: x  ssn 078-05-1120') -join ',' | Should Be 'SSN' }
    It 'ignores a phone number and a date' { (Get-CpPiiKinds 'call 408-555-1234 on 2026-10-29').Count | Should Be 0 }
    It 'ignores a millisecond timestamp that passes Luhn' {
        Test-CpLuhn '1730000000001' | Should Be $true
        (Get-CpPiiKinds '{"ts":1730000000001}').Count | Should Be 0
    }
    It 'finds Amex and Mastercard' {
        Test-CpCardNumber '3782 822463 10005' | Should Be $true
        Test-CpCardNumber '5555555555554444' | Should Be $true
    }
    It 'ignores an invalid SSN (area 000 / 9xx)' { (Get-CpPiiKinds 'id 000-12-3456 and 912-34-5678').Count | Should Be 0 }
}

Describe 'Media scan sees hidden files and skips the kit itself' {
    $root = Join-Path $env:TEMP "cpkit-media-$PID"
    New-Item -ItemType Directory -Force "$root\Desktop" | Out-Null
    Set-Content "$root\Desktop\cards.txt" 'visa 4111 1111 1111 1111'
    (Get-Item "$root\Desktop\cards.txt").Attributes = 'Hidden'
    New-Item -ItemType Directory -Force "$root\AppData\Local" | Out-Null
    Set-Content "$root\AppData\Local\cache.jpg" 'x'
    Set-Content "$root\Desktop\song.MP3" 'x'
    It 'Find-CpFiles returns the hidden file' {
        @(Find-CpFiles -Root $root -NameRegex '\.txt$' | Where-Object { $_ -like '*cards.txt' }).Count | Should Be 1
    }
    It 'Find-CpFiles matches names case-insensitively' {
        @(Find-CpFiles -Root $root -NameRegex '\.mp3$').Count | Should Be 1
    }
    It 'Find-CpFiles skips AppData' {
        @(Find-CpFiles -Root $root -NameRegex '\.jpg$' -SkipDirRegex '\\AppData$').Count | Should Be 0
    }
    It 'resolves the kit root from the module file' {
        # the module does Split-Path (Split-Path $PSScriptRoot), and $PSScriptRoot = ...\windows\modules
        $kitRoot = Split-Path (Split-Path (Split-Path (Get-Command Invoke-CpModMedia).ScriptBlock.File))
        Test-Path (Join-Path $kitRoot 'windows\harden.ps1') | Should Be $true
    }
    Remove-Item $root -Recurse -Force
}

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

# ---- Live run on the District 13 image (2026-10-31): bugs the real image exposed ----
. (Join-Path $kit 'modules\Server.ps1')

Describe 'District 13 live: scoring engine protected (CSSClient / phocus.exe)' {
    It 'CSSClient counts as a scoring service' { Test-CpProtectedService -Name 'CSSClient' -Config $cfg | Should Be $true }
    It 'CCSClient (real CyberPatriot) too'     { Test-CpProtectedService -Name 'CCSClient' -Config $cfg | Should Be $true }
    It 'scoring tasks are tagged leave-alone'  { Get-CpTaskVerdict -Name 'CSSClient Restarter' -Action 'C:\aeacus\CSSClient_Restarter.bat' | Should Match 'SCORING' }
}

Describe 'District 13 live: disguised scheduled tasks' {
    It 'flags GooseDesktop hidden in an Edge-named task' {
        Get-CpTaskVerdict -Name 'MicrosoftEdgeUpdateTaskMachineMain' -Action 'C:\inetpub\wwwroot\aspnet_client\system_web\4_0_30418\GooseDesktop.exe ' | Should Match 'DISGUISED'
    }
    It 'trusts the real Edge updater'   { Get-CpTaskVerdict -Name 'MicrosoftEdgeUpdateTaskMachineCore' -Action 'C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe /c' | Should Be '' }
    It 'trusts a quoted Program Files path' { Get-CpTaskVerdict -Name 'GoogleUpdaterTaskSystem' -Action '"C:\Program Files (x86)\Google\GoogleUpdater\updater.exe" --wake --system' | Should Be '' }
    It 'flags a hidden PowerShell from Downloads' { Get-CpTaskVerdict -Name 'autoroblux' -Action 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\beetee\Downloads\freeroblux.ps1"' | Should Match 'SUSPICIOUS' }
}

Describe 'District 13 live: media report collapses big asset folders' {
    $mk = { param($p, $h) [pscustomobject]@{ FullName = $p; Length = 2048; Attributes = $(if ($h) { [IO.FileAttributes]::Hidden } else { [IO.FileAttributes]::Normal }) } }
    $goose = 1..20 | ForEach-Object { & $mk "C:\inetpub\x\Memes\Meme$_.png" $true }
    $lines = Get-CpMediaLines -Files (@($goose) + @(& $mk 'C:\Users\Public\Downloads\jump-scare.png' $true))
    It 'one line for the 20-file folder' { @($lines | Where-Object { $_ -match '^folder: C:\\inetpub\\x\\Memes .*20 media files \(20 HIDDEN\)' }).Count | Should Be 1 }
    It 'single files still listed with HIDDEN' { @($lines | Where-Object { $_ -match 'jump-scare\.png.*HIDDEN' }).Count | Should Be 1 }
    It 'two lines total' { $lines.Count | Should Be 2 }
}

Describe 'District 13 live: roles guessed from services when DISM is broken' {
    It 'DC + DNS + IIS + ADCS' { (Get-CpRolesFromServices -Services @('NTDS','DNS','W3SVC','CertSvc','Spooler')) -join ',' | Should Be 'AD-Domain-Services,DNS,Web-Server,AD-Certificate' }
}

Describe 'District 13 live: Log on as a service held by service accounts is not "remove"' {
    $inf = "[Privilege Rights]`r`nSeServiceLogonRight = svc_iis_caseportal,SQLServer2005SQLBrowserUser`$WIN-X,hacker`r`nSeDenyNetworkLogonRight = Guest"
    $f = @(Get-CpUserRightsFindings -InfText $inf -ServiceAccounts @('svc_iis_caseportal')) -join "`n"
    It 'keeps the caseportal service account' { $f | Should Not Match 'svc_iis_caseportal' }
    It 'skips $-named groups'                  { $f | Should Not Match 'SQLServer2005' }
    It 'still flags hacker'                    { $f | Should Match 'hacker' }
}

Describe 'District 13 live: broken TEMP detection' {
    It 'missing dir is not writable' { Test-CpWritableDir 'C:\no\such\dir\cpkit' | Should Be $false }
    It 'real temp is writable'       { Test-CpWritableDir $env:TEMP | Should Be $true }
}

Describe 'District 13 live: plan functions iterate per item (Defender crash)' {
    It 'assigning a ,$out result then foreach gives strings, not one array' {
        $plan = Get-CpDefenderPolicyPlan -Values @{ 'Exclusions\Paths\C:\x' = 0; 'DisableAntiSpyware' = 1 }
        $types = foreach ($p in $plan) { $p.GetType().Name }
        ($types | Select-Object -Unique) -join ',' | Should Be 'String'
    }
}

Describe 'District 13 live #2: never remove the scoring engine''s Defender exclusion' {
    It 'keeps Exclusions\Paths\C:\aeacus\phocus.exe, removes others' {
        $p = Get-CpDefenderPolicyPlan -Values @{ 'Exclusions\Paths\C:\aeacus\phocus.exe' = 0; 'Exclusions\Paths\C:\evil' = 0; 'DisableAntiSpyware' = 1 }
        ($p | Sort-Object) -join ',' | Should Be 'DisableAntiSpyware,Exclusions\Paths\C:\evil'
    }
    It 'role guess returns plain names (was printed as System.Object[])' {
        $roles = Get-CpRolesFromServices -Services @('NTDS','DNS')
        "$($roles -join ', ')" | Should Be 'AD-Domain-Services, DNS'
    }
}

Describe 'District 13 live #3: backing up a missing registry key is not a failure' {
    It 'leaves LASTEXITCODE at 0 and makes no file' {
        $run = Join-Path $env:TEMP "cpkit-bk-$PID"; Set-CpContext -RunDir $run
        $global:LASTEXITCODE = 0
        Backup-CpRegistry 'HKCU\Software\cpkit-does-not-exist-12345'
        $global:LASTEXITCODE | Should Be 0
        Test-Path (Join-Path $run 'backup\registry') | Should Be $false
        Set-CpContext; Remove-Item $run -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Regression tests for the final-review findings (Windows side).
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$kit  = Split-Path -Parent $here
Import-Module (Join-Path $kit 'lib\CpCommon.psm1') -Force -DisableNameChecking
. (Join-Path $kit 'modules\Users.ps1')
. (Join-Path $kit 'modules\System.ps1')
. (Join-Path $kit 'modules\Policies.ps1')

Describe 'I7 Get-CpAdminMembers falls back when Get-LocalGroupMember throws (orphaned SID)' {
    Mock Get-LocalGroupMember { throw 'Failed to compare two elements in the array.' }
    Mock Get-CpAdminMembersAdsi { @('hacker','santa') }
    It 'returns the ADSI list instead of an empty list' {
        (Get-CpAdminMembers) -join ',' | Should Be 'hacker,santa'
    }
}

Describe 'I8 Get-CpDefenderPolicyPlan' {
    $vals = @{
        'DisableAntiSpyware' = 1
        'DisableAntiVirus' = 0
        'Real-Time Protection\DisableRealtimeMonitoring' = 1
        'Real-Time Protection\DisableBehaviorMonitoring' = 1
        'Exclusions\Extensions\.exe' = 0
        'SomethingHarmless' = 1
    }
    $plan = Get-CpDefenderPolicyPlan -Values $vals
    It 'removes DisableAntiSpyware=1'      { $plan -contains 'DisableAntiSpyware' | Should Be $true }
    It 'removes real-time disable'         { $plan -contains 'Real-Time Protection\DisableRealtimeMonitoring' | Should Be $true }
    It 'removes policy exclusions'         { $plan -contains 'Exclusions\Extensions\.exe' | Should Be $true }
    It 'leaves a 0 Disable* value alone'   { $plan -contains 'DisableAntiVirus' | Should Be $false }
    It 'leaves unrelated values alone'     { $plan -contains 'SomethingHarmless' | Should Be $false }
}

Describe 'Backlog: quiet failures are logged as FAILED, not done' {
    $run = Join-Path $env:TEMP ('cpkit-t-' + [guid]::NewGuid().ToString('N'))
    Set-CpContext -RunDir $run -Apply -Yes
    It 'a non-terminating error (Write-Error) is FAILED' {
        Invoke-CpAction -Module t -Description 'soft' -Why 'w' -ScriptBlock { Write-Error 'quiet problem' } 6>&1 | Out-Null
        (Get-Content (Join-Path $run 'log.txt') -Raw) | Should Match '\| t \| FAILED \| soft'
    }
    It 'a native command exit code != 0 is FAILED' {
        Invoke-CpAction -Module t -Description 'native' -Why 'w' -ScriptBlock { & cmd.exe /c exit 3 } 6>&1 | Out-Null
        (Get-Content (Join-Path $run 'log.txt') -Raw) | Should Match '\| t \| FAILED \| native'
    }
    It 'a clean action is still done' {
        Invoke-CpAction -Module t -Description 'clean' -Why 'w' -ScriptBlock { & cmd.exe /c exit 0 } 6>&1 | Out-Null
        (Get-Content (Join-Path $run 'log.txt') -Raw) | Should Match '\| t \| ACTION \| clean -> done'
    }
    Set-CpContext -RunDir $run
    Remove-Item $run -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Backlog: config tricky values' {
    $t = Join-Path $env:TEMP 'cpkit-tricky.txt'
    $body = "ADMINS=santa  prancer`r`n# comment`r`nUSERS=dasher`r`nNEW_PASSWORD=Ab#12'xy Z!`r`nCRITICAL_SERVICES=TermService   # README says RDP`r`n"
    [IO.File]::WriteAllText($t, $body, (New-Object Text.UTF8Encoding $true))   # with BOM, like Notepad
    $cfg = Import-CpConfig -Path $t
    It 'BOM does not break the first key'  { ($cfg.Admins -join ',') | Should Be 'santa,prancer' }
    It 'keeps # and apostrophe in password' { $cfg.NewPassword | Should Be "Ab#12'xy Z!" }
    It 'strips inline comment from lists'   { ($cfg.Critical -join ',') | Should Be 'TermService' }
    Remove-Item $t
}

Describe 'Backlog: Defender update/scan only when stale (idempotent re-runs)' {
    It 'fresh signatures + recent scan -> nothing to do' { Test-CpDefenderStale -SignatureAgeDays 0 -QuickScanAgeDays 0 | Should Be $false }
    It 'old signatures -> stale'                         { Test-CpDefenderStale -SignatureAgeDays 2 -QuickScanAgeDays 0 | Should Be $true }
    It 'never scanned -> stale'                          { Test-CpDefenderStale -SignatureAgeDays 0 -QuickScanAgeDays 4294967295 | Should Be $true }
}

Describe 'Re-graded: auditpol backup argument is one token' {
    It 'builds /file:<path> as a single argument' {
        Get-CpAuditpolBackupArg -Path 'C:\a b\x.csv' | Should Be '/file:C:\a b\x.csv'
    }
}

Describe 'Backlog: README critical names resolved BEFORE the disable step' {
    $svcs = @(
        [pscustomobject]@{ Name='FTPSVC';      DisplayName='Microsoft FTP Service' },
        [pscustomobject]@{ Name='W3SVC';       DisplayName='World Wide Web Publishing Service' },
        [pscustomobject]@{ Name='TermService'; DisplayName='Remote Desktop Services' },
        [pscustomobject]@{ Name='MySQL80';     DisplayName='MySQL80' },
        [pscustomobject]@{ Name='Spooler';     DisplayName='Print Spooler' }
    )
    It 'exact service name is kept as-is' {
        (Resolve-CpCriticalServices -Services $svcs -Critical @('w3svc')).Names -join ',' | Should Be 'W3SVC'
    }
    It 'common nickname maps to the service name (FTP -> FTPSVC)' {
        (Resolve-CpCriticalServices -Services $svcs -Critical @('FTP')).Names -join ',' | Should Be 'FTPSVC'
    }
    It 'RDP nickname keeps all three RDP services' {
        $r = Resolve-CpCriticalServices -Services $svcs -Critical @('RDP')
        ($r.Names | Sort-Object) -join ',' | Should Be 'SessionEnv,TermService,UmRdpService'
        $r.NeedsRdp | Should Be $true
    }
    It 'TermService by name also means RDP is needed' {
        (Resolve-CpCriticalServices -Services $svcs -Critical @('TermService')).NeedsRdp | Should Be $true
    }
    It 'a unique display-name match works (mysql -> MySQL80)' {
        (Resolve-CpCriticalServices -Services $svcs -Critical @('mysql')).Names -join ',' | Should Be 'MySQL80'
    }
    It 'an unknown name is reported as missing, not silently dropped' {
        $r = Resolve-CpCriticalServices -Services $svcs -Critical @('Bogus')
        $r.Missing -join ',' | Should Be 'Bogus'
    }
    It 'resolved names protect the real service in the plan' {
        $r = Resolve-CpCriticalServices -Services $svcs -Critical @('FTP')
        $cfg = [pscustomobject]@{ Critical=$r.Names; KeepRdp=$false }
        $plan = Get-CpServicePlan -Services @([pscustomobject]@{ Name='FTPSVC'; StartType='Automatic'; Status='Running' }) -Config $cfg
        @($plan | Where-Object Action -eq 'Disable').Count | Should Be 0
    }
}

Describe 'Backlog: shares module skips Special and role shares' {
    $shares = @(
        [pscustomobject]@{ Name='ADMIN$';      Special=$true;  Path='C:\Windows' },
        [pscustomobject]@{ Name='F$';          Special=$true;  Path='F:\' },
        [pscustomobject]@{ Name='CertEnroll';  Special=$false; Path='C:\Windows\system32\CertSrv\CertEnroll' },
        [pscustomobject]@{ Name='REMINST';     Special=$false; Path='D:\RemoteInstall' },
        [pscustomobject]@{ Name='WsusContent'; Special=$false; Path='D:\WSUS\WsusContent' },
        [pscustomobject]@{ Name='Hidden$';     Special=$false; Path='C:\Hidden' },
        [pscustomobject]@{ Name='Secret';      Special=$false; Path='C:\Secret' },
        [pscustomobject]@{ Name='Docs';        Special=$false; Path='C:\Docs' }
    )
    $cfg = [pscustomobject]@{ KeepShares=@('Docs') }
    $plan = Get-CpSharePlan -Shares $shares -Config $cfg
    $removed = @($plan | Where-Object Action -eq 'Remove' | ForEach-Object Name)
    It 'removes an unknown share'           { $removed -contains 'Secret' | Should Be $true }
    It 'removes a non-special hidden share' { $removed -contains 'Hidden$' | Should Be $true }
    It 'never touches Special admin shares' { @($plan | Where-Object { $_.Name -eq 'ADMIN$' -or $_.Name -eq 'F$' }).Count | Should Be 0 }
    It 'never removes role shares'          { @($removed | Where-Object { $_ -in 'CertEnroll','REMINST','WsusContent' }).Count | Should Be 0 }
    It 'reports role shares as KeepRole'    { @($plan | Where-Object Action -eq 'KeepRole').Count | Should Be 3 }
    It 'keeps README shares'                { @($plan | Where-Object Action -eq 'KeepReadme' | ForEach-Object Name) -join ',' | Should Be 'Docs' }
}

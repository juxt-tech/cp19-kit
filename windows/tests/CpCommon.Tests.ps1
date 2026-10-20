# Pester 3.4 (built into Windows 10/11). Run: Invoke-Pester .\windows\tests
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$kit  = Split-Path -Parent $here
$root = Split-Path -Parent $kit
Import-Module (Join-Path $kit 'lib\CpCommon.psm1') -Force -DisableNameChecking

Describe 'Import-CpConfig' {
    $cfg = Import-CpConfig -Path (Join-Path $root 'config\cp-config.example.txt')
    It 'parses admins as a list' { ($cfg.Admins -join ',') | Should Be 'santa,prancer' }
    It 'parses users'            { ($cfg.Users -join ',')  | Should Be 'cupid,dasher' }
    It 'parses the password'     { $cfg.NewPassword | Should Be 'Cyb3rP@triot!2026' }
    It 'KeepRdp defaults false'  { $cfg.KeepRdp | Should Be $false }
    It 'empty KEEP_SHARES is an empty list' { @($cfg.KeepShares).Count | Should Be 0 }
    It 'throws on a missing file' { { Import-CpConfig -Path 'C:\nope\none.txt' } | Should Throw }
    It 'RequireUsers throws when ADMINS empty' {
        $t = Join-Path $env:TEMP 'cpkit-empty.txt'; Set-Content $t 'USERS=a' -Encoding ASCII
        { Import-CpConfig -Path $t -RequireUsers } | Should Throw
        Remove-Item $t
    }
}

Describe 'Protection guards' {
    $cfg = Import-CpConfig -Path (Join-Path $root 'config\cp-config.example.txt')
    It 'protects config users'      { Test-CpProtectedUser -Name 'santa' -Config $cfg | Should Be $true }
    It 'protects the current user'  { Test-CpProtectedUser -Name $env:USERNAME -Config $cfg | Should Be $true }
    It 'protects built-ins'         { Test-CpProtectedUser -Name 'Administrator' -Config $cfg | Should Be $true }
    It 'does not protect strangers' { Test-CpProtectedUser -Name 'hacker' -Config $cfg | Should Be $false }
    It 'protects critical services (case-insensitive)' { Test-CpProtectedService -Name 'VSFTPD' -Config $cfg | Should Be $true }
    It 'protects the scoring client' { Test-CpProtectedService -Name 'CyberPatriotScoring' -Config $cfg | Should Be $true }
    It 'does not protect others'    { Test-CpProtectedService -Name 'RemoteRegistry' -Config $cfg | Should Be $false }
}

Describe 'Invoke-CpAction / log / backup' {
    $run = Join-Path $env:TEMP ('cpkit-test-' + [guid]::NewGuid().ToString('N'))
    Set-CpContext -RunDir $run
    It 'audit mode never runs the scriptblock' {
        $global:cpTouched = $false
        $out = Invoke-CpAction -Module test -Description 'touch' -Why 'because' -ScriptBlock { $global:cpTouched = $true } 6>&1 | Out-String
        $global:cpTouched | Should Be $false
        $out | Should Match '\[WOULD\] touch'
    }
    It 'apply + yes runs and logs' {
        Set-CpContext -RunDir $run -Apply -Yes
        $global:cpTouched = $false
        Invoke-CpAction -Module test -Description 'touch' -Why 'because' -ScriptBlock { $global:cpTouched = $true } 6>&1 | Out-Null
        $global:cpTouched | Should Be $true
        (Get-Content (Join-Path $run 'log.txt') -Raw) | Should Match '\| test \| ACTION \| touch -> done \| because'
    }
    It 'a throwing action is logged as FAILED and does not stop the script' {
        { Invoke-CpAction -Module test -Description 'boom' -Why 'w' -ScriptBlock { throw 'x' } 6>&1 | Out-Null } | Should Not Throw
        (Get-Content (Join-Path $run 'log.txt') -Raw) | Should Match '\| test \| FAILED \| boom'
    }
    It 'backup keeps the first copy' {
        $f = Join-Path $env:TEMP 'cpkit-bk.txt'; Set-Content $f 'one'
        Backup-CpFile -Path $f; Set-Content $f 'two'; Backup-CpFile -Path $f
        $b = Get-ChildItem (Join-Path $run 'backup') -Recurse -Filter 'cpkit-bk.txt' | Select-Object -First 1
        (Get-Content $b.FullName) | Should Be 'one'
        Remove-Item $f
    }
    It 'findings are recorded' {
        Add-CpFinding -Module test -Text 'look here' 6>&1 | Out-Null
        (Get-Content (Join-Path $run 'findings.txt') -Raw) | Should Match 'look here'
    }
    Set-CpContext -RunDir $run
    Remove-Item $run -Recurse -Force -ErrorAction SilentlyContinue
}

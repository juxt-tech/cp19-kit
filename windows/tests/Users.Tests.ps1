$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$kit  = Split-Path -Parent $here
Import-Module (Join-Path $kit 'lib\CpCommon.psm1') -Force -DisableNameChecking
. (Join-Path $kit 'modules\Users.ps1')

function Has($plan, $action, $name) { @($plan | Where-Object { $_.Action -eq $action -and $_.Name -eq $name }).Count -gt 0 }

Describe 'Get-CpUserPlan (Santa''s Workshop answer key)' {
    $cfg = [pscustomobject]@{ Admins=@('santa'); Users=@('cupid','prancer'); Critical=@(); Allowed=@(); NewPassword='x'; KeepRdp=$false; KeepShares=@() }
    $plan = Get-CpUserPlan -Config $cfg -CurrentUser 'me' `
        -LocalUsers @('santa','prancer','rudolph','Administrator','Guest','me') `
        -Admins @('prancer','Administrator','me') `
        -DisabledUsers @('santa','Guest') `
        -NoPasswordRequired @('prancer') -NeverExpires @('santa')
    It 'enables the disabled authorized admin' { Has $plan 'EnableUser' 'santa' | Should Be $true }
    It 'adds santa to Administrators'          { Has $plan 'AddAdmin' 'santa' | Should Be $true }
    It 'creates missing user cupid'            { Has $plan 'AddUser' 'cupid' | Should Be $true }
    It 'removes unauthorized rudolph'          { Has $plan 'RemoveUser' 'rudolph' | Should Be $true }
    It 'demotes prancer'                       { Has $plan 'RemoveAdmin' 'prancer' | Should Be $true }
    It 'disables the built-in Administrator'   { Has $plan 'DisableBuiltin' 'Administrator' | Should Be $true }
    It 'skips Guest (already disabled)'        { Has $plan 'DisableBuiltin' 'Guest' | Should Be $false }
    It 'never removes the built-in Administrator from the group' { Has $plan 'RemoveAdmin' 'Administrator' | Should Be $false }
    It 'never touches the current user'        { @($plan | Where-Object { $_.Name -eq 'me' }).Count | Should Be 0 }
    It 'requires a password for prancer'       { Has $plan 'SetPassword' 'prancer' | Should Be $true }
    It 'turns off never-expires for santa'     { Has $plan 'PasswordNeverExpiresOff' 'santa' | Should Be $true }
}

Describe 'Get-CpUserPlan on a domain controller' {
    $cfg = [pscustomobject]@{ Admins=@('santa'); Users=@('elf'); Critical=@(); Allowed=@(); NewPassword='x'; KeepRdp=$false; KeepShares=@() }
    $plan = Get-CpUserPlan -Config $cfg -CurrentUser 'me' -IsDC `
        -LocalUsers @('santa','elf','krbtgt','grinch','Administrator') -Admins @('santa','grinch','Administrator') -DisabledUsers @('krbtgt')
    It 'never acts on krbtgt'      { @($plan | Where-Object { $_.Name -eq 'krbtgt' }).Count | Should Be 0 }
    It 'uses AD action names'      { Has $plan 'RemoveADUser' 'grinch' | Should Be $true }
    It 'demotes from Domain Admins' { Has $plan 'RemoveDomainAdmin' 'grinch' | Should Be $true }
}

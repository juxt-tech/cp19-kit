$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$kit  = Split-Path -Parent $here
Import-Module (Join-Path $kit 'lib\CpCommon.psm1') -Force -DisableNameChecking
. (Join-Path $kit 'modules\System.ps1')

function Svc($n, $t, $s) { [pscustomobject]@{ Name = $n; StartType = $t; Status = $s } }
function Has($plan, $action, $name) { @($plan | Where-Object { $_.Action -eq $action -and $_.Name -eq $name }).Count -gt 0 }

Describe 'Get-CpServicePlan' {
    $svcs = @( (Svc RemoteRegistry Automatic Running), (Svc wuauserv Manual Stopped), (Svc Dnscache Automatic Running),
               (Svc TermService Manual Running), (Svc FTPSVC Automatic Running), (Svc simptcp Automatic Running),
               (Svc SNMPTRAP Disabled Stopped), (Svc CyberPatriotScoring Automatic Running) )
    $cfgKeep = [pscustomobject]@{ Admins=@('a'); Users=@(); Critical=@('TermService','FTPSVC'); Allowed=@(); NewPassword=''; KeepRdp=$true; KeepShares=@() }
    $plan = Get-CpServicePlan -Services $svcs -Config $cfgKeep
    It 'disables a running risky service'     { Has $plan 'Disable' 'RemoteRegistry' | Should Be $true }
    It 'disables Simple TCP/IP (CP19 key)'     { Has $plan 'Disable' 'simptcp' | Should Be $true }
    It 'skips an already-disabled service'     { Has $plan 'Disable' 'SNMPTRAP' | Should Be $false }
    It 'enables Windows Update automatically'  { Has $plan 'EnableAuto' 'wuauserv' | Should Be $true }
    It 'never touches DNS Client'              { @($plan | Where-Object Name -eq 'Dnscache').Count | Should Be 0 }
    It 'keeps critical RDP'                    { Has $plan 'Disable' 'TermService' | Should Be $false }
    It 'keeps RDP helper services when RDP is needed' {
        $p = Get-CpServicePlan -Services @((Svc SessionEnv Manual Running), (Svc UmRdpService Manual Running)) -Config $cfgKeep
        @($p | Where-Object Action -eq 'Disable').Count | Should Be 0
    }
    It 'keeps critical FTP and says so'        { Has $plan 'KeepCritical' 'FTPSVC' | Should Be $true }
    It 'never touches the scoring service'     { @($plan | Where-Object Name -eq 'CyberPatriotScoring').Count | Should Be 0 }

    $cfgNoRdp = [pscustomobject]@{ Admins=@('a'); Users=@(); Critical=@(); Allowed=@(); NewPassword=''; KeepRdp=$false; KeepShares=@() }
    $plan2 = Get-CpServicePlan -Services $svcs -Config $cfgNoRdp
    It 'disables RDP when README does not need it' { Has $plan2 'Disable' 'TermService' | Should Be $true }
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$kit  = Split-Path -Parent $here
Import-Module (Join-Path $kit 'lib\CpCommon.psm1') -Force -DisableNameChecking
. (Join-Path $kit 'modules\Reports.ps1')

Describe 'Get-CpSoftwareFlags' {
    $cfg = [pscustomobject]@{ Admins=@('a'); Users=@(); Critical=@(); Allowed=@('Wireshark'); NewPassword=''; KeepRdp=$false; KeepShares=@() }
    $flags = Get-CpSoftwareFlags -Installed @('CCleaner 6.1','Wireshark 4.2.0','Google Chrome','Super Keygen Pro','Npcap 1.7','Microsoft Edge','GooseDesktop') -Config $cfg
    It 'flags CCleaner'            { $flags -contains 'CCleaner 6.1' | Should Be $true }
    It 'flags keygen by keyword'   { $flags -contains 'Super Keygen Pro' | Should Be $true }
    It 'flags GooseDesktop (CP19)' { $flags -contains 'GooseDesktop' | Should Be $true }
    It 'skips allowed Wireshark'   { $flags -contains 'Wireshark 4.2.0' | Should Be $false }
    It 'leaves normal apps alone'  { $flags -contains 'Google Chrome' | Should Be $false }
}

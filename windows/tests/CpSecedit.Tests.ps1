$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$kit  = Split-Path -Parent $here
Import-Module (Join-Path $kit 'lib\CpSecedit.psm1') -Force -DisableNameChecking

$inf = @'
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 0
MinimumPasswordLength = 0
[Event Audit]
AuditSystemEvents = 0
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,0
[Version]
signature="$CHICAGO$"
Revision=1
'@

Describe 'Get-CpInfValue' {
    It 'reads a spaced value'   { Get-CpInfValue -InfText $inf -Section 'System Access' -Key 'MinimumPasswordLength' | Should Be '0' }
    It 'reads a registry value' { Get-CpInfValue -InfText $inf -Section 'Registry Values' -Key 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse' | Should Be '4,0' }
    It 'missing key is null'    { Get-CpInfValue -InfText $inf -Section 'System Access' -Key 'Nope' | Should BeNullOrEmpty }
}

Describe 'Set-CpInfValue' {
    $new = Set-CpInfValue -InfText $inf -Section 'System Access' -Key 'MinimumPasswordLength' -Value '10'
    It 'changes the value'              { Get-CpInfValue -InfText $new -Section 'System Access' -Key 'MinimumPasswordLength' | Should Be '10' }
    It 'leaves other lines identical'   { ($new -split "`r?`n" | Where-Object { $_ -notmatch 'MinimumPasswordLength' }) -join '|' | Should Be (($inf -split "`r?`n" | Where-Object { $_ -notmatch 'MinimumPasswordLength' }) -join '|') }
    It 'keeps the original separator style' { $new | Should Match 'MinimumPasswordLength = 10' }
    $new2 = Set-CpInfValue -InfText $inf -Section 'System Access' -Key 'PasswordHistorySize' -Value '5'
    It 'adds a missing key inside its section' {
        $lines = $new2 -split "`r?`n"
        $i = [array]::IndexOf($lines, 'PasswordHistorySize = 5')
        $i | Should BeGreaterThan ([array]::IndexOf($lines, '[System Access]'))
        $i | Should BeLessThan ([array]::IndexOf($lines, '[Event Audit]'))
    }
    $new3 = Set-CpInfValue -InfText $inf -Section 'Registry Values' -Key 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse' -Value '4,1'
    It 'edits registry values without spaces' { $new3 | Should Match 'LimitBlankPasswordUse=4,1' }
    $new4 = Set-CpInfValue -InfText $inf -Section 'Privilege Rights' -Key 'SeDenyNetworkLogonRight' -Value '*S-1-5-32-546'
    It 'creates a missing section before [Version]' { $new4 | Should Match '\[Privilege Rights\]\r?\nSeDenyNetworkLogonRight = \*S-1-5-32-546' }
}

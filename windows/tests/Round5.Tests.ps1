# Round 5 (2026-11-13): ideas ported from Ripper1004/CyberPatriot-Toolkit - browser policies, PrintNightmare,
# LSA protection, MSS network settings, Zerologon, unquoted service paths, NetSh helpers, BootExecute.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$kit  = Split-Path -Parent $here
Import-Module (Join-Path $kit 'lib\CpCommon.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $kit 'lib\CpSecedit.psm1') -Force -DisableNameChecking
. (Join-Path $kit 'modules\Policies.ps1')
. (Join-Path $kit 'modules\Reports.ps1')
. (Join-Path $kit 'modules\Browsers.ps1')

Describe 'Round 5 security registry settings' {
    $names = @($script:CpExtraSecurityRegistry | ForEach-Object Name)
    foreach ($n in 'RunAsPPL','EnableUserControl','RestrictDriverInstallationToAdministrators','NoWarningNoElevationOnInstall',
                   'UpdatePromptSettings','SafeDllSearchMode','DisableExceptionChainValidation','DisableIPSourceRouting',
                   'EnableICMPRedirect','NoNameReleaseOnDemand','DisableWpad','EnableModuleLogging','ProcessCreationIncludeCmdLine_Enabled',
                   'fAllowFullControl','fAllowUnsolicited','fDisableCdm','DisableRunAs') {
        It "includes $n" { $names -contains $n | Should Be $true }
    }
    It 'sets source routing off for IPv4 AND IPv6' {
        @($script:CpExtraSecurityRegistry | Where-Object Name -eq 'DisableIPSourceRouting').Count | Should Be 2
    }
    It 'module-logging wildcard is a string value' {
        ($script:CpExtraSecurityRegistry | Where-Object { $_.Name -eq '*' }).Type | Should Be 'String'
    }
    It 'every entry has a path, a type and a reason' {
        @($script:CpExtraSecurityRegistry | Where-Object { -not $_.Path -or -not $_.Type -or -not $_.Why }).Count | Should Be 0
    }
    It 'no Path+Name is listed twice (a second value would fight the first)' {
        $keys = @($script:CpExtraSecurityRegistry | ForEach-Object { "$($_.Path)\$($_.Name)" })
        ($keys | Select-Object -Unique).Count | Should Be $keys.Count
    }
    It 'ForceGuest = Classic is a secedit security option' { $script:CpSecurityOptions['MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest'] | Should Be '4,0' }
    It 'DC list enforces Zerologon protection' {
        ($script:CpDcExtraRegistry | Where-Object Name -eq 'FullSecureChannelProtection').Value | Should Be 1
    }
    It 'a missing value is planned, a correct one is not' {
        $w = @($script:CpExtraSecurityRegistry | Where-Object Name -eq 'RunAsPPL')
        (Get-CpRegistryPlan -Wanted $w -Current @{}).Count | Should Be 1
        (Get-CpRegistryPlan -Wanted $w -Current @{ "$($w[0].Path)\RunAsPPL" = 1 }).Count | Should Be 0
    }
}

Describe 'Test-CpLooseExecutionPolicy' {
    It 'Unrestricted is loose' { Test-CpLooseExecutionPolicy 'Unrestricted' | Should Be $true }
    It 'Bypass is loose'       { Test-CpLooseExecutionPolicy 'Bypass' | Should Be $true }
    It 'RemoteSigned is fine'  { Test-CpLooseExecutionPolicy 'RemoteSigned' | Should Be $false }
    It 'Undefined is fine'     { Test-CpLooseExecutionPolicy 'Undefined' | Should Be $false }
}

Describe 'Get-CpUnquotedServicePaths' {
    $s = @(
        [pscustomobject]@{ Name = 'bad';    PathName = 'C:\Program Files\Vuln App\svc.exe -k x' }
        [pscustomobject]@{ Name = 'quoted'; PathName = '"C:\Program Files\Good App\svc.exe" -k x' }
        [pscustomobject]@{ Name = 'svchost';PathName = 'C:\Windows\system32\svchost.exe -k netsvcs -p' }
        [pscustomobject]@{ Name = 'drv';    PathName = '\SystemRoot\System32\drivers\x.sys' }
        [pscustomobject]@{ Name = 'empty';  PathName = $null }
    )
    $r = @(Get-CpUnquotedServicePaths -Services $s)
    It 'flags only the unquoted path with a space' { $r.Count | Should Be 1 }
    It 'names the service'                         { $r[0] | Should Match '^bad: ' }
}

Describe 'Test-CpOddNetshDll' {
    It 'bare System32 name is normal'           { Test-CpOddNetshDll 'ifmon.dll' | Should Be $false }
    It 'full System32 path is normal'           { Test-CpOddNetshDll 'C:\Windows\System32\nshwfp.dll' | Should Be $false }
    It 'a DLL in ProgramData is odd'            { Test-CpOddNetshDll 'C:\ProgramData\x\helper.dll' | Should Be $true }
    It 'a DLL in a System32 subfolder is odd'   { Test-CpOddNetshDll 'C:\Windows\System32\spool\drivers\h.dll' | Should Be $true }
}

Describe 'Get-CpBootExecuteFindings' {
    It 'stock autochk line is fine'    { @(Get-CpBootExecuteFindings -Values @('autocheck autochk *')).Count | Should Be 0 }
    It 'autochk with switches is fine' { @(Get-CpBootExecuteFindings -Values @('autocheck autochk /q /v *')).Count | Should Be 0 }
    It 'an extra program is flagged'   { @(Get-CpBootExecuteFindings -Values @('autocheck autochk *', 'evil.exe')) | Should Be 'evil.exe' }
    It 'empty values are ignored'      { @(Get-CpBootExecuteFindings -Values @('', $null)).Count | Should Be 0 }
}

Describe 'Browsers' {
    It 'Edge: SmartScreen, pop-ups, downloads' {
        $n = @($script:CpEdgeRegistry | ForEach-Object Name)
        foreach ($x in 'SmartScreenEnabled','DefaultPopupsSetting','DownloadRestrictions') { $n -contains $x | Should Be $true }
    }
    It 'Firefox pop-up blocker is locked on' {
        ($script:CpFirefoxRegistry | Where-Object { $_.Name -eq 'Locked' -and $_.Path -like '*PopupBlocking' }).Value | Should Be 1
    }
    $text = @'
user_pref("browser.startup.homepage", "x");
user_pref("dom.disable_open_during_load", false);
user_pref("browser.safebrowsing.malware.enabled", true);
lockPref('xpinstall.whitelist.required', false);
// user_pref("browser.safebrowsing.phishing.enabled", false);
'@
    $bad = @(Get-CpFirefoxBadPrefs -Text $text)
    It 'finds the prefs set to false'      { ($bad -join ',') | Should Be 'dom.disable_open_during_load,xpinstall.whitelist.required' }
    It 'ignores commented-out lines'       { $bad -contains 'browser.safebrowsing.phishing.enabled' | Should Be $false }
    It 'clean file -> nothing'             { @(Get-CpFirefoxBadPrefs -Text 'user_pref("a", 1);').Count | Should Be 0 }
}

Describe 'Defender AMSI does not block any kit script (2026-11-13: a list of attack-tool names in Reports.ps1 did)' {
    foreach ($f in @(Get-ChildItem (Join-Path $kit 'modules') -Filter *.ps1) + @(Get-ChildItem (Join-Path $kit 'lib') -Filter *.psm1) + @(Get-Item (Join-Path $kit 'harden.ps1'))) {
        It "$($f.Name) compiles and loads" {
            $err = $null
            try {
                $sb = [ScriptBlock]::Create([IO.File]::ReadAllText($f.FullName))
                if ($f.Directory.Name -eq 'modules') { . $f.FullName }
            } catch { $err = $_.Exception.Message }
            $err | Should BeNullOrEmpty
        }
    }
}

Describe 'ASCII only (Windows PowerShell 5.1 reads BOM-less files as ANSI)' {
    foreach ($f in 'modules\Browsers.ps1','modules\Policies.ps1','modules\Reports.ps1') {
        It "$f has no non-ASCII byte" {
            @([IO.File]::ReadAllBytes((Join-Path $kit $f)) | Where-Object { $_ -gt 127 }).Count | Should Be 0
        }
    }
}

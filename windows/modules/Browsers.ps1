# Web browsers: Edge / Chrome / Firefox protections by policy, plus a report of Firefox prefs.js lines
# that switch protections off. CP category: Application Security Settings.
# Ideas from Ripper1004/CyberPatriot-Toolkit (Invoke-Browsers, sec_browser).

$script:CpEdgeRegistry = @(
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' SmartScreenEnabled 1 'Edge: SmartScreen blocks phishing / malware sites'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' SmartScreenPuaEnabled 1 'Edge: block potentially unwanted apps'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' DefaultPopupsSetting 2 'Edge: block pop-ups'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' DownloadRestrictions 1 'Edge: block dangerous downloads'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' PasswordManagerEnabled 0 'Edge: does not save passwords'
)
$script:CpChromeRegistry = @(
    New-CpReg 'HKLM:\SOFTWARE\Policies\Google\Chrome' SafeBrowsingProtectionLevel 1 'Chrome: Safe Browsing on'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Google\Chrome' DefaultPopupsSetting 2 'Chrome: block pop-ups'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Google\Chrome' DownloadRestrictions 1 'Chrome: block dangerous downloads'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Google\Chrome' PasswordManagerEnabled 0 'Chrome: does not save passwords'
)
$script:CpFirefoxRegistry = @(
    New-CpReg 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking' Default 1 'Firefox: block pop-ups'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking' Locked 1 'Firefox: users cannot turn the pop-up blocker off'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\InstallAddonsPermission' Default 0 'Firefox: websites cannot install add-ons'
    New-CpReg 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox' PasswordManagerEnabled 0 'Firefox: does not save passwords'
)

# Firefox settings images switch to false (same list as the Linux kit's desktop module).
$script:CpFirefoxBadPrefs = @('dom.disable_open_during_load', 'xpinstall.whitelist.required', 'xpinstall.signatures.required',
    'extensions.blocklist.enabled', 'browser.safebrowsing.malware.enabled', 'browser.safebrowsing.phishing.enabled',
    'browser.safebrowsing.downloads.enabled', 'browser.safebrowsing.downloads.remote.block_dangerous',
    'browser.safebrowsing.downloads.remote.block_potentially_unwanted')

# Pure. Text of a prefs.js / user.js -> names of protections it switches off.
function Get-CpFirefoxBadPrefs([string]$Text) {
    $names = ($script:CpFirefoxBadPrefs | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $re = "(?m)^\s*(user_pref|pref|lockPref|defaultPref|sticky_pref)\(\s*[`"']($names)[`"']\s*,\s*false\s*\)"
    @([regex]::Matches($Text, $re) | ForEach-Object { $_.Groups[2].Value } | Select-Object -Unique)
}

function Find-CpBrowserExe([string[]]$RelPaths) {
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:LOCALAPPDATA")) {
        if (-not $base) { continue }
        foreach ($r in $RelPaths) { $p = Join-Path $base $r; if (Test-Path $p) { return $p } }
    }
    return $null
}

function Invoke-CpModBrowsers {
    param($Config)
    Write-CpHeader 'BROWSERS  (Edge / Chrome / Firefox protections)'
    Invoke-CpRegistrySettings -Module browsers -Wanted $script:CpEdgeRegistry
    $chrome = Find-CpBrowserExe @('Google\Chrome\Application\chrome.exe')
    if ($chrome) {
        Invoke-CpRegistrySettings -Module browsers -Wanted $script:CpChromeRegistry
        Add-CpFinding browsers "Chrome $((Get-Item $chrome).VersionInfo.ProductVersion): update it (Menu > Help > About Google Chrome) and remove unknown extensions (chrome://extensions)"
    } else { Write-CpOk 'Chrome not installed' }
    $ff = Find-CpBrowserExe @('Mozilla Firefox\firefox.exe')
    if ($ff) {
        Invoke-CpRegistrySettings -Module browsers -Wanted $script:CpFirefoxRegistry
        Add-CpFinding browsers "Firefox $((Get-Item $ff).VersionInfo.ProductVersion): update it (Menu > Help > About Firefox); check Settings > Privacy & Security by hand (dangerous content blocking, HTTPS-Only)"
    } else { Write-CpOk 'Firefox not installed' }
    # prefs.js: the image may have switched protections off for a user
    $files = @(Get-ChildItem 'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\prefs.js', 'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\user.js' -Force -ErrorAction SilentlyContinue)
    $bad = 0
    foreach ($f in $files) {
        $off = @(Get-CpFirefoxBadPrefs -Text ([IO.File]::ReadAllText($f.FullName)))
        if ($off.Count) {
            $bad++
            Add-CpFinding browsers "Firefox protections OFF in $($f.FullName): $($off -join ', ')  - close Firefox, then delete those lines (or Settings > Privacy & Security: block pop-ups, warn on add-ons, block dangerous content)"
        }
    }
    if ($files.Count -and -not $bad) { Write-CpOk 'no Firefox profile switches protections off' }
    $edgeExe = Find-CpBrowserExe @('Microsoft\Edge\Application\msedge.exe')
    if ($edgeExe) { Add-CpFinding browsers "Edge $((Get-Item $edgeExe).VersionInfo.ProductVersion): update it (edge://settings/help) and remove unknown extensions (edge://extensions)" }
}

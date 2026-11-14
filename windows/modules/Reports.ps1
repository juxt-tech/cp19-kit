# REPORT-ONLY modules: unwanted software, prohibited media, persistence/backdoors.
# CP categories: Policy Violation (Unwanted Software / Prohibited Files / Malware).
# Nothing here deletes or uninstalls - answer forensics first, then remove by hand.

$script:CpBadSoftware = @('Wireshark','Nmap','Zenmap','Angry IP','Cain','CCleaner','TeamViewer','AnyDesk','uTorrent','BitTorrent',
    'qBittorrent','Vuze','FrostWire','iTunes','Bonjour','Driver Support','Web Companion','NetStumbler','PC Cleaner','GooseDesktop',
    'Npcap','WinPcap','FileZilla Server','Tor Browser','Ophcrack','John the Ripper','Hashcat','Hydra','Metasploit','Burp Suite',
    'Netcat','Steam','Epic Games','Minecraft','Roblox','Discord','Spotify','LogMeIn','RealVNC','TightVNC','UltraVNC','Ammyy',
    'WinSMS','Shareaza','LimeWire','Kazaa','Advanced SystemCare','MyCleanPC','Reimage','SlimCleaner','Ask Toolbar',
    'BitComet','Mimikatz','McAfee','2048','Cheat Engine','Process Hacker','Netscape','Hamachi','RustDesk')
$script:CpBadKeywords = 'crack|keygen|hack|torrent|cheat|password ?(recovery|cracker)|sniff|keylog|spy'

# Pure: which installed program names to flag.
function Get-CpSoftwareFlags {
    param([string[]]$Installed, [Parameter(Mandatory)]$Config)
    $out = @()
    foreach ($p in $Installed) {
        if (-not $p) { continue }
        $allowed = $false
        foreach ($a in $Config.Allowed) { if ($p -like "*$a*") { $allowed = $true } }
        if ($allowed) { continue }
        $hit = $p -match $script:CpBadKeywords
        foreach ($b in $script:CpBadSoftware) { if ($p -like "*$b*") { $hit = $true } }
        if ($hit) { $out += $p }
    }
    return ,$out
}

function Get-CpInstalledPrograms {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, InstallDate
}

function Invoke-CpModSoftware {
    param($Config)
    Write-CpHeader 'SOFTWARE  (report - uninstall by hand in appwiz.cpl AFTER forensics)'
    $progs = @(Get-CpInstalledPrograms)
    $flags = Get-CpSoftwareFlags -Installed ($progs | ForEach-Object DisplayName) -Config $Config
    foreach ($f in $flags) {
        $p = $progs | Where-Object DisplayName -eq $f | Select-Object -First 1
        Add-CpFinding software "UNWANTED: $f $($p.DisplayVersion)  [$($p.Publisher)]  uninstall: $($p.UninstallString)"
    }
    if ($flags.Count -eq 0) { Write-CpOk 'no known unwanted programs' }
    $ctx = Get-CpContext
    if ($ctx.RunDir) { $progs | Sort-Object DisplayName | Format-Table -AutoSize | Out-String -Width 250 | Set-Content (Join-Path $ctx.RunDir 'installed-programs.txt') -Encoding ASCII; Write-Host "  full list: $(Join-Path $ctx.RunDir 'installed-programs.txt')" }
    $odd = Get-ChildItem 'C:\' -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(PerfLogs|Program Files|Program Files \(x86\)|ProgramData|Users|Windows|Windows\.old|inetpub|cpkit-runs|Recovery|\$.*|Config\.Msi|Documents and Settings|System Volume Information|OneDriveTemp|CyberPatriot.*)$' }
    foreach ($d in $odd) { Add-CpFinding software "non-standard folder on C:\: $($d.FullName)" }
    foreach ($root in "$env:ProgramFiles\WindowsPowerShell\Modules", "$env:windir\System32\WindowsPowerShell\v1.0\Modules", "${env:ProgramFiles(x86)}\WindowsPowerShell\Modules") {
        $names = @(Get-ChildItem $root -Directory -ErrorAction SilentlyContinue | ForEach-Object Name)
        foreach ($m in (Get-CpBadPsModules -Names $names)) { Add-CpFinding software "UNWANTED: PowerShell attack module '$m' in $root  (delete the folder after forensics)" }
    }
}

# Pure: Luhn check, so random 16-digit numbers (order IDs, GUID pieces) aren't reported as cards.
function Test-CpLuhn([string]$Digits) {
    $d = $Digits -replace '\D', ''
    if ($d.Length -lt 13 -or $d.Length -gt 19) { return $false }
    $sum = 0; $alt = $false
    for ($i = $d.Length - 1; $i -ge 0; $i--) {
        $n = [int][string]$d[$i]
        if ($alt) { $n *= 2; if ($n -gt 9) { $n -= 9 } }
        $sum += $n; $alt = -not $alt
    }
    return ($sum % 10 -eq 0)
}

# Pure: Luhn alone passes 1 in 10 random numbers (13-digit millisecond timestamps in logs),
# so also require a real card prefix + length: Visa, Mastercard, Amex, Discover.
function Test-CpCardNumber([string]$Text) {
    $d = $Text -replace '\D', ''
    $brand = ($d -match '^4' -and $d.Length -in 13, 16, 19) -or ($d -match '^(5[1-5]|2[2-7])' -and $d.Length -eq 16) -or
             ($d -match '^3[47]' -and $d.Length -eq 15) -or ($d -match '^6(011|5|4[4-9])' -and $d.Length -in 16..19)
    return ($brand -and (Test-CpLuhn $d))
}

# Pure: what kind of sensitive data a text holds ('credit card', 'SSN'), for "plaintext PII file" vulns.
function Get-CpPiiKinds([string]$Text) {
    $out = @()
    foreach ($m in [regex]::Matches($Text, '(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])')) {
        if (Test-CpCardNumber $m.Value) { $out += 'credit card'; break }
    }
    # SSN rules: area not 000/666/9xx, group not 00, serial not 0000
    if ($Text -match '(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])') { $out += 'SSN' }
    return ,$out
}

# Pure. Files = objects with FullName, Length, Attributes. One line per file, except a folder with
# more than $Max media files becomes ONE line (District 13: GooseDesktop's 50 asset images).
function Get-CpMediaLines {
    param($Files = @(), [int]$Max = 8)
    $out = @()
    foreach ($g in @($Files | Group-Object { Split-Path $_.FullName -Parent })) {
        $hid = @($g.Group | Where-Object { $_.Attributes -band [IO.FileAttributes]::Hidden }).Count
        if ($g.Count -gt $Max) {
            $eg = ($g.Group | Select-Object -First 3 | ForEach-Object { Split-Path $_.FullName -Leaf }) -join ', '
            $out += "folder: $($g.Name)  has $($g.Count) media files$(if ($hid) { " ($hid HIDDEN)" }), e.g. $eg  (program assets? malware folder? check it)"
            continue
        }
        foreach ($f in $g.Group) {
            $out += "file: $($f.FullName)  ($([math]::Round($f.Length/1KB))KB)$(if ($f.Attributes -band [IO.FileAttributes]::Hidden) { '  HIDDEN' })"
        }
    }
    return ,$out
}

function Invoke-CpModMedia {
    param($Config)
    Write-CpHeader 'MEDIA / PROHIBITED FILES  (report only)'
    $mediaRe = '\.(mp3|mp4|avi|mkv|mov|wav|flac|ogg|m4a|wma|aac|wmv|flv|webm|jpg|jpeg|png|gif|zip|7z|rar|tar|gz|kdbx|pcap|pcapng)$'
    $suspRe  = 'password|passwd|secret|credit|\.(exe|msi|bat|vbs|ps1|hta|scr)$'
    $textRe  = '\.(txt|csv|log|rtf|md|xml|json|ini|dat|bak)$'
    $roots = @('C:\Users') + @(Get-ChildItem 'C:\' -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(Windows|Program Files.*|ProgramData|Users|PerfLogs|Recovery|\$.*|System Volume Information|cpkit-runs|Config\.Msi|Documents and Settings)$' -and $_.Name -notmatch (Get-CpScoringRegex) } | ForEach-Object FullName)
    # Find-CpFiles sees HIDDEN files (CP plants them with attrib +h; plain Get-ChildItem misses them).
    # AppData is skipped: browser caches are full of images and nobody scores them.
    $kitRoot = Split-Path (Split-Path $PSScriptRoot)   # don't report the kit's own scripts / its download zip
    # never list the scoring engine's own files (C:\aeacus\assets\*.png, *.wav): deleting them breaks scoring
    $skipDir = '\\AppData$|\\node_modules$|\\\.git$|\\WindowsPowerShell\\Modules$|\\(' + (Get-CpScoringRegex) + ')[^\\]*$|^' + [regex]::Escape($kitRoot) + '$'
    $n = 0
    $files = foreach ($r in $roots) {
        Find-CpFiles -Root $r -NameRegex "$mediaRe|$suspRe|$textRe" -SkipDirRegex $skipDir | Where-Object { [IO.Path]::GetFileName($_) -notlike 'cp19-kit*' } | ForEach-Object { New-Object IO.FileInfo $_ }
    }
    $tag = { param($f) if ($f.Attributes -band [IO.FileAttributes]::Hidden) { '  HIDDEN' } else { '' } }
    $mediaLines = Get-CpMediaLines -Files @($files | Where-Object { $_.Name -match $mediaRe })
    foreach ($line in $mediaLines) { Add-CpFinding media $line; $n++ }
    foreach ($f in $files) {
        if ($f.Name -notmatch $mediaRe -and $f.FullName -match '^C:\\Users\\' -and $f.Name -match $suspRe -and $f.Name -ne 'desktop.ini') { Add-CpFinding media "suspicious file: $($f.FullName)$(& $tag $f)"; $n++ }
        # plaintext card numbers / SSNs ("unencrypted medical records", "hidden file with credit cards"); license texts are full of numbers
        if ($f.Name -match $textRe -and $f.Name -notmatch '(?i)license|eula|notice|readme' -and $f.Length -lt 2MB) {
            $kinds = @(); try { $kinds = Get-CpPiiKinds ([IO.File]::ReadAllText($f.FullName)) } catch { }
            if ($kinds.Count) { Add-CpFinding media "plaintext $($kinds -join ' + ') in: $($f.FullName)$(& $tag $f)  (forensics first, then delete)"; $n++ }
        }
    }
    Write-Host "  $n file(s) listed in findings.txt"
}

# Pure. A tag for a scheduled-task finding line. District 13 hid GooseDesktop.exe in a task named
# MicrosoftEdgeUpdateTaskMachineMain; the scoring engine's own tasks must be left alone.
function Get-CpTaskVerdict([string]$Name, [string]$Action) {
    if ("$Name $Action" -match (Get-CpScoringRegex)) { return '   <- SCORING ENGINE, leave it alone' }
    $exe = ($Action -replace '^\s*"?([^"]+?\.(exe|bat|cmd|ps1|vbs|js))"?.*$', '$1')
    $trusted = $exe -match '(?i)^(%systemroot%|%windir%|C:\\Windows\\|C:\\Program Files)'
    if ($Name -match '(?i)microsoft|edge|google|windows|update|onedrive|adobe' -and -not $trusted) { return '   <- DISGUISED: named like a vendor task but runs from a non-system folder' }
    if ($Action -match '(?i)\\Users\\|\\Temp\\|\\inetpub\\|\\Public\\|-enc|encodedcommand|http[s]?://|-WindowStyle\W+Hidden') { return '   <- SUSPICIOUS location/flags' }
    return ''
}

# Pure. LSA package lists (HKLM\SYSTEM\CurrentControlSet\Control\Lsa). Anything Windows does not ship
# there is loaded into LSASS at boot and sees every password (mimilib, password-filter backdoors).
$script:CpLsaDefaults = @('scecli','rassfm','msv1_0','kerberos','schannel','wdigest','tspkg','pku2u','cloudap','livessp','negoexts','""','')
function Get-CpLsaPackageFindings {
    param([string[]]$Notification = @(), [string[]]$Security = @(), [string[]]$Authentication = @())
    $out = @()
    foreach ($set in @(@('Notification Packages', $Notification), @('Security Packages', $Security), @('Authentication Packages', $Authentication))) {
        foreach ($p in @($set[1])) {
            if ($script:CpLsaDefaults -contains ([string]$p).Trim().ToLower()) { continue }
            $out += "LSA $($set[0]) lists '$p' - not a Windows default: this DLL loads into LSASS and sees every password (HKLM\SYSTEM\CurrentControlSet\Control\Lsa)"
        }
    }
    return $out
}
# Pure (given -Bad). PowerShell module folder names that are attack tools (Baldi's Basics scored removing
# DSInternals). The tool names live in lib\bad-ps-modules.txt: spelled out in this file, Defender's AMSI
# flagged Reports.ps1 as malicious and blocked the whole kit (found 2026-11-13).
$script:CpBadPsModuleFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'lib\bad-ps-modules.txt'
function Get-CpBadPsModuleList {
    @(Get-Content $script:CpBadPsModuleFile -ErrorAction SilentlyContinue | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^#' })
}
function Get-CpBadPsModules([string[]]$Names, [string[]]$Bad = (Get-CpBadPsModuleList)) {
    return @($Names | Where-Object { $n = $_; @($Bad | Where-Object { $n -like "$_*" }).Count -gt 0 })
}
# Pure. Folders in the machine PATH outside Windows / Program Files: a program dropped there runs instead
# of the real one when an admin types its name (Baldi's Basics: C:\temp, writable by Everyone).
function Get-CpOddPathEntries([string]$Path) {
    return @($Path -split ';' | ForEach-Object { $_.Trim().TrimEnd('\') } | Where-Object {
        $_ -and $_ -notmatch '(?i)^(%SystemRoot%|%windir%|%ProgramFiles(\(x86\))?%|%SYSTEMROOT%|C:\\Windows|C:\\Program Files( \(x86\))?|C:\\ProgramData\\(chocolatey|Microsoft))(\\|$)' })
}

function Invoke-CpModPersistence {
    param($Config)
    Write-CpHeader 'PERSISTENCE / BACKDOORS  (report only)'
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                   'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') {
        $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Add-CpFinding persistence "Run key $k : $($_.Name) = $($_.Value)" }
    }
    foreach ($d in "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') {
        Get-ChildItem $d -File -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini' | ForEach-Object { Add-CpFinding persistence "startup folder item: $($_.FullName)" }
    }
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' } | ForEach-Object {
        $a = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
        Add-CpFinding persistence "scheduled task $($_.TaskPath)$($_.TaskName) [$($_.Author)]: $a$(Get-CpTaskVerdict -Name $_.TaskName -Action $a)"
    }
    $w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($w.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { Add-CpFinding persistence "Winlogon Userinit tampered: $($w.Userinit)" }
    if ($w.Shell -ne 'explorer.exe') { Add-CpFinding persistence "Winlogon Shell tampered: $($w.Shell)" }
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object { $dbg = (Get-ItemProperty $_.PSPath).Debugger; if ($dbg) { Add-CpFinding persistence "IFEO debugger hijack: $($_.PSChildName) -> $dbg (sticky-keys backdoor?)" } }
    $hosts = Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*[^#\s]' }
    foreach ($h in $hosts) { Add-CpFinding persistence "hosts file entry: $h" }
    $ctx = Get-CpContext
    $listen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
        $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue)
        [pscustomobject]@{ Port = $_.LocalPort; Address = $_.LocalAddress; PID = $_.OwningProcess; Process = $proc.ProcessName; Path = $proc.Path }
    } | Sort-Object Port -Unique
    if ($ctx.RunDir) { $listen | Format-Table -AutoSize | Out-String -Width 250 | Set-Content (Join-Path $ctx.RunDir 'listening.txt') -Encoding ASCII; Write-Host "  listening ports: $(Join-Path $ctx.RunDir 'listening.txt')" }
    $listen | Where-Object { $_.Path -and $_.Path -notmatch '(?i)\\Windows\\|\\Program Files' } | ForEach-Object { Add-CpFinding persistence "listener on port $($_.Port): $($_.Process) $($_.Path)  (backdoor? forensics often asks the port)" }
    # generic words only count on runnable files (Nmap ships *backdoor*.nse scripts that are just detection rules)
    Find-CpFiles -Root 'C:\' -NameRegex '^(nc|nc64|ncat|netcat|bd)\.exe$|(backdoor|keylog).*\.(exe|dll|sys|ps1|bat|cmd|vbs|js|hta|scr)$|^mimi(katz|drv|lib)|^psexec' -SkipDirRegex '\\Windows\\WinSxS$|\\cpkit-runs$' |
        ForEach-Object { Add-CpFinding persistence "suspicious binary: $_" }

    # --- less obvious spots (persistence-themed practice images) ---
    # GlobalFlag + SilentProcessExit: runs a program whenever another one exits
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue | ForEach-Object {
        $mp = (Get-ItemProperty $_.PSPath).MonitorProcess; if ($mp) { Add-CpFinding persistence "SilentProcessExit: when $($_.PSChildName) exits, runs $mp" } }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $a = (Get-ItemProperty $k -ErrorAction SilentlyContinue).AppInit_DLLs; if ($a) { Add-CpFinding persistence "AppInit_DLLs ($k): $a  (loads into every GUI program)" } }
    # WMI event subscriptions: survive reboots, invisible in Task Scheduler
    Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'SCM Event Log Consumer' } |
        ForEach-Object { Add-CpFinding persistence "WMI event consumer '$($_.Name)' ($($_.CimClass.CimClassName)): $($_.CommandLineTemplate)$($_.ScriptText)" }
    # accessibility tools swapped for cmd.exe = logon-screen backdoor (sticky keys)
    foreach ($b in 'sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe','AtBroker.exe') {
        $p = Join-Path "$env:windir\System32" $b
        if (-not (Test-Path $p)) { continue }
        $sig = Get-AuthenticodeSignature $p -ErrorAction SilentlyContinue
        $desc = (Get-Item $p).VersionInfo.FileDescription
        if (($sig -and $sig.Status -ne 'Valid') -or $desc -match 'Command Processor|PowerShell|Explorer') { Add-CpFinding persistence "$p is not the real $b (signature $($sig.Status), '$desc') - accessibility backdoor" }
    }
    # tasks hidden under \Microsoft\ that run scripts from user-writable places
    Get-ScheduledTask -TaskPath '\Microsoft\*' -ErrorAction SilentlyContinue | Where-Object State -ne 'Disabled' | ForEach-Object {
        $a = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
        # (no plain cscript/wscript: Windows' own CleanupOldPerfLogs task uses cscript on a System32 .vbs)
        if ($a -match '(?i)\\Users\\|\\Temp\\|\\Public\\|\\inetpub\\|-enc|encodedcommand|http[s]?://|mshta|regsvr32 /s /i') { Add-CpFinding persistence "suspicious Microsoft-folder task $($_.TaskPath)$($_.TaskName): $a" }
    }
    # drivers loaded from outside Windows (mimikatz mimidrv, rootkits)
    Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)\\Windows\\|\\Program Files|^\\SystemRoot\\|^System32\\' } |
        ForEach-Object { Add-CpFinding persistence "driver '$($_.Name)' ($($_.State)) loads from: $($_.PathName)" }
    # ---- Round 4: places the Baldi's Basics and Dead by Daylight images used ----
    $wer = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs' -ErrorAction SilentlyContinue).Debugger
    if ($wer) { Add-CpFinding persistence "Windows Error Reporting hang debugger set: $wer  (runs when any program hangs - delete the value HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs\Debugger)" }
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $osc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig' -ErrorAction SilentlyContinue
    $lsaF = Get-CpLsaPackageFindings -Notification @($lsa.'Notification Packages') -Security (@($lsa.'Security Packages') + @($osc.'Security Packages')) -Authentication @($lsa.'Authentication Packages')
    foreach ($x in $lsaF) { Add-CpFinding persistence $x }
    foreach ($hive in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -notmatch '_Classes$' })) {
        $sid = $hive.PSChildName
        $envk = Get-ItemProperty "Registry::HKEY_USERS\$sid\Environment" -ErrorAction SilentlyContinue
        if ($envk.UserInitMprLogonScript) { Add-CpFinding persistence "logon script for user $sid (HKU\$sid\Environment\UserInitMprLogonScript): $($envk.UserInitMprLogonScript)  - delete the value AND the file" }
        if ($envk.SSLKEYLOGFILE) { Add-CpFinding persistence "SSLKEYLOGFILE set for user $sid -> $($envk.SSLKEYLOGFILE)  (browser TLS keys are written to disk: delete the variable and the file)" }
        $pol = Get-ItemProperty "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
        foreach ($v in 'DisableTaskMgr','DisableRegistryTools') {
            if ($pol.$v) { Add-CpFinding persistence "$v = $($pol.$v) for user $sid (the image locked a tool) - fix: reg delete `"HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Policies\System`" /v $v /f" }
        }
    }
    $menv = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -ErrorAction SilentlyContinue
    if ($menv.SSLKEYLOGFILE) { Add-CpFinding persistence "SSLKEYLOGFILE set for the whole machine -> $($menv.SSLKEYLOGFILE)  (TLS keys are written to disk: delete the variable and the file)" }
    foreach ($d in (Get-CpOddPathEntries -Path ([string]$menv.Path))) {
        Add-CpFinding persistence "machine PATH contains $d  (outside Windows / Program Files: a program dropped there can run instead of the real one - remove it from PATH unless the README software needs it; check who can write to the folder)"
    }
    # Group Policy scripts: run as SYSTEM at boot / as the user at logon (Baldi: startup.vbs in SYSVOL re-created an admin)
    $gpDirs = @("$env:windir\System32\GroupPolicy\Machine\Scripts", "$env:windir\System32\GroupPolicy\User\Scripts")
    if (Test-Path "$env:windir\SYSVOL\domain\Policies") {
        $gpDirs += @(Get-ChildItem "$env:windir\SYSVOL\domain\Policies" -Directory -ErrorAction SilentlyContinue | ForEach-Object { "$($_.FullName)\MACHINE\Scripts"; "$($_.FullName)\USER\Scripts" })
        $gpDirs += "$env:windir\SYSVOL\domain\scripts"
    }
    foreach ($d in $gpDirs) {
        Get-ChildItem $d -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(scripts|psscripts)\.ini$' -or $_.Length -gt 10 } |
            ForEach-Object { Add-CpFinding persistence "Group Policy / logon script: $($_.FullName)  (runs at startup or logon - read it; scripts with passwords are a scored finding)" }
    }
    # Trust providers (SIP): a DLL here decides whether a signature is valid; Dead by Daylight hid malware in one
    $sipDlls = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0' -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Dll } | Where-Object { $_ } | Sort-Object -Unique)
    foreach ($dll in $sipDlls) {
        $full = [Environment]::ExpandEnvironmentVariables($dll)
        if ($full -notmatch '\\') { $full = Join-Path "$env:windir\System32" $full }
        if (-not (Test-Path $full)) { continue }
        $sig = Get-AuthenticodeSignature $full -ErrorAction SilentlyContinue
        if (-not $sig -or $sig.Status -ne 'Valid' -or "$($sig.SignerCertificate.Subject)" -notmatch 'Microsoft') {
            Add-CpFinding persistence "signature-check provider DLL is not signed by Microsoft: $full  (registered under HKLM\SOFTWARE\Microsoft\Cryptography\OID - unregister with regsvr32 /u, then delete)"
        }
    }
    # ---- Round 5 (ideas from Ripper1004/CyberPatriot-Toolkit) ----
    $svcs = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name, PathName)
    foreach ($x in (Get-CpUnquotedServicePaths -Services $svcs)) {
        Add-CpFinding persistence "UNQUOTED service path with spaces (a program dropped at the first space runs as SYSTEM): $x  - fix: put quotes around the .exe path in HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath"
    }
    $nsh = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NetSh' -ErrorAction SilentlyContinue
    if ($nsh) {
        foreach ($p in ($nsh.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
            $dll = "$($p.Value)"
            $odd = Test-CpOddNetshDll -Dll $dll
            if (-not $odd) {
                $full = Join-Path "$env:windir\System32" $dll
                if (Test-Path $full) { $sig = Get-AuthenticodeSignature $full -ErrorAction SilentlyContinue; $odd = (-not $sig -or $sig.Status -ne 'Valid') }
            }
            if ($odd) { Add-CpFinding persistence "NetSh helper DLL '$($p.Name)' = $dll is not a signed Windows DLL (runs every time netsh starts) - delete the value under HKLM\SOFTWARE\Microsoft\NetSh" }
        }
    }
    $boot = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue).BootExecute
    foreach ($x in (Get-CpBootExecuteFindings -Values @($boot))) {
        Add-CpFinding persistence "BootExecute runs '$x' before Windows starts (default is only 'autocheck autochk *') - remove it from HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute"
    }
    $profiles = @("$PSHOME\profile.ps1", "$PSHOME\Microsoft.PowerShell_profile.ps1", "$env:windir\SysWOW64\WindowsPowerShell\v1.0\profile.ps1") +
        @(Get-ChildItem 'C:\Users\*\Documents\WindowsPowerShell\*profile.ps1', 'C:\Users\*\Documents\PowerShell\*profile.ps1' -Force -ErrorAction SilentlyContinue | ForEach-Object FullName)
    foreach ($p in ($profiles | Select-Object -Unique)) {
        if (Test-Path $p) { Add-CpFinding persistence "PowerShell profile (runs every time PowerShell starts): $p  - read it; a clean image has none" }
    }
}

# Pure. Services = objects with Name + PathName. Returns "name: path" for unquoted paths whose .exe part
# contains a space (C:\Program Files\x y\svc.exe -> Windows tries C:\Program.exe first).
function Get-CpUnquotedServicePaths {
    param($Services)
    $out = @()
    foreach ($s in @($Services)) {
        $p = "$($s.PathName)".Trim()
        if (-not $p -or $p.StartsWith('"')) { continue }
        $exe = if ($p -match '^(.+?\.exe)') { $Matches[1] } else { $p }
        if ($exe -match ' ' -and $exe -match '^[A-Za-z]:\\') { $out += "$($s.Name): $p" }
    }
    return $out
}

# Pure. True when a NetSh helper value points outside System32/SysWOW64 (a bare file name means System32).
function Test-CpOddNetshDll([string]$Dll) {
    if (-not $Dll) { return $false }
    $d = [Environment]::ExpandEnvironmentVariables($Dll)
    if ($d -notmatch '\\') { return $false }
    return ($d -notmatch '(?i)^[A-Za-z]:\\Windows\\(System32|SysWOW64)\\[^\\]+\.dll$')
}

# Pure. BootExecute entries that are not the stock autochk line.
function Get-CpBootExecuteFindings {
    param($Values)
    @(@($Values) | Where-Object { "$_".Trim() -and "$_".Trim() -notmatch '(?i)^autocheck\s+autochk(\s+/\S+)*\s+\*$' })
}

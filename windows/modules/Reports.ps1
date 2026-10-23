# REPORT-ONLY modules: unwanted software, prohibited media, persistence/backdoors.
# CP categories: Policy Violation (Unwanted Software / Prohibited Files / Malware).
# Nothing here deletes or uninstalls - answer forensics first, then remove by hand.

$script:CpBadSoftware = @('Wireshark','Nmap','Zenmap','Angry IP','Cain','CCleaner','TeamViewer','AnyDesk','uTorrent','BitTorrent',
    'qBittorrent','Vuze','FrostWire','iTunes','Bonjour','Driver Support','Web Companion','NetStumbler','PC Cleaner','GooseDesktop',
    'Npcap','WinPcap','FileZilla Server','Tor Browser','Ophcrack','John the Ripper','Hashcat','Hydra','Metasploit','Burp Suite',
    'Netcat','Steam','Epic Games','Minecraft','Roblox','Discord','Spotify','LogMeIn','RealVNC','TightVNC','UltraVNC','Ammyy',
    'WinSMS','Shareaza','LimeWire','Kazaa','Advanced SystemCare','MyCleanPC','Reimage','SlimCleaner','Ask Toolbar')
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
}

function Invoke-CpModMedia {
    param($Config)
    Write-CpHeader 'MEDIA / PROHIBITED FILES  (report only)'
    $ext = '*.mp3','*.mp4','*.avi','*.mkv','*.mov','*.wav','*.flac','*.ogg','*.m4a','*.wma','*.aac','*.wmv','*.flv','*.webm','*.jpg','*.jpeg','*.png','*.gif','*.zip','*.7z','*.rar','*.tar','*.gz','*.kdbx','*.pcap','*.pcapng'
    $roots = @('C:\Users') + @(Get-ChildItem 'C:\' -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(Windows|Program Files.*|ProgramData|Users|PerfLogs|Recovery|\$.*|System Volume Information|cpkit-runs)$' } | ForEach-Object FullName)
    $n = 0
    foreach ($r in $roots) {
        Get-ChildItem $r -Recurse -File -Include $ext -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\AppData\\Local\\(Microsoft|Packages|Temp)\\|\\AppData\\Roaming\\Microsoft\\|\\Windows\\' } |
            ForEach-Object { Add-CpFinding media "file: $($_.FullName)  ($([math]::Round($_.Length/1KB))KB)"; $n++ }
    }
    Get-ChildItem 'C:\Users' -Recurse -File -Include '*password*','*passwd*','*secret*','*credit*','*.exe','*.msi','*.bat','*.vbs','*.ps1' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\(Desktop|Documents|Downloads|Music|Pictures|Videos)\\' } |
        ForEach-Object { Add-CpFinding media "suspicious file: $($_.FullName)"; $n++ }
    Write-Host "  $n file(s) listed in findings.txt"
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
        Add-CpFinding persistence "scheduled task $($_.TaskPath)$($_.TaskName) [$($_.Author)]: $a"
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
    Get-ChildItem 'C:\' -Recurse -File -Include 'nc.exe','nc64.exe','ncat.exe','netcat.exe','bd.exe','*backdoor*','*keylog*','mimikatz*','psexec*' -ErrorAction SilentlyContinue |
        ForEach-Object { Add-CpFinding persistence "suspicious binary: $($_.FullName)" }
}

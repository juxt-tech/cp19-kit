# Firewall, Defender, services, shares, remote access, updates, Windows features.
# CP categories: Defensive Countermeasures, Service Auditing, Uncategorized OS Settings, OS Updates.

$script:CpBadServices = @(
    'RemoteRegistry','SNMPTRAP','SNMP','TapiSrv','NetTcpPortSharing','RasMan','RpcLocator','simptcp','TlntSvr',
    'FTPSVC','W3SVC','WMSvc','SSDPSRV','upnphost','iphlpsvc','Browser','lfsvc','MapsBroker','XblAuthManager',
    'XblGameSave','XboxNetApiSvc','XboxGipSvc','RemoteAccess','SharedAccess','WinRM','Fax','irmon','icssvc',
    'WebClient','MSiSCSI'
)
$script:CpRdpServices = @('TermService','SessionEnv','UmRdpService')   # only disabled when KEEP_RDP=no
$script:CpMustRun = @('wuauserv','WinDefend','mpssvc','EventLog','wscsvc','BFE')
$script:CpNeverTouch = @('Dnscache','Dhcp','RpcSs','LSM','LanmanWorkstation','Netlogon','NTDS','DNS','W32Time')

# Pure. Services = objects with Name, StartType, Status.
function Get-CpServicePlan {
    param([Parameter(Mandatory)]$Services, [Parameter(Mandatory)]$Config)
    $bad = @($script:CpBadServices)
    if (-not $Config.KeepRdp) { $bad += $script:CpRdpServices }
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($s in $Services) {
        $n = [string]$s.Name
        if ($script:CpNeverTouch -contains $n) { continue }
        if (Test-CpProtectedService -Name $n -Config $Config) {
            if ($bad -contains $n -or $script:CpRdpServices -contains $n) { $plan.Add([pscustomobject]@{ Action='KeepCritical'; Name=$n }) }
            continue
        }
        if ($bad -contains $n -and ([string]$s.StartType -ne 'Disabled' -or [string]$s.Status -eq 'Running')) {
            $plan.Add([pscustomobject]@{ Action='Disable'; Name=$n })
        }
        if ($script:CpMustRun -contains $n -and [string]$s.StartType -ne 'Automatic') {
            $plan.Add([pscustomobject]@{ Action='EnableAuto'; Name=$n })
        }
    }
    return ,$plan.ToArray()
}

function Invoke-CpModServices {
    param($Config)
    Write-CpHeader 'SERVICES'
    $svcs = @(Get-Service | Select-Object Name, DisplayName, @{n='StartType';e={[string]$_.StartType}}, @{n='Status';e={[string]$_.Status}})
    $plan = Get-CpServicePlan -Services $svcs -Config $Config
    if ($plan.Count -eq 0) { Write-CpOk 'no risky services enabled; core services automatic' }
    foreach ($a in $plan) {
        $n = $a.Name; $dn = ($svcs | Where-Object Name -eq $n).DisplayName
        switch ($a.Action) {
            'KeepCritical' { Write-CpOk "$n ($dn) kept - README critical" }
            'Disable'      { Invoke-CpAction services "stop + disable $n ($dn)" 'risky service not required by README' { Stop-Service -Name $n -Force -ErrorAction SilentlyContinue; Set-Service -Name $n -StartupType Disabled -ErrorAction Stop }.GetNewClosure() }
            'EnableAuto'   { Invoke-CpAction services "set $n ($dn) Automatic + start" 'core security service must run' { Set-Service -Name $n -StartupType Automatic -ErrorAction Stop; Start-Service -Name $n -ErrorAction SilentlyContinue }.GetNewClosure() }
        }
    }
    foreach ($c in $Config.Critical) {
        $s = Get-Service -Name $c -ErrorAction SilentlyContinue
        if (-not $s) { Add-CpFinding services "critical service '$c' not found (README needs the service NAME, e.g. TermService, W3SVC, FTPSVC)"; continue }
        if ($s.Status -ne 'Running') { Invoke-CpAction services "start critical service $c" 'README says it must run' { Set-Service -Name $c -StartupType Automatic; Start-Service -Name $c -ErrorAction Stop }.GetNewClosure() }
    }
    # services running from odd places = classic backdoor
    Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)\\Windows\\|\\Program Files|\\ProgramData\\Microsoft\\Windows Defender' } |
        ForEach-Object { Add-CpFinding services "service '$($_.Name)' runs from: $($_.PathName)" }
}

function Invoke-CpModFirewall {
    param($Config)
    Write-CpHeader 'FIREWALL  (all profiles)'
    foreach ($p in Get-NetFirewallProfile) {
        $ok = $p.Enabled -eq 'True' -and $p.DefaultInboundAction -eq 'Block' -and $p.DefaultOutboundAction -eq 'Allow' -and
              $p.NotifyOnListen -eq 'True' -and $p.AllowUnicastResponseToMulticast -eq 'False' -and $p.LogBlocked -eq 'True'
        if ($ok) { Write-CpOk "$($p.Name) profile hardened"; continue }
        $name = $p.Name
        Invoke-CpAction firewall "$name profile: on, block inbound, allow outbound, notify, no unicast reply, log drops" 'scored firewall profile settings' {
            Set-NetFirewallProfile -Name $name -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
                -NotifyOnListen True -AllowUnicastResponseToMulticast False -LogBlocked True -LogAllowed False -ErrorAction Stop }.GetNewClosure()
    }
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayGroup -eq $null -or $_.DisplayGroup -eq '' } |
        ForEach-Object { Add-CpFinding firewall "custom inbound ALLOW rule: '$($_.DisplayName)'  (needed by README?)" }
}

function Invoke-CpModDefender {
    param($Config)
    Write-CpHeader 'WINDOWS DEFENDER'
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $mp) {
        Add-CpFinding defender 'Defender not available. Server: Install-WindowsFeature Windows-Defender (then reboot). Third-party AV? check README.'
        return
    }
    $want = [ordered]@{ DisableRealtimeMonitoring=$false; DisableBehaviorMonitoring=$false; DisableIOAVProtection=$false;
                        DisableScriptScanning=$false; PUAProtection=1; MAPSReporting=2; SubmitSamplesConsent=1 }
    foreach ($k in $want.Keys) {
        if ("$($mp.$k)" -eq "$($want[$k])") { Write-CpOk "$k = $($want[$k])"; continue }
        $v = $want[$k]
        Invoke-CpAction defender "Defender $k -> $v (now $($mp.$k))" 'antivirus protection must be fully on' { $h = @{ $k = $v }; Set-MpPreference @h -ErrorAction Stop }.GetNewClosure()
    }
    foreach ($t in 'ExclusionExtension','ExclusionPath','ExclusionProcess','ExclusionIpAddress') {
        foreach ($x in @($mp.$t | Where-Object { $_ })) {
            $type = $t; $val = $x
            Invoke-CpAction defender "remove Defender $type '$val'" 'exclusions let malware hide (CP19 scored .exe exclusion)' { $h = @{ $type = $val }; Remove-MpPreference @h -ErrorAction Stop }.GetNewClosure()
        }
    }
    Invoke-CpAction defender 'update Defender signatures + start a quick scan in the background' 'fresh signatures find planted malware' {
        Update-MpSignature -ErrorAction SilentlyContinue; Start-MpScan -ScanType QuickScan -AsJob | Out-Null }
}

function Invoke-CpModShares {
    param($Config)
    Write-CpHeader 'SHARES + SMB'
    $default = @('ADMIN$','C$','D$','E$','IPC$','print$','NETLOGON','SYSVOL')
    foreach ($s in Get-SmbShare -ErrorAction SilentlyContinue) {
        if ($default -contains $s.Name) { continue }
        if ($Config.KeepShares -contains $s.Name) { Write-CpOk "share $($s.Name) kept (README)"; continue }
        $acc = (Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join ', '
        Add-CpFinding shares "share '$($s.Name)' -> $($s.Path)  access: $acc  (forensics questions often ask about this - note it first)"
        $n = $s.Name
        Invoke-CpAction shares "stop sharing '$n' ($($s.Path))" 'non-default share not in KEEP_SHARES' { Remove-SmbShare -Name $n -Force -ErrorAction Stop }.GetNewClosure()
    }
    $srv = Get-SmbServerConfiguration
    if ($srv.EnableSMB1Protocol) { Invoke-CpAction shares 'disable SMBv1 server' 'SMBv1 = WannaCry/EternalBlue' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop } } else { Write-CpOk 'SMBv1 server off' }
    if (-not $srv.RequireSecuritySignature) { Invoke-CpAction shares 'require SMB signing (server)' 'prevents SMB relay/tampering' { Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction Stop } } else { Write-CpOk 'SMB signing required' }
    if (-not $srv.EncryptData) { Add-CpFinding shares 'SMB encryption off (Set-SmbServerConfiguration -EncryptData $true) - can break old clients, decide by README' }
    $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($f -and $f.State -eq 'Enabled') { Invoke-CpAction shares 'remove SMB1Protocol feature (reboot later)' 'SMBv1 client+server removed' { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null } }
}

function Invoke-CpModRemote {
    param($Config)
    Write-CpHeader 'REMOTE DESKTOP / ASSISTANCE'
    $ts  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $deny = (Get-ItemProperty $ts -ErrorAction SilentlyContinue).fDenyTSConnections
    $help = (Get-ItemProperty $ts -ErrorAction SilentlyContinue).fAllowToGetHelp
    if ($help -ne 0) { Invoke-CpAction remote 'turn off Remote Assistance' 'unsolicited remote control' { Backup-CpRegistry 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'; Set-ItemProperty $ts fAllowToGetHelp 0 -Type DWord } } else { Write-CpOk 'Remote Assistance off' }
    if ($Config.KeepRdp) {
        Write-Host '  README needs RDP: keeping it ON and hardening it'
        if ($deny -ne 0) { Invoke-CpAction remote 'enable Remote Desktop' 'README requires RDP' { Set-ItemProperty $ts fDenyTSConnections 0 -Type DWord; Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue } }
        $r = Get-ItemProperty $rdp -ErrorAction SilentlyContinue
        if ($r.UserAuthentication -ne 1) { Invoke-CpAction remote 'require Network Level Authentication for RDP' 'CP19 scored: NLA on' { Backup-CpRegistry 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Set-ItemProperty $rdp UserAuthentication 1 -Type DWord } } else { Write-CpOk 'RDP NLA required' }
        if ($r.SecurityLayer -ne 2) { Invoke-CpAction remote 'RDP security layer = TLS' 'encrypts RDP with TLS' { Set-ItemProperty $rdp SecurityLayer 2 -Type DWord } } else { Write-CpOk 'RDP uses TLS' }
        if ($r.MinEncryptionLevel -lt 3) { Invoke-CpAction remote 'RDP encryption level = High' 'strong RDP encryption' { Set-ItemProperty $rdp MinEncryptionLevel 3 -Type DWord } }
    } elseif ($deny -ne 1) {
        Invoke-CpAction remote 'disable Remote Desktop connections' 'README does not require RDP (KEEP_RDP=no)' { Backup-CpRegistry 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'; Set-ItemProperty $ts fDenyTSConnections 1 -Type DWord }
    } else { Write-CpOk 'Remote Desktop off' }
}

function Invoke-CpModUpdates {
    param($Config)
    Write-CpHeader 'WINDOWS UPDATE'
    $au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $cur = Get-ItemProperty $au -ErrorAction SilentlyContinue
    if ($cur.NoAutoUpdate -ne 0 -or $cur.AUOptions -ne 4) {
        Invoke-CpAction updates 'automatic updates: download + install automatically (AUOptions=4)' 'scored: Windows automatic update settings' {
            Backup-CpRegistry 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            New-Item -Path $au -Force | Out-Null
            Set-ItemProperty $au NoAutoUpdate 0 -Type DWord; Set-ItemProperty $au AUOptions 4 -Type DWord
            Set-ItemProperty $au ScheduledInstallDay 0 -Type DWord
        }.GetNewClosure()
    } else { Write-CpOk 'automatic updates configured' }
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    foreach ($v in 'DisableWindowsUpdateAccess','DoNotConnectToWindowsUpdateInternetLocations','WUServer') {
        $x = (Get-ItemProperty $wu -ErrorAction SilentlyContinue).$v
        if ($x) { Add-CpFinding updates "WindowsUpdate policy '$v' = $x (blocks updates - remove it)" }
    }
    Invoke-CpAction updates 'open Settings > Windows Update (click Check for updates; let it run in background)' 'OS updates are scored' { Start-Process 'ms-settings:windowsupdate' }
    foreach ($app in 'Mozilla Firefox','Google Chrome','Notepad++','Microsoft Edge','7-Zip','VLC','Adobe') {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "$app*" } | ForEach-Object { Add-CpFinding updates "update by hand: $($_.DisplayName) $($_.DisplayVersion)  (CP scores app updates)" }
    }
}

function Invoke-CpModFeatures {
    param($Config)
    Write-CpHeader 'WINDOWS FEATURES'
    foreach ($f in 'TelnetClient','TFTP','SMB1Protocol','SimpleTCP','TelnetServer','IIS-FTPServer','MicrosoftWindowsPowerShellV2Root','MicrosoftWindowsPowerShellV2') {
        $x = Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue
        if (-not $x -or $x.State -ne 'Enabled') { continue }
        if ($f -like 'IIS-*' -and ($Config.Critical -contains 'FTPSVC' -or $Config.Critical -contains 'W3SVC')) { Write-CpOk "$f kept (README critical)"; continue }
        $name = $f
        Invoke-CpAction features "turn off Windows feature $name (no reboot now)" 'insecure/unneeded feature' { Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -ErrorAction Stop | Out-Null }.GetNewClosure()
    }
}

# Firewall, Defender, services, shares, remote access, updates, Windows features.
# CP categories: Defensive Countermeasures, Service Auditing, Uncategorized OS Settings, OS Updates.

$script:CpBadServices = @(
    'RemoteRegistry','SNMPTRAP','SNMP','TapiSrv','NetTcpPortSharing','RasMan','RpcLocator','simptcp','TlntSvr',
    'FTPSVC','W3SVC','WMSvc','SSDPSRV','upnphost','iphlpsvc','Browser','lfsvc','MapsBroker','XblAuthManager',
    'XblGameSave','XboxNetApiSvc','XboxGipSvc','RemoteAccess','SharedAccess','WinRM','Fax','irmon','icssvc',
    'WebClient','MSiSCSI'
)
$script:CpRdpServices = @('TermService','SessionEnv','UmRdpService')   # only disabled when KEEP_RDP=no
# Answer keys score DHCP Client, Event Log and Server (LanmanServer) as "running + automatic".
$script:CpMustRun = @('wuauserv','WinDefend','mpssvc','EventLog','wscsvc','BFE','Dhcp','LanmanServer')
# ...and Automatic is not enough for these: a planted "Automatic but stopped" still loses the points.
# (wuauserv is left out: it stops by itself when idle, so a re-run would never show 0 changes.)
$script:CpMustBeRunning = @('WinDefend','mpssvc','EventLog','BFE','Dhcp','LanmanServer')
$script:CpNeverTouch = @('Dnscache','RpcSs','LSM','LanmanWorkstation','Netlogon','NTDS','DNS','W32Time')

# Pure. Services = objects with Name, StartType, Status.
function Get-CpServicePlan {
    param([Parameter(Mandatory)]$Services, [Parameter(Mandatory)]$Config)
    $bad = @($script:CpBadServices)
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($s in $Services) {
        $n = [string]$s.Name
        if ($script:CpNeverTouch -contains $n) { continue }
        if (Test-CpProtectedService -Name $n -Config $Config) {
            if ($bad -contains $n -or $script:CpRdpServices -contains $n) { $plan.Add([pscustomobject]@{ Action='KeepCritical'; Name=$n }) }
            continue
        }
        # TermService also runs the LOCAL console session: stopping it live freezes keyboard/mouse
        # (District 13). The Remote module's fDenyTSConnections=1 blocks RDP at once; the service stops at reboot.
        if (-not $Config.KeepRdp -and $script:CpRdpServices -contains $n) {
            if ([string]$s.StartType -ne 'Disabled') { $plan.Add([pscustomobject]@{ Action='DisableOnReboot'; Name=$n }) }
            continue
        }
        if ($bad -contains $n -and ([string]$s.StartType -ne 'Disabled' -or [string]$s.Status -eq 'Running')) {
            $plan.Add([pscustomobject]@{ Action='Disable'; Name=$n })
        }
        if ($script:CpMustRun -contains $n -and ([string]$s.StartType -ne 'Automatic' -or
                ($script:CpMustBeRunning -contains $n -and [string]$s.Status -ne 'Running'))) {
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
            'DisableOnReboot' { Invoke-CpAction services "disable $n ($dn) - stops at next reboot" 'RDP not required by README; a live stop freezes the console' { Set-Service -Name $n -StartupType Disabled -ErrorAction Stop }.GetNewClosure() }
            'EnableAuto'   {
                # wuauserv may legitimately stay stopped until needed; the others must really start
                $ea = if ($script:CpMustBeRunning -contains $n) { 'Stop' } else { 'SilentlyContinue' }
                Invoke-CpAction services "set $n ($dn) Automatic + start" 'core service must run (scored)' { Set-Service -Name $n -StartupType Automatic -ErrorAction Stop; Start-Service -Name $n -ErrorAction $ea }.GetNewClosure() }
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
        Where-Object { -not $_.DisplayGroup } |
        ForEach-Object { Add-CpFinding firewall "custom inbound ALLOW rule: '$($_.DisplayName)'  (needed by README?)" }
}

# Defender threat actions: 6 = Allow, 8 = UserDefined, 9 = NoAction. 0 = default (fine), 2 = Quarantine.
$script:CpBadThreatActions = @('6','8','9')

# Pure: Mp = object with Low/Moderate/High/Severe/UnknownThreatDefaultAction. Returns the property names to reset.
function Get-CpThreatActionPlan {
    param([Parameter(Mandatory)]$Mp)
    $out = @()
    foreach ($p in 'LowThreatDefaultAction','ModerateThreatDefaultAction','HighThreatDefaultAction','SevereThreatDefaultAction','UnknownThreatDefaultAction') {
        if ("$($Mp.$p)" -in $script:CpBadThreatActions) { $out += $p }
    }
    return ,$out
}

# Pure: which Defender *policy* values to delete. Values = @{ 'Sub\Key\ValueName' = data }.
# Group Policy values beat Set-MpPreference, so planted "Disable*=1" policies must go.
function Get-CpDefenderPolicyPlan {
    param([Parameter(Mandatory)][hashtable]$Values)
    $out = @()
    foreach ($k in $Values.Keys) {
        $leaf = ($k -split '\\')[-1]
        # District 13 excludes C:\aeacus\phocus.exe: removing that lets Defender quarantine the scoring engine
        if ($k -match (Get-CpScoringRegex)) { continue }
        if ($k -like 'Exclusions\*') { $out += $k; continue }
        if ($leaf -like 'Disable*' -and "$($Values[$k])" -ne '0') { $out += $k; continue }
        # "default action for severe threats = Allow / No action" (PPTH answer key)
        if ($k -like 'Threats\ThreatSeverityDefaultAction\*' -and "$($Values[$k])" -in $script:CpBadThreatActions) { $out += $k }
    }
    return ,$out
}

function Get-CpDefenderPolicyValues {
    $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $h = @{}
    if (-not (Test-Path $base)) { return $h }
    foreach ($key in @(Get-Item $base) + @(Get-ChildItem $base -Recurse -ErrorAction SilentlyContinue)) {
        $rel = ($key.PSPath -replace '^.*\\Windows Defender\\?', '')
        foreach ($v in $key.GetValueNames()) { if ($v) { $h[$(if ($rel) { "$rel\$v" } else { $v })] = $key.GetValue($v) } }
    }
    return $h
}

# Pure: update + scan only when needed, so a second apply makes 0 changes.
function Test-CpDefenderStale {
    param([long]$SignatureAgeDays, [long]$QuickScanAgeDays)
    return ($SignatureAgeDays -ge 1 -or $QuickScanAgeDays -ge 1)
}

function Invoke-CpModDefender {
    param($Config)
    Write-CpHeader 'WINDOWS DEFENDER'
    $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    # assign first: "foreach ($x in Get-Fn)" hands a ",$out" result over as ONE array item (crashed on District 13)
    $polPlan = Get-CpDefenderPolicyPlan -Values (Get-CpDefenderPolicyValues)
    foreach ($p in $polPlan) {
        $sub = Split-Path $p -Parent; $name = Split-Path $p -Leaf
        $path = if ($sub) { Join-Path $base $sub } else { $base }
        Invoke-CpAction defender "delete Defender policy value $p" 'group-policy Disable*/exclusions override the Defender settings' {
            Backup-CpRegistry 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'
            Remove-ItemProperty -Path $path -Name $name -ErrorAction Stop }.GetNewClosure()
    }
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $mp) {
        Add-CpFinding defender 'Defender not available (Get-MpPreference failed: WinDefend missing or its WMI class broken). Removed a DisableAntiSpyware policy above? reboot and re-run. Feature uninstalled (Server)? Install-WindowsFeature Windows-Defender, reboot. Third-party AV? check README.'
        return
    }
    $want = [ordered]@{ DisableRealtimeMonitoring=$false; DisableBehaviorMonitoring=$false; DisableIOAVProtection=$false;
                        DisableScriptScanning=$false; PUAProtection=1; MAPSReporting=2; SubmitSamplesConsent=1 }
    foreach ($k in $want.Keys) {
        if ("$($mp.$k)" -eq "$($want[$k])") { Write-CpOk "$k = $($want[$k])"; continue }
        $v = $want[$k]
        Invoke-CpAction defender "Defender $k -> $v (now $($mp.$k))" 'antivirus protection must be fully on' { $h = @{ $k = $v }; Set-MpPreference @h -ErrorAction Stop }.GetNewClosure()
    }
    $threatPlan = Get-CpThreatActionPlan -Mp $mp
    foreach ($k in $threatPlan) {
        $name = $k
        Invoke-CpAction defender "Defender $name -> Quarantine (now $($mp.$name))" 'threats must not be allowed / ignored' { $h = @{ $name = 'Quarantine' }; Set-MpPreference @h -ErrorAction Stop }.GetNewClosure()
    }
    foreach ($t in 'ExclusionExtension','ExclusionPath','ExclusionProcess','ExclusionIpAddress') {
        foreach ($x in @($mp.$t | Where-Object { $_ -and $_ -notmatch (Get-CpScoringRegex) })) {
            $type = $t; $val = $x
            Invoke-CpAction defender "remove Defender $type '$val'" 'exclusions let malware hide (CP19 scored .exe exclusion)' { $h = @{ $type = $val }; Remove-MpPreference @h -ErrorAction Stop }.GetNewClosure()
        }
    }
    $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($st -and -not (Test-CpDefenderStale -SignatureAgeDays $st.AntivirusSignatureAge -QuickScanAgeDays $st.QuickScanAge)) {
        Write-CpOk 'signatures current and quick scan within a day'
    } else {
        Invoke-CpAction defender 'update Defender signatures + start a quick scan in the background' 'fresh signatures find planted malware' {
            Update-MpSignature -ErrorAction SilentlyContinue; Start-MpScan -ScanType QuickScan -AsJob | Out-Null }
    }
}

# Shares a role needs (AD CS, WDS, WSUS, DC) - removing them breaks the role, so report only.
$script:CpRoleShares = @('NETLOGON','SYSVOL','print$','CertEnroll','REMINST','WSUSTemp','WsusContent','UpdateServicesPackages')

# Pure. Shares = objects with Name, Special, Path.
function Get-CpSharePlan {
    param([Parameter(Mandatory)]$Shares, [Parameter(Mandatory)]$Config)
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($s in $Shares) {
        $n = [string]$s.Name
        if ($s.Special -or $n -eq 'IPC$') { continue }   # ADMIN$, C$, D$ ... created by Windows itself
        if (@($Config.KeepShares) -contains $n) { $plan.Add([pscustomobject]@{ Action='KeepReadme'; Name=$n; Path=$s.Path }); continue }
        if (@($script:CpRoleShares | Where-Object { $_ -ieq $n }).Count) { $plan.Add([pscustomobject]@{ Action='KeepRole'; Name=$n; Path=$s.Path }); continue }
        $plan.Add([pscustomobject]@{ Action='Remove'; Name=$n; Path=$s.Path })
    }
    return ,$plan.ToArray()
}

function Invoke-CpModShares {
    param($Config)
    Write-CpHeader 'SHARES + SMB'
    $all = @(Get-SmbShare -ErrorAction SilentlyContinue)
    foreach ($a in (Get-CpSharePlan -Shares $all -Config $Config)) {
        $n = $a.Name
        $acc = (Get-SmbShareAccess -Name $n -ErrorAction SilentlyContinue | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join ', '
        switch ($a.Action) {
            'KeepReadme' { Write-CpOk "share $n kept (README)" }
            'KeepRole'   { Write-CpOk "share $n kept (server role share)"; Add-CpFinding shares "role share '$n' -> $($a.Path)  access: $acc  (kept; check Everyone has no Full/Change)" }
            'Remove'     {
                Add-CpFinding shares "share '$n' -> $($a.Path)  access: $acc  (forensics questions often ask about this - note it first)"
                Invoke-CpAction shares "stop sharing '$n' ($($a.Path))" 'non-default share not in KEEP_SHARES' { Remove-SmbShare -Name $n -Force -ErrorAction Stop }.GetNewClosure()
            }
        }
    }
    $srv = Get-SmbServerConfiguration
    if ($srv.EnableSMB1Protocol) { Invoke-CpAction shares 'disable SMBv1 server' 'SMBv1 = WannaCry/EternalBlue' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop } } else { Write-CpOk 'SMBv1 server off' }
    if (-not $srv.RequireSecuritySignature) { Invoke-CpAction shares 'require SMB signing (server)' 'prevents SMB relay/tampering' { Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction Stop } } else { Write-CpOk 'SMB signing required' }
    # Smb2DialectMin only exists on Win11 24H2 / Server 2025 (L'Equipe key: "SMB minimum version 3.1.1")
    if ($srv.PSObject.Properties['Smb2DialectMin']) {
        if ("$($srv.Smb2DialectMin)" -ne 'SMB311') { Invoke-CpAction shares "SMB minimum dialect $($srv.Smb2DialectMin) -> SMB311" 'scored: SMB minimum version 3.1.1' { Set-SmbServerConfiguration -Smb2DialectMin SMB311 -Force -ErrorAction Stop } } else { Write-CpOk 'SMB minimum dialect 3.1.1' }
    }
    if (-not $srv.EncryptData) { Add-CpFinding shares 'SMB encryption off (Set-SmbServerConfiguration -EncryptData $true) - can break old clients, decide by README' }
    $f = $null
    try { $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop }
    catch { Add-CpFinding shares "could not check the SMB1Protocol feature ($($_.Exception.Message.Split("`n")[0])) - check by hand in Server Manager > Features" }
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
        # answer keys check the Group Policy copies too (gpedit > Remote Desktop Session Host > Security)
        $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        Invoke-CpRegistrySettings -Module remote -Wanted @(
            New-CpReg $pol UserAuthentication 1 'policy: require NLA'
            New-CpReg $pol SecurityLayer 2 'policy: RDP security layer = SSL'
            New-CpReg $pol MinEncryptionLevel 3 'policy: RDP encryption = High'
            New-CpReg $pol fEncryptRPCTraffic 1 'policy: require secure RPC communication'
            New-CpReg $pol fPromptForPassword 1 'policy: always prompt for password'
        )
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
    Add-CpFinding updates 'Windows Update: Settings > Windows Update > Check for updates, let it install in the background (OS updates are scored)'
    foreach ($app in 'Mozilla Firefox','Google Chrome','Notepad++','Microsoft Edge','7-Zip','VLC','Adobe') {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "$app*" } | ForEach-Object { Add-CpFinding updates "update by hand: $($_.DisplayName) $($_.DisplayVersion)  (CP scores app updates)" }
    }
}

function Invoke-CpModFeatures {
    param($Config)
    Write-CpHeader 'WINDOWS FEATURES'
    foreach ($f in 'TelnetClient','TFTP','SMB1Protocol','SimpleTCP','TelnetServer','IIS-FTPServer','MicrosoftWindowsPowerShellV2Root','MicrosoftWindowsPowerShellV2') {
        # DISM throws (not just errors) when TEMP is broken; one failure would kill the whole module
        try { $x = Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction Stop }
        catch { Add-CpFinding features "could not check Windows feature $f ($($_.Exception.Message.Split("`n")[0])) - check by hand: optionalfeatures.exe"; continue }
        if (-not $x -or $x.State -ne 'Enabled') { continue }
        if ($f -like 'IIS-*' -and ($Config.Critical -contains 'FTPSVC' -or $Config.Critical -contains 'W3SVC')) { Write-CpOk "$f kept (README critical)"; continue }
        $name = $f
        Invoke-CpAction features "turn off Windows feature $name (no reboot now)" 'insecure/unneeded feature' { Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -ErrorAction Stop | Out-Null }.GetNewClosure()
    }
}

# Server 2019/2022 extras: Active Directory users + domain password policy (domain controllers),
# and reports for roles, DNS, IIS and FTP. CP categories: User Auditing, Account Policies,
# Application Security Settings.

# Pure. Service names -> Get-WindowsFeature role names, for when DISM is broken.
function Get-CpRolesFromServices([string[]]$Services) {
    $map = [ordered]@{ NTDS='AD-Domain-Services'; DNS='DNS'; W3SVC='Web-Server'; CertSvc='AD-Certificate'; DHCPServer='DHCP'; FTPSVC='Web-Server' }
    $out = @(); foreach ($k in $map.Keys) { if ($Services -contains $k -and $out -notcontains $map[$k]) { $out += $map[$k] } }
    return ,$out
}

# Pure. Users = objects with SamAccountName, UseDESKeyOnly, TrustedForDelegation, AccountNotDelegated,
# SIDHistory, Description. Returns Action (DesOff | NotDelegated | Finding), Name, Text.
function Get-CpAdUserFindings {
    param([Parameter(Mandatory)]$Users, [string[]]$DomainAdmins = @(), [Parameter(Mandatory)]$Config)
    $out = New-Object System.Collections.Generic.List[object]
    $add = { param($a, $n, $t) $out.Add([pscustomobject]@{ Action = $a; Name = $n; Text = $t }) }
    foreach ($u in $Users) {
        $n = [string]$u.SamAccountName
        if ($u.UseDESKeyOnly) { & $add 'DesOff' $n 'DES is a broken cipher (Baldi: "no longer uses DES encryption for Kerberos")' }
        # README admins only: delegating a Domain Admin's logon to another server hands that server the domain
        if (($DomainAdmins -contains $n) -and (@($Config.Admins) -contains $n) -and -not $u.AccountNotDelegated) {
            & $add 'NotDelegated' $n 'Domain Admin accounts must be "sensitive and cannot be delegated" (Dead by Daylight)'
        }
        if (@($u.SIDHistory).Count -gt 0) {
            & $add 'Finding' $n "AD user $n has a SID history ($(@($u.SIDHistory) -join ', ')) - hidden membership of that old account/group. Remove: Set-ADUser $n -Remove @{SIDHistory='<the SID>'}"
        }
        if ([string]$u.Description -match '(?i)pass(word|wd)?\b|\bpwd\b|\bpw\s*[:=]') {
            & $add 'Finding' $n "AD user $n has a password in its Description field: '$($u.Description)' - clear the field and change that password"
        }
        if ($u.TrustedForDelegation) {
            & $add 'Finding' $n "AD user $n is trusted for UNCONSTRAINED delegation - ADUC > $n > Delegation > 'Do not trust this user for delegation' unless the README needs it"
        }
    }
    return $out.ToArray()
}
# Pure. Members (DNs) of "Pre-Windows 2000 Compatible Access" that let unauthenticated clients read AD.
function Get-CpPre2000BadMembers([string[]]$MemberDns) {
    return @($MemberDns | Where-Object { $_ -match '^CN=S-1-(5-7|1-0),' })
}
# Pure. dSHeuristics: 7th character '2' = anonymous LDAP operations allowed.
function Test-CpAnonymousLdap([string]$Heuristics) { return ($Heuristics.Length -ge 7 -and $Heuristics[6] -eq '2') }
function Get-CpFixedHeuristics([string]$Heuristics) { return $Heuristics.Substring(0, 6) + '0' + $Heuristics.Substring(7) }
# Pure. Aces = access rules on the domain root. One line per account that can copy every password hash
# (DCSync = "Replicating Directory Changes All") or has full control, other than the built-in holders.
$script:CpDcSyncOk = '(?i)^(NT AUTHORITY\\(SYSTEM|ENTERPRISE DOMAIN CONTROLLERS)|BUILTIN\\Administrators|.*\\(Domain Admins|Enterprise Admins|Domain Controllers|Enterprise Read-only Domain Controllers|Administrators)|S-1-5-(9|18)|S-1-5-32-544)$'
function Get-CpDcSyncFindings {
    param([Parameter(Mandatory)]$Aces)
    $who = New-Object System.Collections.Generic.List[string]
    foreach ($a in $Aces) {
        if ("$($a.AccessControlType)" -ne 'Allow') { continue }
        $id = "$($a.IdentityReference)"
        if ($id -match $script:CpDcSyncOk) { continue }
        $rights = "$($a.ActiveDirectoryRights)"
        $isSync = ($rights -match 'ExtendedRight' -and "$($a.ObjectType)" -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
        $isFull = ($rights -match 'GenericAll')
        if (($isSync -or $isFull) -and -not $who.Contains($id)) { $who.Add($id) }
    }
    return @($who | ForEach-Object { "$_ can copy every password hash in the domain (DCSync / full control on the domain object) - ADUC > View > Advanced Features > right-click the domain > Properties > Security: remove that entry unless the README says otherwise" })
}

function Invoke-CpModServer {
    param($Config, [switch]$IsDC)
    Write-CpHeader 'SERVER  (roles, AD, DNS, IIS, FTP)'
    $roles = @()
    try { $roles = @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | ForEach-Object Name) }
    catch {
        # District 13: broken C:\Windows\Temp makes Get-WindowsFeature throw. Guess roles from services so AD still gets audited.
        $roles = Get-CpRolesFromServices -Services @(Get-Service | ForEach-Object Name)   # no @(): it would wrap the array again
        Add-CpFinding server "Get-WindowsFeature failed ($($_.Exception.Message.Split("`n")[0])) - roles guessed from services: $($roles -join ', ')"
    }
    Write-Host "  installed roles: $($roles -join ', ')"
    if ($IsDC) {
        # One failed AD call must not take DNS / IIS / DHCP down with it.
        try { Invoke-CpServerAD -Config $Config }
        catch { Add-CpFinding server "Active Directory part stopped: $($_.Exception.Message.Split("`n")[0])  - changes before this line are logged; re-run -Module Server" }
    }
    if ($roles -contains 'DNS') { Invoke-CpServerDns }
    if ($roles -contains 'DHCP') { Invoke-CpServerDhcp }
    if ($roles -contains 'DNS') {
        # A stopped DNS service makes Get-DnsServerZone THROW (District 13), which ended the whole module.
        $zones = try { @(Get-DnsServerZone -ErrorAction Stop) } catch {
            Add-CpFinding server "DNS zones not checked ($($_.Exception.Message.Trim())). DNS Server service running? Start it (Services module does when DNS is README-critical), then re-run -Module Server"; @() }
        $zones | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' } | ForEach-Object {
            $z = $_.ZoneName
            if ($_.SecureSecondaries -eq 'TransferAnyServer') {
                Invoke-CpAction server "DNS zone ${z}: no zone transfers to any server" 'zone transfer leaks every host record' { Set-DnsServerPrimaryZone -Name $z -SecureSecondaries NoTransfer -ErrorAction Stop }.GetNewClosure()
            }
            if ($_.DynamicUpdate -eq 'NonsecureAndSecure') {
                Invoke-CpAction server "DNS zone ${z}: secure dynamic updates only" 'nonsecure updates let anyone add records' { Set-DnsServerPrimaryZone -Name $z -DynamicUpdate Secure -ErrorAction SilentlyContinue }.GetNewClosure()
            }
        }
    }
    if ($roles -contains 'Web-Server') {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        Get-Website -ErrorAction SilentlyContinue | ForEach-Object { Add-CpFinding server "IIS site '$($_.Name)' state=$($_.State) path=$($_.PhysicalPath) bindings=$(($_.Bindings.Collection | ForEach-Object bindingInformation) -join ' ')" }
        $db = Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath 'IIS:\' -ErrorAction SilentlyContinue
        if ($db.Value) { Invoke-CpAction server 'IIS: turn off directory browsing' 'directory listings leak files' { Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $false -PSPath 'IIS:\' } }
        Add-CpFinding server 'IIS: check anonymous auth, SSL, logging, request filtering per README (CIS IIS benchmark)'
        $ftp = Get-WebConfigurationProperty -Filter /system.ftpServer/security/authentication/anonymousAuthentication -Name enabled -PSPath 'IIS:\' -ErrorAction SilentlyContinue
        if ($ftp.Value) { Add-CpFinding server 'FTP anonymous authentication is ON - turn off unless README needs it (IIS Manager > FTP Authentication)' }
    }
}

# DNS server settings scored on the DC answer keys. Everything here is harmless to name resolution.
function Invoke-CpServerDns {
    try {
        $vq = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -ErrorAction SilentlyContinue).EnableVersionQuery
        if ($vq -ne 0) { Invoke-CpAction server 'DNS: stop answering version queries (dnscmd /config /EnableVersionQuery 0)' 'the version tells an attacker which exploits fit' { & dnscmd.exe /config /EnableVersionQuery 0 | Out-Null } }
        else { Write-CpOk 'DNS version query off' }
        $diag = Get-DnsServerDiagnostics -ErrorAction Stop
        if (-not $diag.EnableLoggingForZoneDataWriteEvent) { Invoke-CpAction server 'DNS: log zone data write events' 'zone changes leave no trace otherwise' { Set-DnsServerDiagnostics -EnableLoggingForZoneDataWriteEvent $true -ErrorAction Stop } }
        $sc = Get-DnsServerScavenging -ErrorAction Stop
        if (-not $sc.ScavengingState) { Invoke-CpAction server 'DNS: turn on scavenging of stale records (7 days, all zones)' 'stale records pile up and can be hijacked' { Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7.00:00:00 -ApplyOnAllZones -ErrorAction Stop } }
        $rec = Get-DnsServerRecursion -ErrorAction Stop
        if ($rec.Enable) { Add-CpFinding server 'DNS recursion is ON. Some images score turning it off (dnsmgmt.msc > server > Properties > Advanced > Disable recursion). DO IT LAST and only if nothing else works: without recursion this server cannot look up internet names, which can stop the scoring report from updating. Undo: Set-DnsServerRecursion -Enable $true' }
    } catch { Add-CpFinding server "DNS server settings not checked ($($_.Exception.Message.Trim().Split("`n")[0])) - is the DNS Server service running?" }
}
function Invoke-CpServerDhcp {
    try {
        $al = Get-DhcpServerAuditLog -ErrorAction Stop
        if (-not $al.Enable) { Invoke-CpAction server 'DHCP: turn on audit logging' 'no record of who got which address' { Set-DhcpServerAuditLog -Enable $true -ErrorAction Stop } }
        else { Write-CpOk 'DHCP audit logging on' }
        $st = Get-DhcpServerSetting -ErrorAction Stop
        if ([int]$st.ConflictDetectionAttempts -lt 1) { Invoke-CpAction server 'DHCP: conflict detection attempts = 2' 'duplicate addresses knock machines off the network' { Set-DhcpServerSetting -ConflictDetectionAttempts 2 -ErrorAction Stop } }
        if ($st.IsDomainJoined -and -not $st.IsAuthorized) { Add-CpFinding server 'DHCP server is NOT authorized in Active Directory - dhcpmgmt.msc > right-click the server > Authorize (or: Add-DhcpServerInDC)' }
        Add-CpFinding server 'DHCP by hand (dhcpmgmt.msc): IPv4 > Properties > DNS > Name Protection on; services.msc > DHCP Server > Recovery > Restart the Service; C:\Windows\System32\dhcp files not writable by Users'
    } catch { Add-CpFinding server "DHCP server settings not checked ($($_.Exception.Message.Trim().Split("`n")[0]))" }
}
function Invoke-CpServerAD {
    param($Config)
    Import-Module ActiveDirectory -ErrorAction Stop
    # Retried reads: right after boot the first AD query can fail once ("A local error has occurred").
    $dom = Invoke-CpRetry { Get-ADDomain -ErrorAction Stop }
    $users  = @(Invoke-CpRetry { Get-ADUser -Filter * -ErrorAction Stop -Properties PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, AllowReversiblePasswordEncryption, PasswordLastSet,
        UseDESKeyOnly, TrustedForDelegation, AccountNotDelegated, SIDHistory, Description })
    $das    = @(Get-ADGroupMember 'Domain Admins' -ErrorAction SilentlyContinue | Where-Object objectClass -eq 'user' | ForEach-Object SamAccountName)
    $svc = Get-CpServiceAccounts -AllUsers ($users | ForEach-Object SamAccountName) -IsDC
    $plan = Get-CpUserPlan -Config $Config -CurrentUser $env:USERNAME -IsDC `
        -LocalUsers ($users | ForEach-Object SamAccountName) -Admins $das `
        -DisabledUsers ($users | Where-Object { -not $_.Enabled } | ForEach-Object SamAccountName) `
        -NoPasswordRequired ($users | Where-Object PasswordNotRequired | ForEach-Object SamAccountName) `
        -NeverExpires ($users | Where-Object PasswordNeverExpires | ForEach-Object SamAccountName) -ServiceAccounts $svc `
        -RecentPassword ($users | Where-Object { $_.PasswordLastSet -gt (Get-Date).AddHours(-6) } | ForEach-Object SamAccountName)
    $pw = if ($Config.NewPassword) { ConvertTo-SecureString $Config.NewPassword -AsPlainText -Force } else { $null }
    foreach ($a in $plan) {
        $n = $a.Name
        switch ($a.Action) {
            'RemoveADUser'      { Invoke-CpAction server "delete AD user $n" 'not in README' { Remove-ADUser -Identity $n -Confirm:$false -ErrorAction Stop }.GetNewClosure() }
            'AddADUser'         { if (-not $pw) { Add-CpFinding server "README user $n missing (no NEW_PASSWORD) - create in ADUC"; continue }
                                  Invoke-CpAction server "create AD user $n" 'listed in README but missing' { New-ADUser -Name $n -SamAccountName $n -AccountPassword $pw -Enabled $true -ErrorAction Stop }.GetNewClosure() }
            'EnableADUser'      { Invoke-CpAction server "enable AD user $n" 'authorized account disabled' { Enable-ADAccount -Identity $n -ErrorAction Stop }.GetNewClosure() }
            'AddDomainAdmin'    { Invoke-CpAction server "add $n to Domain Admins" 'authorized admin' { Add-ADGroupMember 'Domain Admins' -Members $n -ErrorAction Stop }.GetNewClosure() }
            'RemoveDomainAdmin' { Invoke-CpAction server "remove $n from Domain Admins" 'not an authorized admin' { Remove-ADGroupMember 'Domain Admins' -Members $n -Confirm:$false -ErrorAction Stop }.GetNewClosure() }
            'DisableBuiltin'    { Invoke-CpAction server "disable built-in $n" 'built-in accounts are attack targets' { Disable-ADAccount -Identity $n -ErrorAction Stop }.GetNewClosure() }
            'SetPassword'       { Invoke-CpAction server "require a password for $n" 'PASSWD_NOTREQD flag set' { Set-ADUser -Identity $n -PasswordNotRequired $false -ErrorAction Stop }.GetNewClosure() }
            'PasswordNeverExpiresOff' { Invoke-CpAction server "make $n's password expire" 'never-expires is scored' { Set-ADUser -Identity $n -PasswordNeverExpires $false -ErrorAction Stop }.GetNewClosure() }
            'ResetPassword'     { if (-not $pw) { Add-CpFinding server "RESET_PASSWORDS=yes but NEW_PASSWORD is empty - $n not reset"; continue }
                                  Invoke-CpAction server "reset password for $n" 'RESET_PASSWORDS=yes (README says passwords are compromised)' { Set-ADAccountPassword -Identity $n -Reset -NewPassword $pw -ErrorAction Stop }.GetNewClosure() }
            'KeepServiceAccount' { Add-CpFinding server "AD user $n is not in the README but looks like a SERVICE ACCOUNT (SPN / runs a service or IIS app pool / svc_ name) - kept. Delete only if nothing uses it" }
            'KeepServiceAdmin'   { Add-CpFinding server "service account $n is a Domain Admin - kept (removing can stop its service). Check the README" }
        }
    }
    foreach ($u in $users) {
        if ($u.DoesNotRequirePreAuth) { $n = $u.SamAccountName; Invoke-CpAction server "require Kerberos pre-auth for $n" 'AS-REP roasting' { Set-ADAccountControl -Identity $n -DoesNotRequirePreAuth $false }.GetNewClosure() }
        if ($u.AllowReversiblePasswordEncryption) { $n = $u.SamAccountName; Invoke-CpAction server "no reversible encryption for $n" 'stores password recoverably' { Set-ADUser -Identity $n -AllowReversiblePasswordEncryption $false }.GetNewClosure() }
    }
    # ---- Round 4: items scored on the Baldi's Basics and Dead by Daylight DC images ----
    foreach ($x in (Get-CpAdUserFindings -Users $users -DomainAdmins $das -Config $Config)) {
        $n = $x.Name
        switch ($x.Action) {
            'DesOff'       { Invoke-CpAction server "turn off 'Use only Kerberos DES encryption' for $n" $x.Text { Set-ADAccountControl -Identity $n -UseDESKeyOnly $false -ErrorAction Stop }.GetNewClosure() }
            'NotDelegated' { Invoke-CpAction server "mark admin $n 'Account is sensitive and cannot be delegated'" $x.Text { Set-ADUser -Identity $n -AccountNotDelegated $true -ErrorAction Stop }.GetNewClosure() }
            'Finding'      { Add-CpFinding server $x.Text }
        }
    }
    $id = $dom.DistinguishedName
    try {
        $maq = (Get-ADObject -Identity $id -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop).'ms-DS-MachineAccountQuota'
        if ($null -ne $maq -and [int]$maq -gt 0) {
            Invoke-CpAction server "ms-DS-MachineAccountQuota $maq -> 0" 'any user may join 10 computers to the domain (noPac / CVE-2021-42287 path)' { Set-ADDomain -Identity $id -Replace @{ 'ms-DS-MachineAccountQuota' = 0 } -ErrorAction Stop }.GetNewClosure()
        } else { Write-CpOk 'users cannot join computers to the domain' }
    } catch { Add-CpFinding server "ms-DS-MachineAccountQuota not checked ($($_.Exception.Message.Split("`n")[0]))" }
    try {
        $bad = Get-CpPre2000BadMembers -MemberDns @((Get-ADGroup -Identity 'S-1-5-32-554' -Properties member -ErrorAction Stop).member)
        foreach ($m in $bad) {
            $dn = $m
            Invoke-CpAction server "remove $(($dn -split ',')[0]) (Anonymous / Everyone) from 'Pre-Windows 2000 Compatible Access'" 'lets clients with no account read Active Directory' { Set-ADGroup -Identity 'S-1-5-32-554' -Remove @{ member = $dn } -ErrorAction Stop }.GetNewClosure()
        }
    } catch { Add-CpFinding server "Pre-Windows 2000 Compatible Access not checked ($($_.Exception.Message.Split("`n")[0]))" }
    try {
        $dsDn = "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE -ErrorAction Stop).configurationNamingContext)"
        $h = [string](Get-ADObject -Identity $dsDn -Properties dSHeuristics -ErrorAction Stop).dSHeuristics
        if (Test-CpAnonymousLdap $h) {
            $new = Get-CpFixedHeuristics $h
            Invoke-CpAction server "dSHeuristics $h -> $new (anonymous LDAP off)" 'anyone on the network can query the directory without logging in' { Set-ADObject -Identity $dsDn -Replace @{ dSHeuristics = $new } -ErrorAction Stop }.GetNewClosure()
        } else { Write-CpOk 'anonymous LDAP operations off' }
    } catch { Add-CpFinding server "dSHeuristics not checked ($($_.Exception.Message.Split("`n")[0]))" }
    try {
        foreach ($x in (Get-CpDcSyncFindings -Aces @((Get-Acl -Path "AD:\$id" -ErrorAction Stop).Access))) { Add-CpFinding server $x }
    } catch { Add-CpFinding server "domain ACL (DCSync rights) not checked ($($_.Exception.Message.Split("`n")[0])) - by hand: ADUC > Advanced Features > domain > Properties > Security" }
    Get-ADGroup -Filter 'ManagedBy -like "*"' -Properties ManagedBy -ErrorAction SilentlyContinue | ForEach-Object {
        Add-CpFinding server "AD group '$($_.Name)' is managed by $(($_.ManagedBy -split ',')[0] -replace '^CN=') - that account can change its members. ADUC > group > Managed By > Clear, unless the README says so"
    }
    Add-CpFinding server 'AD by hand: gpmc.msc > Default Domain Policy > Delegation (Authenticated Users must not be able to edit it); Account Policies > Kerberos Policy > Enforce user logon restrictions; ADUC: accounts with "Store password using reversible encryption" / odd logon scripts'
    foreach ($g in 'Enterprise Admins','Schema Admins','Administrators','Backup Operators','Account Operators','Server Operators','DnsAdmins','Group Policy Creator Owners') {
        $m = @(Get-ADGroupMember $g -ErrorAction SilentlyContinue | ForEach-Object SamAccountName)
        if ($m.Count) { Add-CpFinding server "AD group '$g': $($m -join ', ')  (check README)" }
    }
    $p = Get-ADDefaultDomainPasswordPolicy
    $ok = $p.MinPasswordLength -ge 10 -and $p.ComplexityEnabled -and $p.PasswordHistoryCount -ge 5 -and $p.MaxPasswordAge.Days -in 30..90 -and
          $p.MinPasswordAge.Days -ge 10 -and $p.LockoutThreshold -in 5..50 -and $p.LockoutDuration.TotalMinutes -ge 30 -and -not $p.ReversibleEncryptionEnabled
    if ($ok) { Write-CpOk 'domain password policy compliant' } else {
        $id = $dom.DistinguishedName
        Invoke-CpAction server 'set domain password + lockout policy (10 chars, complex, history 5, age 10-90d, lockout 5/30m)' 'domain policy overrides local policy on a DC' {
            Set-ADDefaultDomainPasswordPolicy -Identity $id -MinPasswordLength 10 -ComplexityEnabled $true -PasswordHistoryCount 5 `
                -MaxPasswordAge 90.00:00:00 -MinPasswordAge 10.00:00:00 -LockoutThreshold 5 -LockoutDuration 00:30:00 `
                -LockoutObservationWindow 00:30:00 -ReversibleEncryptionEnabled $false -ErrorAction Stop }.GetNewClosure()
    }
}

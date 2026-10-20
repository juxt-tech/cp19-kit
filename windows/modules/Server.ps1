# Server 2019/2022 extras: Active Directory users + domain password policy (domain controllers),
# and reports for roles, DNS, IIS and FTP. CP categories: User Auditing, Account Policies,
# Application Security Settings.

function Invoke-CpModServer {
    param($Config, [switch]$IsDC)
    Write-CpHeader 'SERVER  (roles, AD, DNS, IIS, FTP)'
    $roles = @(Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | ForEach-Object Name)
    Write-Host "  installed roles: $($roles -join ', ')"
    if ($IsDC) { Invoke-CpServerAD -Config $Config }
    if ($roles -contains 'DNS') {
        Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' } | ForEach-Object {
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

function Invoke-CpServerAD {
    param($Config)
    Import-Module ActiveDirectory -ErrorAction Stop
    $dom = Get-ADDomain
    $users  = @(Get-ADUser -Filter * -Properties PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, AllowReversiblePasswordEncryption)
    $das    = @(Get-ADGroupMember 'Domain Admins' -ErrorAction SilentlyContinue | Where-Object objectClass -eq 'user' | ForEach-Object SamAccountName)
    $plan = Get-CpUserPlan -Config $Config -CurrentUser $env:USERNAME -IsDC `
        -LocalUsers ($users | ForEach-Object SamAccountName) -Admins $das `
        -DisabledUsers ($users | Where-Object { -not $_.Enabled } | ForEach-Object SamAccountName) `
        -NoPasswordRequired ($users | Where-Object PasswordNotRequired | ForEach-Object SamAccountName) `
        -NeverExpires ($users | Where-Object PasswordNeverExpires | ForEach-Object SamAccountName)
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
        }
    }
    foreach ($u in $users) {
        if ($u.DoesNotRequirePreAuth) { $n = $u.SamAccountName; Invoke-CpAction server "require Kerberos pre-auth for $n" 'AS-REP roasting' { Set-ADAccountControl -Identity $n -DoesNotRequirePreAuth $false }.GetNewClosure() }
        if ($u.AllowReversiblePasswordEncryption) { $n = $u.SamAccountName; Invoke-CpAction server "no reversible encryption for $n" 'stores password recoverably' { Set-ADUser -Identity $n -AllowReversiblePasswordEncryption $false }.GetNewClosure() }
    }
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

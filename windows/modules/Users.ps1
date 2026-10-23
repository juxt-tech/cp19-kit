# Users module: accounts + Administrators membership match the README.
# CP category: User Auditing. Built-in Administrator/Guest are disabled, never deleted.
# The account running the script is never removed, demoted, disabled or re-passworded.

function Get-CpUserPlan {
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][string]$CurrentUser,
        [string[]]$LocalUsers = @(),
        [string[]]$Admins = @(),               # current members of Administrators (or Domain Admins)
        [string[]]$DisabledUsers = @(),
        [string[]]$NoPasswordRequired = @(),
        [string[]]$NeverExpires = @(),
        [switch]$IsDC
    )
    $builtin  = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount','defaultuser0','krbtgt')
    $listed   = @($Config.Admins) + @($Config.Users)
    $p = if ($IsDC) { @{ Remove='RemoveADUser'; Add='AddADUser'; Enable='EnableADUser'; AddA='AddDomainAdmin'; DelA='RemoveDomainAdmin' } }
         else       { @{ Remove='RemoveUser';   Add='AddUser';   Enable='EnableUser';   AddA='AddAdmin';       DelA='RemoveAdmin' } }
    $plan = New-Object System.Collections.Generic.List[object]
    $add  = { param($a, $n) $plan.Add([pscustomobject]@{ Action = $a; Name = $n }) }

    foreach ($u in $LocalUsers) {
        if ($u -ieq $CurrentUser -or $builtin -contains $u) { continue }
        if ($listed -notcontains $u) { & $add $p.Remove $u }
    }
    foreach ($u in $listed) {
        if ($u -ieq $CurrentUser) { continue }
        if ($LocalUsers -notcontains $u) { & $add $p.Add $u }
        elseif ($DisabledUsers -contains $u) { & $add $p.Enable $u }
    }
    foreach ($a in $Config.Admins) {
        if ($a -ieq $CurrentUser) { continue }
        if ($Admins -notcontains $a) { & $add $p.AddA $a }
    }
    foreach ($m in $Admins) {
        if ($m -ieq $CurrentUser -or $builtin -contains $m) { continue }
        if ($Config.Admins -notcontains $m) { & $add $p.DelA $m }
    }
    foreach ($b in 'Administrator','Guest') {
        if ($b -ieq $CurrentUser) { continue }
        if ($LocalUsers -contains $b -and $DisabledUsers -notcontains $b) { & $add 'DisableBuiltin' $b }
    }
    foreach ($u in $NoPasswordRequired) {
        if ($u -ine $CurrentUser -and $listed -contains $u) { & $add 'SetPassword' $u }
    }
    foreach ($u in $NeverExpires) {
        if ($u -ine $CurrentUser -and $listed -contains $u) { & $add 'PasswordNeverExpiresOff' $u }
    }
    return ,$plan.ToArray()
}

# ADSI fallback: works even when the group holds an orphaned SID (Get-LocalGroupMember then throws).
function Get-CpAdminMembersAdsi {
    $name = (Get-LocalGroup -SID 'S-1-5-32-544').Name
    $g = [ADSI]("WinNT://$env:COMPUTERNAME/$name,group")
    foreach ($m in @($g.Invoke('Members'))) {
        $path = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
        $cls  = $m.GetType().InvokeMember('Class',  'GetProperty', $null, $m, $null)
        if ($cls -eq 'User' -and $path -match "WinNT://([^/]+/)?$([regex]::Escape($env:COMPUTERNAME))/([^/]+)$") { $Matches[2] }
    }
}

function Get-CpAdminMembers {
    try {
        @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
            Where-Object { $_.PrincipalSource -eq 'Local' -and $_.ObjectClass -eq 'User' } |
            ForEach-Object { ($_.Name -split '\\')[-1] })
    } catch {
        Write-Host '  (Get-LocalGroupMember failed - orphaned SID in Administrators? using ADSI instead)' -ForegroundColor Yellow
        @(Get-CpAdminMembersAdsi)
    }
}

function Get-CpLocalUserState {
    $users = @(Get-LocalUser)
    $wmi   = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True')
    $admins = @(Get-CpAdminMembers)
    [pscustomobject]@{
        LocalUsers         = @($users | ForEach-Object Name)
        Admins             = $admins
        DisabledUsers      = @($users | Where-Object { -not $_.Enabled } | ForEach-Object Name)
        NoPasswordRequired = @($wmi | Where-Object { -not $_.PasswordRequired } | ForEach-Object Name)
        NeverExpires       = @($wmi | Where-Object { -not $_.PasswordExpires } | ForEach-Object Name)
    }
}

function Invoke-CpModUsers {
    param([Parameter(Mandatory)]$Config, [switch]$IsDC)
    Write-CpHeader 'USERS  (README authorized admins/users)'
    if ($Config.Admins.Count -eq 0) { Add-CpFinding users 'ADMINS is empty in the config - users module skipped'; return }
    if ($IsDC) { Write-Host '  Domain controller detected - use the Server module for AD users.'; return }
    $s = Get-CpLocalUserState
    Write-Host "  admins in config : $($Config.Admins -join ' ')"
    Write-Host "  users in config  : $($Config.Users -join ' ')"
    Write-Host "  local users      : $($s.LocalUsers -join ' ')"
    Write-Host "  Administrators   : $($s.Admins -join ' ')"
    $plan = Get-CpUserPlan -Config $Config -CurrentUser $env:USERNAME -LocalUsers $s.LocalUsers -Admins $s.Admins `
        -DisabledUsers $s.DisabledUsers -NoPasswordRequired $s.NoPasswordRequired -NeverExpires $s.NeverExpires
    if ($plan.Count -eq 0) { Write-CpOk 'accounts already match the README' }
    $pw = $null
    if ($Config.NewPassword) { $pw = ConvertTo-SecureString $Config.NewPassword -AsPlainText -Force }
    $adminGroup = (Get-LocalGroup -SID 'S-1-5-32-544').Name
    $userGroup  = (Get-LocalGroup -SID 'S-1-5-32-545').Name
    foreach ($a in $plan) {
        $n = $a.Name
        switch ($a.Action) {
            'RemoveUser'  { Invoke-CpAction users "delete user $n (profile folder kept)" 'not in README' { Remove-LocalUser -Name $n -ErrorAction Stop }.GetNewClosure() }
            'AddUser'     {
                if (-not $pw) { Add-CpFinding users "README user $n is missing but NEW_PASSWORD is empty - create by hand"; continue }
                Invoke-CpAction users "create user $n" 'listed in README but missing' { New-LocalUser -Name $n -Password $pw -ErrorAction Stop | Out-Null; Add-LocalGroupMember -Group $userGroup -Member $n -ErrorAction SilentlyContinue }.GetNewClosure() }
            'EnableUser'  { Invoke-CpAction users "enable user $n" 'authorized account is disabled' { Enable-LocalUser -Name $n -ErrorAction Stop }.GetNewClosure() }
            'AddAdmin'    { Invoke-CpAction users "add $n to Administrators" 'authorized admin' { Add-LocalGroupMember -Group $adminGroup -Member $n -ErrorAction Stop }.GetNewClosure() }
            'RemoveAdmin' { Invoke-CpAction users "remove $n from Administrators" 'not an authorized admin' { Remove-LocalGroupMember -Group $adminGroup -Member $n -ErrorAction Stop }.GetNewClosure() }
            'DisableBuiltin' { Invoke-CpAction users "disable built-in $n" 'built-in accounts are attack targets' { Disable-LocalUser -Name $n -ErrorAction Stop }.GetNewClosure() }
            'SetPassword' {
                if (-not $pw) { Add-CpFinding users "$n may have no password - set one by hand"; continue }
                Invoke-CpAction users "set password for $n + require one" 'account allowed to have no password' { Set-LocalUser -Name $n -Password $pw -ErrorAction Stop; & net.exe user $n /passwordreq:yes | Out-Null }.GetNewClosure() }
            'PasswordNeverExpiresOff' { Invoke-CpAction users "make $n's password expire" "'password never expires' is scored" { Set-LocalUser -Name $n -PasswordNeverExpires $false -ErrorAction Stop }.GetNewClosure() }
        }
    }
    # Report-only: other privileged local groups
    foreach ($sid in 'S-1-5-32-555','S-1-5-32-580','S-1-5-32-551','S-1-5-32-547') {
        $g = Get-LocalGroup -SID $sid -ErrorAction SilentlyContinue
        if (-not $g) { continue }
        $m = @(Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | ForEach-Object Name)
        if ($m.Count) { Add-CpFinding users "group '$($g.Name)' members: $($m -join ', ')  (check README)" }
    }
    $g = Get-LocalGroup -SID 'S-1-5-32-546' -ErrorAction SilentlyContinue   # Guests should hold only Guest
    if ($g) {
        $m = @(Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split '\\')[-1] } | Where-Object { $_ -ine 'Guest' })
        if ($m.Count) { Add-CpFinding users "group '$($g.Name)' has extra members: $($m -join ', ')  (only Guest belongs there)" }
    }
}

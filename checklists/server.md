# Windows Server 2019/2022 Checklist (CyberPatriot 19)

**Do everything in `windows.md` first.** It's the same kit; the menu adds a **Server** module automatically.
This file covers the extras. Format: `[ ] what — why — how to check`.

## 0. Is it a domain controller?
- [ ] `(Get-CimInstance Win32_OperatingSystem).ProductType` is **2** → it's a **DC** (the kit uses the same test and prints "(domain controller)" in its banner). The AD DS role being *installed* is not enough: the server must also be *promoted* (Server Manager shows no "Promote this server" flag, and `dsa.msc` opens a domain).
  - On a DC, accounts live in **Active Directory** (`dsa.msc`), not Local Users. The kit's Users/AccountPolicy modules step aside and the **Server** module does AD users + the domain password policy.
  - `krbtgt` is a system account: never touch it.

## 1. Forensics first (Server favourites)
- [ ] Which port does the backdoor listen on? `netstat -ano | findstr LISTEN` → PID → `Get-Process -Id PID | select Path`. (CP19 training image: `bd.exe`.)
- [ ] Path of an unwanted program? Search C:, or `Get-Process`. (CP19: GooseDesktop.)
- [ ] Share questions → `Get-SmbShare`, `Get-SmbShareAccess`.
- [ ] AD questions → `Get-ADUser name -Properties *`, `Get-ADGroupMember 'Domain Admins'`.

## 2. Server module (menu item "Server")
| Does | Why |
|---|---|
| AD users: delete non-README, create missing, enable authorized, fix **Domain Admins**, disable Guest | User Auditing |
| AD flags: require Kerberos pre-auth (no AS-REP roasting), no reversible encryption, password must expire, password required | Account Policies |
| Domain password policy: length 10, complex, history 5, age 10–90 days, lockout 5 / 30 min | Account Policies (on a DC the domain policy wins) |
| Lists Enterprise/Schema Admins, Backup/Account/Server Operators, DnsAdmins | privilege review |
| DNS: no zone transfers to any server; secure dynamic updates only | App Security Settings |
| IIS: lists sites; directory browsing off; flags FTP anonymous auth | App Security Settings |

## 3. Manual Server items
- [ ] **Remote Desktop:** many Server READMEs require it → `KEEP_RDP=yes` → the kit keeps it on with **NLA + TLS** (CP19 scored "RDP NLA enabled" **and** "Remote Desktop remains enabled").
- [ ] **Windows Defender missing?** Server Manager > Add Roles and Features > Features > Microsoft Defender Antivirus (old club review: "Windows Security was missing on Server").
- [ ] **Shares:** keep README-required shares (`KEEP_SHARES=`), remove the rest. The script never removes admin shares (`C$`, `ADMIN$`) or role shares (`NETLOGON`, `SYSVOL`, `CertEnroll`, `REMINST`, WSUS); it lists them in findings. Check NTFS + share permissions on the kept ones (no `Everyone: Full`).
- [ ] **IIS** (if critical): remove default/sample sites the README doesn't need, require SSL, turn on logging, turn off anonymous auth where not needed. Reference: CIS IIS 10 benchmark / OWASP IIS hardening.
- [ ] **FTP** (if critical): no anonymous logon, require SSL, logon attempt restrictions on.
- [ ] **DNS** (if critical): turn off recursion if it's authoritative-only; logging on.
- [ ] **Group Policy on a DC:** `gpmc.msc` > Default Domain Policy / Default Domain Controllers Policy carry the password, audit and user-rights settings. Edit them there; local policy is overridden.
- [ ] **Roles you don't need** (README doesn't mention them): Fax, Telnet Server, TFTP, SNMP, Print and Document Services → remove in Server Manager.
- [ ] **Updates:** `sconfig` option 6, or Settings > Windows Update.

## 4. Lose-points list (Server-specific)
- Removing a README-required **role** (DNS, IIS, AD DS, File Server).
- Deleting a README-required share, or the `NETLOGON`/`SYSVOL` shares on a DC.
- Disabling RDP when the README says remote admins use it.
- Demoting yourself from Domain Admins.

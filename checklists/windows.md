# Windows 10/11 Checklist (CyberPatriot 19)

> **Windows status:** the Windows/Server script passes 143 unit tests and was checked against four public practice-image answer keys (District 13, L'Équipe du Dictateur, Cincinnati Zoo, Princeton-Plainsboro), but has **never been run on a real CyberPatriot image**. Run AUDIT first, apply **one module at a time** with a snapshot before each, and refresh the score report after every module. If a module errors or the score drops, revert the snapshot and do that section by hand from this checklist.

**Order:** 0 Setup → 1 Forensics → 2 Audit → 3 Apply → 4 Findings → 5 Manual → 6 Don'ts. **Click a section to open it.** Snapshot before every numbered section.

<details>
<summary><b>0. Setup</b> (first 5 minutes): snapshot, README, config</summary>

- [ ] Take a VMware snapshot named `start`: it's your undo button for everything (VM > Snapshot > Take Snapshot).
- [ ] Read the **README twice**. Write down: authorized admins, authorized users, critical services, required software, anything "must stay". Removing a README thing **loses** points.
- [ ] Note your own username (top of the README or `whoami`). The kit never touches it, and you shouldn't either.
- [ ] Copy `config\cp-config.example.txt` to `cp-config.txt` and fill it in from the README. The script reads it to protect README items.
  - Critical services: use the **service name** (Remote Desktop = `TermService`, IIS = `W3SVC`, FTP = `FTPSVC`, SMB = `LanmanServer`, DNS = `DNS`). Nicknames `RDP FTP IIS SMB SSH print` also work. The banner prints `protected: X -> Y` for each one; a yellow **WARNING not found** means fix the config before `-Apply`.
  - README wants RDP? `KEEP_RDP=yes`. README names shares? `KEEP_SHARES=name1 name2`.
- [ ] Open the scoring report shortcut on the desktop. Keep it open; refresh after each section.

</details>

<details>
<summary><b>1. Forensics questions FIRST</b> (~5–10 points each): methods table inside</summary>

Answer **before** deleting anything: the evidence might be the file you'd delete.
- [ ] Open each `Forensics Question N.txt` on the Desktop. Type the answer after `ANSWER:` and save.

| Question about… | How |
|---|---|
| a file's hash | `Get-FileHash file -Algorithm MD5` / `SHA1` / `SHA256` |
| encoded text | base64: `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('...'))`; else CyberChef / dcode.fr cipher identifier |
| a share | `Get-SmbShare`, `Get-SmbShareAccess -Name X` |
| file permissions / SDDL | `(Get-Acl 'path').Sddl`, `icacls path` |
| who changed a password / made a user | Event Viewer > Security, IDs **4720** (user created), **4724** (password reset), **4732** (added to group). Enable auditing first if empty |
| a backdoor's port | `netstat -ano` then match the PID in Task Manager > Details |
| browser history | open the browser > History, or the user's profile folder |
| a program's location | `Get-Process name \| select Path`, or `where.exe name` |
| a hidden user / group detail | `net user name`, `Get-LocalUser name \| fl *` |

</details>

<details>
<summary><b>2. Run the kit in AUDIT mode</b> (changes nothing)</summary>

- [ ] PowerShell **as Administrator** in the kit folder:
  `powershell -ExecutionPolicy Bypass -File .\windows\harden.ps1 -All`
- [ ] Read the `[WOULD]` lines. Anything that would remove a README thing? Fix your config, then re-run the audit.

</details>

<details>
<summary><b>3. Apply, one module at a time</b>: what each of the 12 modules does</summary>

Run `harden.ps1 -Apply` and pick from the menu in this order. After each one, refresh the score report: **a score drop = undo** (revert the snapshot, or use the files in `C:\cpkit-runs\<time>\backup`).

| # | Module | What it does | Why it scores |
|---|---|---|---|
| 1 | Users | delete non-README users; create missing ones; enable disabled authorized ones; fix Administrators; disable Guest + built-in Administrator; "password never expires" off; lists other privileged groups and extra Guests members | User Auditing |
| 2 | AccountPolicy | length 10, complexity on, history 5, max age 90, min age 10, reversible off, lockout 5 / 30 min / reset 30 | Account Policies |
| 3 | AuditPolicy | every category Success + Failure | Local Policies |
| 4 | SecurityOptions | UAC on + secure desktop, no anonymous SAM/share enumeration, NTLMv2 only, no LM hash, SMB signing, CTRL+ALT+DEL, don't show last user, lock after 15 min idle, no shutdown from the logon screen; insecure guest logons off, SmartScreen = Warn, AutoPlay off, WDigest off, DEP for all programs (skipped if BitLocker is on); **reports** risky User Rights Assignment entries (incl. a plain user with *Log on as a service*) | Local Policies |
| 5 | Firewall | all 3 profiles on, block inbound, allow outbound, notify, no unicast response | Defensive Countermeasures |
| 6 | Defender | real-time, PUA, cloud on; **removes exclusions** (CP19 had a `.exe` exclusion); threat default actions "Allow / No action" → Quarantine; updates signatures; quick scan | Defensive Countermeasures |
| 7 | Services | disables RemoteRegistry, Telnet, SNMP, Simple TCP/IP (`simptcp`), FTP/IIS (unless critical), UPnP, Xbox, etc.; Windows Update automatic; DHCP Client, Event Log, Server, Firewall, BFE **automatic and running** | Service Auditing |
| 8 | Remote | RDP off (or ON + NLA + TLS + secure RPC, also as Group Policy, if `KEEP_RDP=yes`); Remote Assistance off | Uncategorized OS Settings |
| 9 | Shares | removes non-default shares (lists access first; never admin or role shares); SMBv1 off; SMB signing; SMB minimum 3.1.1 (Win11 24H2 / Server 2025 only) | Uncategorized OS Settings |
| 10 | Features | Telnet client, TFTP, SMB1, PowerShell v2 off | Uncategorized OS Settings |
| 11 | Updates | auto-update policy; reminds you (findings) to run Windows Update; lists apps to update | OS + App Updates |
| 12 | Software / Persistence / Media | **reports only** → `findings.txt` | Unwanted Software / Malware / Prohibited Files |

</details>

<details>
<summary><b>4. Work through findings.txt by hand</b>: software, backdoors, media, user rights</summary>

- [ ] **Unwanted software:** `appwiz.cpl`, uninstall each flagged program the README doesn't need (CCleaner, TeamViewer, AnyDesk, Wireshark, Nmap, games, torrent clients, "driver updaters", GooseDesktop, etc.). The score report shows "Removed X". *(Old checklists say to install CCleaner/IObit: CP now scores them as unwanted.)*
- [ ] **Backdoors:** suspicious listeners / `nc.exe` / `bd.exe` / odd services / Run keys / scheduled tasks. Kill the process, delete the binary, remove the Run key/task/service (`sc.exe delete name`). Malware.
- [ ] **Media + prohibited files:** delete media in user folders and odd `C:\` folders, plus files like `passwords.txt`. Lines marked `HIDDEN` were hidden with `attrib +h`; lines saying `plaintext credit card` / `SSN` are PII files (practice keys score these as "unencrypted records"). **Only after forensics.** Prohibited Files.
- [ ] **Hosts file** (`C:\Windows\System32\drivers\etc\hosts`): remove non-README entries. Malware/redirects.
- [ ] **IFEO debugger / sticky keys** (`sethc.exe` replaced): restore it. For an IFEO hijack, delete **both** the registry value and the file it points to (District 13: `powershell.exe` → `powrshell.exe`). Malware.
- [ ] **Other persistence lines:** `SilentProcessExit`, `AppInit_DLLs`, `WMI event consumer`, `suspicious Microsoft-folder task`, `driver ... loads from`. Remove what isn't from Windows or a README program. WMI: `Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer` / `__EventFilter` / `__FilterToConsumerBinding`, then `| Remove-CimInstance` on the bad ones. Malware.
- [ ] **User rights** (`userrights` lines): `secpol.msc` > Local Policies > User Rights Assignment, remove the named account/group from that right. Typical plants: a user in *Debug programs*, *Everyone* in *Take ownership*, Guest allowed to log on.

<details>
<summary>Safe User Rights values (and the ones NOT to copy from old checklists)</summary>

| Right | Should hold |
|---|---|
| Access Credential Manager as a trusted caller · Act as part of the OS · Create a token object · Enable delegation · Lock pages in memory | **No one** |
| Debug programs · Load/unload device drivers · Take ownership · Manage auditing and security log · Force shutdown from a remote system | Administrators |
| Back up / Restore files | Administrators (+ Backup Operators is the default) |
| Allow log on locally | Administrators, Users (**not Guest**) |
| Allow log on through Remote Desktop | Administrators, Remote Desktop Users |
| Deny access to this computer from the network · Deny log on locally | include **Guest** |

**Don't** set *Log on as a service* to "No one": services stop starting. **Don't** enable *Audit: shut down system immediately if unable to log security audits*: a full log blue-screens the box. Disabling IPv6 / NetBIOS / adapter bindings only if the README asks: it can break the score upload.
</details>

</details>

<details>
<summary><b>5. Manual-only items</b>: browsers, Windows Update, passwords, lock screen</summary>

- [ ] **Browsers** (Firefox/Chrome/Edge): update; turn on pop-up blocker, safe browsing / phishing protection ("Block dangerous and deceptive content"), HTTPS-Only Mode, automatic updates, and "Do Not Track"; turn off saving passwords and Firefox Accounts; remove suspicious extensions and homepage hijacks. App Security Settings.
- [ ] **Folder permissions** the README mentions (e.g. "X must not write to the Memes folder"): folder > Properties > Security > Advanced, remove the user's Write/Modify. Check `icacls folder` afterwards.
- [ ] **Remote Desktop Users / Remote Management Users:** the Users module lists their members in findings. Remove anyone the README doesn't name (`Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member name`).
- [ ] **Attack Surface Reduction** (if Office is installed): practice keys scored "Block Win32 API calls from Office macros": `Add-MpPreference -AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions Enabled`.
- [ ] **UAC "Only elevate executables that are signed and validated"**: scored on one practice image, but it blocks unsigned installers. Turn it on last (secpol.msc > Security Options), and only if nothing you still need to install is unsigned.
- [ ] **Update the apps the README mentions** (Firefox, Chrome, Notepad++, 7-Zip, VLC…) to the latest version. App Updates.
- [ ] **Windows Update:** Settings > Windows Update > Check for updates; let it install. OS Updates (often several points).
- [ ] **User passwords:** set a strong password for any README user with a weak or blank one: `net user name NewP@ss2026!`. Never change your own unless the README says to.
- [ ] **Screen saver / lock:** require a password on resume, timeout ≤ 15 min (Settings > Personalization > Lock screen). Uncategorized.
- [ ] **AutoPlay off:** the SecurityOptions module sets the policy; also flip Settings > Bluetooth & devices > AutoPlay > off. Uncategorized.
- [ ] **Critical service settings** the README describes (e.g. IIS, FTP, a database): secure their own configs. App Security Settings.
- [ ] **BitLocker:** only if the README asks.

</details>

<details>
<summary><b>6. Things that LOSE points</b> (read once before you start)</summary>

- Removing or demoting a README user or admin, or deleting the user you're logged in as.
- Stopping or uninstalling a README-required service or program (RDP, FTP, IIS, a game the README says is approved…).
- Deleting forensics evidence before answering the question.
- Breaking networking (disabling the DNS Client, DHCP, or the network adapter) → the score can't upload. Also leave the adapter's DNS server setting alone (District 13 penalty: "It's always DNS").
- Uninstalling a tool the README uses (District 13 penalized removing Wireshark and Notepad++). Put README tools in `ALLOWED_SOFTWARE` so the kit doesn't flag them.
- Deleting or disabling a **service account** a README site or database uses (e.g. an IIS app-pool / SQL login account), or stopping its IIS site / app pool.
- Touching anything named CyberPatriot / scoring.
- If the score drops: **revert to your last snapshot**, re-do the steps since then, and skip the one that hurt.

</details>

# Windows 10/11 Checklist (CyberPatriot 19)

Format: `[ ] what — why — how to check`. Work top to bottom. **Snapshot before every numbered section.**
Scored categories (official): User Auditing · Account Policies · Local Policies · Defensive Countermeasures · Service Auditing · OS Updates · App Updates · App Security Settings · Unwanted Software · Prohibited Files · Malware · Uncategorized OS Settings · Forensics.

---

## 0. Setup (first 5 minutes)
- [ ] Take a VMware snapshot named `start` — it's your undo button for everything — VM > Snapshot > Take Snapshot
- [ ] Read the **README twice**. Write down: authorized admins, authorized users, critical services, required software, anything "must stay". — Removing a README thing **loses** points.
- [ ] Note your own username (top of the README or `whoami`). — The kit never touches it, but you shouldn't either.
- [ ] Copy `config\cp-config.example.txt` to `cp-config.txt` and fill it in from the README. — The script reads it to protect README items.
  - Critical services: use the **service name** (Remote Desktop = `TermService`, IIS = `W3SVC`, FTP = `FTPSVC`, SMB = `LanmanServer`, DNS = `DNS`). Nicknames `RDP FTP IIS SMB SSH print` also work. The script's banner prints `protected: X -> Y` for each one; a yellow **WARNING not found** means fix the config before `-Apply`.
  - README wants RDP? `KEEP_RDP=yes`. README names shares? `KEEP_SHARES=name1 name2`.
- [ ] Open the scoring report shortcut on the desktop. Keep it open; refresh after each section.

## 1. Forensics questions FIRST
Each is worth ~5–10 points. Answer **before** deleting anything (the evidence might be the file you'd delete).
- [ ] Open each `Forensics Question N.txt` on the Desktop. Type the answer after `ANSWER:` and save.
- Methods that come up again and again:
  | Question about… | How |
  |---|---|
  | a file's hash | `Get-FileHash file -Algorithm MD5` / `SHA1` / `SHA256` |
  | encoded text | base64: `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('...'))`; else CyberChef / dcode.fr cipher identifier |
  | a share | `Get-SmbShare`, `Get-SmbShareAccess -Name X` |
  | file permissions / SDDL | `(Get-Acl 'path').Sddl`, `icacls path` |
  | who changed a password / made a user | Event Viewer > Security, IDs **4720** (user created), **4724** (password reset), **4732** (added to group) — enable auditing first if empty |
  | a backdoor's port | `netstat -ano` then match the PID in Task Manager > Details |
  | browser history | open the browser > History, or the user's profile folder |
  | a program's location | `Get-Process name | select Path`, or `where.exe name` |
  | a hidden user / group detail | `net user name`, `Get-LocalUser name | fl *` |

## 2. Run the kit in AUDIT mode (changes nothing)
- [ ] PowerShell **as Administrator** in the kit folder:
  `powershell -ExecutionPolicy Bypass -File .\windows\harden.ps1 -All`
- [ ] Read the `[WOULD]` lines. Anything that would remove a README thing? Fix your config, then re-run the audit.

## 3. Apply, one module at a time (snapshot between)
Run `harden.ps1 -Apply` and pick from the menu in this order. After each one, refresh the score report: **a score drop = undo** (revert the snapshot, or use the files in `C:\cpkit-runs\<time>\backup`).

| # | Module | What it does | Why it scores |
|---|---|---|---|
| 1 | Users | delete non-README users; create missing ones; enable disabled authorized ones; fix Administrators; disable Guest + built-in Administrator; "password never expires" off | User Auditing |
| 2 | AccountPolicy | length 10, complexity on, history 5, max age 90, min age 10, reversible off, lockout 5 / 30 min / reset 30 | Account Policies |
| 3 | AuditPolicy | every category Success + Failure | Local Policies |
| 4 | SecurityOptions | UAC on + secure desktop, no anonymous SAM/share enumeration, NTLMv2 only, no LM hash, SMB signing, CTRL+ALT+DEL, don't show last user | Local Policies |
| 5 | Firewall | all 3 profiles on, block inbound, allow outbound, notify, no unicast response | Defensive Countermeasures |
| 6 | Defender | real-time, PUA, cloud on; **removes exclusions** (CP19 had a `.exe` exclusion); updates signatures; quick scan | Defensive Countermeasures |
| 7 | Services | disables RemoteRegistry, Telnet, SNMP, Simple TCP/IP (`simptcp`), FTP/IIS (unless critical), UPnP, Xbox, etc.; Windows Update automatic | Service Auditing |
| 8 | Remote | RDP off (or ON + NLA + TLS if `KEEP_RDP=yes`); Remote Assistance off | Uncategorized OS Settings |
| 9 | Shares | removes non-default shares (lists access first); SMBv1 off; SMB signing | Uncategorized OS Settings |
| 10 | Features | Telnet client, TFTP, SMB1, PowerShell v2 off | Uncategorized OS Settings |
| 11 | Updates | auto-update policy; reminds you (findings) to run Windows Update; lists apps to update | OS + App Updates |
| 12 | Software / Persistence / Media | **reports only** → `findings.txt` | Unwanted Software / Malware / Prohibited Files |

## 4. Work through findings.txt by hand
- [ ] **Unwanted software:** `appwiz.cpl`, uninstall each flagged program the README doesn't need (CCleaner, TeamViewer, AnyDesk, Wireshark, Nmap, games, torrent clients, "driver updaters", GooseDesktop, etc.). — Policy Violation: Unwanted Software. — The score report shows "Removed X".
- [ ] **Backdoors:** suspicious listeners / `nc.exe` / `bd.exe` / odd services / Run keys / scheduled tasks. Kill the process, delete the binary, remove the Run key/task/service (`sc.exe delete name`). — Malware.
- [ ] **Media + prohibited files:** delete media in user folders and odd `C:\` folders, plus files like `passwords.txt`. **Only after forensics.** — Prohibited Files.
- [ ] **Hosts file** (`C:\Windows\System32\drivers\etc\hosts`): remove non-README entries. — Malware/redirects.
- [ ] **IFEO debugger / sticky keys** (`sethc.exe` replaced): restore it. — Malware.

## 5. Manual-only items (the script can't do these)
- [ ] **Browsers** (Firefox/Chrome/Edge): update; turn on pop-up blocker, safe browsing / phishing protection, and "Do Not Track"; turn off saving passwords; remove suspicious extensions and homepage hijacks. — App Security Settings.
- [ ] **Update the apps the README mentions** (Firefox, Chrome, Notepad++, 7-Zip, VLC…) to the latest version. — App Updates.
- [ ] **Windows Update:** Settings > Windows Update > Check for updates; let it install. — OS Updates (often several points).
- [ ] **User passwords:** set a strong password for any README user with a weak or blank one: `net user name NewP@ss2026!`. Never change your own unless the README says to.
- [ ] **Screen saver / lock:** require a password on resume, timeout ≤ 15 min (Settings > Personalization > Lock screen). — Uncategorized.
- [ ] **AutoPlay off:** Settings > Bluetooth & devices > AutoPlay > off. — Uncategorized.
- [ ] **Critical service settings** the README describes (e.g. IIS, FTP, a database): secure their own configs. — App Security Settings.
- [ ] **BitLocker:** only if the README asks.

## 6. Things that LOSE points (penalties)
- Removing or demoting a README user or admin, or deleting the user you're logged in as.
- Stopping or uninstalling a README-required service or program (RDP, FTP, IIS, a game the README says is approved…).
- Deleting forensics evidence before answering the question.
- Breaking networking (disabling the DNS Client, DHCP, or the network adapter) → the score can't upload.
- Touching anything named CyberPatriot / scoring.
- If the score drops: **revert to your last snapshot**, re-do the steps since then, and skip the one that hurt.

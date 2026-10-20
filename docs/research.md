# Research Notes — 2026-10-19

These are the sources behind the design. Each entry says what we took from the source. **Reference only: no code is copied.**

## 1. Club sources (CyberPatriot Discord + Drive)
| Source | What it gives us |
|---|---|
| Win10 practice-image vuln sheet (Google Sheet `1069LX…`) | **Exact scored value ranges**: lockout duration 30–60, lockout threshold 5–50, reset counter 30–60, password history 5–10, min age 10–30, max age 30–90, min length 8–14, complexity on, reversible encryption off. All 9 audit categories = Success+Failure. Security options list (see §4). Firewall: all 3 profiles on, inbound block, outbound allow, notify yes, unicast response no. Services disabled: Remote Registry, SNMP Trap, Telephony, Net.Tcp Port Sharing, RasMan, RPC Locator. Windows Update must stay Automatic+Running. Telnet Client feature off. Startup item `nc`. Stop sharing `C:\`. |
| Santa's Workshop answer key (PDF) | User module must also **create missing authorized users** (Cupid) and **re-enable disabled authorized admins** (Santa), not just delete. Forensics use `Get-SmbShare`/`Get-SmbShareAccess`/`Get-Acl` (SDDL). Media in odd folders like `C:\Universal Truths`. |
| SysHardening 6 writeup (Linux) | Scored items: SSH config owned by root, PermitRootLogin no, PermitEmptyPasswords no, Protocol 2; nginx server_tokens off plus app misconfigs; app config driven by the README (minecraft); malicious user-creation script; ASLR `kernel.randomize_va_space=2`; `tcp_syncookies=1`; PAM failed-login lockout; pwnkit exploit file. Lesson: **app-specific vulns are README-driven and manual** → checklist, not script. |
| Club round-review slides (CPXV–CPXVII) | Win: event log 4724, Process Hacker for forensics, `lusrmgr.msc`, netcat backdoors (check netstat/Task Manager), npcap port lookup, missing Windows Security feature on Server. Linux: `/etc/ftpusers`, `icmp_echo_ignore_broadcasts`, `/etc/shadow` perms 640, SMTP purge, `sources.list` uncomment, `tree` for MP3s, `dpkg -l` for hacking tools, vsftpd encryption/no-anon, sshd hardening, reset Chromium settings. |
| CP vulnerability categories (official PDF, CP-XIII) | The 13 scoring categories. **Checklists are organised by these.** |
| CP19 practice round | Images: Windows 11, Server 2022, Mint 21. Packet Tracer in a VM. |

## 2. CP19 round targets (from Ripper1004's README, plausible, unverified)
- Round 1: **Windows 11/10, Linux Mint 21**
- Round 2: **Server 2022, Debian 12**
- → The Linux script must support **Mint 21 + Debian 12** (Ubuntu 22/24 as a bonus).

## 3. CP19 Server 2022 training image (from jxv133's read-only checker)
Scored checks: unauthorized users/admins removed; insecure password changed; min password length; audit account logon [Failure]; lockout threshold set; **Defender must not exclude `.exe`**; unauthorized shares off + required share kept; critical files present; **Simple TCP/IP Services** stopped+disabled; Windows updates; **Chrome + Notepad++ updated**; GooseDesktop, CCleaner and netcat `bd.exe` removed (**answer forensics first: bd.exe listening port, GooseDesktop path**); **RDP stays enabled + NLA on**; SMB1 disabled.

## 4. Public repos reviewed (≥3 per OS)
| Repo | OS | License | Ideas taken (no code copied) |
|---|---|---|---|
| WhereIsXuezugi/CPLHF | Linux | MIT | lib/ module split; `--dry-run`; idempotent modules; SSH password auth default ON; dual-use tools (nmap/wireshark/netcat) confirm-before-purge; never touch unknown packages (could be the scoring agent); no GRUB password; outbound firewall allow-all; listening-port baseline before hardening. |
| ninayxx/mint21_script | Mint 21 | none | critical-services whitelist asked first; **default-package manifest for Mint 21** to spot added packages; sysctl set. |
| maytees/cypat-ubuntu-script | Ubuntu | none | lightdm guest off; prompt-driven flow. |
| BiermanM/CyberPatriot-Scripts | Ubuntu/Debian | none | coverage list (old, 2016): ufw, login.defs, pam, cron, UID-0 check, hacking-tool purge list. |
| tinkerrc/cypalinux | Linux | none | per-task small scripts; logging. |
| Ripper1004/CyberPatriot-Toolkit | All | **none (all rights reserved)** | Closest to our design: audit/apply modes, README config, backups, findings to-do report, **container test harness that plants ~30 vulns**. Reference for structure and test idea only. |
| xFaraday/EzScript | Windows | none | menu-driven; netstat summary; features list. **Anti-pattern:** sets every user's password to the same string, renames accounts. |
| AwSkies/CPWindowsScripts | Win10/Server | none | secedit `.inf` templates; service lists. |
| ProgrammerManan/CyberPatriot-Scripts | Win11/Server | none | CIS-section-numbered modules; AD hardening; SMBv1; Defender settings. |
| frxyoz/windowssecurer | Windows | none | Defender, audit policy, RDP, features. |
| jxv133-sys/server2022-checker | Server 2022 | none | **read-only self-check** idea; capture forensics evidence first; secedit-export parsing. |
| DavidBootle/Server2016Scripts | Server | none | server features/roles. |

### Patterns to avoid (seen in repos)
- Blanket password reset for every user, including the competitor's own account → lockout. We only set passwords for listed users and never touch the current user.
- Auto-deleting media files or hacking tools → destroys forensics evidence and authorized files.
- Disabling every service not on an allow-list → breaks critical services and the scoring client.
- Auto-reboot mid-script.
- Strict firewall outbound rules → can block the scoring engine.

## 5. Testing capability on Sanh's PC
- Docker 29 + WSL Ubuntu → **Linux script tested in Mint 21 / Debian 12 / Ubuntu containers with planted vulns** (built by us).
- PowerShell 5.1 → parse check + run **audit mode** (read-only) on a Windows VM. Apply mode only on a VM with a snapshot, never on the host.
- VMware `vmrun` present → can drive a practice-image VM later.
- shellcheck / PSScriptAnalyzer not installed (can be added: shellcheck via Docker, PSScriptAnalyzer via PSGallery).

## 6. Still unread / unavailable
- Club "CyberPatriot Notes" Google Doc (2020): not public (export returned a login page).
- Discord CDN attachments (CIS PDFs, `daniel_plaza` Windows hardening PDF): expiring links. Public CIS benchmarks are used instead.
- Dudcom/TroyHS and 0x000NULL/CSSR zips failed to download. Optional; the coverage above is enough.
- Cisco question bank (60 KB) and the 2025 Cisco NetAcad supplement doc are downloaded, for the Cisco playbook phase.

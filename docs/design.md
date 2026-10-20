# CyberPatriot Hardening Kit — Design

Status: DRAFT, awaiting Sanh's approval · 2026-10-19

## Intent / why
Sanh's school team (CyberPatriot 19, team st-6, Gold tier) wants repeatable, safe hardening for every OS, plus a Cisco playbook.
- Sanh competes on **Cisco**. **Teammates** run the OS scripts.
- **No AI help is allowed during scored rounds.** Everything must be usable cold by a teammate who didn't write it.
- Sanh also wants to **learn from it**. Every step must say *why*, not just *what*.
- First scored round: **Round 1, Oct 22–25, 2026**. Round 2: Nov 12–15.

## Goals
1. One script per OS family, organised as a **menu of independent modules**.
   - Each module runs **audit first** (shows what it would change, changes nothing) → asks → applies → logs.
2. A **README-driven config file**. The teammate fills in authorized users/admins, critical services and allowed software from the round README. The script never deletes or disables anything on those lists.
3. **Checkpoints:**
   - The checklist says "VMware snapshot before each module".
   - The script keeps a change log plus backups of every file it edits, so a single module can be undone by hand.
4. A **checklist per OS**, ordered: README → forensics → quick wins → script modules → manual-only items.
   - Each item has a one-line "why", plus how to verify it on the score report.
5. A **Cisco playbook**: checklist plus copy-paste config blocks, built for solo use in the Packet Tracer VM.
6. Delivered in a **public GitHub repo** with a one-line download per OS.

## Non-goals
- One-click "run everything" mode. Rejected: it breaks critical services and teaches nothing.
- Forensics automation. Answers depend on the image, so the checklist gives methods only.
- Scripts for Cisco. Packet Tracer runs inside a locked VM; nothing can execute there.
- Exploit or attack tooling of any kind.

## Anti-goals (failure even if it "works")
- Destroys forensic evidence: deletes media files or users before the forensics questions are answered.
- Removes an authorized user or disables a README-critical service, which loses points.
- Locks the team out: wrong password change, firewall blocking the scoring engine, SSH lockout.
- Touches the CyberPatriot scoring client or files. That's tampering and means disqualification.
- Copy-pasted code from other teams' repos. Ideas only; the code is written fresh.

## Targets
| Script | OS (CP-19 practice round evidence) | Fallback |
|---|---|---|
| `windows/harden.ps1` | Windows 11 | Windows 10 |
| `windows/harden.ps1` + `-Server` module | Server 2022 | Server 2019 |
| `linux/harden.sh` | Linux Mint 21 | Ubuntu 22/24, Debian 12 |
| `cisco/` (docs only) | Packet Tracer 8.x in the CP testing VM | — |

## Module list (draft — final list after source research)
**Windows (PowerShell 5.1, run as Admin)**
- users: remove unauthorized users and admins, fix group membership, disable Guest/Administrator, set passwords for listed users
- password/lockout policy
- audit policy
- security options: export via `secedit`, edit, re-import, with a backup .inf
- firewall
- services: disable a known-bad list minus the critical list
- Windows Defender on, updates
- shares
- RDP / remote assistance, following the README
- unwanted software report (the teammate decides what to uninstall)
- prohibited media files report (report only — forensics may need them)
- scheduled tasks / startup / hosts file report
- `-Server` only: AD users/groups, DNS, IIS, SMB settings

**Linux (bash, run with sudo)**
- users/sudo/groups, UID-0 check, empty passwords
- password policy: `login.defs`, `pam_pwquality`, faillock
- ufw
- sshd hardening (only if SSH is critical, otherwise report)
- services: report + disable non-critical
- apt sources + updates
- hacking tools / prohibited packages report
- media files report
- file permissions (`/etc/shadow`, `/etc/passwd`, etc.)
- sysctl network hardening
- cron/systemd timers/rc.local report
- critical-service configs (vsftpd, apache, samba, etc.), driven by the README

## Safety rules (apply to every module)
- `-Audit` / `--audit` is the default. Applying needs an explicit flag or a y/N prompt.
- Back up every edited file to `cpkit-backup/<timestamp>/` before editing.
- Never touch: the CyberPatriot folder/service, the scoring client, or anything in the config's critical lists.
- Never delete files. Media and tools are only *reported* (the teammate removes them by hand after forensics).
- Every action goes to `cpkit-log.txt` with what, before → after, and why.

## Sources
- Club: 29 slide decks (2022–2026), Windows answer-key sheet, Linux SysHardening-6 writeup, CIS PDFs posted in Discord. Some Discord channels (#windows, #linux, #resources-dump) haven't been read yet.
- Public repos: ≥3 per OS, reference only. A credits list in the repo says which idea came from where.
- CIS benchmarks for Win11, Server 2022 and Ubuntu 22, for the checklist "why" lines.

## Verification
- Static: `bash -n` + shellcheck, PowerShell parser + PSScriptAnalyzer. Run here.
- Real: Sanh or teammates run each module in audit mode, then apply mode, on CP-19 practice images or club practice images in VMware, with snapshots, and report anything that breaks.

## Builder's calls (Claude's, not agreed)
- PowerShell 5.1 (built into every image) and bash. No Python dependency.
- Repo at `C:\Users\dkgo1\cyberpatriot-kit`, its own git repo, pushed to a new public GitHub repo once Sanh approves.
- Config file format: simple `KEY=value` / one-item-per-line text, so teammates can edit it in Notepad or nano.
- Priority if time runs short before Round 1: Windows → Linux → Server module → Cisco playbook. Sanh's Cisco cheat sheet already exists as a stopgap.

## Open questions for Sanh
- None blocking. GitHub repo name and visibility get confirmed at push time.

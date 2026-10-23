# CyberPatriot Hardening Kit

Audit-first, README-driven hardening scripts and checklists for CyberPatriot 19.

> **Windows status:** the Windows/Server script passes 86 unit tests but has **never been run on a real CyberPatriot image**. Run AUDIT first, apply **one module at a time** with a snapshot before each, and refresh the score report after every module. If a module errors or the score drops, revert the snapshot and do that section by hand from the checklist.

| OS | Script | Checklist |
|---|---|---|
| Windows 10 / 11 | `windows/harden.ps1` | [checklists/windows.md](checklists/windows.md) |
| Windows Server 2019 / 2022 | `windows/harden.ps1` (adds a Server module automatically) | [checklists/server.md](checklists/server.md) |
| Linux Mint 21 / Debian 12 / Ubuntu 22-24 | `linux/harden.sh` | [checklists/linux.md](checklists/linux.md) |
| Cisco Packet Tracer + NetAcad quiz | (no script, it runs in a locked VM) | [checklists/cisco.md](checklists/cisco.md) + `cisco/templates/` |

## The rules (read before your first round)
1. **Forensics questions first.** The scripts never delete files, but you might, and the evidence could be the file.
2. **Fill `cp-config.txt` from the round README.** Admins, users, critical services, allowed software. Anything listed there is never removed, disabled or demoted. Neither is the account you're logged in as, nor the CyberPatriot scoring client.
3. **Audit is the default.** Without `--apply` / `-Apply`, nothing changes; you get a list of `[WOULD]` lines.
4. **Apply one module at a time and take a VMware snapshot between them.** Every change asks y/N, is logged to `log.txt`, and the original file is copied to `backup/`.
5. **Media, unwanted programs and backdoors are only reported** (`findings.txt`). You remove them by hand after forensics.

## Quick start

### Windows (PowerShell as Administrator)
```powershell
cd $env:USERPROFILE\Desktop
iwr https://github.com/juxt-tech/cp19-kit/archive/refs/heads/main.zip -OutFile kit.zip; Expand-Archive kit.zip .; cd cp19-kit-main
copy config\cp-config.example.txt cp-config.txt; notepad cp-config.txt          # fill from the README
powershell -ExecutionPolicy Bypass -File .\windows\harden.ps1 -All              # AUDIT: read the [WOULD] lines
powershell -ExecutionPolicy Bypass -File .\windows\harden.ps1 -Apply            # menu, one module at a time
```
Run folder: `C:\cpkit-runs\<time>\` (log.txt, findings.txt, backup\, listening.txt, installed-programs.txt)

### Linux
```bash
wget -qO- https://github.com/juxt-tech/cp19-kit/archive/refs/heads/main.tar.gz | tar xz && cd cp19-kit-main
cp config/cp-config.example.txt cp-config.txt && nano cp-config.txt             # fill from the README
sudo bash linux/harden.sh --all                                                  # AUDIT
sudo bash linux/harden.sh --apply                                                # menu, one module at a time
```
Run folder: `/root/cpkit-runs/<time>/`

## Modules
**Linux:** users · passwords · firewall · ssh · sysctl · perms · services · software · updates · persistence (report) · media (report)
**Windows:** Users · AccountPolicy · AuditPolicy · SecurityOptions · Firewall · Defender · Services · Remote · Shares · Features · Updates · Software (report) · Persistence (report) · Media (report) · Server (Server only: AD, DNS, IIS)

## Undo
- Best: revert to your last VMware snapshot.
- One file: copy it back from the run's `backup/` folder (the same path inside).
- Windows policy: `backup\secpol-before.inf` → `secedit /configure /db x.sdb /cfg secpol-before.inf`; audit policy: `auditpol /restore /file:backup\auditpol.csv`; registry: double-click the `.reg` in `backup\registry`.

## Tests
- Linux: `bash linux/tests/run-tests.sh` builds a vulnerable Mint 21, Debian 12 and Ubuntu 22.04 container. It checks that audit changes nothing, that apply fixes every planted vuln (36 checks), that README users/services survive, and that a second run changes nothing.
- Linux services under a real systemd: `bash linux/tests/systemd-test.sh` (service + socket + path units disabled, README services kept).
- Windows: `Invoke-Pester .\windows\tests` (Pester 3.4, built into Windows) runs 99 unit tests of the decision logic.

## Credits (ideas only, no code copied)
Club slide decks and answer keys (CyberPatriot Discord), the CP vulnerability-category guide, and these public projects for ideas and structure: WhereIsXuezugi/CPLHF (MIT), Ripper1004/CyberPatriot-Toolkit, ninayxx/mint21_script, maytees/cypat-ubuntu-script, BiermanM/CyberPatriot-Scripts, tinkerrc/cypalinux, xFaraday/EzScript, AwSkies/CPWindowsScripts, ProgrammerManan/CyberPatriot-Scripts, frxyoz/windowssecurer, jxv133-sys/cyberpatriot-server2022-checker, DavidBootle/Server2016Scripts, ponkio/CyberPatriot. See [docs/research.md](docs/research.md).

> Scripts must not be run during a scored round in a way that breaks CyberPatriot rules. AI help is not allowed during scored rounds. Everything here was prepared beforehand.

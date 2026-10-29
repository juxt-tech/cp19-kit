# Improvement Backlog

The improve/debug loop takes the **first unchecked item** each iteration:
write a failing test → fix → run every suite → commit → push → tick it here.
When the list is empty, the loop runs a discovery pass (shellcheck, PSScriptAnalyzer, systemd test) to find new items. If discovery finds nothing, the loop stops.

## Bugs / correctness (from the final review)
- [x] Linux updates: Debian 12 uses deb822 `/etc/apt/sources.list.d/debian.sources` and Mint uses `official-package-repositories.list`. Commented/disabled sources there aren't fixed or flagged. **Done:** *.list + deb822 handled; only official mirrors re-enabled (unit 80/80, matrix 32/32 x3).
- [x] Linux ordering: passwords/firewall install packages (libpam-pwquality, ufw) BEFORE the updates module re-enables disabled sources, so those installs fail on an image with broken sources. **Done:** new `sources` module (2nd in order) re-enables + apt-get update; matrix plants broken sources (RED: no ufw/pwquality → GREEN 34/34 x3). Also added a CRLF guard test.
- [x] Windows: non-terminating errors and native exit codes are logged as `ACTION done`. **Done:** Invoke-CpAction captures error records + checks LASTEXITCODE (Pester 67/67).
- [x] Config parsing (both OSes): a `#` inside NEW_PASSWORD truncates it; an apostrophe breaks `xargs` (Linux); a UTF-8 BOM breaks the first key. **Done:** whole-line comments only; password kept verbatim; BOM stripped (unit 85/85, Pester 70/70).
- [x] Windows: check README-critical service names exist BEFORE the disable step (Linux already does). A wrong name (`FTP` instead of `FTPSVC`) means the real service gets disabled = lost points. **Done:** `Resolve-CpCriticalServices` runs before any module (name, nickname, display name); missing names = yellow warning + finding; RDP critical implies KEEP_RDP (Pester 86/86).
- [x] Linux passwords: a `pam-auth-update` refusal (local modifications) is still logged as done; `remember=0` counts as ok. **Done:** refusal reproduced in Ubuntu 22.04 (exit 0, no faillock); now verified after the call -> FAILED + finding; remember < 5 raised to 5 (unit 93/93, matrix plants remember=0).
- [x] Windows: the Updates/Defender-signature steps always log ACTION, so a second apply never shows 0 changes. **Done:** Defender update/scan only when ≥1 day stale; Windows Update → findings reminder (Pester 73/73).
- [x] Windows shares: skip `Special` shares and role shares (CertEnroll, REMINST, WSUS*, `*$` admin shares). **Done:** `Get-CpSharePlan`; role shares kept + listed in findings; a non-special `Hidden$` share is still removed (Pester 86/86).
- [x] Linux media: exclude the kit's own run dir (`/root/cpkit-runs`) from the media/archive report. **Done:** `media_not_kit` drops run dirs + the kit download (only when named cp19-kit*), unit 95/95.
- [x] server.md: "AD-DS installed" doesn't mean it's a DC; say "ProductType 2 / Server Manager shows AD DS as a role and the box is promoted". **Done:** ProductType 2 test (same as the kit) + promoted check.

## Test coverage
- [x] Linux services module under real systemd: run the scenario in a systemd-enabled container (cups/avahi/vsftpd units, socket activation). **Done:** `linux/tests/systemd-test.sh` (systemd PID 1): cups/avahi service+socket+path disabled and stopped, README `ftp` keeps vsftpd, second run 0 changes (15/15).
- [x] shellcheck every `.sh` (docker `koalaman/shellcheck`); fix real warnings. **Done:** clean at warning level; `.shellcheckrc` documents the cross-file false positives; fixed `ls | grep` in persistence. Found + fixed a real bug: creating a README user ran `sh -c "... echo '$u:$PASS'"`, so a `'` in NEW_PASSWORD broke it (and was shell injection) -> `_add_user` with printf (unit test).
- [x] PSScriptAnalyzer every `.ps1`/`.psm1`; fix real warnings. **Done (in a pwsh container, host untouched):** errors are by design (plaintext config password -> SecureString); fixed dead `$wl` and a null comparison. Rest = style (Write-Host is the UI).
- [ ] Windows end-to-end: audit, then apply, on a Win11 / Server 2022 practice VM. **Needs Sanh** (VM + snapshot); the loop skips it and leaves it here.

## Practice-image answer keys (2026-10-29, docs/research.md section 7)
- [x] **Penalty fix:** Users/Server deleted every non-README account, including service accounts (District 13: `svc_iis_caseportal` -5). **Done:** accounts used by a service, IIS app pool, SPN, or named `svc_*`/`sql_*`/`*_svc` are kept + reported, never deleted or demoted (scheduled-task users not counted: backdoor tasks run as the hacker).
- [x] Services: DHCP Client, Server (LanmanServer) must be Automatic; DHCP/Event Log/Server/Firewall/BFE/Defender must also be *running* (an "Automatic but stopped" plant was missed). wuauserv excluded from the running check (it idles).
- [x] SecurityOptions: insecure guest logons off, SmartScreen Warn, AutoPlay off, WDigest off (registry, via new `Invoke-CpRegistrySettings`), DEP OptOut via bcdedit (skipped when BitLocker is on).
- [x] User rights: a plain account holding *Log on as a service / batch job* is reported.
- [x] Defender: threat default actions Allow/NoAction/UserDefined -> Quarantine; matching `ThreatSeverityDefaultAction` policy values removed.
- [x] Remote (KEEP_RDP): GP copies of NLA / SSL / High encryption + secure RPC + always prompt for password.
- [x] Shares: SMB minimum dialect 3.1.1 where the OS supports it (Win11 24H2 / Server 2025).
- [x] Media: sees HIDDEN files (Get-ChildItem without -Force never did), flags plaintext credit cards (Luhn) / SSNs in text files, skips the kit's own folder.
- [x] Persistence: SilentProcessExit, AppInit_DLLs, WMI event consumers, swapped accessibility binaries, script tasks hidden under `\Microsoft\`, drivers loaded from outside Windows, mimidrv. C:\ binary search 450s -> 78s on a big disk (`Find-CpFiles`).
- [x] Checklist: Firefox items, folder ACLs, RDP/WinRM group members, ASR, signed-elevation, District 13 penalties.
- [ ] Run against a real practice image (Sanh downloads it; then audit -> one module at a time -> score report).

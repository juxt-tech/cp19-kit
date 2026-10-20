# Improvement Backlog

The improve/debug loop takes the **first unchecked item** each iteration:
write a failing test → fix → run every suite → commit → push → tick it here.
When the list is empty, the loop runs a discovery pass (shellcheck, PSScriptAnalyzer, systemd test) to find new items. If discovery finds nothing, the loop stops.

## Bugs / correctness (from the final review)
- [x] Linux updates: Debian 12 uses deb822 `/etc/apt/sources.list.d/debian.sources` and Mint uses `official-package-repositories.list`. Commented/disabled sources there aren't fixed or flagged. **Done:** *.list + deb822 handled; only official mirrors re-enabled (unit 80/80, matrix 32/32 x3).
- [x] Linux ordering: passwords/firewall install packages (libpam-pwquality, ufw) BEFORE the updates module re-enables disabled sources, so those installs fail on an image with broken sources. **Done:** new `sources` module (2nd in order) re-enables + apt-get update; matrix plants broken sources (RED: no ufw/pwquality → GREEN 34/34 x3). Also added a CRLF guard test.
- [ ] Windows: non-terminating errors and native exit codes are logged as `ACTION done` (Set-ItemProperty, Set-Service, net.exe, Set-WebConfigurationProperty). Add `-ErrorAction Stop` and check `$LASTEXITCODE`.
- [ ] Config parsing (both OSes): a `#` inside NEW_PASSWORD truncates it; an apostrophe breaks `xargs` (Linux); a UTF-8 BOM breaks the first key.
- [ ] Linux passwords: a `pam-auth-update` refusal (local modifications) is still logged as done; `remember=0` counts as ok.
- [ ] Windows: the Updates/Defender-signature steps always log ACTION, so a second apply never shows 0 changes. Only act when something is actually stale.
- [ ] Windows shares: skip `Special` shares and role shares (CertEnroll, REMINST, WSUS*, `*$` admin shares).
- [ ] Linux media: exclude the kit's own run dir (`/root/cpkit-runs`) from the media/archive report.
- [ ] Windows: check README-critical service names exist BEFORE the disable step (Linux already does).
- [ ] server.md: "AD-DS installed" doesn't mean it's a DC; say "ProductType 2 / Server Manager shows AD DS as a role and the box is promoted".

## Test coverage
- [ ] Linux services module under real systemd: run the scenario in a systemd-enabled container (cups/avahi/vsftpd units, socket activation).
- [ ] shellcheck every `.sh` (docker `koalaman/shellcheck`); fix real warnings.
- [ ] PSScriptAnalyzer every `.ps1`/`.psm1`; fix real warnings.
- [ ] Windows end-to-end: audit, then apply, on a Win11 / Server 2022 practice VM. **Needs Sanh** (VM + snapshot); the loop skips it and leaves it here.

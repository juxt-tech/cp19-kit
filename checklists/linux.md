# Linux Checklist: Mint 21 / Debian 12 / Ubuntu (CyberPatriot 19)

Round 1 = Mint 21. Round 2 = Debian 12. The kit works on both.

**Order:** 0 Setup → 1 Forensics → 2 Audit → 3 Apply → 4 Findings → 5 Manual → 6 Don'ts. **Click a section to open it.** Snapshot before every numbered section.

<details>
<summary><b>0. Setup</b>: snapshot, README, get the kit, config</summary>

- [ ] VMware snapshot `start`.
- [ ] Read the README twice: admins, users, **critical services** (ssh? ftp? apache? samba?), required software, special app notes.
- [ ] Open a terminal and use `sudo` per command (a root shell comes later, before the passwords module).
- [ ] Get the kit: `wget -qO- https://github.com/juxt-tech/cp19-kit/archive/main.tar.gz | tar xz && cd cp19-kit-main`
- [ ] `cp config/cp-config.example.txt cp-config.txt && nano cp-config.txt` and fill it from the README.
  - Services use **systemd unit names**: `ssh`, `vsftpd`, `apache2`, `nginx`, `smbd`, `mariadb` (Debian 12's MySQL), `postfix`. The kit also understands README words like `mysql`, `samba`, `ftp`, `apache` and protects every unit they could mean.
  - Your own username goes in `ADMINS`.

</details>

<details>
<summary><b>1. Forensics FIRST</b>: methods table inside</summary>

- [ ] Questions are on the Desktop (`~/Desktop/Forensics Question N.txt`). Answer after `ANSWER:`.

| Question about… | How |
|---|---|
| hostname / OS | `hostname`, `cat /etc/os-release` |
| a hash | `md5sum f`, `sha256sum f` |
| encoded text | `echo '...' \| base64 -d`; ROT13: `tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
| a user/group fact | `id user`, `getent group name`, `grep user /etc/passwd` |
| where a program/file is | `which prog`, `find / -name 'x*' 2>/dev/null`, `locate` |
| which process listens on a port | `sudo ss -tulpn` |
| browser history | Firefox: `~/.mozilla/firefox/*/places.sqlite` (opening History in the browser is easier) |
| config passwords (app, web panel, RCON…) | `grep -ri password /etc/<app> /opt/<app> /var/www` |
| a CVE | search the program + "CVE" (e.g. pkexec → CVE-2021-4034) |

</details>

<details>
<summary><b>2. Audit run</b> (changes nothing)</summary>

- [ ] `sudo bash linux/harden.sh --all` → read every `[WOULD]` line. Would it remove a README user, service or tool? Fix `cp-config.txt` and re-run.

</details>

<details>
<summary><b>3. Apply one module at a time</b>: what each module does + the lockout warning</summary>

`sudo bash linux/harden.sh --apply` → menu. Snapshot between modules; refresh the score report after each one.

| # | Module | What it does | Category |
|---|---|---|---|
| 1 | users | delete non-README users (home dirs kept); create missing; sudo group = README admins; delete extra UID-0 accounts; passwords for empty-password users (all README users with `RESET_PASSWORDS=yes`, never yours); lock root; guest login off; `Defaults !authenticate` in sudoers commented out; system accounts (sys, daemon…) get nologin; lightdm X over TCP off; **reports** duplicate UIDs, gdm3/lightdm autologin, NOPASSWD sudo rules, system accounts with shells | User Auditing |
| 1b | sources | re-enables official apt sources (Debian `.sources`, Mint/Ubuntu `.list`) + `apt-get update`; **comments out Kali/Parrot repo lines**; other unknown repos stay as they are (reported) | OS Updates |
| 1c | integrity | unlocks `chattr +i/+a` files the kit must edit (crontab, passwd, sudoers…), reports other locked files; checks every package file (`dpkg -V`, ~1 min) and **reinstalls edited security tools** (ufw, PAM, sudo, passwd, login, ssh, coreutils…), reports the rest; flags `pam_deny.so` copied from `pam_permit.so` | Malware / OS Settings |
| ⚠ | before `passwords` | open a **second terminal and run `sudo -i`** first. Lockout applies to sudo too: 5 wrong passwords locks YOU out for 30 min. Unlock from the root shell: `faillock --user <name> --reset` | — |
| 2 | passwords | `login.defs` max 90 / min 10 / warn 7 (+ `chage` existing users; a password older than 90 days also gets its age reset, or it would expire at once and break logins, Dovecot/webmail included); pwquality minlen 10 + every char class; `remember=5`; remove `nullok`; faillock 5 tries / 30 min (via pam-auth-update, self-checking). If it says **pam_faillock was NOT added**, common-auth was hand-edited: read it for planted lines (`pam_permit`, `pam_exec`), then `pam-auth-update --force` | Account Policies |
| 3 | firewall | ufw on, deny in, allow out, open ports for critical services, logging | Defensive Countermeasures |
| 4 | ssh | PermitRootLogin no, no empty passwords, MaxAuthTries 4, X11 off… validated with `sshd -t` (done even when ssh isn't critical: nothing here locks anyone out) | App Security Settings |
| 4b | apps | only for README-critical services, each validated + rolled back: **Apache** ServerTokens Prod, ServerSignature Off, TraceEnable Off, no `Indexes`; **PHP** expose_php Off, cookie_httponly; **Postfix** VRFY off, HELO required, banner without version; **Dovecot** ssl=yes (if a cert exists), no debug passwords; **Roundcube** installer off, then webmail→Dovecot over `ssl://localhost:993`; **BIND** `version "none"` + `allow-transfer { none; }` (checked with `named-checkconf`); **ProFTPD** RootLogin off, DefaultRoot ~, no version banner; **Pure-FTPd** NoAnonymous + ChrootEveryone; **reports** Postfix open relay (`mynetworks 0.0.0.0/0`), BIND open to `any`, ProFTPD `<Anonymous>`. **Log in to webmail once afterwards.** | App Security Settings |
| 5 | sysctl | ASLR 2, SYN cookies, no redirects/source routing, rp_filter, martians, ip_forward 0 | Uncategorized OS Settings |
| 6 | perms | shadow/gshadow 640, passwd/group 644, sudoers 440, sshd_config 600; world-writable files under /etc and world-writable dirs without the sticky bit (/etc, /var/mail, /var/www…) fixed; lists odd SUID files | OS Permissions |
| 7 | services | stops risky services (ftp, web, samba, telnet, cups, avahi, snmp…) unless critical; starts critical ones; masks Ctrl-Alt-Del reboot | Service Auditing |
| 7b | logging | installs + starts **auditd** with watch rules (passwd/shadow/sudoers/sshd/PAM/cron/logins, sudo/su/useradd); rsyslog running; world-writable logs fixed; **AppArmor** installed + enabled (complain-mode profiles reported); **core dumps off** (`* hard core 0`, systemd-coredump Storage=none) | Local Policy / Uncategorized OS Settings |
| 7c | desktop | **automatic + guest login off** (gdm3, lightdm, sddm); gdm no X over TCP / XDMCP; **screen lock after 5 min** + **no USB/CD automount/autorun** for every user (dconf, locked); **Firefox protections back on** in every profile (pop-up blocker, add-on install warning, signed add-ons, malware/phishing/download blocking). Close Firefox first; it skips a profile while Firefox is open | Account Policies / App Security Settings |
| 8 | software | purges hacking tools/games (john, hydra, nmap, wireshark, ophcrack, aircrack, netcat-traditional, games, torrents) unless allowed | Unwanted Software |
| 9 | updates | auto-updates on, full upgrade (slow, it asks first) | OS Updates |
| 10 | persistence / media | **report only** → `findings.txt` (cron, units, rc.local, shell start-up hooks incl. fake aliases / `PROMPT_COMMAND` / `LD_PRELOAD`, init.d + autostart + per-user units not from a package, PAM modules not from a package, **web shells** in /var/www, **netcat/python/bash listening on a port**) | Malware / Prohibited Files |

</details>

<details>
<summary><b>4. Work through findings.txt by hand</b>: backdoors, SUID, media, keys, sudoers</summary>

- [ ] **Cron / timers / rc.local / .bashrc** backdoors (`nc -e`, `/dev/tcp`, `bash -i`): delete the line or file; kill the process (`sudo ss -tulpnp`, `sudo kill PID`). Malware. Also check each user's crontab: `sudo crontab -u <user> -l`.
- [ ] **NON-DEFAULT /etc/crontab line** + **executable not from any package**: a short name (`pearl`, `update`) in crontab pointing at an unpackaged script is the classic plant (ETH007 image: Perl reverse shell). `file /usr/bin/NAME; head /usr/bin/NAME`, then delete the cron line and the file. If the edit fails: `lsattr /etc/crontab` → `sudo chattr -i -a /etc/crontab`.
- [ ] **EDITED package file** the kit did not reinstall (e.g. `systemd` journald units): read the change, then `sudo apt-get install --reinstall <package>`.
- [ ] **Unusual SUID binaries** (find, vim, python, bash with SUID): `sudo chmod u-s /path`. OS Permissions.
- [ ] **Media + prohibited files**: `sudo rm` them (after forensics). Prohibited Files.
- [ ] **authorized_keys** with unknown keys → remove the line. Malware.
- [ ] **/etc/hosts** entries you didn't expect → remove. Malware.
- [ ] **sudoers NOPASSWD** rules → remove (`sudo visudo`, plus files in `/etc/sudoers.d`). User Auditing.
- [ ] **Duplicate UID** (two names, one UID): the one not in the README is a hidden twin → `sudo userdel <name>` (keep the README one).
- [ ] **Autologin** (gdm3 `AutomaticLoginEnable=true` in `/etc/gdm3/custom.conf`, or lightdm `autologin-user=`): turn it off unless the README needs it.
- [ ] **Recently installed / non-packaged files** in `/opt`, `/usr/local/bin` → check each one against the README.
- [ ] **Dual-use packages** (netcat-openbsd, tcpdump, socat) → remove if the README doesn't need them.
- [ ] **POSSIBLE BACKDOOR: 'nc'/'python3'/'bash' listens on ...**: forensics may ask the port. Find what starts it (cron, unit, rc.local), remove that, then `sudo kill PID`. Malware.
- [ ] **possible WEB SHELL**: a PHP file that runs `$_GET`/`$_POST` or decodes base64 → read it, answer forensics, delete it (keep the README site's real files). Malware.
- [ ] **PAM module not from any package** → `grep -r <name> /etc/pam.d`, remove that line, delete the `.so`. It can log every password. Malware.
- [ ] **boot script / autostart entry / per-user systemd service not from a package** → read it; disable (`sudo systemctl disable --now X`, `systemctl --user` for user units) and delete if it's a backdoor.
- [ ] **shell startup file** (fake `alias sudo=...`, `PROMPT_COMMAND`, `LD_PRELOAD`) → comment the line out in that file. Malware.
- [ ] **AppArmor profile in COMPLAIN mode** → `sudo aa-enforce <profile>`; test the critical service afterwards.

</details>

<details>
<summary><b>5. Manual-only items</b>: critical service configs, Firefox, updates, lock screen</summary>

- [ ] **Critical service configs** the README cares about. These are worth a lot and are image-specific.
  - **After every edit:** `sudo systemctl restart <svc> && systemctl is-active <svc>`. If it's not `active`, read `journalctl -u <svc> -n 20` and undo that one line. A critical service that won't start loses more points than the setting earns.

<details>
<summary>Per-service settings (vsftpd, apache, nginx, samba, mysql, php)</summary>

- **vsftpd** (`/etc/vsftpd.conf`): `anonymous_enable=NO` (old checklists say ON: wrong), `local_enable=YES`, `ssl_enable=YES` (needs `rsa_cert_file` to exist, e.g. `/etc/ssl/certs/ssl-cert-snakeoil.pem`; check the restart), `chroot_local_user=YES` (vsftpd refuses a writable chroot: if login breaks, add `allow_writeable_chroot=YES`). `/etc/ftpusers` is a **DENY list**: system accounts (root, daemon…) belong there; README users who need FTP must NOT be in it, and unauthorized FTP users should be (old club review).
- **apache2**: `ServerTokens Prod`, `ServerSignature Off`, `Options -Indexes`, `TraceEnable Off`.
- **nginx**: `server_tokens off;`, check `root` points where the README says, watch `alias` off-by-slash.
- **samba**: `guest ok = no`, `map to guest = never`, `smb encrypt = required`, `min protocol = SMB2`.
- **mysql/mariadb**: `bind-address = 127.0.0.1`, `local-infile = 0`; `sudo mysql_secure_installation` (root password, no anonymous users, no remote root, drop test DB).
- **php** (`/etc/php/*/apache2/php.ini`): `expose_php = Off`, `allow_url_include = Off`, `allow_url_fopen = Off`. Add `disable_functions = exec,shell_exec,passthru,system,popen,proc_open` only if the README's web app doesn't need them (test the site after).
- **bind9** (`/etc/bind/named.conf.options`, kit does version + allow-transfer): `allow-recursion` only for local nets, no `allow-update { any; }`; check with `sudo named-checkconf` before restarting `named`.
- **postfix**: `mynetworks = 127.0.0.0/8 [::1]/128` (never `0.0.0.0/0` = open relay), `smtpd_relay_restrictions` keeps `reject_unauth_destination`; `sudo postfix check`.
- **proftpd** (`/etc/proftpd/proftpd.conf`): comment out the `<Anonymous>` block unless public FTP is required; `sudo proftpd -t` before restart.
- **the README's own app** (game server, web panel…): do exactly what the README says.

</details>

- [ ] **Firefox:** the `desktop` module fixes settings files; by hand: update it, HTTPS-Only Mode, don't save passwords, remove unknown extensions (Settings > Privacy & Security). App Security Settings.
- [ ] **Mint Update Manager:** Edit > Preferences > Automation → turn on automatic updates; Edit > Software Sources → official mirrors. OS Updates (GUI-scored).
- [ ] **Screen lock:** the `desktop` module sets it for GNOME/Cinnamon/MATE. Xfce, or if the score doesn't move: System Settings > Screensaver → lock after ≤ 15 min, require password.
- [ ] **Passwords** for README users that look weak: `sudo passwd user`.
- [ ] **auditd / AppArmor:** done by the `logging` module. Check: `systemctl is-active auditd`, `sudo aa-status`.

</details>

<details>
<summary><b>6. Things that LOSE points</b> (read once before you start)</summary>

- Deleting a README user, or removing yourself from sudo.
- Removing or stopping a critical service or its package (the kit protects only what's in `cp-config.txt`; spell it right).
- `PasswordAuthentication no` in SSH when nobody has keys = lockout. The kit keeps it **yes**.
- Disabling IPv6 when the README or a service uses it (old checklists do this by default: only do it if asked).
- Deleting media/files before answering forensics.
- Firewall rules that block the critical service's port.
- Setting a password max age by hand on an old image without `chage -d today`: every password expires at once and services that log in through PAM (Dovecot/webmail, FTP, Samba) reject users. The kit handles it.
- Changing the auto-login user's password (README usually says you don't have to; it can lock you out).
- `apt purge` / `apt autoremove` that also removes the desktop or a critical package: **read the package list** before answering Y.
- Deleting files in `/usr`, `/lib`, `/etc` because they "look odd": check `dpkg -S FILE` first.
- Two teammates working on the same image, or rebooting in the middle of updates.
- **Score went down?** Stop. Undo the LAST change (backup below), refresh the report twice; still down → revert to the last snapshot. Earned points stay earned.
- Undo: revert the snapshot, or copy back from `/root/cpkit-runs/<time>/backup/`.

</details>

<details>
<summary><b>7. Lessons from the practice run</b> (ETH007 Debian 11 image: kit alone 0 → 44/100, 0 penalties)</summary>

- **Forensics first, then the kit.** The persistence module offers to quarantine reverse-shell programs: answer the questions that mention them before you say yes. Quarantined files stay in `/root/cpkit-runs/<time>/quarantine/`.
- **After the `apps` module, log in to webmail once** (and test any other critical service yourself). The kit checks configs, not your exact setup.
- **The score report lags.** It is rewritten about once a minute; right after a reboot the first pass can show a critical service as "stopped" before it has started. Wait two refreshes before panicking.
- **"FAILED" in the kit output means look at it**: on that image it was a `chattr +i` locked file. `lsattr FILE`, then `sudo chattr -i -a FILE`.
- **Image makers edit real tools** (ufw that did nothing, `pam_deny.so` replaced by `pam_permit.so`). The integrity module checks every package file; read its `EDITED package file` findings.
- **What the kit cannot do:** forensics questions, README-specific app settings (read the README twice), and updates on an end-of-life OS (Debian 11's security mirror is gone; Debian 12 is fine).
- Remaining points after the kit are hand work: findings.txt (section 4), section 5, and the README.

</details>

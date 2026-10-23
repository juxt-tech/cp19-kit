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
| 1 | users | delete non-README users (home dirs kept); create missing; sudo group = README admins; delete extra UID-0 accounts; passwords for empty-password users; lock root; guest login off; **reports** duplicate UIDs, gdm3/lightdm autologin, NOPASSWD sudo rules, system accounts with shells | User Auditing |
| 1b | sources | re-enables official apt sources (Debian `.sources`, Mint/Ubuntu `.list`) + `apt-get update`; unknown repos stay off | OS Updates |
| ⚠ | before `passwords` | open a **second terminal and run `sudo -i`** first. Lockout applies to sudo too: 5 wrong passwords locks YOU out for 30 min. Unlock from the root shell: `faillock --user <name> --reset` | — |
| 2 | passwords | `login.defs` max 90 / min 10 / warn 7 (+ `chage` existing users); pwquality minlen 10 + every char class; `remember=5`; remove `nullok`; faillock 5 tries / 30 min (via pam-auth-update, self-checking). If it says **pam_faillock was NOT added**, common-auth was hand-edited: read it for planted lines (`pam_permit`, `pam_exec`), then `pam-auth-update --force` | Account Policies |
| 3 | firewall | ufw on, deny in, allow out, open ports for critical services, logging | Defensive Countermeasures |
| 4 | ssh | (only if ssh is critical) PermitRootLogin no, no empty passwords, MaxAuthTries 4, X11 off… validated with `sshd -t` | App Security Settings |
| 5 | sysctl | ASLR 2, SYN cookies, no redirects/source routing, rp_filter, martians, ip_forward 0 | Uncategorized OS Settings |
| 6 | perms | shadow/gshadow 640, passwd/group 644, sudoers 440, sshd_config 600; lists odd SUID + world-writable files | OS Permissions |
| 7 | services | stops risky services (ftp, web, samba, telnet, cups, avahi, snmp…) unless critical; starts critical ones; masks Ctrl-Alt-Del reboot | Service Auditing |
| 8 | software | purges hacking tools/games (john, hydra, nmap, wireshark, ophcrack, aircrack, netcat-traditional, games, torrents) unless allowed | Unwanted Software |
| 9 | updates | auto-updates on, full upgrade (slow, it asks first) | OS Updates |
| 10 | persistence / media | **report only** → `findings.txt` | Malware / Prohibited Files |

</details>

<details>
<summary><b>4. Work through findings.txt by hand</b>: backdoors, SUID, media, keys, sudoers</summary>

- [ ] **Cron / timers / rc.local / .bashrc** backdoors (`nc -e`, `/dev/tcp`, `bash -i`): delete the line or file; kill the process (`sudo ss -tulpnp`, `sudo kill PID`). Malware. Also check each user's crontab: `sudo crontab -u <user> -l`.
- [ ] **Unusual SUID binaries** (find, vim, python, bash with SUID): `sudo chmod u-s /path`. OS Permissions.
- [ ] **Media + prohibited files**: `sudo rm` them (after forensics). Prohibited Files.
- [ ] **authorized_keys** with unknown keys → remove the line. Malware.
- [ ] **/etc/hosts** entries you didn't expect → remove. Malware.
- [ ] **sudoers NOPASSWD** rules → remove (`sudo visudo`, plus files in `/etc/sudoers.d`). User Auditing.
- [ ] **Duplicate UID** (two names, one UID): the one not in the README is a hidden twin → `sudo userdel <name>` (keep the README one).
- [ ] **Autologin** (gdm3 `AutomaticLoginEnable=true` in `/etc/gdm3/custom.conf`, or lightdm `autologin-user=`): turn it off unless the README needs it.
- [ ] **Recently installed / non-packaged files** in `/opt`, `/usr/local/bin` → check each one against the README.
- [ ] **Dual-use packages** (netcat-openbsd, tcpdump, socat) → remove if the README doesn't need them.

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
- **the README's own app** (game server, web panel…): do exactly what the README says.

</details>

- [ ] **Firefox:** update, block pop-ups, turn on phishing/malware protection, don't save passwords (Settings > Privacy & Security). App Security Settings.
- [ ] **Mint Update Manager:** Edit > Preferences > Automation → turn on automatic updates; Edit > Software Sources → official mirrors. OS Updates (GUI-scored).
- [ ] **Screen lock** (Mint: System Settings > Screensaver → lock after ≤ 15 min, require password).
- [ ] **Passwords** for README users that look weak: `sudo passwd user`.
- [ ] **auditd** (Debian rounds): `sudo apt install auditd && sudo systemctl enable --now auditd`.
- [ ] **AppArmor** enabled: `sudo aa-status`.

</details>

<details>
<summary><b>6. Things that LOSE points</b> (read once before you start)</summary>

- Deleting a README user, or removing yourself from sudo.
- Removing or stopping a critical service or its package (the kit protects only what's in `cp-config.txt`; spell it right).
- `PasswordAuthentication no` in SSH when nobody has keys = lockout. The kit keeps it **yes**.
- Disabling IPv6 when the README or a service uses it (old checklists do this by default: only do it if asked).
- Deleting media/files before answering forensics.
- Firewall rules that block the critical service's port.
- Undo: revert the snapshot, or copy back from `/root/cpkit-runs/<time>/backup/`.

</details>

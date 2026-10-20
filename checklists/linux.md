# Linux Checklist: Mint 21 / Debian 12 / Ubuntu (CyberPatriot 19)

Format: `[ ] what — why — how to check`. **Snapshot before every numbered section.**
Round 1 = Mint 21. Round 2 = Debian 12. The kit works on both.

## 0. Setup
- [ ] VMware snapshot `start`.
- [ ] Read the README twice: admins, users, **critical services** (ssh? ftp? apache? samba?), required software, special app notes.
- [ ] Open a terminal: `sudo -i` is NOT needed; use `sudo` per command.
- [ ] Get the kit: `wget -qO- https://github.com/juxt-tech/cp19-kit/archive/main.tar.gz | tar xz && cd cp19-kit-main`
- [ ] `cp config/cp-config.example.txt cp-config.txt && nano cp-config.txt` and fill it from the README.
  - Services use **systemd unit names**: `ssh`, `vsftpd`, `apache2`, `nginx`, `smbd`, `mariadb` (Debian 12's MySQL), `postfix`. The kit also understands README words like `mysql`, `samba`, `ftp`, `apache` and protects every unit they could mean.
  - Your own username goes in `ADMINS`.

## 1. Forensics FIRST
- [ ] Questions are on the Desktop (`~/Desktop/Forensics Question N.txt`). Answer after `ANSWER:`.
  | Question about… | How |
  |---|---|
  | hostname / OS | `hostname`, `cat /etc/os-release` |
  | a hash | `md5sum f`, `sha256sum f` |
  | encoded text | `echo '...' | base64 -d`; ROT13: `tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
  | a user/group fact | `id user`, `getent group name`, `grep user /etc/passwd` |
  | where a program/file is | `which prog`, `find / -name 'x*' 2>/dev/null`, `locate` |
  | which process listens on a port | `sudo ss -tulpn` |
  | browser history | Firefox: `~/.mozilla/firefox/*/places.sqlite` (open History in the browser is easier) |
  | config passwords (app, web panel, RCON…) | `grep -ri password /etc/<app> /opt/<app> /var/www` |
  | a CVE | search the program + "CVE" (e.g. pkexec → CVE-2021-4034) |

## 2. Audit run (changes nothing)
- [ ] `sudo bash linux/harden.sh --all` → read every `[WOULD]` line. Would it remove a README user, service or tool? Fix `cp-config.txt` and re-run.

## 3. Apply one module at a time
`sudo bash linux/harden.sh --apply` → menu. Snapshot between modules; refresh the score report after each one.

| # | Module | What it does | Category |
|---|---|---|---|
| 1 | users | delete non-README users (home dirs kept); create missing; sudo group = README admins; delete extra UID-0 accounts; passwords for empty-password users; lock root; guest login off | User Auditing |
| ⚠ | before `passwords` | open a **second terminal and run `sudo -i`** first. Lockout applies to sudo too: 5 wrong passwords locks YOU out for 30 min. Unlock from the root shell: `faillock --user <name> --reset` | — |
| 2 | passwords | `login.defs` max 90 / min 10 / warn 7 (+ `chage` existing users); pwquality minlen 10 + every char class; `remember=5`; remove `nullok`; faillock 5 tries / 30 min (via pam-auth-update, self-checking) | Account Policies |
| 3 | firewall | ufw on, deny in, allow out, open ports for critical services, logging | Defensive Countermeasures |
| 4 | ssh | (only if ssh is critical) PermitRootLogin no, no empty passwords, MaxAuthTries 4, X11 off… validated with `sshd -t` | App Security Settings |
| 5 | sysctl | ASLR 2, SYN cookies, no redirects/source routing, rp_filter, martians, ip_forward 0 | Uncategorized OS Settings |
| 6 | perms | shadow/gshadow 640, passwd/group 644, sudoers 440, sshd_config 600; lists odd SUID + world-writable files | OS Permissions |
| 7 | services | stops risky services (ftp, web, samba, telnet, cups, avahi, snmp…) unless critical; starts critical ones | Service Auditing |
| 8 | software | purges hacking tools/games (john, hydra, nmap, wireshark, ophcrack, aircrack, netcat-traditional, games, torrents) unless allowed | Unwanted Software |
| 9 | updates | uncomments sources, auto-updates on, full upgrade (slow, it asks first) | OS Updates |
| 10 | persistence / media | **report only** → `findings.txt` | Malware / Prohibited Files |

## 4. Work through findings.txt by hand
- [ ] **Cron / timers / rc.local / .bashrc** backdoors (`nc -e`, `/dev/tcp`, `bash -i`): delete the line or file; kill the process (`sudo ss -tulpnp`, `sudo kill PID`). — Malware.
- [ ] **Unusual SUID binaries** (find, vim, python, bash with SUID): `sudo chmod u-s /path`. — OS Permissions.
- [ ] **Media + prohibited files**: `sudo rm` them (after forensics). — Prohibited Files.
- [ ] **authorized_keys** with unknown keys → remove the line. — Malware.
- [ ] **/etc/hosts** entries you didn't expect → remove. — Malware.
- [ ] **sudoers NOPASSWD** rules → remove (`sudo visudo`, plus files in `/etc/sudoers.d`). — User Auditing.
- [ ] **Recently installed / non-packaged files** in `/opt`, `/usr/local/bin` → check each one against the README.
- [ ] **Dual-use packages** (netcat-openbsd, tcpdump, socat) → remove if the README doesn't need them.

## 5. Manual-only items
- [ ] **Critical service configs** the README cares about. These are worth a lot and are image-specific:
  - vsftpd (`/etc/vsftpd.conf`): `anonymous_enable=NO`, `local_enable=YES`, `ssl_enable=YES`, `chroot_local_user=YES`. `/etc/ftpusers` is a **DENY list**: system accounts (root, daemon…) belong there; README users who need FTP must NOT be in it, and unauthorized FTP users should be (old club review).
  - apache2: `ServerTokens Prod`, `ServerSignature Off`, `Options -Indexes`, TraceEnable Off.
  - nginx: `server_tokens off;`, check `root` points where the README says, watch `alias` off-by-slash.
  - samba: `guest ok = no`, `map to guest = never`, `smb encrypt = required`, `min protocol = SMB2`.
  - mysql: bind-address 127.0.0.1, no anonymous users, root has a password.
  - the README's own app (game server, web panel…): do exactly what the README says.
- [ ] **Firefox:** update, block pop-ups, turn on phishing/malware protection, don't save passwords (Settings > Privacy & Security). — App Security Settings.
- [ ] **Mint Update Manager:** Edit > Preferences > Automation → turn on automatic updates; Edit > Software Sources → official mirrors. — OS Updates (GUI-scored).
- [ ] **Screen lock** (Mint: System Settings > Screensaver → lock after ≤ 15 min, require password).
- [ ] **Passwords** for README users that look weak: `sudo passwd user`.
- [ ] **auditd** (Debian rounds): `sudo apt install auditd && sudo systemctl enable --now auditd`.
- [ ] **AppArmor** enabled: `sudo aa-status`.

## 6. Things that LOSE points
- Deleting a README user, or removing yourself from sudo.
- Removing or stopping a critical service or its package (the kit protects only what's in `cp-config.txt`; spell it right).
- `PasswordAuthentication no` in SSH when nobody has keys = lockout. The kit keeps it **yes**.
- Deleting media/files before answering forensics.
- Firewall rules that block the critical service's port.
- Undo: revert the snapshot, or copy back from `/root/cpkit-runs/<time>/backup/`.

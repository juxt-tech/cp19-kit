#!/usr/bin/env bash
# Run after `harden.sh --apply --yes` on a planted container. Arg: run dir.
RUN="$1"; PASS=0; FAIL=0
t() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then PASS=$((PASS+1)); echo "  ok   $name"; else FAIL=$((FAIL+1)); echo "  FAIL $name"; fi; }
f() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then FAIL=$((FAIL+1)); echo "  FAIL $name"; else PASS=$((PASS+1)); echo "  ok   $name"; fi; }

echo "== verify: fixes"
f "unauthorized user hacker removed"      id hacker
f "hidden UID-0 toor removed"             getent passwd toor
f "prancer (user) removed from sudo"      sh -c "id -nG prancer | grep -qw sudo"
t "missing README user cupid created"     id cupid
t "dasher now has a password"             sh -c "passwd -S dasher | awk '{exit !(\$2==\"P\")}'"
t "root locked"                           sh -c "passwd -S root | awk '{exit !(\$2==\"L\")}'"
t "/etc/shadow is 640"                    sh -c "[ \$(stat -c %a /etc/shadow) = 640 ]"
t "PermitRootLogin no"                    grep -qx "PermitRootLogin no" /etc/ssh/sshd_config
t "sshd config still valid"               sshd -t
t "syncookies persisted"                  grep -qx "net.ipv4.tcp_syncookies=1" /etc/sysctl.d/zz-cpkit.conf
t "PASS_MAX_DAYS 90"                      grep -qE "^PASS_MAX_DAYS[[:space:]]+90$" /etc/login.defs
t "pam_faillock enabled"                  grep -q pam_faillock.so /etc/pam.d/common-auth
t "password history remember=5"           grep -qE "^[^#]*pam_unix.so.*remember=5" /etc/pam.d/common-password
t "pwquality installed despite broken sources" sh -c "dpkg -s libpam-pwquality | grep -q 'ok installed'"
t "pwquality minlen set"                  grep -qE "^minlen = 10" /etc/security/pwquality.conf
f "john purged"                           sh -c "dpkg -s john 2>/dev/null | grep -q 'ok installed'"
t "ufw active"                            sh -c "ufw status | grep -q 'Status: active'"
t "ufw allows ftp (critical)"             sh -c "ufw status | grep -qE '^21/tcp'"
t "ufw allows ssh (critical)"             sh -c "ufw status | grep -qE '^22/tcp'"

t "UID-0 README user blitzen kept"         id blitzen
t "blitzen no longer UID 0"               sh -c "[ \$(id -u blitzen) -ge 1000 ]"
t "sysctl.conf override commented out"    grep -q "^# cpkit disabled: net.ipv4.ip_forward=1" /etc/sysctl.conf
t "sshd keys inserted above Match block"  sh -c "awk '/^Match/{m=NR} /^UsePAM yes/{u=NR} END{exit !(u && u<m)}' /etc/ssh/sshd_config"

f "kali repo line still live"             grep -rqE '^[[:space:]]*deb .*kali' /etc/apt/sources.list.d/
t "kali repo commented by the kit"        grep -q "cpkit disabled (other distro's repo)" /etc/apt/sources.list.d/kali.list
f "/etc/vsftpd.conf world-writable"       sh -c "[ \$(( 0\$(stat -c %a /etc/vsftpd.conf) & 2 )) -ne 0 ]"
t "prancer password reset to NEW_PASSWORD" sh -c "echo 'Cyb3rP@triot!2026' | pamtester login prancer authenticate"
t "old password not expired by max 90 (santa account check)" sh -c "echo 'Santa#2026pass' | pamtester login santa authenticate acct_mgmt"

t "edited ufw reinstalled (dpkg -V clean)"  sh -c "[ -z \"\$(dpkg -V ufw | awk '\$1 ~ /^..5/ && \$2 != \"c\"')\" ]"
t "edited ufw listed in findings"         grep -q "EDITED package file: /usr/sbin/ufw" "$RUN/findings.txt"
t "pam_deny.so restored (not a copy of pam_permit.so)" sh -c "d=\$(dirname \$(find / -xdev -name pam_permit.so -path '*security*' | head -1)); ! cmp -s \$d/pam_deny.so \$d/pam_permit.so"
f "ufw's sysctl.conf still turns martian logging off at boot" grep -qE '^net/ipv4/conf/all/log_martians=0' /etc/ufw/sysctl.conf
t "planted crontab line listed"           grep -q "NON-DEFAULT /etc/crontab line: \* \* \* \* \* root pearl" "$RUN/findings.txt"
t "reverse-shell cron line disabled"      grep -q "^# cpkit disabled (reverse shell): \* \* \* \* \* root pearl" /etc/crontab
f "reverse shell still in place"          test -e /usr/local/bin/pearl
t "reverse shell kept in quarantine"      test -f "$RUN/quarantine/pearl"
t "unowned binary listed"                 grep -q "executable not from any package: /usr/local/bin/oddtool" "$RUN/findings.txt"
f "sudoers !authenticate still live"      grep -qE '^[[:space:]]*Defaults.*!authenticate' /etc/sudoers.d/README
t "sudoers still valid"                   visudo -c
t "sys has no login shell"                sh -c "getent passwd sys | grep -qE '(nologin|false)$'"
f "/var/mail world-writable"              sh -c "[ \$(( 0\$(stat -c %a /var/mail) & 2 )) -ne 0 ]"

f "find still has the SUID bit"            sh -c '[ -u "$(command -v find)" ]'
t "/tmp has the sticky bit again"         sh -c '[ -k /tmp ]'
f "/etc/ld.so.preload still in place"     test -e /etc/ld.so.preload
t "ld.so.preload kept in quarantine"      test -f "$RUN/quarantine/ld.so.preload"
t "mysql service account has no login shell" sh -c "getent passwd mysql | grep -qE '(nologin|false)$'"
t "second sshd port listed"               grep -q "sshd also listens on port 2222" "$RUN/findings.txt"
t "hidden cron file listed"               grep -q "HIDDEN file in a cron directory: /etc/cron.d/.maintenance" "$RUN/findings.txt"
t "extra sudoers rule listed"             grep -q "sudoers rule in /etc/sudoers.d/botrunner" "$RUN/findings.txt"
t "anonymous FTP off (critical vsftpd)"   grep -qx "anonymous_enable=NO" /etc/vsftpd.conf
t "ptrace restriction persisted"          grep -qx "kernel.yama.ptrace_scope=1" /etc/sysctl.d/zz-cpkit.conf
echo "== verify: authorized things untouched"
t "santa still exists"                    id santa
t "santa still in sudo"                   sh -c "id -nG santa | grep -qw sudo"
t "prancer still exists"                  id prancer
t "santa (running the kit) keeps its password" sh -c "echo 'Santa#2026pass' | pamtester login santa authenticate"
f "wrong password rejected"               sh -c "echo 'nope' | pamtester login santa authenticate"
t "nmap kept (ALLOWED_SOFTWARE)"          sh -c "dpkg -s nmap | grep -q 'ok installed'"
t "vsftpd kept (CRITICAL)"                sh -c "dpkg -s vsftpd | grep -q 'ok installed'"
t "media NOT deleted"                     test -f /home/santa/Music/song.mp3
t "media listed in findings"              grep -q "song.mp3" "$RUN/findings.txt"
t "cron backdoor listed in findings"      grep -q "nc -e /bin/bash" "$RUN/findings.txt"
t "backups taken"                         test -f "$RUN/backup/etc/ssh/sshd_config"
t "log written"                           grep -q " | ACTION | " "$RUN/log.txt"
f "media report skips the kit run dir"     grep -q "media.*cpkit-runs" "$RUN/findings.txt"

echo "== verify: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

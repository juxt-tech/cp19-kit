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
t "syncookies persisted"                  grep -qx "net.ipv4.tcp_syncookies=1" /etc/sysctl.d/99-cpkit.conf
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

echo "== verify: authorized things untouched"
t "santa still exists"                    id santa
t "santa still in sudo"                   sh -c "id -nG santa | grep -qw sudo"
t "prancer still exists"                  id prancer
t "santa can still log in (good pw)"      sh -c "echo 'Santa#2026pass' | pamtester login santa authenticate"
f "wrong password rejected"               sh -c "echo 'nope' | pamtester login santa authenticate"
t "nmap kept (ALLOWED_SOFTWARE)"          sh -c "dpkg -s nmap | grep -q 'ok installed'"
t "vsftpd kept (CRITICAL)"                sh -c "dpkg -s vsftpd | grep -q 'ok installed'"
t "media NOT deleted"                     test -f /home/santa/Music/song.mp3
t "media listed in findings"              grep -q "song.mp3" "$RUN/findings.txt"
t "cron backdoor listed in findings"      grep -q "nc -e /bin/bash" "$RUN/findings.txt"
t "backups taken"                         test -f "$RUN/backup/etc/ssh/sshd_config"
t "log written"                           grep -q " | ACTION | " "$RUN/log.txt"

echo "== verify: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

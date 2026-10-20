#!/usr/bin/env bash
# Backdoors / persistence. CP category: Policy Violation: Malware.
# REPORT ONLY - a human decides; some cron jobs and services are legitimate.

CP_SUSPICIOUS_RE='nc |ncat|netcat|/dev/tcp|bash -i|sh -i|python.*socket|perl.*socket|socat|curl .*\|.*sh|wget .*\|.*sh|base64 -d|mkfifo|chmod \+s|useradd|\.\/[a-z]+ &'

mod_persistence() {
    cp_header "PERSISTENCE / BACKDOORS  (report only)"
    local u f l
    for u in $(cut -d: -f1 /etc/passwd); do
        l="$(crontab -l -u "$u" 2>/dev/null | grep -Ev '^\s*(#|$)')"
        [ -n "$l" ] && while read -r line; do cp_finding persistence "crontab of $u: $line"; done <<< "$l"
    done
    for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /etc/anacrontab; do
        [ -f "$f" ] || continue
        grep -EHn "$CP_SUSPICIOUS_RE" "$f" 2>/dev/null | while read -r l; do cp_finding persistence "SUSPICIOUS cron: $l"; done
    done
    ls /etc/cron.d 2>/dev/null | grep -Ev '^(e2scrub_all|php|popularity-contest|anacron|sysstat|\.placeholder)$' | while read -r f; do
        cp_finding persistence "non-default /etc/cron.d entry: $f"
    done
    command -v systemctl >/dev/null && systemctl list-timers --all --no-legend 2>/dev/null | awk '{print $(NF-1)}' | \
        grep -Ev '^(apt-daily|apt-daily-upgrade|dpkg-db-backup|e2scrub_all|fstrim|logrotate|man-db|motd-news|systemd-tmpfiles-clean|anacron|fwupd-refresh|ua-timer|update-notifier-.*|phpsessionclean|snapd.*|sysstat-.*)\.timer$' | \
        while read -r t; do cp_finding persistence "non-default systemd timer: $t"; done
    find /etc/systemd/system /lib/systemd/system -name '*.service' -newer /etc/hostname 2>/dev/null | head -30 | while read -r f; do
        cp_finding persistence "service file newer than install: $f  ($(grep -m1 '^ExecStart' "$f" 2>/dev/null))"
    done
    [ -s /etc/rc.local ] && grep -Ev '^\s*(#|$|exit 0)' /etc/rc.local | while read -r l; do cp_finding persistence "rc.local: $l"; done
    for f in /root/.bashrc /root/.profile /etc/profile /etc/bash.bashrc /etc/profile.d/*.sh /home/*/.bashrc /home/*/.profile /home/*/.bash_aliases; do
        [ -f "$f" ] && grep -EHn "$CP_SUSPICIOUS_RE|^alias (sudo|ls|cd|su)=" "$f" 2>/dev/null | while read -r l; do
            cp_finding persistence "shell startup file: $l"
        done
    done
    grep -Ev '^\s*(#|$)|localhost|127\.0\.1\.1|ip6-|::1|ff0[02]::' /etc/hosts 2>/dev/null | while read -r l; do
        cp_finding persistence "/etc/hosts entry: $l"
    done
    find / -xdev -type f \( -name 'nc' -o -name 'ncat' -o -name 'netcat' -o -name '*.elf' -o -name 'pwnkit*' -o -name '*backdoor*' \
        -o -name '*keylog*' -o -name '*rootkit*' \) -not -path '/usr/bin/*' -not -path '/bin/*' -not -path '/proc/*' 2>/dev/null | \
        head -30 | while read -r f; do cp_finding persistence "suspicious binary/file: $f"; done
    if [ -n "$CP_RUN" ] && command -v ss >/dev/null; then ss -tulpn > "$CP_RUN/listening.txt" 2>/dev/null; echo "  listening ports saved to $CP_RUN/listening.txt"; fi
    return 0
}

#!/usr/bin/env bash
# Backdoors / persistence. CP category: Policy Violation: Malware.
# REPORT ONLY - a human decides; some cron jobs and services are legitimate.

CP_SUSPICIOUS_RE='nc |ncat|netcat|/dev/tcp|bash -i|sh -i|python.*socket|perl.*socket|socat|curl .*\|.*sh|wget .*\|.*sh|base64 -d|mkfifo|chmod \+s|useradd|\.\/[a-z]+ &'

# Pure-ish (reads the link). 0 = report this unit file from /etc/systemd/system.
# Symlinks made by "systemctl enable" point into /lib|/usr/lib/systemd (package units) and masks point
# at /dev/null: both are noise. Report regular files and links that point anywhere else (1984 image:
# a unit linked to /opt/... with an ncat reverse shell in ExecStart).
persist_unit_suspect() {
    local f="$1" t re="${CP_UNIT_LIB_RE:-^/(usr/)?lib/systemd/}"
    if [ -L "$f" ]; then
        t="$(readlink -f "$f" 2>/dev/null)"
        [ "$t" = /dev/null ] && return 1
        [[ "$t" =~ $re ]] && return 1
    fi
    return 0
}

# Pure. Lines of an /etc/crontab that Debian does not ship (variables, comments, run-parts/anacron
# lines skipped). ETH007 image: "* * * * * root pearl" (a Perl reverse shell) in a chattr-locked crontab.
persist_crontab_extra() {
    grep -Ev '^[[:space:]]*(#|$|[A-Za-z_]+=)' "$1" 2>/dev/null | grep -Ev 'run-parts --report /etc/cron\.(hourly|daily|weekly|monthly)'
}

# Pure. A system-crontab line on stdin -> the command's first word ("@reboot user cmd" too).
cron_line_cmd() {
    awk '{ if ($1 ~ /^@/) print $3; else print $7 }'
}
# 0 when FILE's content looks like a reverse shell / bind shell (pentestmonkey, /dev/tcp, nc -e, pty).
revshell_suspect() {
    grep -aqiE 'reverse[ -]?shell|/dev/tcp/|use Socket|socket\.socket|IO::Socket|fsockopen|pty\.spawn|(nc|ncat|netcat)[^|;]*[[:space:]]-[ec][[:space:]]|bash -i|sh -i' "$1" 2>/dev/null
}
# Comment the exact line out of /etc/crontab and move the program into the run's quarantine dir
# (kept as evidence, execute bit removed). Never deletes.
_persist_quarantine() {
    local line="$1" path="$2" q="$CP_RUN/quarantine" tmp
    mkdir -p "$q"
    tmp="$(mktemp)"
    awk -v l="$line" '$0 == l { print "# cpkit disabled (reverse shell): " $0; next } { print }' /etc/crontab > "$tmp" && cat "$tmp" > /etc/crontab
    rm -f "$tmp"
    chattr -i -a "$path" 2>/dev/null   # ETH007: the reverse shell itself was chattr +i
    mv "$path" "$q/" && chmod a-x "$q/$(basename "$path")"
}

# Executables in the bin dirs that no package owns (each real dir once: /bin = /usr/bin on merged-usr).
_persist_unowned_bins() {
    local owned="$1" d r seen="" f n=0
    for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
        r="$(readlink -f "$d" 2>/dev/null)"; [ -d "$r" ] || continue
        cp_in_list "$r" "$seen" && continue; seen="$seen $r"
        while read -r f; do
            grep -qxF "$f" "$owned" && continue
            if [ -L "$f" ]; then   # update-alternatives links, or links to a packaged file
                case "$(readlink "$f")" in /etc/alternatives/*) continue ;; esac
                grep -qxF "$(readlink -f "$f")" "$owned" && continue
            fi
            case "$f" in /usr/local/sbin/cpkit-test-agent) continue ;; esac   # practice harness, reported elsewhere
            cp_finding persistence "executable not from any package: $f  ($(file -b "$f" 2>/dev/null | cut -c1-60))"
            n=$((n+1))
        done < <(find "$r" -maxdepth 1 \( -type f -o -type l \) -perm -u+x 2>/dev/null | sort)
    done
    [ "$n" = 0 ] && echo "  ok   every executable in the bin dirs belongs to a package"
}

_persist_units() {
    local f owned n=0
    owned="$(mktemp)"; cp_owned_files > "$owned"
    while read -r f; do
        persist_unit_suspect "$f" || continue
        grep -qxF "$f" "$owned" && continue          # shipped by a package
        local x; x="$(grep -m1 -E '^ExecStart' "$(readlink -f "$f")" 2>/dev/null)"
        if echo "$x" | grep -Eq "$CP_SUSPICIOUS_RE"; then cp_finding persistence "SUSPICIOUS unit: $f  ($x)"
        else cp_finding persistence "unit not from a package: $f  ($x)"; fi
        n=$((n+1))
    done < <(find /etc/systemd/system \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \) 2>/dev/null | sort)
    [ "$n" = 0 ] && echo "  ok   no hand-made units in /etc/systemd/system"
    # Edited package units (a planted ExecStart in a real service) show up in the integrity module (dpkg -V).
    _persist_unowned_bins "$owned"
    rm -f "$owned"
}

mod_persistence() {
    cp_header "PERSISTENCE / BACKDOORS  (report only)"
    local u f l
    for u in $(cut -d: -f1 /etc/passwd); do
        l="$(crontab -l -u "$u" 2>/dev/null | grep -Ev '^\s*(#|$)')"
        [ -n "$l" ] && while read -r line; do cp_finding persistence "crontab of $u: $line"; done <<< "$l"
    done
    local cmd p owned
    owned="$(mktemp)"; cp_owned_files > "$owned"
    while IFS= read -r l; do
        cp_finding persistence "NON-DEFAULT /etc/crontab line: $l  (what does it run? remove after forensics)"
        cmd="$(echo "$l" | cron_line_cmd)"
        p="$(PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin command -v "$cmd" 2>/dev/null)"
        [ -n "$p" ] && [ -f "$p" ] || continue
        p="$(readlink -f "$p")"
        # Only a program no package owns AND whose content is a reverse shell: high confidence.
        if ! grep -qxF "$p" "$owned" && revshell_suspect "$p"; then
            cp_backup /etc/crontab
            cp_act persistence "disable cron line '$l' and move $p to the run's quarantine/ (kept as evidence)" \
                "it runs a reverse shell as root - ANSWER FORENSICS FIRST" _persist_quarantine "$l" "$p"
        fi
    done < <(persist_crontab_extra /etc/crontab)
    rm -f "$owned"
    for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /etc/anacrontab; do
        [ -f "$f" ] || continue
        grep -EHn "$CP_SUSPICIOUS_RE" "$f" 2>/dev/null | while read -r l; do cp_finding persistence "SUSPICIOUS cron: $l"; done
    done
    for f in /etc/cron.d/*; do
        [ -e "$f" ] || continue
        case "${f##*/}" in e2scrub_all|php|popularity-contest|anacron|sysstat|.placeholder) continue ;; esac
        cp_finding persistence "non-default /etc/cron.d entry: ${f##*/}"
    done
    command -v systemctl >/dev/null && systemctl list-timers --all --no-legend 2>/dev/null | awk '{print $(NF-1)}' | \
        grep -Ev '^(apt-daily|apt-daily-upgrade|dpkg-db-backup|e2scrub_all|fstrim|logrotate|man-db|motd-news|systemd-tmpfiles-clean|anacron|fwupd-refresh|ua-timer|update-notifier-.*|phpsessionclean|snapd.*|sysstat-.*)\.timer$' | \
        while read -r t; do cp_finding persistence "non-default systemd timer: $t"; done
    _persist_units
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

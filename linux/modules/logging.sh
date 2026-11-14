#!/usr/bin/env bash
# Logging + auditing + AppArmor + core dumps.
# CP categories: Local Policy (auditing), Uncategorized OS Settings, Defensive Countermeasures.
# Ideas from Ripper1004/CyberPatriot-Toolkit (sec_logging, sec_apparmor, sec_kernel core dumps).

CP_AUDIT_RULES_FILE=/etc/audit/rules.d/50-cpkit.rules

# Pure. Audit rules for the paths that exist under ROOT ("" = the real system). Watches the files
# attackers change (accounts, sudo, ssh/PAM, cron, logins) and the programs they use.
logging_audit_rules() {
    local root="${1:-}" p
    echo "## Added by the CyberPatriot kit (logging module)"
    for p in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/security/opasswd; do [ -e "$root$p" ] && echo "-w $p -p wa -k identity"; done
    for p in /etc/sudoers /etc/sudoers.d; do [ -e "$root$p" ] && echo "-w $p -p wa -k sudoers"; done
    for p in /etc/ssh/sshd_config /etc/pam.d; do [ -e "$root$p" ] && echo "-w $p -p wa -k auth_config"; done
    for p in /etc/crontab /etc/cron.d /var/spool/cron; do [ -e "$root$p" ] && echo "-w $p -p wa -k cron"; done
    for p in /etc/hosts /etc/hostname; do [ -e "$root$p" ] && echo "-w $p -p wa -k network"; done
    for p in /var/log/lastlog /var/log/faillog /var/log/wtmp /var/log/btmp; do [ -e "$root$p" ] && echo "-w $p -p wa -k logins"; done
    for p in /usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/sbin/useradd /usr/sbin/usermod /usr/sbin/insmod /usr/sbin/rmmod /usr/sbin/modprobe; do
        [ -e "$root$p" ] && echo "-w $p -p x -k privileged"
    done
    return 0
}

# Pure. Lines in a limits file that allow core dumps (core limit above 0 / unlimited).
core_limit_lines() {
    [ -f "$1" ] || return 0
    grep -nE '^[[:space:]]*[^#[:space:]]+[[:space:]]+(soft|hard|-)[[:space:]]+core[[:space:]]+([1-9][0-9]*|unlimited|infinity|-1)([[:space:]]|$)' "$1"
}
# Comment those lines out; in limits.conf also add "* hard core 0" (before "# End of file" if present).
core_limits_fix() {
    local f="$1" tmp
    tmp="$(mktemp)"
    awk '
        /^[ \t]*[^# \t]+[ \t]+(soft|hard|-)[ \t]+core[ \t]+([1-9][0-9]*|unlimited|infinity|-1)([ \t]|$)/ { print "# " $0 "   # core dumps off (cpkit)"; next }
        { print }' "$f" > "$tmp"
    if [ "${f##*/}" = limits.conf ] && ! grep -qE '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0([[:space:]]|$)' "$tmp"; then
        if grep -qi '^#[[:space:]]*end of file' "$tmp"; then
            awk '!d && tolower($0) ~ /^#[ \t]*end of file/ { print "*               hard    core            0"; d=1 } { print }' "$tmp" > "$tmp.2" && mv "$tmp.2" "$tmp"
        else
            echo "*               hard    core            0" >> "$tmp"
        fi
    fi
    cat "$tmp" > "$f"; rm -f "$tmp"
}
core_limits_ok() {   # limits.conf has "* hard core 0" and no file raises the limit
    local f
    grep -qE '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0([[:space:]]|$)' "${1:-/etc/security/limits.conf}" 2>/dev/null || return 1
    for f in "${1:-/etc/security/limits.conf}" "${2:-/etc/security/limits.d}"/*.conf; do
        [ -n "$(core_limit_lines "$f")" ] && return 1
    done
    return 0
}

# Pure. Profiles listed under "profiles are in complain mode" in aa-status output (stdin).
aa_complain_profiles() {
    awk '/profiles are in complain mode/ { f=1; next } /profiles are|processes|^[0-9]+ / { f=0 } f { gsub(/^[ \t]+/, ""); if ($0 != "") print }'
}

_log_install() { DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"; }
_log_enable() { systemctl enable --now "$1"; }
_log_write_rules() {   # write the rules file, then load it (fails quietly in containers without audit)
    mkdir -p "$(dirname "$CP_AUDIT_RULES_FILE")"
    cp_backup "$CP_AUDIT_RULES_FILE"
    logging_audit_rules "" > "$CP_AUDIT_RULES_FILE" || return 1
    command -v augenrules >/dev/null && augenrules --load >/dev/null 2>&1
    return 0
}
_log_coredump_conf() {   # systemd-coredump keeps nothing
    local f=/etc/systemd/coredump.conf
    cp_backup "$f"
    ini_set "$f" Coredump Storage none; ini_set "$f" Coredump ProcessSizeMax 0
    return 0
}

mod_logging() {
    cp_header "LOGGING / AUDITING / APPARMOR / CORE DUMPS"
    local sysd=0 f p
    [ -d /run/systemd/system ] && sysd=1

    # rsyslog writes /var/log/auth.log (Debian 12 ships only the journal)
    if ! dpkg -s rsyslog >/dev/null 2>&1; then
        cp_act logging "apt-get install rsyslog" "writes /var/log/auth.log, syslog... (who logged in, sudo use)" _log_install rsyslog
    elif [ "$sysd" = 1 ] && ! systemctl is-active --quiet rsyslog; then
        cp_act logging "systemctl enable --now rsyslog" "system logs are not being written" _log_enable rsyslog
    else echo "  ok   rsyslog installed and running"; fi

    # auditd: install, run, watch the files attackers change
    if ! dpkg -s auditd >/dev/null 2>&1; then
        cp_act logging "apt-get install auditd" "security auditing (records password-file, sudo and SSH-config changes)" _log_install auditd
    fi
    if dpkg -s auditd >/dev/null 2>&1 || [ "$CP_MODE" = audit ]; then
        if [ "$sysd" = 1 ] && dpkg -s auditd >/dev/null 2>&1; then
            if systemctl is-active --quiet auditd && systemctl is-enabled --quiet auditd 2>/dev/null; then echo "  ok   auditd running + enabled"
            else cp_act logging "systemctl enable --now auditd" "audit daemon is off" _log_enable auditd; fi
        fi
        if [ -f "$CP_AUDIT_RULES_FILE" ] && [ "$(logging_audit_rules "")" = "$(cat "$CP_AUDIT_RULES_FILE")" ]; then echo "  ok   audit rules in $CP_AUDIT_RULES_FILE"
        else cp_act logging "write audit rules to $CP_AUDIT_RULES_FILE + augenrules --load" "watch accounts, sudoers, sshd/PAM config, cron, logins, sudo/su/useradd" _log_write_rules; fi
    fi
    grep -qsE '^[[:space:]]*-e[[:space:]]+0' /etc/audit/rules.d/*.rules /etc/audit/audit.rules && \
        cp_finding logging "an audit rule file has '-e 0' (auditing switched OFF): $(grep -lsE '^[[:space:]]*-e[[:space:]]+0' /etc/audit/rules.d/*.rules /etc/audit/audit.rules | xargs) - delete that line"

    # Log files anyone can edit = an attacker can erase their tracks
    local ww
    ww="$(find /var/log -xdev -type f -perm -o+w 2>/dev/null | head -50)"
    if [ -n "$ww" ]; then
        cp_act logging "chmod o-w on $(echo "$ww" | wc -l) world-writable log file(s): $(echo "$ww" | head -3 | xargs)..." "anyone could erase the logs" xargs -r -d '\n' chmod o-w <<< "$ww"
    else echo "  ok   no world-writable log files"; fi

    # AppArmor
    if ! dpkg -s apparmor >/dev/null 2>&1; then
        cp_act logging "apt-get install apparmor apparmor-utils" "confines programs like web servers if they get hacked" _log_install apparmor apparmor-utils
    elif [ "$sysd" = 1 ] && systemctl list-unit-files apparmor.service >/dev/null 2>&1 && ! systemctl is-enabled --quiet apparmor 2>/dev/null; then
        cp_act logging "systemctl enable --now apparmor" "AppArmor service is disabled" _log_enable apparmor
    else echo "  ok   apparmor installed"; fi
    if [ -r /sys/module/apparmor/parameters/enabled ] && [ "$(cat /sys/module/apparmor/parameters/enabled)" != Y ]; then
        cp_finding logging "AppArmor is OFF in the kernel. If /etc/default/grub has apparmor=0 or security=..., remove it, then sudo update-grub and reboot (end of round)"
    fi
    grep -qsE 'apparmor=0|security=(selinux|none|tomoyo)' /etc/default/grub && \
        cp_finding logging "/etc/default/grub turns AppArmor off: $(grep -E 'apparmor=0|security=' /etc/default/grub | head -1)"
    if command -v aa-status >/dev/null; then
        aa-status 2>/dev/null | aa_complain_profiles | while read -r p; do
            cp_finding logging "AppArmor profile in COMPLAIN (log-only) mode: $p  -> sudo aa-enforce $p  (skip if it belongs to a critical service that then breaks)"
        done
    fi

    # Core dumps can hold passwords from memory
    if core_limits_ok; then echo "  ok   core dumps off (limits.conf * hard core 0)"
    else
        for f in /etc/security/limits.conf /etc/security/limits.d/*.conf; do
            [ -f "$f" ] || continue
            [ "${f##*/}" = limits.conf ] || [ -n "$(core_limit_lines "$f")" ] || continue
            cp_backup "$f"
            cp_act logging "core dumps off in $f (* hard core 0)" "a crashed program's memory copy can contain passwords" core_limits_fix "$f"
        done
    fi
    if [ -f /etc/systemd/coredump.conf ]; then
        if [ "$(ini_get /etc/systemd/coredump.conf Coredump Storage)" = none ]; then echo "  ok   systemd-coredump Storage=none"
        else cp_act logging "Storage=none, ProcessSizeMax=0 in /etc/systemd/coredump.conf" "systemd keeps no core dumps" _log_coredump_conf; fi
    fi
    return 0
}

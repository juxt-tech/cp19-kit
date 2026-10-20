#!/usr/bin/env bash
# SSH server hardening. CP category: Application Security Settings (critical service).
# Only edits sshd when the README lists ssh as critical; otherwise reports.
# PasswordAuthentication stays YES so nobody gets locked out (no keys are provisioned in CP images).

CP_SSH_WANT=(
    "PermitRootLogin no"
    "PermitEmptyPasswords no"
    "PasswordAuthentication yes"
    "Protocol 2"
    "X11Forwarding no"
    "MaxAuthTries 4"
    "LoginGraceTime 60"
    "ClientAliveInterval 300"
    "ClientAliveCountMax 3"
    "HostbasedAuthentication no"
    "IgnoreRhosts yes"
    "PermitUserEnvironment no"
    "UsePAM yes"
)

# Pure: prints "SET key value" for every wanted key whose value in FILE differs.
plan_ssh() {
    local file="$1" kv k v
    for kv in "${CP_SSH_WANT[@]}"; do
        k="${kv%% *}"; v="${kv#* }"
        [ "$(cp_conf_get "$file" "$k")" = "$v" ] || echo "SET $k $v"
    done
}

_ssh_installed() { [ -f /etc/ssh/sshd_config ]; }
_ssh_critical()  { cp_is_protected_service ssh || cp_is_protected_service sshd; }

_ssh_validate_or_restore() {
    if command -v sshd >/dev/null && ! sshd -t 2>/tmp/cpkit-sshd-t; then
        cp -a "$CP_RUN/backup/etc/ssh/sshd_config" /etc/ssh/sshd_config
        echo "  !! sshd -t failed; sshd_config restored:"; sed 's/^/     /' /tmp/cpkit-sshd-t
        cp_log ssh FAILED "sshd_config edit" restored "sshd -t failed"
        return 1
    fi
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
}

mod_ssh() {
    cp_header "SSH  (sshd_config)"
    if ! _ssh_installed; then echo "  ok   openssh-server not installed"; return 0; fi
    if ! _ssh_critical; then
        cp_finding ssh "openssh-server is installed but ssh is NOT in CRITICAL_SERVICES - if the README doesn't need it, remove it (services/software modules) "
        return 0
    fi
    local f=/etc/ssh/sshd_config plan act k v d changed=0
    cp_backup "$f"
    plan="$(plan_ssh "$f")"
    [ -z "$plan" ] && echo "  ok   sshd_config already compliant"
    while read -r act k v; do
        [ -n "$act" ] || continue
        cp_act ssh "set $k $v (now: $(cp_conf_get "$f" "$k" || true))" "CIS / CP-scored sshd setting" cp_set_conf "$f" "$k" "$v"
        changed=1
    done <<< "$plan"
    # Drop-ins are read FIRST by sshd and win - fix conflicting values there too.
    for d in /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$d" ] || continue
        for kv in "${CP_SSH_WANT[@]}"; do
            k="${kv%% *}"; v="${kv#* }"
            local cur; cur="$(cp_conf_get "$d" "$k")"
            if [ -n "$cur" ] && [ "$cur" != "$v" ]; then
                cp_backup "$d"
                cp_act ssh "set $k $v in $d (now: $cur)" "drop-in overrides sshd_config" cp_set_conf "$d" "$k" "$v"
                changed=1
            fi
        done
    done
    if [ "$(stat -c '%U:%a' "$f")" != "root:600" ]; then
        cp_act ssh "chown root:root + chmod 600 $f" "only root may read/edit sshd config" sh -c "chown root:root $f && chmod 600 $f"
    fi
    [ "$CP_MODE" = apply ] && [ "$changed" = 1 ] && _ssh_validate_or_restore
    awk -F: '$3>=1000 {print $6}' /etc/passwd | while read -r h; do
        [ -s "$h/.ssh/authorized_keys" ] && cp_finding ssh "authorized_keys present: $h/.ssh/authorized_keys (check for planted keys)"
    done
    [ -s /root/.ssh/authorized_keys ] && cp_finding ssh "root has authorized_keys: /root/.ssh/authorized_keys"
    return 0
}

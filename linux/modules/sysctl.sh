#!/usr/bin/env bash
# Kernel / network hardening via /etc/sysctl.d/99-cpkit.conf. CP category: Uncategorized OS Settings.

CP_SYSCTL=(
    "kernel.randomize_va_space=2"
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
    "net.ipv4.icmp_ignore_bogus_error_responses=1"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.secure_redirects=0"
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.send_redirects=0"
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.conf.default.rp_filter=1"
    "net.ipv4.conf.all.log_martians=1"
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"
    "net.ipv6.conf.all.accept_source_route=0"
    "kernel.dmesg_restrict=1"
    "kernel.kptr_restrict=2"
    "fs.protected_symlinks=1"
    "fs.protected_hardlinks=1"
    "fs.suid_dumpable=0"
)
CP_SYSCTL_FILE=/etc/sysctl.d/99-cpkit.conf

_sysctl_write() {
    { echo "# written by cpkit - kernel/network hardening"; printf '%s\n' "${CP_SYSCTL[@]}"; echo "net.ipv4.ip_forward=0"; } > "$CP_SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true
}

# Pure: uncommented lines in FILE that set one of our keys to a different value.
# Prints "KEY<TAB>original line". /etc/sysctl.conf loads AFTER sysctl.d, so these would win.
plan_sysctl_conflicts() {
    local file="$1" kv k want line lk lv
    [ -f "$file" ] || return 0
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || continue
        lk="$(echo "${line%%=*}" | tr -d '[:space:]')"; lv="$(echo "${line#*=}" | tr -d '[:space:]')"
        for kv in "${CP_SYSCTL[@]}" "net.ipv4.ip_forward=0"; do
            k="${kv%%=*}"; want="${kv#*=}"
            [ "$lk" = "$k" ] && [ "$lv" != "$want" ] && printf '%s\t%s\n' "$k" "$line"
        done
    done < "$file"
}

_sysctl_comment() {  # FILE KEY  - comment out every live line setting KEY
    local re; re="$(printf '%s' "$2" | sed 's/\./\\./g')"
    sed -i -E "s|^([[:space:]]*${re}[[:space:]]*=.*)$|# cpkit disabled: \1|" "$1"
}

mod_sysctl() {
    cp_header "SYSCTL  (kernel + network)"
    local kv k want cur bad=0 f line
    for kv in "${CP_SYSCTL[@]}" "net.ipv4.ip_forward=0"; do
        k="${kv%%=*}"; want="${kv#*=}"
        cur="$(sysctl -n "$k" 2>/dev/null || echo '?')"
        grep -qsx "$k=$want" "$CP_SYSCTL_FILE" || { echo "  -    $k = $cur (want $want)"; bad=1; continue; }
        [ "$cur" = "$want" ] || cp_finding sysctl "$k is $cur live but $want in $CP_SYSCTL_FILE (reboot or run: sysctl --system)"
    done
    if [ "$bad" = 0 ]; then echo "  ok   all kernel settings persistent in $CP_SYSCTL_FILE"
    else
        cp_finding sysctl "ip_forward is set to 0 - if the README says this box routes traffic, set it back to 1"
        # Some keys are read-only inside containers; the file still makes them persistent on a real VM.
        cp_act sysctl "write $CP_SYSCTL_FILE and run sysctl --system" "ASLR, SYN cookies, no redirects/source routing" _sysctl_write
    fi
    # Other files that would override ours (sysctl.conf loads last).
    for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
        [ -f "$f" ] && [ "$f" != "$CP_SYSCTL_FILE" ] || continue
        while IFS=$'\t' read -r k line; do
            [ -n "$k" ] || continue
            cp_backup "$f"
            cp_act sysctl "comment out '$line' in $f" "it overrides the hardened value of $k" _sysctl_comment "$f" "$k"
        done < <(plan_sysctl_conflicts "$f")
    done
    return 0
}

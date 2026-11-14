#!/usr/bin/env bash
# Kernel / network hardening via /etc/sysctl.d/zz-cpkit.conf. CP category: Uncategorized OS Settings.

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
    "net.ipv4.conf.default.log_martians=1"
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"
    "net.ipv6.conf.all.accept_source_route=0"
    "kernel.dmesg_restrict=1"
    "kernel.kptr_restrict=2"
    "fs.protected_symlinks=1"
    "fs.protected_hardlinks=1"
    "fs.suid_dumpable=0"
    "kernel.yama.ptrace_scope=1"
    "kernel.sysrq=0"
    "kernel.core_uses_pid=1"
    "kernel.perf_event_paranoid=3"
    "kernel.unprivileged_bpf_disabled=1"
    "net.core.bpf_jit_harden=2"
    "net.ipv4.tcp_rfc1337=1"
    "net.ipv4.conf.default.secure_redirects=0"
    "net.ipv6.conf.default.accept_source_route=0"
    "fs.protected_fifos=2"
    "fs.protected_regular=2"
)
# zz- so it loads AFTER every NN-*.conf (sysctl.d files load in name order, the last one wins). As 99-cpkit
# it lost to procps' 99-protect-links.conf (fs.protected_fifos=1); editing that package file made the
# integrity module reinstall procps on every run (second apply never 0 changes).
CP_SYSCTL_FILE=/etc/sysctl.d/zz-cpkit.conf

_sysctl_write() {
    { echo "# written by cpkit - kernel/network hardening"; printf '%s\n' "${CP_SYSCTL[@]}"; echo "net.ipv4.ip_forward=0"; } > "$CP_SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true
}

# Pure: uncommented lines in FILE that set one of our keys to a different value.
# Prints "KEY<TAB>original line". /etc/sysctl.conf loads AFTER sysctl.d, so these would win.
# Keys may be written with slashes (net/ipv4/...): /etc/ufw/sysctl.conf does, and ufw applies
# it every time it starts - stock ufw sets log_martians=0, undoing ours at each boot.
plan_sysctl_conflicts() {
    local file="$1" kv k want line lk lv
    [ -f "$file" ] || return 0
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || continue
        lk="$(echo "${line%%=*}" | tr -d '[:space:]' | tr '/' '.')"; lv="$(echo "${line#*=}" | tr -d '[:space:]')"
        for kv in "${CP_SYSCTL[@]}" "net.ipv4.ip_forward=0"; do
            k="${kv%%=*}"; want="${kv#*=}"
            [ "$lk" = "$k" ] && [ "$lv" != "$want" ] && printf '%s\t%s\n' "$k" "$line"
        done
    done < "$file"
}

# 0 = leave FILE alone: a package's sysctl.d file that loads before ours (ours wins; editing it would only
# make the integrity module reinstall the package). /etc/sysctl.conf and ufw's file load later: never skipped.
sysctl_ours_wins() {
    local f="$1" ours
    ours="$(basename "${CP_SYSCTL_FILE}")"
    case "$f" in */sysctl.d/*) ;; *) return 1 ;; esac
    [[ "$(basename "$f")" < "$ours" ]] || return 1
    dpkg -S "$f" >/dev/null 2>&1 || dpkg -S "$(readlink -f "$f")" >/dev/null 2>&1
}

_sysctl_comment() {  # FILE KEY  - comment out every live line setting KEY (dot or slash form)
    local re; re="$(printf '%s' "$2" | sed 's/\./[.\/]/g')"
    sed -i -E "s|^([[:space:]]*${re}[[:space:]]*=.*)$|# cpkit disabled: \1|" "$1"
}

mod_sysctl() {
    cp_header "SYSCTL  (kernel + network)"
    local kv k want cur bad=0 f line
    for kv in "${CP_SYSCTL[@]}" "net.ipv4.ip_forward=0"; do
        k="${kv%%=*}"; want="${kv#*=}"
        cur="$(sysctl -n "$k" 2>/dev/null || echo '?')"
        grep -qsx "$k=$want" "$CP_SYSCTL_FILE" || { echo "  -    $k = $cur (want $want)"; bad=1; continue; }
        [ "$cur" = "$want" ] || [ "$cur" = "?" ] || cp_finding sysctl "$k is $cur live but $want in $CP_SYSCTL_FILE (reboot or run: sysctl --system)"
    done
    if [ "$bad" = 0 ]; then echo "  ok   all kernel settings persistent in $CP_SYSCTL_FILE"
    else
        cp_finding sysctl "ip_forward is set to 0 - if the README says this box routes traffic, set it back to 1"
        # Some keys are read-only inside containers; the file still makes them persistent on a real VM.
        cp_act sysctl "write $CP_SYSCTL_FILE and run sysctl --system" "ASLR, SYN cookies, no redirects/source routing" _sysctl_write
    fi
    # Other files that would override ours (sysctl.conf loads last).
    for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /etc/ufw/sysctl.conf; do
        [ -f "$f" ] && [ "$f" != "$CP_SYSCTL_FILE" ] || continue
        sysctl_ours_wins "$f" && continue
        while IFS=$'\t' read -r k line; do
            [ -n "$k" ] || continue
            cp_backup "$f"
            cp_act sysctl "comment out '$line' in $f" "it overrides the hardened value of $k" _sysctl_comment "$f" "$k"
        done < <(plan_sysctl_conflicts "$f")
    done
    return 0
}

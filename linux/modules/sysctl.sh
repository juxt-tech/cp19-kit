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

mod_sysctl() {
    cp_header "SYSCTL  (kernel + network)"
    local kv k want cur bad=0
    for kv in "${CP_SYSCTL[@]}" "net.ipv4.ip_forward=0"; do
        k="${kv%%=*}"; want="${kv#*=}"
        cur="$(sysctl -n "$k" 2>/dev/null || echo '?')"
        if [ "$cur" = "$want" ] && grep -qs "^$k=$want" "$CP_SYSCTL_FILE"; then continue; fi
        echo "  -    $k = $cur (want $want)"; bad=1
    done
    if [ "$bad" = 0 ]; then echo "  ok   all kernel settings applied and persistent"; return 0; fi
    cp_finding sysctl "ip_forward is set to 0 - if the README says this box routes traffic, set it back to 1"
    # Some keys are read-only inside containers; the file still makes them persistent on a real VM.
    cp_act sysctl "write $CP_SYSCTL_FILE and run sysctl --system" "ASLR, SYN cookies, no redirects/source routing" _sysctl_write
    grep -rhsE '^[^#]*=' /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null | grep -E 'randomize_va_space *= *[01]|tcp_syncookies *= *0|ip_forward *= *1' | while read -r l; do
        cp_finding sysctl "weak setting in another sysctl file (it may load after ours): $l"
    done
    return 0
}

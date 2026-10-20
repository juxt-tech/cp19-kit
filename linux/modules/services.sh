#!/usr/bin/env bash
# Services. CP category: Service Auditing.
# Disables a known list of risky services UNLESS the README marks them critical.

CP_BAD_SERVICES="apache2 nginx lighttpd vsftpd proftpd pure-ftpd smbd nmbd samba telnet inetd xinetd openbsd-inetd \
rsh-server rlogin rexec nfs-server nfs-kernel-server rpcbind snmpd cups cups-browsed avahi-daemon isc-dhcp-server \
bind9 named postfix exim4 dovecot squid mysql mariadb postgresql tftpd-hpa atftpd xrdp vncserver x11vnc minetest-server"

# Pure. Arg: space-separated unit names (active or enabled). Prints DISABLE/KEEP lines.
plan_services() {
    local u base
    for u in $1; do
        base="${u%.service}"; base="${base%.socket}"
        cp_in_list "$base" "$CP_BAD_SERVICES" || continue
        if cp_is_protected_service "$base"; then
            echo "KEEP $base (critical)"
        else
            echo "DISABLE $base"
        fi
    done
}

_has_systemd() { [ -d /run/systemd/system ]; }

mod_services() {
    cp_header "SERVICES"
    if ! _has_systemd; then
        echo "  systemd is not running here - services module is REPORT ONLY"
        cp_finding services "systemd not running; services were not checked"
        return 0
    fi
    local units plan act s
    units="$( { systemctl list-unit-files --type=service,socket --state=enabled --no-legend 2>/dev/null | awk '{print $1}';
                systemctl list-units --type=service,socket --state=running --no-legend 2>/dev/null | awk '{print $1}'; } | sort -u | xargs)"
    plan="$(plan_services "$units")"
    [ -z "$plan" ] && echo "  ok   no risky services enabled"
    while read -r act s rest; do
        case "$act" in
            KEEP) echo "  ok   $s kept (README critical)" ;;
            DISABLE) cp_act services "stop + disable $s" "risky service not required by README" \
                        sh -c "systemctl disable --now '$s' 2>/dev/null || systemctl disable --now '$s.socket'" ;;
        esac
    done <<< "$plan"
    for s in $CP_CRITICAL; do
        s="${s%.service}"
        if systemctl list-unit-files "$s.service" --no-legend 2>/dev/null | grep -q .; then
            systemctl is-active --quiet "$s" || cp_act services "start + enable $s" "README critical service must be running" systemctl enable --now "$s"
        else
            cp_finding services "critical service '$s' is not installed (check README spelling: unit name e.g. ssh, vsftpd, apache2)"
        fi
    done
    command -v ss >/dev/null && ss -tulpnH 2>/dev/null | awk '{print $1, $5, $7}' | while read -r l; do
        cp_finding services "listening: $l"
    done
    return 0
}

#!/usr/bin/env bash
# Services. CP category: Service Auditing.
# Disables a known list of risky services UNLESS the README marks them critical
# (README words like "mysql" or "samba" are expanded to the real unit names - see common.sh).

CP_BAD_SERVICES="apache2 nginx lighttpd vsftpd proftpd pure-ftpd smbd nmbd samba telnet inetd xinetd openbsd-inetd \
rsh-server rlogin rexec nfs-server nfs-kernel-server rpcbind snmpd cups cups-browsed avahi-daemon isc-dhcp-server \
bind9 named postfix exim4 dovecot squid mysql mariadb postgresql tftpd-hpa atftpd xrdp vncserver x11vnc minetest-server"

# Pure. Arg: unit names (.service/.socket/.path, active or enabled). One DISABLE/KEEP line per service.
plan_services() {
    local u base seen=""
    for u in $1; do
        base="${u%.service}"; base="${base%.socket}"; base="${base%.path}"
        cp_in_list "$base" "$seen" && continue
        seen="$seen $base"
        cp_in_list "$base" "$CP_BAD_SERVICES" || continue
        if cp_is_protected_service "$base"; then
            echo "KEEP $base (critical)"
        else
            echo "DISABLE $base"
        fi
    done
}

_has_systemd() { [ -d /run/systemd/system ]; }

# Stop + disable the service and any socket/path unit that would start it again.
_svc_disable() {
    local s="$1" t any=1
    for t in service socket path; do
        if systemctl list-unit-files "$s.$t" --no-legend 2>/dev/null | grep -q .; then
            systemctl disable --now "$s.$t" && any=0
        fi
    done
    return $any
}

mod_services() {
    cp_header "SERVICES"
    if ! _has_systemd; then
        echo "  systemd is not running here - services module is REPORT ONLY"
        cp_finding services "systemd not running; services were not checked"
        return 0
    fi
    local c found s units plan act
    # Check README critical names FIRST so typos show up before anything is disabled.
    for c in $CP_CRITICAL; do
        found=""
        for s in $(CP_CRITICAL="$c"; cp_expand_critical; echo "$CP_CRITICAL_ALL"); do
            systemctl list-unit-files "$s.service" --no-legend 2>/dev/null | grep -q . && found="$found $s"
        done
        if [ -z "$found" ]; then cp_finding services "critical service '$c' matches no installed unit (check spelling: ssh, vsftpd, apache2, smbd, mariadb...)"; continue; fi
        for s in $found; do
            systemctl is-active --quiet "$s" || cp_act services "start + enable $s" "README critical service must be running" systemctl enable --now "$s"
        done
    done
    units="$( { systemctl list-unit-files --type=service,socket,path --state=enabled --no-legend 2>/dev/null | awk '{print $1}';
                systemctl list-units --type=service,socket,path --state=running,listening --no-legend 2>/dev/null | awk '{print $1}'; } | sort -u | xargs)"
    plan="$(plan_services "$units")"
    [ -z "$plan" ] && echo "  ok   no risky services enabled"
    while read -r act s _; do
        case "$act" in
            KEEP) echo "  ok   $s kept (README critical)" ;;
            DISABLE) cp_act services "stop + disable $s (and its socket/path units)" "risky service not required by README" _svc_disable "$s" ;;
        esac
    done <<< "$plan"
    command -v ss >/dev/null && ss -tulpnH 2>/dev/null | awk '{print $1, $5, $7}' | while read -r l; do
        cp_finding services "listening: $l"
    done
    return 0
}

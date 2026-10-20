#!/usr/bin/env bash
# UFW firewall. CP category: Defensive Countermeasures.
# deny incoming, allow outgoing (never block the scoring engine), open ports only for critical services.

# Critical service -> ufw allow arguments
declare -A CP_FW_PORTS=(
    [ssh]="22/tcp" [sshd]="22/tcp" [vsftpd]="21/tcp" [proftpd]="21/tcp" [pure-ftpd]="21/tcp"
    [apache2]="80/tcp 443/tcp" [nginx]="80/tcp 443/tcp" [lighttpd]="80/tcp 443/tcp"
    [smbd]="139/tcp 445/tcp" [samba]="139/tcp 445/tcp" [mysql]="3306/tcp" [mariadb]="3306/tcp"
    [postgresql]="5432/tcp" [postfix]="25/tcp" [dovecot]="143/tcp 993/tcp" [bind9]="53"
    [named]="53" [isc-dhcp-server]="67/udp" [cups]="631/tcp" [xrdp]="3389/tcp" [vnc]="5900/tcp"
)

_fw_install() { DEBIAN_FRONTEND=noninteractive apt-get install -y ufw; }

mod_firewall() {
    cp_header "FIREWALL  (ufw)"
    if ! command -v ufw >/dev/null; then
        cp_act firewall "install ufw" "no firewall tool present" _fw_install
        command -v ufw >/dev/null || return 0
    fi
    local status s c port ports="" known
    status="$(ufw status verbose 2>/dev/null)"
    for c in $CP_CRITICAL; do
        known=0
        for s in $(CP_CRITICAL="$c"; cp_expand_critical; echo "$CP_CRITICAL_ALL"); do
            [ -n "${CP_FW_PORTS[$s]:-}" ] && { known=1; ports="$ports ${CP_FW_PORTS[$s]}"; }
        done
        [ "$known" = 0 ] && cp_finding firewall "critical service '$c' has no known port - open it by hand if it listens on the network"
    done
    for port in $(echo $ports | tr ' ' '\n' | awk 'NF && !seen[$0]++'); do
        if echo "$status" | grep -qE "^${port%/*}(/${port#*/})?[[:space:]].*ALLOW"; then echo "  ok   $port allowed"
        else cp_act firewall "ufw allow $port" "a README critical service listens here" ufw allow "$port"; fi
    done
    echo "$status" | grep -q "Default: deny (incoming)" && echo "  ok   default deny incoming" \
        || cp_act firewall "ufw default deny incoming" "block unsolicited inbound traffic" ufw default deny incoming
    echo "$status" | grep -q "allow (outgoing)" && echo "  ok   default allow outgoing" \
        || cp_act firewall "ufw default allow outgoing" "never block the scoring engine" ufw default allow outgoing
    echo "$status" | grep -qE "^Logging: on" && echo "  ok   logging on" \
        || cp_act firewall "ufw logging on" "keeps a record of blocked traffic" ufw logging on
    echo "$status" | grep -q "^Status: active" && echo "  ok   ufw active" \
        || cp_act firewall "ufw --force enable" "turn the firewall on" ufw --force enable
    echo "$status" | grep -E "ALLOW" | grep -vE "^(22|21|80|443|139|445)" | while read -r l; do
        cp_finding firewall "existing allow rule: $l  (needed by README?)"
    done
    return 0
}

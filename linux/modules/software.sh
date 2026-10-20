#!/usr/bin/env bash
# Prohibited software. CP category: Policy Violation: Unwanted Software / Malware.
# Purges known hacking tools and games (one confirm each). Dual-use tools are only reviewed.

CP_BAD_PKGS="john john-data hydra hydra-gtk nmap zenmap ophcrack ophcrack-cli aircrack-ng wireshark wireshark-qt \
wireshark-gtk tshark ettercap-* kismet nikto sqlmap medusa netcat-traditional ncat fcrackzip p0f dsniff \
burpsuite metasploit* armitage hashcat crunch rainbowcrack yersinia macchanger driftnet \
freeciv* aisleriot gnome-mines gnome-sudoku gnome-mahjongg minetest* supertux* openarena* \
telnet rsh-client rsh-redone-client talk ftp transmission* deluge qbittorrent vuze frostwire"
CP_REVIEW_PKGS="netcat-openbsd tcpdump socat snort openvpn x11vnc remmina"

_pkg_match() {  # PKG "PATTERNS"  (glob-aware)
    local p
    for p in $2; do
        # shellcheck disable=SC2053
        [[ "$1" == $p ]] && return 0
    done
    return 1
}

# Pure. Arg: installed package names. Prints PURGE / REVIEW lines.
plan_software() {
    local pkg
    for pkg in $1; do
        _pkg_match "$pkg" "$CP_ALLOWED" && continue
        echo "$pkg" | grep -Eqi "$CP_SCORING_RE" && continue
        if _pkg_match "$pkg" "$CP_BAD_PKGS"; then echo "PURGE $pkg"
        elif _pkg_match "$pkg" "$CP_REVIEW_PKGS"; then echo "REVIEW $pkg"
        fi
    done
}

mod_software() {
    cp_header "SOFTWARE  (hacking tools, games, P2P)"
    local installed plan act p
    installed="$(dpkg-query -W -f='${Package} ${Status}\n' 2>/dev/null | awk '$4=="installed"{print $1}' | xargs)"
    plan="$(plan_software "$installed")"
    [ -z "$plan" ] && echo "  ok   no known bad packages"
    while read -r act p; do
        case "$act" in
            PURGE)  cp_act software "apt purge $p" "prohibited tool/game (not in ALLOWED_SOFTWARE)" \
                        sh -c "DEBIAN_FRONTEND=noninteractive apt-get purge -y '$p'" ;;
            REVIEW) cp_finding software "dual-use package $p installed - remove only if README doesn't need it" ;;
        esac
    done <<< "$plan"
    [ "$CP_MODE" = apply ] && [ -n "$plan" ] && cp_act software "apt autoremove" "remove leftover dependencies" \
        sh -c "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y"
    command -v snap >/dev/null && snap list 2>/dev/null | awk 'NR>1{print $1}' | while read -r s; do
        cp_finding software "snap installed: $s"
    done
    # Recently installed packages are where image makers hide things.
    zgrep -h ' install ' /var/log/dpkg.log* 2>/dev/null | sort | tail -25 | awk '{print $1, $4}' | while read -r d p; do
        cp_finding software "recently installed ($d): $p"
    done
    find /opt /usr/local/bin /usr/local/sbin -maxdepth 2 -mindepth 1 2>/dev/null | head -40 | while read -r f; do
        cp_finding software "non-packaged file: $f"
    done
    return 0
}

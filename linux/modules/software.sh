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

# Pure: read `apt-get -s purge PKG` output on stdin, print every OTHER package it would remove.
apt_sim_extra() {
    awk -v p="$1" '/^(Purg|Remv) / && $2 != p {print $2}'
}

mod_software() {
    cp_header "SOFTWARE  (hacking tools, games, P2P)"
    local installed plan act p purges extra e
    installed="$(dpkg-query -W -f='${Package} ${Status}\n' 2>/dev/null | awk '$4=="installed"{print $1}' | xargs)"
    plan="$(plan_software "$installed")"
    purges="$(echo "$plan" | awk '$1=="PURGE"{print $2}' | xargs)"
    [ -z "$plan" ] && echo "  ok   no known bad packages"
    while read -r act p; do
        case "$act" in
            PURGE)
                # Never let a purge silently take other packages with it (e.g. a metapackage holding ufw).
                extra=""
                for e in $(apt-get -s purge "$p" 2>/dev/null | apt_sim_extra "$p"); do
                    cp_in_list "$e" "$purges" || extra="$extra $e"
                done
                if [ -n "$extra" ]; then
                    cp_finding software "NOT purged $p: it would also remove$extra - decide by hand"
                    continue
                fi
                cp_act software "apt purge $p" "prohibited tool/game (not in ALLOWED_SOFTWARE)" \
                    sh -c "DEBIAN_FRONTEND=noninteractive apt-get purge -y '$p'" ;;
            REVIEW) cp_finding software "dual-use package $p installed - remove only if README doesn't need it" ;;
        esac
    done <<< "$plan"
    [ -n "$plan" ] && cp_finding software "leftover dependencies: run 'sudo apt-get autoremove' by hand AFTER reading its list"
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

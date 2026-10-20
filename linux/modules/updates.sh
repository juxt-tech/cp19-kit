#!/usr/bin/env bash
# Updates. CP categories: Operating System Updates / Application Updates.

CP_OFFICIAL_MIRRORS='(deb\.debian\.org|security\.debian\.org|ftp\.[a-z.]*debian\.org|archive\.ubuntu\.com|security\.ubuntu\.com|ports\.ubuntu\.com|[a-z]+\.archive\.ubuntu\.com|packages\.linuxmint\.com|linuxmint\.[a-z.]+|archive\.canonical\.com)'

# 0 = FILE has a disabled OFFICIAL source (commented deb line in *.list, or "Enabled: no" in deb822 *.sources).
upd_source_needs_fix() {
    case "$1" in
        *.sources) grep -qiE '^[[:space:]]*Enabled:[[:space:]]*no' "$1" ;;
        *) grep -qE "^[[:space:]]*#[[:space:]]*deb[[:space:]]+(\[[^]]*\][[:space:]]+)?https?://$CP_OFFICIAL_MIRRORS" "$1" ;;
    esac
}

# Re-enable official sources only - a commented-out unknown repo stays off (it may be planted).
upd_fix_source() {
    case "$1" in
        *.sources) sed -i -E 's/^([[:space:]]*Enabled:[[:space:]]*)no[[:space:]]*$/\1yes/I' "$1" ;;
        *) sed -i -E "s#^[[:space:]]*\#[[:space:]]*(deb[[:space:]]+(\[[^]]*\][[:space:]]+)?https?://$CP_OFFICIAL_MIRRORS)#\1#" "$1" ;;
    esac
}
_upd_auto() {
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
}
_upd_run() { DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade; }

_upd_refresh() { DEBIAN_FRONTEND=noninteractive apt-get update; }

# Quick step that runs BEFORE any module installs packages (pwquality, ufw):
# re-enable official apt sources, then refresh the package lists.
mod_sources() {
    [ "${mod_sources_quiet:-0}" = 1 ] || cp_header "APT SOURCES  (so later modules can install packages)"
    local f fixed=0
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [ -f "$f" ] || continue
        if upd_source_needs_fix "$f"; then
            cp_backup "$f"
            cp_act sources "re-enable official sources in $f" "disabled sources = no installs, no security updates" upd_fix_source "$f"
            fixed=1
        fi
    done
    if [ "$fixed" = 1 ]; then
        cp_act sources "apt-get update" "load package lists from the re-enabled sources" _upd_refresh
    else
        echo "  ok   official apt sources enabled"
    fi
    return 0
}

mod_updates() {
    cp_header "UPDATES"
    mod_sources_quiet=1 mod_sources
    grep -rhsE '^[^#]*deb ' /etc/apt/sources.list.d/ /etc/apt/sources.list 2>/dev/null | \
        grep -Ev 'debian\.org|ubuntu\.com|linuxmint\.com|canonical\.com|mirror' | while read -r l; do
        cp_finding updates "unusual apt source: $l"
    done
    if grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades && grep -qs 'Update-Package-Lists "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
        echo "  ok   automatic updates enabled"
    else
        cp_backup /etc/apt/apt.conf.d/20auto-upgrades
        cp_act updates "enable daily automatic update checks + unattended upgrades" "scored: automatic updates" _upd_auto
    fi
    dpkg -s unattended-upgrades >/dev/null 2>&1 || cp_act updates "install unattended-upgrades" "needed for automatic security updates" \
        sh -c "DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades"
    [ -f /etc/linuxmint/info ] && cp_finding updates "Mint: also open Update Manager > Edit > Preferences > Automation and turn on automatic updates (GUI-scored)"
    cp_finding updates "update critical apps the README names (firefox, the web server, etc.) - they're scored separately"
    if [ "${CP_SKIP_UPGRADE:-0}" = 1 ]; then echo "  (full upgrade skipped: CP_SKIP_UPGRADE=1)"; return 0; fi
    cp_act updates "apt-get update && apt-get -y upgrade (can take 10+ minutes)" "OS updates are scored" _upd_run
    return 0
}

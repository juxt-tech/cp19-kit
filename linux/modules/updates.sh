#!/usr/bin/env bash
# Updates. CP categories: Operating System Updates / Application Updates.

_upd_sources() { sed -i -E 's/^#[[:space:]]*(deb(-src)?[[:space:]]+(http|https|mirror))/\1/' /etc/apt/sources.list; }
_upd_auto() {
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
}
_upd_run() { DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade; }

mod_updates() {
    cp_header "UPDATES"
    if [ -f /etc/apt/sources.list ] && grep -qE '^#[[:space:]]*deb[[:space:]]+(http|https)' /etc/apt/sources.list; then
        cp_backup /etc/apt/sources.list
        cp_act updates "uncomment deb lines in /etc/apt/sources.list" "commented sources = no security updates" _upd_sources
    fi
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

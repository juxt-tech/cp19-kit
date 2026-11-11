#!/usr/bin/env bash
# Integrity: package files that were edited after install, and files locked with chattr.
# CP categories: Malware / Uncategorized OS Settings. Seen on ETH007 Arena (Debian 11):
# /usr/sbin/ufw edited to launch a browser instead of working, pam_deny.so replaced,
# journald units edited, /etc/crontab locked immutable around a reverse-shell cron line.
#
# Security tools are reinstalled (apply); everything else is reported with the exact fix.

# Reinstalling these restores the original files and is safe on a live box.
CP_REINSTALL_PKGS="ufw libpam-modules libpam-modules-bin libpam-runtime sudo passwd login openssh-server \
openssh-client coreutils procps findutils grep sed util-linux iproute2 net-tools psmisc cron bash \
libpam-pwquality iptables"
# Files the kit edits itself: an immutable bit here makes those modules fail.
CP_UNLOCK_FILES="/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/crontab /etc/login.defs \
/etc/ssh/sshd_config /etc/sysctl.conf /etc/security/pwquality.conf /etc/security/faillock.conf \
/etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/common-account /etc/apt/sources.list \
/etc/hosts /etc/lightdm/lightdm.conf /etc/default/ufw /etc/ufw/ufw.conf"

# Pure. `dpkg -V` lines on stdin -> paths whose checksum changed, conffiles excluded (admins edit those).
integ_changed_files() {
    awk '$1 ~ /^..5/ && $2 != "c" { print $NF }'
}

integ_reinstall_ok() { cp_in_list "$1" "$CP_REINSTALL_PKGS"; }

# Pure. `lsattr` lines on stdin -> files with the immutable (i) or append-only (a) flag.
integ_locked_files() {
    # lsattr -R also prints "/dir:" headers and blank lines: the flags field is letters and dashes only.
    awk '{ f = $1; sub(/^[^ ]+[ \t]+/, "", $0) } f ~ /^[-A-Za-z]+$/ && f ~ /[ia]/ { print $0 }'
}

# Exact installed version first: restores the files without upgrading anything, and works when the
# newer version in the index is already gone from the mirror (Debian 11 after EOL: 404 on security.d.o).
_integ_reinstall() {
    local v; v="$(dpkg-query -W -f='${Version}' "$1" 2>/dev/null)"
    export DEBIAN_FRONTEND=noninteractive
    { [ -n "$v" ] && apt-get install -y --reinstall "$1=$v" >/dev/null 2>&1; } \
        || apt-get install -y --reinstall "$1" >/dev/null 2>&1 \
        || apt-get install -y --only-upgrade "$1" >/dev/null 2>&1
    [ -z "$(dpkg -V "$1" 2>/dev/null | integ_changed_files)" ]   # verify, don't trust the exit code
}

# 0 when pam_deny.so in DIR is byte-identical to pam_permit.so (ETH007 image): every "deny" lets you in.
integ_pam_deny_is_permit() {
    local d="$1"
    [ -f "$d/pam_deny.so" ] && [ -f "$d/pam_permit.so" ] && cmp -s "$d/pam_deny.so" "$d/pam_permit.so"
}

mod_integrity() {
    cp_header "INTEGRITY  (edited package files, chattr-locked files)"
    local f p pkgs="" changed
    # 1. Locked files: unlock the ones later modules must edit; report every locked file under /etc.
    # shellcheck disable=SC2086  # $CP_UNLOCK_FILES is split into paths on purpose
    while read -r f; do
        [ -n "$f" ] || continue
        if cp_in_list "$f" "$CP_UNLOCK_FILES" || [[ "$f" == /etc/cron.d/* ]] || [[ "$f" == /etc/sudoers.d/* ]] || [[ "$f" == /etc/pam.d/* ]]; then
            cp_act integrity "chattr -i -a $f" "locked file: the kit (and you) cannot fix or clean it" chattr -i -a "$f"
        else
            cp_finding integrity "locked (chattr +i/+a) file: $f  - check it, then: chattr -i -a '$f'"
        fi
    done < <({ lsattr -d $CP_UNLOCK_FILES 2>/dev/null; lsattr -R /etc /var/spool/cron 2>/dev/null; } | integ_locked_files | sort -u)

    for f in /lib/*/security /usr/lib/*/security /lib/security; do
        integ_pam_deny_is_permit "$f" && cp_finding integrity "$f/pam_deny.so IS A COPY OF pam_permit.so - failed logins are let in. Reinstall libpam-modules (this module does it)"
    done

    # 2. Package files edited after install (~1 min).
    echo "  checking package file checksums (dpkg -V, about a minute)..."
    changed="$(dpkg -V 2>/dev/null | integ_changed_files)"
    if [ -z "$changed" ]; then echo "  ok   no package file was edited"; return 0; fi
    while read -r f; do
        p="$(dpkg -S "$f" 2>/dev/null | head -1 | cut -d: -f1)"
        [ -n "$p" ] || p="?"
        cp_finding integrity "EDITED package file: $f  (package $p)"
        cp_in_list "$p" "$pkgs" || pkgs="$pkgs $p"
    done <<< "$changed"
    for p in $pkgs; do
        if integ_reinstall_ok "$p"; then
            cp_act integrity "reinstall $p (its files were edited)" "a trojaned security tool lies to you" _integ_reinstall "$p"
        else
            cp_finding integrity "package $p has edited files - after checking them: sudo apt-get install --reinstall $p"
        fi
    done
    return 0
}

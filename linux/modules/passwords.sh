#!/usr/bin/env bash
# Password + lockout policy. CP category: Account Policies.
# Values: PASS_MAX_DAYS 90, PASS_MIN_DAYS 10, PASS_WARN_AGE 7, minlen 10 + 1 of each class,
# remember 5, faillock deny 5 / unlock 1800s. PAM is edited through pam-auth-update profiles so
# Debian's jump counts stay correct; any PAM edit that loses pam_unix is rolled back.

_pw_set() {  # FILE KEY VALUE [SEP]  - audit-aware wrapper around cp_set_conf
    local cur; cur="$(cp_conf_get "$1" "$2")"
    if [ "$cur" = "$3" ]; then echo "  ok   $2 = $3 ($1)"; return; fi
    cp_act passwords "set $2 ${4:- }$3 in $1 (now: ${cur:-unset})" "password policy" cp_set_conf "$1" "$2" "$3" "${4:- }"
}

_pam_ok() { grep -q pam_unix.so /etc/pam.d/common-auth && grep -q pam_unix.so /etc/pam.d/common-password; }

_pam_restore_if_broken() {
    if ! _pam_ok; then
        local f
        for f in common-auth common-password common-account; do
            [ -f "$CP_RUN/backup/etc/pam.d/$f" ] && cp -a "$CP_RUN/backup/etc/pam.d/$f" "/etc/pam.d/$f"
        done
        echo "  !! PAM edit reverted (pam_unix line missing after edit)"
        cp_log passwords FAILED "pam edit" reverted "sanity check failed"
    fi
}

_faillock_profiles() {
    cat > /usr/share/pam-configs/cpkit-faillock <<'EOF'
Name: cpkit: lock account after failed logins (pam_faillock authfail)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
EOF
    cat > /usr/share/pam-configs/cpkit-faillock-notify <<'EOF'
Name: cpkit: pam_faillock preauth + account check
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth
Account-Type: Primary
Account:
	required	pam_faillock.so
EOF
    DEBIAN_FRONTEND=noninteractive pam-auth-update --enable cpkit-faillock --enable cpkit-faillock-notify
    _faillock_verify   # pam-auth-update exits 0 even when it refuses, so check the result
}

# pam-auth-update refuses (and still exits 0) when common-auth was hand-edited.
_faillock_verify() {
    local f="${1:-/etc/pam.d/common-auth}"
    grep -qE '^[^#]*pam_faillock\.so' "$f" && return 0
    echo "       pam_faillock was NOT added: $f has hand edits pam-auth-update won't overwrite"
    cp_finding passwords "pam_faillock NOT enabled: pam-auth-update refused (hand-edited $f). Read the file for planted lines, then run: pam-auth-update --force (see checklists/linux.md, lockout)"
    return 1
}

# remember= value on the active pam_unix line ("" when there is none).
pam_remember_value() {
    grep -E '^[^#]*pam_unix\.so' "${1:-/etc/pam.d/common-password}" | grep -oE 'remember=[0-9]+' | head -1 | cut -d= -f2
}
_pam_remember() {
    sed -i -E '/^[^#]*pam_unix\.so/{s/remember=[0-9]+/remember=5/;/remember=/!s/(pam_unix\.so.*)$/\1 remember=5/}' "${1:-/etc/pam.d/common-password}"
}
_pam_nullok()   { sed -i -E 's/[[:space:]]nullok(_secure)?//g' /etc/pam.d/common-auth /etc/pam.d/common-password; }

mod_passwords() {
    cp_header "PASSWORDS  (login.defs, pwquality, history, lockout)"
    _pw_set /etc/login.defs PASS_MAX_DAYS 90
    _pw_set /etc/login.defs PASS_MIN_DAYS 10
    _pw_set /etc/login.defs PASS_WARN_AGE 7
    case "$(cp_conf_get /etc/login.defs ENCRYPT_METHOD)" in
        SHA512|YESCRYPT) echo "  ok   ENCRYPT_METHOD strong" ;;   # yescrypt (Debian 12) is stronger; never downgrade
        *) _pw_set /etc/login.defs ENCRYPT_METHOD SHA512 ;;
    esac

    if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
        cp_act passwords "install libpam-pwquality" "enforces password complexity" \
            sh -c "DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality"
    fi
    if [ -f /etc/security/pwquality.conf ] || [ "$CP_MODE" = audit ]; then
        local k
        for k in "minlen 10" "ucredit -1" "lcredit -1" "dcredit -1" "ocredit -1" "dictcheck 1" "usercheck 1"; do
            set -- $k; _pw_set /etc/security/pwquality.conf "$1" "$2" " = "
        done
    fi

    [ -f /etc/pam.d/common-password ] || { cp_finding passwords "no /etc/pam.d/common-password - not a Debian-family system?"; return 0; }
    cp_backup /etc/pam.d/common-auth; cp_backup /etc/pam.d/common-password; cp_backup /etc/pam.d/common-account

    local rem; rem="$(pam_remember_value)"
    if [ -n "$rem" ] && [ "$rem" -ge 5 ]; then echo "  ok   password history remember=$rem"
    else cp_act passwords "set remember=5 on pam_unix (was: ${rem:-none})" "blocks reusing the last 5 passwords" _pam_remember; fi

    if grep -qE 'nullok' /etc/pam.d/common-auth /etc/pam.d/common-password; then
        cp_act passwords "remove nullok from PAM" "nullok lets accounts with empty passwords log in" _pam_nullok
    else echo "  ok   no nullok in PAM"; fi

    for k in "deny 5" "unlock_time 1800" "fail_interval 900"; do
        set -- $k; _pw_set /etc/security/faillock.conf "$1" "$2" " = "
    done
    if grep -qE '^[^#]*pam_faillock\.so' /etc/pam.d/common-auth; then echo "  ok   pam_faillock already in common-auth"
    elif command -v pam-auth-update >/dev/null; then
        cp_act passwords "enable pam_faillock via pam-auth-update" "locks accounts after 5 failed logins" _faillock_profiles
    else cp_finding passwords "pam-auth-update missing - add pam_faillock by hand"; fi

    [ "$CP_MODE" = apply ] && _pam_restore_if_broken

    grep -nE 'pam_permit\.so|pam_exec\.so' /etc/pam.d/common-auth 2>/dev/null | grep -v 'required[[:space:]]*pam_permit' | while read -r l; do
        cp_finding passwords "suspicious line in common-auth: $l"
    done
    # existing accounts keep old max-age until chage is run
    local u
    for u in $(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd); do
        local max; max="$(chage -l "$u" 2>/dev/null | awk -F': ' '/Maximum number/ {print $2}')"
        if [ "$max" != "90" ]; then
            cp_act passwords "chage -M 90 -m 10 -W 7 $u (now max=$max)" "login.defs only affects NEW users" chage -M 90 -m 10 -W 7 "$u"
        fi
    done
}

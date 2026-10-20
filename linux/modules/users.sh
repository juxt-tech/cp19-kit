#!/usr/bin/env bash
# Users module: make accounts and sudo membership match the README.
# CP category: User Auditing. Never deletes home directories (files may be forensics evidence).

# Pure planner. Args: "HUMANS" "SUDO_MEMBERS" "UID0_ACCOUNTS" "EMPTY_PASSWORD_ACCOUNTS"
# Prints one action per line. Reads only its args + CP_ADMINS/CP_USERS/SUDO_USER.
plan_users() {
    local humans="$1" sudoers="$2" uid0="$3" emptypw="$4" u
    if [ -z "$CP_ADMINS" ]; then
        echo "users: ADMINS is empty in the config - refusing to plan (fill it from the README)" >&2
        return 1
    fi
    for u in $humans; do
        if ! cp_in_list "$u" "$CP_ADMINS $CP_USERS" && [ "$u" != "${SUDO_USER:-}" ]; then
            echo "REMOVE_USER $u"
        fi
    done
    for u in $CP_ADMINS $CP_USERS; do
        cp_in_list "$u" "$humans" || echo "ADD_USER $u"
    done
    for u in $sudoers; do
        cp_in_list "$u" "$CP_ADMINS" || [ "$u" = "${SUDO_USER:-}" ] || echo "DEL_SUDO $u"
    done
    for u in $CP_ADMINS; do
        cp_in_list "$u" "$sudoers" || echo "ADD_SUDO $u"
    done
    for u in $uid0; do
        [ "$u" = "root" ] || echo "DEL_UID0 $u"
    done
    for u in $emptypw; do
        [ "$u" = "root" ] || echo "SET_PASS $u"
    done
    echo "LOCK_ROOT"
}

_users_state() {
    HUMANS="$(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd | xargs)"
    SUDOERS="$(getent group sudo | cut -d: -f4 | tr ',' ' ' | xargs)"
    UID0="$(awk -F: '$3==0 {print $1}' /etc/passwd | xargs)"
    EMPTYPW="$(awk -F: '$2=="" {print $1}' /etc/shadow | xargs)"
}

_set_pass() { echo "$1:$CP_NEWPASS" | chpasswd; }

mod_users() {
    cp_header "USERS  (README authorized admins/users)"
    local plan line act u
    _users_state
    echo "  admins in config : $CP_ADMINS"
    echo "  users in config  : $CP_USERS"
    echo "  humans on box    : $HUMANS"
    echo "  sudo group       : $SUDOERS"
    plan="$(plan_users "$HUMANS" "$SUDOERS" "$UID0" "$EMPTYPW")" || return 0
    while read -r act u; do
        case "$act" in
            REMOVE_USER) cp_act users "delete user $u (home kept)" "not in README" userdel "$u" ;;
            ADD_USER)
                if [ -z "$CP_NEWPASS" ]; then cp_finding users "README user $u missing but NEW_PASSWORD empty - create by hand"; continue; fi
                cp_act users "create user $u" "listed in README but missing" sh -c "useradd -m -s /bin/bash '$u' && echo '$u:$CP_NEWPASS' | chpasswd" ;;
            DEL_SUDO)    cp_act users "remove $u from sudo" "not an authorized admin" gpasswd -d "$u" sudo ;;
            ADD_SUDO)    cp_act users "add $u to sudo" "authorized admin" gpasswd -a "$u" sudo ;;
            DEL_UID0)    cp_backup /etc/passwd; cp_backup /etc/shadow
                         cp_act users "delete hidden root account $u (UID 0)" "only root may have UID 0" userdel -f "$u" ;;
            SET_PASS)
                if [ -z "$CP_NEWPASS" ]; then cp_finding users "$u has an EMPTY password - set one by hand"; continue; fi
                cp_act users "set password for $u" "account has an empty password" _set_pass "$u" ;;
            LOCK_ROOT)
                if passwd -S root 2>/dev/null | awk '{exit !($2=="L")}'; then echo "  ok   root already locked"
                else cp_act users "lock root password" "admins use sudo; direct root login is a target" passwd -l root; fi ;;
        esac
    done <<< "$plan"
    # Other admin-ish groups and sudoers rules: report only (a human decides).
    for g in admin wheel adm lpadmin sambashare; do
        local mem; mem="$(getent group "$g" | cut -d: -f4)"
        [ -n "$mem" ] && cp_finding users "group $g members: $mem  (check against README)"
    done
    grep -rhsE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ | while read -r l; do
        cp_finding users "sudoers NOPASSWD rule: $l"
    done
    awk -F: '$3<1000 && $3!=0 && $7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1" "$7}' /etc/passwd | while read -r n sh; do
        cp_finding users "system account $n has a login shell ($sh)"
    done
    _users_guest_login
}

# LightDM (Mint) guest + autologin.
_users_guest_login() {
    [ -d /etc/lightdm ] || return 0
    local f=/etc/lightdm/lightdm.conf.d/50-cpkit.conf
    if grep -rqs '^allow-guest=false' /etc/lightdm/; then echo "  ok   guest login disabled"
    else cp_act users "disable guest login (lightdm)" "guest sessions bypass accounts" \
        sh -c "mkdir -p /etc/lightdm/lightdm.conf.d && printf '[Seat:*]\nallow-guest=false\ngreeter-hide-users=true\n' > $f"; fi
    grep -rhs '^autologin-user=' /etc/lightdm/ | while read -r l; do
        cp_finding users "lightdm $l  (remove it unless README needs autologin)"
    done
}

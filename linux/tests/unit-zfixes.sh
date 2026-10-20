# Sourced by unit.sh. Regression tests for the final-review findings.
echo "== review fixes"
CP_ADMINS="santa"; CP_USERS="dasher"; SUDO_USER=""; CP_ME=""

# C1: a README user planted with UID 0 is FIXED (new UID), never deleted / re-added
p="$(plan_users "dasher" "" "root santa" "")"
case $'\n'"$p"$'\n' in *$'\nFIX_UID0 santa\n'*) ok "C1 listed uid0 user gets FIX_UID0";; *) bad "C1 listed uid0 user gets FIX_UID0" "$p";; esac
case "$p" in *"DEL_UID0 santa"*) bad "C1 listed uid0 user not deleted" "$p";; *) ok "C1 listed uid0 user not deleted";; esac
case "$p" in *"ADD_USER santa"*) bad "C1 uid0 user not re-added" "$p";; *) ok "C1 uid0 user not re-added";; esac

# I10: operator detected without SUDO_USER (sudo su -) via CP_ME
CP_ME="operatorx"
p="$(plan_users "operatorx dasher" "operatorx santa" "root" "")"
case "$p" in *"REMOVE_USER operatorx"*|*"DEL_SUDO operatorx"*) bad "I10 CP_ME operator protected" "$p";; *) ok "I10 CP_ME operator protected";; esac
CP_ME=""

# C2: service aliases - mysql protects mariadb, samba protects smbd+nmbd
CP_CRITICAL="mysql samba"; cp_expand_critical
yes_ "C2 mysql protects mariadb"  cp_is_protected_service mariadb
yes_ "C2 samba protects smbd"     cp_is_protected_service smbd
yes_ "C2 samba protects nmbd"     cp_is_protected_service nmbd
p="$(plan_services "mariadb.service smbd.service")"
case "$p" in *DISABLE*) bad "C2 aliased critical not disabled" "$p";; *) ok "C2 aliased critical not disabled";; esac

# I3: service + socket of the same thing planned once
CP_CRITICAL=""; cp_expand_critical
eq "I3 cups.service+socket planned once" "$(plan_services "cups.service cups.socket cups.path" | grep -c 'DISABLE cups')" "1"

# I5: duplicate keys -> conflict detected; new keys go above Match blocks
f="$T/sshd_dup"
printf 'PermitRootLogin no\nPermitRootLogin yes\n' > "$f"
no_ "I5 conflicting duplicates not reported as compliant" test "$(cp_conf_get "$f" PermitRootLogin)" = "no"
printf 'Port 22\nMatch User sftp\n  ChrootDirectory /srv\n' > "$f"
cp_set_conf "$f" UsePAM yes
eq "I5 new key inserted before Match" "$(grep -n '' "$f" | grep -m1 -E 'UsePAM|Match' | cut -d: -f2-)" "UsePAM yes"

# I4: conflicting sysctl lines in other files are found
f="$T/sysctl.conf"
printf 'net.ipv4.ip_forward=1\n# net.ipv4.tcp_syncookies=0\nnet.ipv4.tcp_syncookies = 0\nvm.swappiness=10\n' > "$f"
c="$(plan_sysctl_conflicts "$f")"
case "$c" in *"net.ipv4.ip_forward"*) ok "I4 ip_forward=1 conflict found";; *) bad "I4 ip_forward conflict" "$c";; esac
case "$c" in *"net.ipv4.tcp_syncookies"*) ok "I4 spaced syncookies conflict found";; *) bad "I4 syncookies conflict" "$c";; esac
case "$c" in *swappiness*) bad "I4 unrelated key left alone" "$c";; *) ok "I4 unrelated key left alone";; esac

# I6: apt simulation - extra packages that a purge would drag along
sim=$'Purg telnet [0.17-44]\nRemv ubuntu-standard [1.481]\nPurg telnet-ssl [1]'
eq "I6 dependents detected" "$(apt_sim_extra telnet <<< "$sim" | xargs)" "ubuntu-standard telnet-ssl"
eq "I6 lone purge has no extras" "$(apt_sim_extra john <<< 'Purg john [1.9]' | xargs)" ""
CP_ADMINS="santa prancer"; CP_USERS="cupid dasher"; CP_CRITICAL="ssh vsftpd"; cp_expand_critical

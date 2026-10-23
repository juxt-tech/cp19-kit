# Sourced by unit.sh. Tests for plan_users (pure).
echo "== users: plan_users"
CP_ADMINS="santa prancer"; CP_USERS="cupid dasher"
# humans on box: santa prancer dasher hacker ; sudo members: santa dasher ; uid0: root toor ; empty pw: dasher
SUDO_USER=""
p="$(plan_users "santa prancer dasher hacker" "santa dasher" "root toor" "dasher")"
has() { case $'\n'"$p"$'\n' in *$'\n'"$2"$'\n'*) ok "$1";; *) bad "$1" "plan was: $(echo "$p" | tr '\n' ';')";; esac; }
hasnt() { case $'\n'"$p"$'\n' in *$'\n'"$2"$'\n'*) bad "$1" "plan was: $(echo "$p" | tr '\n' ';')";; *) ok "$1";; esac; }
has   "unknown human removed"           "REMOVE_USER hacker"
has   "missing listed user added"       "ADD_USER cupid"
has   "non-admin in sudo demoted"       "DEL_SUDO dasher"
has   "admin not in sudo promoted"      "ADD_SUDO prancer"
has   "extra uid0 account flagged"      "DEL_UID0 toor"
hasnt "root uid0 left alone"            "DEL_UID0 root"
has   "empty password gets one"         "SET_PASS dasher"
has   "root locked"                     "LOCK_ROOT"
hasnt "authorized user never removed"   "REMOVE_USER santa"

SUDO_USER="operatorx"
p="$(plan_users "santa operatorx" "santa operatorx" "root" "")"
hasnt "sudo-invoking user never removed even if not in config" "REMOVE_USER operatorx"
hasnt "sudo-invoking user never demoted"                       "DEL_SUDO operatorx"
SUDO_USER=""

CP_ADMINS=""
no_ "plan refuses with empty ADMINS" plan_users "a" "a" "root" ""
CP_ADMINS="santa prancer"

# Ideas from ponkio/CyberPatriot: duplicate UIDs, gdm3 autologin
f="$T/passwd_dup"
printf 'root:x:0:0::/root:/bin/bash\nsanta:x:1000:1000::/home/santa:/bin/bash\nsneaky:x:1000:1000::/home/sneaky:/bin/bash\ncupid:x:1001:1001::/home/cupid:/bin/bash\n' > "$f"
eq "duplicate UID found"         "$(dup_uids "$f")" "1000 santa sneaky"
printf 'root:x:0:0::/root:/bin/bash\nsanta:x:1000:1000::/home/santa:/bin/bash\n' > "$f"
eq "no duplicate UID -> empty"   "$(dup_uids "$f")" ""
g="$T/gdm-custom.conf"
printf '[daemon]\nAutomaticLoginEnable = true\nAutomaticLogin = santa\n' > "$g"
yes_ "gdm3 autologin detected"   gdm_autologin_on "$g"
printf '[daemon]\n# AutomaticLoginEnable = true\nAutomaticLoginEnable=false\n' > "$g"
no_  "gdm3 autologin off ignored" gdm_autologin_on "$g"

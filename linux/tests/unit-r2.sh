# Sourced by unit.sh. Fixes found on the first real Linux image (ETH007 Arena, Debian 11, 2026-11-10).

echo "== r2: scoring client names protected"
yes_ "CSSClient service protected (Aeacus unit name)" cp_is_protected_service CSSClient.service
yes_ "phocus protected (Aeacus binary)"               cp_is_protected_service phocus

echo "== r2: RESET_PASSWORDS parsed on Linux"
printf 'ADMINS=a\nUSERS=b\nRESET_PASSWORDS=yes\n' > "$T/cfg-reset.txt"
cp_load_config "$T/cfg-reset.txt" 2>"$T/cfg-reset.err"
eq   "RESET_PASSWORDS value"            "$CP_RESETPW" "yes"
no_  "RESET_PASSWORDS not 'unknown key'" grep -q "unknown key" "$T/cfg-reset.err"
cp_load_config "$ROOT/config/cp-config.example.txt"   # later test files expect the example config

echo "== r2: plan_users RESET_PASS"
CP_ADMINS="santa prancer"; CP_USERS="cupid dasher"; SUDO_USER=""; CP_ME="santa"; CP_RESETPW=yes
# humans: santa prancer dasher ; cupid missing ; dasher has empty pw ; prancer changed today
p="$(plan_users "santa prancer dasher" "santa prancer" "root" "dasher" "prancer")"
has()   { case $'\n'"$p"$'\n' in *$'\n'"$2"$'\n'*) ok "$1";; *) bad "$1" "plan was: $(echo "$p" | tr '\n' ';')";; esac; }
hasnt() { case $'\n'"$p"$'\n' in *$'\n'"$2"$'\n'*) bad "$1" "plan was: $(echo "$p" | tr '\n' ';')";; *) ok "$1";; esac; }
hasnt "current user's password never reset (auto-login user)" "RESET_PASS santa"
hasnt "password changed today not reset again (2nd run clean)" "RESET_PASS prancer"
hasnt "empty-password user gets SET_PASS, not a 2nd reset"     "RESET_PASS dasher"
hasnt "missing user is created, not reset"                     "RESET_PASS cupid"
p="$(plan_users "santa prancer dasher" "santa prancer" "root" "" "")"
has   "README admin gets RESET_PASS"                           "RESET_PASS prancer"
has   "README user gets RESET_PASS"                            "RESET_PASS dasher"
CP_RESETPW=""
p="$(plan_users "santa prancer dasher" "santa prancer" "root" "" "")"
hasnt "no RESET_PASS unless RESET_PASSWORDS=yes"               "RESET_PASS prancer"
CP_ME=""

echo "== r2: password age would expire at once"
# today 20768, password from day 19725 (1043 days old): max 90 expires it -> logins (and Dovecot PAM) fail
yes_ "1043-day-old password expires under max 90"  pw_would_expire 19725 20768 90
no_  "10-day-old password is fine under max 90"     pw_would_expire 20758 20768 90
no_  "lastchg 0 (forced change) left alone"         pw_would_expire 0 20768 90
no_  "empty lastchg left alone"                     pw_would_expire "" 20768 90

echo "== r2: foreign-distro apt repos"
l="$T/kali.list"
printf 'deb http://deb.debian.org/debian/ bullseye main\ndeb http://http.kali.org/kali kali-rolling main non-free contrib\ndeb-src http://http.kali.org/kali kali-rolling main\n# deb http://http.kali.org/kali old main\ndeb http://dl.google.com/linux/chrome/deb/ stable main\n' > "$l"
eq   "two live kali lines found"            "$(upd_foreign_lines "$l" | wc -l | tr -d ' ')" "2"
upd_disable_foreign "$l"
eq   "no live kali lines after fix"         "$(upd_foreign_lines "$l" | wc -l | tr -d ' ')" "0"
yes_ "debian line untouched"                grep -qx "deb http://deb.debian.org/debian/ bullseye main" "$l"
yes_ "other third-party repo untouched (report only)" grep -qx "deb http://dl.google.com/linux/chrome/deb/ stable main" "$l"
no_  "disabled kali line not re-enabled as official" upd_source_needs_fix "$l"

echo "== r2: persistence unit filter"
mkdir -p "$T/units/multi-user.target.wants" "$T/lib/systemd/system" "$T/opt"
: > "$T/lib/systemd/system/cron.service"; : > "$T/opt/evil.service"; : > "$T/units/backdoor.service"
ln -s "$T/lib/systemd/system/cron.service" "$T/units/multi-user.target.wants/cron.service"
ln -s "$T/opt/evil.service" "$T/units/multi-user.target.wants/evil.service"
ln -s /dev/null "$T/units/masked.service"
CP_UNIT_LIB_RE="^$T/lib/systemd/"
no_  "symlink into /lib/systemd not reported" persist_unit_suspect "$T/units/multi-user.target.wants/cron.service"
yes_ "symlink to /opt reported"               persist_unit_suspect "$T/units/multi-user.target.wants/evil.service"
yes_ "regular unit file reported"             persist_unit_suspect "$T/units/backdoor.service"
no_  "masked unit (-> /dev/null) not reported" persist_unit_suspect "$T/units/masked.service"
unset CP_UNIT_LIB_RE

echo "== r2: media report skips vendor code and the harness kit dir"
eq "vendor + node_modules + /root/cpkit dropped" \
   "$(printf '/var/www/html/vendor/x/Password.php\n/srv/app/node_modules/p/password.js\n/root/cpkit/linux/modules/passwords.sh\n/home/bob/passwords.txt\n' | CP_KIT_ROOT=/root/cpkit media_not_kit)" \
   "/home/bob/passwords.txt"

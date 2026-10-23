# Sourced by unit.sh. PAM history + lockout: no false "done" / false "ok".
echo "== passwords: PAM remember + faillock"

f="$T/common-password"
printf 'password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt remember=0\n' > "$f"
eq  "remember=0 is read as 0 (not ok)"     "$(pam_remember_value "$f")" "0"
_pam_remember "$f"
eq  "remember=0 raised to 5"               "$(pam_remember_value "$f")" "5"
eq  "only one remember= on the line"       "$(grep -o 'remember=' "$f" | wc -l | tr -d ' ')" "1"
printf 'password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt\n' > "$f"
_pam_remember "$f"
eq  "missing remember= added as 5"         "$(pam_remember_value "$f")" "5"
printf '# pam_unix.so remember=9\npassword\trequired\tpam_unix.so sha512\n' > "$f"
eq  "commented remember= ignored"          "$(pam_remember_value "$f")" ""

a="$T/common-auth"
printf 'auth\t[success=1 default=ignore]\tpam_unix.so\n# auth required pam_faillock.so authfail\n' > "$a"
CP_MODE=apply; CP_YES=1
cp_act passwords "enable pam_faillock (refused case)" "test" _faillock_verify "$a" >/dev/null
yes_ "pam-auth-update refusal logged FAILED, not done" grep -q "| passwords | FAILED | enable pam_faillock (refused case)" "$CP_RUN/log.txt"
yes_ "refusal leaves a findings entry"                 grep -q "pam_faillock NOT enabled" "$CP_RUN/findings.txt"
printf 'auth\t[default=die]\tpam_faillock.so authfail\n' >> "$a"
cp_act passwords "enable pam_faillock (ok case)" "test" _faillock_verify "$a" >/dev/null
yes_ "real faillock line counts as done"               grep -q "| passwords | ACTION | enable pam_faillock (ok case) -> done" "$CP_RUN/log.txt"
CP_MODE=audit; CP_YES=0

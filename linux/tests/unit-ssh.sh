# Sourced by unit.sh. Tests for plan_ssh (pure: reads only the file given).
echo "== ssh: plan_ssh"
f="$T/sshd_config"
printf 'PermitRootLogin yes\nX11Forwarding yes\n' > "$f"
p="$(plan_ssh "$f")"
case $'\n'"$p"$'\n' in *$'\nSET PermitRootLogin no\n'*) ok "root login flagged";; *) bad "root login flagged" "$p";; esac
case $'\n'"$p"$'\n' in *$'\nSET PermitEmptyPasswords no\n'*) ok "missing key flagged";; *) bad "missing key flagged" "$p";; esac
case $'\n'"$p"$'\n' in *$'\nSET PasswordAuthentication yes\n'*) ok "password auth kept ON (no lockout)";; *) bad "password auth kept ON" "$p";; esac
: > "$f"
for kv in "${CP_SSH_WANT[@]}"; do echo "$kv" >> "$f"; done
eq "compliant file gives empty plan" "$(plan_ssh "$f")" ""

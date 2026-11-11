# Sourced by unit.sh. Tampered package files, immutable files, planted cron + binaries
# (all seen on ETH007 Arena, Debian 11: edited ufw + pam_deny.so, immutable /etc/crontab
# running a Perl reverse shell /usr/bin/pearl).

echo "== integrity: dpkg -V parsing"
v="$(printf '%s\n' \
  '??5??????   /lib/x86_64-linux-gnu/security/pam_deny.so' \
  '??5?????? c /etc/ssh/sshd_config' \
  '??5??????   /usr/sbin/ufw' \
  'missing     /usr/share/doc/foo/README' \
  '.M.......   /usr/bin/bar' | integ_changed_files)"
eq "md5-changed non-conffiles only" "$(echo "$v" | xargs)" "/lib/x86_64-linux-gnu/security/pam_deny.so /usr/sbin/ufw"

echo "== integrity: which packages get reinstalled"
yes_ "ufw reinstalled"            integ_reinstall_ok ufw
yes_ "libpam-modules reinstalled" integ_reinstall_ok libpam-modules
yes_ "sudo reinstalled"           integ_reinstall_ok sudo
no_  "systemd only reported"      integ_reinstall_ok systemd
no_  "README app (dovecot) only reported" integ_reinstall_ok dovecot-core

echo "== integrity: immutable / append-only attrs"
eq "lsattr i and a flags parsed" \
   "$(printf '%s\n' '----ia--------e------- /etc/crontab' '--------------e------- /etc/passwd' '-----a--------e------- /var/log/x' | integ_locked_files | xargs)" \
   "/etc/crontab /var/log/x"

echo "== persistence: /etc/crontab lines that are not Debian's"
c="$T/crontab"
printf 'SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/bin\n# m h dom mon dow user command\n*  *    * * *   root    pearl\n17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\nMAILTO=root\n' > "$c"
eq "only the planted line reported" "$(persist_crontab_extra "$c" | sed 's/[[:space:]]\+/ /g')" "* * * * * root pearl"

echo "== persistence: merged-usr path variants"
eq "/lib path also as /usr/lib" "$(echo /lib/systemd/system/ssh.service | pkg_path_variants | xargs)" "/lib/systemd/system/ssh.service /usr/lib/systemd/system/ssh.service"
eq "/usr/bin path also as /bin" "$(echo /usr/bin/perl | pkg_path_variants | xargs)" "/usr/bin/perl /bin/perl"
eq "/etc path unchanged"        "$(echo /etc/passwd | pkg_path_variants | xargs)" "/etc/passwd"

echo "== integrity: pam_deny.so swapped for pam_permit.so"
mkdir -p "$T/sec"; printf 'permit-bytes' > "$T/sec/pam_permit.so"; printf 'deny-bytes' > "$T/sec/pam_deny.so"
no_  "real pam_deny not flagged"          integ_pam_deny_is_permit "$T/sec"
cp "$T/sec/pam_permit.so" "$T/sec/pam_deny.so"
yes_ "pam_deny copied from pam_permit flagged" integ_pam_deny_is_permit "$T/sec"

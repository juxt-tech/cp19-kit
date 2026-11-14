# Sourced by unit.sh. Round 4 (2026-11-11): gaps found in the BotForge (Mint 22), Baldi's Basics and
# Dead by Daylight answer keys, plus app settings for the services CP images use most.

echo "== r4: SUID bit on programs that hand out a root shell (GTFOBins)"
eq "find/python/vim/bash/nmap flagged; passwd, sudo, ssh-keysign and an unknown tool are not" \
   "$(printf '%s\n' /usr/bin/find /usr/bin/python3.11 /usr/bin/vim.basic /bin/bash /usr/bin/passwd /usr/bin/sudo /usr/local/bin/healthcheck /usr/bin/nmap /usr/lib/openssh/ssh-keysign | suid_never_list | xargs)" \
   "/usr/bin/find /usr/bin/python3.11 /usr/bin/vim.basic /bin/bash /usr/bin/nmap"

echo "== r4: /tmp without the sticky bit"
mkdir "$T/tmpa" "$T/tmpb"; chmod 0777 "$T/tmpa"; chmod 1777 "$T/tmpb"
yes_ "0777 dir needs the sticky bit"   dir_needs_sticky "$T/tmpa"
no_  "1777 dir is fine"                dir_needs_sticky "$T/tmpb"
no_  "missing dir is skipped"          dir_needs_sticky "$T/nope"
tf="$T/tmp.conf"
printf '#comment\nd /tmp 0777 root root -\nD /var/tmp 777 root root 30d\nd /run/x 0777 root root -\nq /tmp 1777 root root 10d\n' > "$tf"
eq   "tmpfiles.d lines that recreate /tmp without sticky" "$(tmpfiles_bad_lines "$tf" | wc -l | tr -d ' ')" "2"
tmpfiles_fix "$tf"
eq   "no bad line left after the fix"  "$(tmpfiles_bad_lines "$tf" | wc -l | tr -d ' ')" "0"
yes_ "/tmp line now 1777"              grep -qx 'd /tmp 1777 root root -' "$tf"
yes_ "/var/tmp line now 1777"          grep -qx 'D /var/tmp 1777 root root 30d' "$tf"
yes_ "other paths untouched"           grep -qx 'd /run/x 0777 root root -' "$tf"

echo "== r4: /etc/ld.so.preload (library forced into every program)"
pl="$T/ld.so.preload"
printf '# comment\n\n/usr/local/lib/libhc.so\n/lib/x86_64-linux-gnu/libfoo.so  /opt/x.so\n' > "$pl"
eq "entries listed (comments skipped, several per line too)" "$(persist_preload_libs "$pl" | xargs)" "/usr/local/lib/libhc.so /lib/x86_64-linux-gnu/libfoo.so /opt/x.so"
eq "missing file -> nothing" "$(persist_preload_libs "$T/none")" ""

echo "== r4: polkit rules that say yes without a password"
r="$T/49-nopasswd.rules"
printf 'polkit.addRule(function(action, subject) {\n if (subject.user == "jlee") { return polkit.Result.YES; }\n});\n' > "$r"
yes_ "Result.YES rule flagged"          polkit_grants_yes "$r"
printf '[x]\nIdentity=unix-user:joe\nAction=*\nResultAny=yes\n' > "$T/x.pkla"
yes_ "pkla ResultAny=yes flagged"       polkit_grants_yes "$T/x.pkla"
printf 'polkit.addAdminRule(function(action, subject) { return ["unix-group:sudo"]; });\n' > "$r"
no_  "admin-identity rule not flagged"  polkit_grants_yes "$r"

echo "== r4: hidden files in cron directories"
mkdir -p "$T/cron.d"; : > "$T/cron.d/.placeholder"; : > "$T/cron.d/.maintenance"; : > "$T/cron.d/normal"
eq "hidden cron file listed, .placeholder is not" "$(persist_hidden_cron "$T/cron.d" | xargs)" "$T/cron.d/.maintenance"

echo "== r4: service accounts with a login shell"
p="$T/passwd-svc"
printf 'mysql:x:994:984:MySQL Server:/home/mysql:/bin/bash\nredis:x:110:115::/var/lib/redis:/usr/sbin/nologin\npostgres:x:113:120::/var/lib/postgresql:/bin/bash\nsshd:x:105:65534::/run/sshd:/bin/sh\nsanta:x:1000:1000::/home/santa:/bin/bash\n' > "$p"
eq "mysql + sshd flagged; postgres (ships with bash) and humans left alone" "$(sys_shell_fix_list "$p" | xargs)" "mysql sshd"

echo "== r4: sudoers rules beyond the defaults"
s="$T/sudoers-extra"
printf 'Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%%admin ALL=(ALL) ALL\n%%sudo\tALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n#includedir /etc/sudoers.d\n# a comment\n\nbotrunner ALL=(ALL) ALL\nmford ALL=(ALL) NOPASSWD: ALL\nCmnd_Alias X = /bin/ls\n' > "$s"
eq "only the extra rule is listed (NOPASSWD has its own check)" "$(sudo_extra_rules "$s")" "botrunner ALL=(ALL) ALL"

echo "== r4: more risky services"
r4_crit="$CP_CRITICAL"
CP_CRITICAL=""; cp_expand_critical
eq "redis, inetd telnet, rsync daemon disabled; ssh left alone" \
   "$(plan_services "redis-server.service inetutils-inetd.service rsync.service ssh.service" | xargs)" "DISABLE redis-server DISABLE inetutils-inetd DISABLE rsync"
CP_CRITICAL="redis"; cp_expand_critical
eq "README 'redis' keeps redis-server" "$(plan_services "redis-server.service" | xargs)" "KEEP redis-server (critical)"
CP_CRITICAL="$r4_crit"; cp_expand_critical

echo "== r4: sshd"
f="$T/sshd_r4"
printf 'Port 22\n#Port 2200\nPort 2222\nPermitRootLogin no\n' > "$f"
eq "extra port 2222 reported; 22 and comments are not" "$(ssh_extra_ports "$f" | xargs)" "2222"
case $'\n'"$(plan_ssh "$f")"$'\n' in *$'\nSET AllowTcpForwarding no\n'*) ok "tcp forwarding planned off";; *) bad "tcp forwarding planned off";; esac
case $'\n'"$(plan_ssh "$f")"$'\n' in *$'\nSET LogLevel VERBOSE\n'*) ok "LogLevel VERBOSE planned";; *) bad "LogLevel VERBOSE planned";; esac

echo "== r4: sysctl list"
yes_ "ptrace restricted"       cp_in_list "kernel.yama.ptrace_scope=1" "${CP_SYSCTL[*]}"
yes_ "magic SysRq off"         cp_in_list "kernel.sysrq=0" "${CP_SYSCTL[*]}"
yes_ "tcp_rfc1337 on"          cp_in_list "net.ipv4.tcp_rfc1337=1" "${CP_SYSCTL[*]}"

echo "== r4: ini helpers (smb.conf / my.cnf sections)"
i="$T/smb.conf"
printf '[global]\n   workgroup = WORKGROUP\n;   server min protocol = NT1\n   Server Min Protocol = NT1\n[share]\n   path = /srv\n   guest ok = yes\n   restrict anonymous = 0\n' > "$i"
eq "ini_get reads the section's live value (case-insensitive key)" "$(ini_get "$i" global "server min protocol")" "NT1"
eq "ini_get ignores other sections"       "$(ini_get "$i" global "restrict anonymous")" ""
ini_set "$i" global "server min protocol" SMB2
ini_set "$i" global "restrict anonymous" 2
eq "existing key replaced"                "$(ini_get "$i" global "server min protocol")" "SMB2"
eq "replaced in place, not duplicated"    "$(grep -ciE '^[[:space:]]*server min protocol' "$i")" "1"
eq "missing key added under [global]"     "$(ini_get "$i" global "restrict anonymous")" "2"
eq "share section untouched"              "$(ini_get "$i" share "restrict anonymous")" "0"
eq "commented example left alone"         "$(grep -c '^;   server min protocol = NT1' "$i")" "1"

echo "== r4: apps - samba"
printf '[global]\n server min protocol = NT1\n null passwords = yes\n[pub]\n guest ok = yes\n[priv]\n guest ok = no\n' > "$i"
eq "weak protocol, anonymous and null passwords planned" "$(apps_samba_plan "$i" | tr '\n' '|')" "server min protocol=SMB2|restrict anonymous=2|null passwords=no|"
eq "guest share named"                    "$(apps_samba_guest_shares "$i" | xargs)" "pub"
printf '[global]\n restrict anonymous = 2\n' > "$i"
eq "hardened smb.conf -> nothing"         "$(apps_samba_plan "$i")" ""

echo "== r4: apps - vsftpd"
v="$T/vsftpd.conf"
printf 'listen=NO\nanonymous_enable=YES\n#xferlog_enable=YES\nanon_upload_enable=YES\n' > "$v"
eq "anonymous, anonymous upload and logging planned" "$(apps_vsftpd_plan "$v" | xargs)" "anonymous_enable=NO anon_upload_enable=NO xferlog_enable=YES"
printf 'anonymous_enable=NO\nxferlog_enable=YES\n' > "$v"
eq "hardened vsftpd.conf -> nothing"      "$(apps_vsftpd_plan "$v")" ""
: > "$v"
eq "empty file = compiled defaults (anonymous on, no transfer log)" "$(apps_vsftpd_plan "$v" | xargs)" "anonymous_enable=NO xferlog_enable=YES"

echo "== r4: apps - nginx"
n="$T/nginx.conf"
printf 'http {\n\t# server_tokens off;\n\tssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3\n}\n' > "$n"
no_  "commented server_tokens = version shown"   apps_nginx_tokens_off "$n"
apps_nginx_tokens_fix "$n"
yes_ "server_tokens off after the fix"           apps_nginx_tokens_off "$n"
eq   "exactly one live server_tokens line"       "$(grep -cE '^[[:space:]]*server_tokens' "$n")" "1"
yes_ "TLSv1 / TLSv1.1 flagged"                   apps_nginx_weak_tls "$n"
apps_nginx_tls_fix "$n"
no_  "no weak TLS after the fix"                 apps_nginx_weak_tls "$n"
yes_ "TLS 1.2 + 1.3 kept"                        grep -qE '^[[:space:]]*ssl_protocols TLSv1\.2 TLSv1\.3;' "$n"
printf 'http {\n\tserver_tokens on;\n}\n' > "$n"
apps_nginx_tokens_fix "$n"
yes_ "server_tokens on -> off"                   apps_nginx_tokens_off "$n"
printf 'http {\n\tsendfile on;\n}\n' > "$n"
apps_nginx_tokens_fix "$n"
yes_ "added inside http {} when missing"         apps_nginx_tokens_off "$n"
yes_ "sendfile line untouched"                   grep -q 'sendfile on;' "$n"
printf 'http {\n\tssl_protocols TLSv1.2 TLSv1.3;\n}\n' > "$n"
no_  "TLS 1.2/1.3 only is not flagged"           apps_nginx_weak_tls "$n"

echo "== r4: apps - php"
ph="$T/php-r4.ini"
printf 'expose_php = Off\nsession.cookie_httponly = 1\nallow_url_include = On\ndisplay_errors = On\n' > "$ph"
eq "remote includes and error display planned off" "$(apps_php_plan "$ph" | xargs)" "allow_url_include=Off display_errors=Off"

echo "== r4: apps - mysql / mariadb"
m="$T/50-server.cnf"
printf '[server]\n[mysqld]\nuser = mysql\nbind-address = 0.0.0.0\nlocal_infile = 1\n[embedded]\n' > "$m"
eq "open bind address and local infile planned" "$(apps_mysql_plan "$m" | xargs)" "bind-address=127.0.0.1 local_infile=0"
printf '[mysqld]\nbind-address = 127.0.0.1\nlocal-infile=0\n' > "$m"
eq "hardened -> nothing"                        "$(apps_mysql_plan "$m")" ""
printf '[mysqld]\nuser = mysql\n' > "$m"
eq "keys not in this file -> nothing (set elsewhere or default)" "$(apps_mysql_plan "$m")" ""

echo "== r4: permissions - stricter than wanted is fine, looser is not"
yes_ "600 is within 644"          perm_within 600 644
yes_ "640 is within 640"          perm_within 640 640
no_  "644 is looser than 600"     perm_within 644 600
no_  "666 is looser than 640"     perm_within 666 640
no_  "SUID 4755 is not within 755" perm_within 4755 755

echo "== r4: apps - mysql skip-grant-tables (no passwords at all)"
printf '[mysqld]\nuser = mysql\nskip-grant-tables\n# skip-grant-tables\n' > "$m"
yes_ "live skip-grant-tables found"       apps_mysql_skip_grant "$m"
apps_mysql_skip_grant_off "$m"
no_  "none left after the fix"            apps_mysql_skip_grant "$m"
yes_ "kept as a cpkit comment"            grep -q '^# cpkit disabled: skip-grant-tables' "$m"
yes_ "other lines untouched"              grep -qx 'user = mysql' "$m"

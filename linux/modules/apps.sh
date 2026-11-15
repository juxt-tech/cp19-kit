#!/usr/bin/env bash
# Application security settings for README-critical services. CP category: Application Security Settings.
# Only safe, standard settings; each service's config is validated after editing and restored
# from backup if validation fails. (ETH007 Arena: Apache ServerTokens OS / Signature On / TraceEnable On /
# directory listing, PHP expose_php, Postfix VRFY, Dovecot ssl = no, Roundcube installer enabled.)

# ---------- pure planners (tested) ----------
# Prints KEY=VALUE for each apache security.conf key that differs.
apps_apache_plan() {
    local f="$1" kv
    for kv in "ServerTokens=Prod" "ServerSignature=Off" "TraceEnable=Off"; do
        [ "$(cp_conf_get "$f" "${kv%%=*}")" = "${kv#*=}" ] || echo "$kv"
    done
}
apps_apache_indexes_on() { grep -qE '^[[:space:]]*Options.*[[:space:]]\+?Indexes' "$1" 2>/dev/null; }
apps_apache_noindexes()  { sed -i -E '/^[[:space:]]*Options[[:space:]]/ s/[[:space:]]+\+?Indexes//' "$1"; }

apps_php_plan() {
    local f="$1" kv
    for kv in "expose_php=Off" "session.cookie_httponly=1" "allow_url_include=Off" "display_errors=Off"; do
        [ "$(cp_conf_get "$f" "${kv%%=*}")" = "${kv#*=}" ] || echo "$kv"
    done
}

apps_roundcube_installer_on()  { grep -qE "^[[:space:]]*\\\$config\['enable_installer'\][[:space:]]*=[[:space:]]*true" "$1" 2>/dev/null; }
apps_roundcube_installer_off() { sed -i -E "s/^([[:space:]]*\\\$config\['enable_installer'\][[:space:]]*=[[:space:]]*)true/\1false/" "$1"; }

# Roundcube talking plain IMAP to a local Dovecot (imap_host 'localhost:143' / default_host 'localhost').
apps_roundcube_plain_imap() {
    grep -qE "^[[:space:]]*\\\$config\['(imap_host|default_host)'\][[:space:]]*=[[:space:]]*'(localhost|127\.0\.0\.1)(:143)?'" "$1" 2>/dev/null
}
# Switch to implicit TLS on 993 with peer checks off (Dovecot's cert is self-signed snakeoil).
# Verified on ETH007: real webmail login still works, "SSL between webmail and Dovecot" scored.
apps_roundcube_to_ssl() {
    sed -i -E "s#^([[:space:]]*\\\$config\['imap_host'\][[:space:]]*=[[:space:]]*)'(localhost|127\.0\.0\.1)(:143)?'#\1'ssl://\2:993'#;
               s#^([[:space:]]*\\\$config\['default_host'\][[:space:]]*=[[:space:]]*)'(localhost|127\.0\.0\.1)(:143)?'#\1'ssl://\2'#" "$1"
    grep -q "default_host'\] *= *'ssl://" "$1" && ! grep -q "default_port'\]" "$1" && echo "\$config['default_port'] = 993;" >> "$1"
    grep -q "imap_conn_options'\]" "$1" || \
        echo "\$config['imap_conn_options'] = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]];  // cpkit: self-signed dovecot cert" >> "$1"
}
_apps_roundcube_ssl() {
    apps_roundcube_to_ssl "$1"
    if command -v php >/dev/null && ! php -l "$1" >/dev/null 2>&1; then echo "       php -l failed - restoring $1"; _apps_restore "$1"; return 1; fi
}

# vsftpd: KEY=WANTED for each setting whose value (or compiled default, when the key is absent) differs.
# Compiled defaults: anonymous_enable=YES, anon_upload/mkdir=NO, xferlog_enable=NO.
apps_vsftpd_plan() {
    local f="$1" e k want def cur
    for e in "anonymous_enable NO YES" "anon_upload_enable NO NO" "anon_mkdir_write_enable NO NO" "xferlog_enable YES NO"; do
        read -r k want def <<< "$e"
        cur="$(cp_conf_get "$f" "$k" | tr '[:lower:]' '[:upper:]')"; [ -n "$cur" ] || cur="$def"
        [ "$cur" = "$want" ] || echo "$k=$want"
    done
}
# nginx: 0 when the version banner is hidden (a live "server_tokens off;" and no live "on").
apps_nginx_tokens_off() {
    grep -qE '^[[:space:]]*server_tokens[[:space:]]+off[[:space:]]*;' "$1" 2>/dev/null &&
        ! grep -qE '^[[:space:]]*server_tokens[[:space:]]+(on|build)' "$1"
}
# Live line -> off; else uncomment the stock "# server_tokens off;"; else add it inside http { }.
apps_nginx_tokens_fix() {
    local f="$1"
    if grep -qE '^[[:space:]]*server_tokens[[:space:]]' "$f"; then
        sed -i -E 's/^([[:space:]]*)server_tokens[[:space:]]+[^;]*;/\1server_tokens off;/' "$f"
    elif grep -qE '^[[:space:]]*#[[:space:]]*server_tokens[[:space:]]+off' "$f"; then
        sed -i -E '0,/^([[:space:]]*)#[[:space:]]*(server_tokens[[:space:]]+off[[:space:]]*;)/s//\1\2/' "$f"
    else
        sed -i -E '0,/^[[:space:]]*http[[:space:]]*\{/s//&\n\tserver_tokens off;/' "$f"
    fi
}
# nginx: 0 when a live ssl_protocols line still offers SSLv2/3, TLS 1.0 or TLS 1.1.
apps_nginx_weak_tls() {
    grep -E '^[[:space:]]*ssl_protocols[[:space:]]' "$1" 2>/dev/null | sed 's/#.*//' | grep -qE 'SSLv[23]|TLSv1([[:space:];]|\.1)'
}
apps_nginx_tls_fix() { sed -i -E 's/^([[:space:]]*)ssl_protocols[[:space:]][^;]*;/\1ssl_protocols TLSv1.2 TLSv1.3;/' "$1"; }
# Samba [global]: SMB1 off, no anonymous enumeration, no empty passwords.
apps_samba_plan() {
    local f="$1"
    case "$(ini_get "$f" global "server min protocol" | tr '[:lower:]' '[:upper:]')" in
        NT1|LANMAN1|LANMAN2|CORE|COREPLUS|SMB1) echo "server min protocol=SMB2" ;; esac
    [ "$(ini_get "$f" global "restrict anonymous")" = 2 ] || echo "restrict anonymous=2"
    case "$(ini_get "$f" global "null passwords" | tr '[:upper:]' '[:lower:]')" in yes|true|1) echo "null passwords=no" ;; esac
}
# Shares that let guests in (report: the README may want a public share).
apps_samba_guest_shares() {
    awk '/^[ \t]*[#;]/ { next }
         /^[ \t]*\[.*\]/ { s = $0; gsub(/^[ \t]*\[|\][ \t]*$/, "", s); next }
         tolower($0) ~ /^[ \t]*(guest ok|public)[ \t]*=[ \t]*(yes|true|1)/ && tolower(s) != "global" { print s }' "$1" 2>/dev/null | awk '!seen[$0]++'
}
# MySQL/MariaDB [mysqld] in ONE file: a bind address that is not loopback, LOAD DATA LOCAL switched on.
# Keys this file does not set print nothing (another file or the default decides).
apps_mysql_plan() {
    local f="$1" k v
    for k in bind-address bind_address; do
        v="$(ini_get "$f" mysqld "$k")"
        case "$v" in ''|127.0.0.1|localhost|::1) ;; *) echo "$k=127.0.0.1" ;; esac
    done
    for k in local-infile local_infile; do
        case "$(ini_get "$f" mysqld "$k" | tr '[:upper:]' '[:lower:]')" in 1|on|true) echo "$k=0" ;; esac
    done
}
# skip-grant-tables = the database accepts any login with no password at all.
apps_mysql_skip_grant()     { grep -qE '^[[:space:]]*skip[-_]grant[-_]tables' "$1" 2>/dev/null; }
apps_mysql_skip_grant_off() { sed -i -E 's/^[[:space:]]*(skip[-_]grant[-_]tables.*)$/# cpkit disabled: \1/' "$1"; }

# ---------- appliers (validate or restore) ----------
# Restart SERVICE; if it does not come back, restore FILES from the run's backup and restart again.
# Without systemd (test containers) there is nothing to restart: the edit stands.
_apps_svc_check() {
    local s="$1"; shift
    [ -d /run/systemd/system ] || return 0
    if systemctl restart "$s" 2>/dev/null && sleep 1 && systemctl is-active --quiet "$s"; then return 0; fi
    echo "       $s did not come back - restoring $*"; _apps_restore "$@"; systemctl restart "$s" 2>/dev/null; return 1
}
_apps_vsftpd_set() { cp_set_conf "$1" "$2" "$3" "="; _apps_svc_check vsftpd "$1"; }
_apps_nginx_check() {   # FILES...
    if ! command -v nginx >/dev/null || nginx -t >/dev/null 2>&1; then
        [ -d /run/systemd/system ] && systemctl reload nginx 2>/dev/null; return 0
    fi
    echo "       nginx -t failed - restoring $*"; _apps_restore "$@"; return 1
}
_apps_nginx_tokens() { apps_nginx_tokens_fix "$1"; _apps_nginx_check "$1"; }
_apps_nginx_tls()    { apps_nginx_tls_fix "$1"; _apps_nginx_check "$1"; }
_apps_samba_set() {   # FILE KEY VALUE
    ini_set "$1" global "$2" "$3"
    if command -v testparm >/dev/null && ! testparm -s "$1" >/dev/null 2>&1; then
        echo "       testparm rejected smb.conf - restoring"; _apps_restore "$1"; return 1
    fi
    _apps_svc_check smbd "$1"
}
_apps_mysql_unit() { if systemctl list-unit-files mariadb.service --no-legend 2>/dev/null | grep -q .; then echo mariadb; else echo mysql; fi; }
_apps_mysql_set()  { ini_set "$1" mysqld "$2" "$3"; _apps_svc_check "$(_apps_mysql_unit)" "$1"; }
_apps_mysql_nogrant() { apps_mysql_skip_grant_off "$1"; _apps_svc_check "$(_apps_mysql_unit)" "$1"; }
_apps_php_fpm_set() {   # FILE KEY VALUE  (file: /etc/php/VER/fpm/php.ini)
    local ver; ver="$(echo "$1" | awk -F/ '{print $4}')"
    cp_set_conf "$1" "$2" "$3" " = "
    if command -v "php-fpm$ver" >/dev/null && ! "php-fpm$ver" -t >/dev/null 2>&1; then
        echo "       php-fpm$ver -t failed - restoring $1"; _apps_restore "$1"; return 1
    fi
    [ -d /run/systemd/system ] && systemctl reload "php$ver-fpm" 2>/dev/null
    return 0
}
_apps_restore() { local f; for f in "$@"; do [ -e "$CP_RUN/backup$f" ] && cp -a "$CP_RUN/backup$f" "$f"; done; }

# ---- BIND (named.conf.options) ----
apps_bind_line() {   # KEY -> the line the kit writes
    case "$1" in
        version) echo 'version "none";' ;;
        allow-transfer) echo 'allow-transfer { none; };' ;;
    esac
}
# Pure. Keys to fix inside "options { }": version missing or not "none"; allow-transfer missing or "any".
# An allow-transfer naming real servers (a secondary DNS) is left alone.
apps_bind_plan() {
    local f="$1"
    [ -f "$f" ] || return 0
    awk '
        function braces(s,  o, c) { o = gsub(/\{/, "{", s); c = gsub(/\}/, "}", s); return o - c }
        /^[ \t]*(#|\/\/)/ { next }
        !inopt && /^[ \t]*options[ \t]*\{/ { inopt=1; depth=braces($0); next }
        inopt {
            if (depth == 1 && $0 ~ /^[ \t]*version[ \t]/) { v=1; if ($0 !~ /"none"/) badv=1 }
            if (depth == 1 && $0 ~ /^[ \t]*allow-transfer[ \t{]/) { t=1; if ($0 ~ /\{[ \t]*any/) badt=1 }
            depth += braces($0); if (depth <= 0) inopt=0
        }
        END { if (!v || badv) print "version"; if (!t || badt) print "allow-transfer" }' "$f"
}
# Pure on FILE: replace the live KEY line(s) inside options { } with the kit line, else add it
# right under "options {".
apps_bind_write() {
    local f="$1" k="$2" line tmp
    line="$(apps_bind_line "$k")"; tmp="$(mktemp)"
    awk -v k="$k" -v l="$line" '
        function braces(s,  o, c) { o = gsub(/\{/, "{", s); c = gsub(/\}/, "}", s); return o - c }
        !inopt && !done && /^[ \t]*options[ \t]*\{/ { print; print "\t" l; done=1; inopt=1; depth=braces($0); next }
        inopt && $0 !~ /^[ \t]*(#|\/\/)/ {
            if (depth == 1 && $0 ~ "^[ \t]*" k "[ \t{]") next
            depth += braces($0); if (depth <= 0) inopt=0
        }
        { print }' "$f" > "$tmp"
    cat "$tmp" > "$f"; rm -f "$tmp"
}
_apps_bind_set() {   # FILE KEY
    apps_bind_write "$1" "$2"
    if command -v named-checkconf >/dev/null && ! named-checkconf >/dev/null 2>&1; then
        echo "       named-checkconf failed - restoring $1"; _apps_restore "$1"; return 1
    fi
    [ -d /run/systemd/system ] && { systemctl reload named 2>/dev/null || systemctl reload bind9 2>/dev/null; }
    return 0
}

# ---- ProFTPD / Pure-FTPd ----
# Pure. "Key value" lines (space-separated) that differ from the wanted value.
apps_proftpd_plan() {
    local f="$1" kv k v
    for kv in "RootLogin off" "DefaultRoot ~" 'ServerIdent on "FTP server ready"'; do
        k="${kv%% *}"; v="${kv#* }"
        [ "$(cp_conf_get "$f" "$k")" = "$v" ] || echo "$kv"
    done
}
_apps_proftpd_set() {   # FILE KEY VALUE
    cp_set_conf "$1" "$2" "$3"; [ $? -eq 1 ] && return 1
    if command -v proftpd >/dev/null && ! proftpd -t >/dev/null 2>&1; then
        echo "       proftpd -t failed - restoring $1"; _apps_restore "$1"; return 1
    fi
    _apps_svc_check proftpd "$1"
}
# Pure. Pure-FTPd switches (one file per setting in conf/) that are not "yes".
apps_pureftpd_plan() {
    local d="$1" k
    for k in NoAnonymous ChrootEveryone; do
        [ "$(tr -d '[:space:]' < "$d/$k" 2>/dev/null | tr '[:upper:]' '[:lower:]')" = yes ] || echo "$k"
    done
}
_apps_pureftpd_set() {   # DIR NAME
    cp_backup "$1/$2"; echo yes > "$1/$2" || return 1
    _apps_svc_check pure-ftpd "$1/$2"
}

_apps_apache_apply() {   # FILES...: security.conf edits + Indexes removal already done by callers; validate
    if apache2ctl configtest >/dev/null 2>&1; then systemctl reload apache2; return 0; fi
    echo "       apache2ctl configtest failed - restoring"; _apps_restore "$@"; systemctl reload apache2; return 1
}
_apps_set_and_check_apache() {   # FILE KEY VALUE
    cp_set_conf "$1" "$2" "$3"; local rc=$?; [ $rc -eq 2 ] && return 0
    _apps_apache_apply "$1"
}
_apps_noindexes_and_check() { apps_apache_noindexes "$1"; _apps_apache_apply "$1"; }
_apps_php_set() { cp_set_conf "$1" "$2" "$3" " = "; [ $? -eq 1 ] && return 1; _apps_apache_apply "$1"; }

_apps_postconf() {   # KEY VALUE
    local old; old="$(postconf -h "$1" 2>/dev/null)"
    postconf -e "$1=$2" || return 1
    if postfix check >/dev/null 2>&1; then systemctl reload postfix; return 0; fi
    postconf -e "$1=$old"; echo "       postfix check failed - $1 restored"; return 1
}

_apps_dovecot_set() {   # FILE KEY VALUE
    cp_set_conf "$1" "$2" "$3" " = "; [ $? -eq 1 ] && return 1
    if doveconf -n >/dev/null 2>&1 && systemctl restart dovecot && systemctl is-active --quiet dovecot; then return 0; fi
    echo "       dovecot rejected the change - restoring $1"; _apps_restore "$1"; systemctl restart dovecot; return 1
}
# Readable certificate + key behind "ssl_cert = </path" / "ssl_key = </path" (else enabling ssl breaks dovecot).
_apps_dovecot_cert_ok() {
    local c k; c="$(doveconf -h ssl_cert 2>/dev/null | sed 's/^<//')"; k="$(doveconf -hP ssl_key 2>/dev/null | head -1 | sed 's/^<//')"
    [ -r "$c" ] && { [ -z "$k" ] || [ "${k#-----}" != "$k" ] || [ -r "$k" ]; }
}

mod_apps() {
    cp_header "APPS  (security settings of README-critical services)"
    local f kv k v any=0
    if cp_is_protected_service apache2 && [ -d /etc/apache2 ]; then
        any=1
        f=/etc/apache2/conf-available/security.conf
        if [ -f "$f" ]; then
            cp_backup "$f"
            while IFS= read -r kv; do
                [ -n "$kv" ] || continue; k="${kv%%=*}"; v="${kv#*=}"
                cp_act apps "set $k $v in $f (now: $(cp_conf_get "$f" "$k"))" "hides versions / blocks TRACE" _apps_set_and_check_apache "$f" "$k" "$v"
            done <<< "$(apps_apache_plan "$f")"
            [ -e /etc/apache2/conf-enabled/security.conf ] || cp_act apps "a2enconf security" "security.conf is not enabled" sh -c "a2enconf -q security && systemctl reload apache2"
        fi
        for f in /etc/apache2/apache2.conf /etc/apache2/sites-enabled/*.conf; do
            [ -f "$f" ] && apps_apache_indexes_on "$f" || continue
            cp_backup "$f"
            cp_act apps "remove 'Indexes' from Options in $f" "directory listing shows every file in a folder" _apps_noindexes_and_check "$f"
        done
        for f in /etc/php/*/apache2/php.ini; do
            [ -f "$f" ] || continue
            cp_backup "$f"
            while IFS= read -r kv; do
                [ -n "$kv" ] || continue; k="${kv%%=*}"; v="${kv#*=}"
                cp_act apps "set $k = $v in $f (now: $(cp_conf_get "$f" "$k"))" "PHP hardening" _apps_php_set "$f" "$k" "$v"
            done <<< "$(apps_php_plan "$f")"
        done
        while read -r f; do
            apps_roundcube_installer_on "$f" || continue
            cp_backup "$f"
            cp_act apps "set enable_installer = false in $f" "Roundcube's web installer can reconfigure the mail system" apps_roundcube_installer_off "$f"
        done < <(find /var/www /usr/share/roundcube /etc/roundcube -maxdepth 3 -name config.inc.php 2>/dev/null)
    fi
    if cp_is_protected_service postfix && command -v postconf >/dev/null; then
        any=1
        for kv in "disable_vrfy_command=yes" "smtpd_helo_required=yes" "smtpd_banner=\$myhostname ESMTP"; do
            k="${kv%%=*}"; v="${kv#*=}"
            [ "$(postconf -h "$k" 2>/dev/null)" = "$v" ] && continue
            cp_act apps "postconf $k = $v (now: $(postconf -h "$k" 2>/dev/null))" "stops user enumeration / version leaks" _apps_postconf "$k" "$v"
        done
    fi
    if cp_is_protected_service dovecot && command -v doveconf >/dev/null; then
        any=1
        f=/etc/dovecot/conf.d/10-ssl.conf
        if [ "$(doveconf -h ssl 2>/dev/null)" = no ] && [ -f "$f" ]; then
            if _apps_dovecot_cert_ok; then
                cp_backup "$f"
                cp_act apps "set ssl = yes in $f (now: no)" "IMAP passwords travel in clear text" _apps_dovecot_set "$f" ssl yes
            else cp_finding apps "dovecot ssl = no but no readable certificate - set ssl_cert/ssl_key first"; fi
        fi
        f=/etc/dovecot/conf.d/10-auth.conf
        if [ "$(doveconf -h auth_debug_passwords 2>/dev/null)" = yes ] && [ -f "$f" ]; then
            cp_backup "$f"; cp_act apps "set auth_debug_passwords = no in $f" "logs passwords in clear text" _apps_dovecot_set "$f" auth_debug_passwords no
        fi
        # Webmail -> Dovecot over SSL, only once Dovecot really serves IMAPS on 993.
        if [ "$(doveconf -h ssl 2>/dev/null)" != no ] && timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/993' 2>/dev/null; then
            while read -r f; do
                apps_roundcube_plain_imap "$f" || continue
                cp_backup "$f"
                cp_act apps "Roundcube -> Dovecot over SSL (ssl://localhost:993) in $f" "webmail logins cross IMAP in clear text" _apps_roundcube_ssl "$f"
                cp_finding apps "Roundcube now uses ssl://localhost:993 - log in to webmail once to check (restore: $CP_RUN/backup$f)"
            done < <(find /var/www /usr/share/roundcube /etc/roundcube -maxdepth 3 -name config.inc.php 2>/dev/null)
        elif [ "$CP_MODE" = audit ] && [ "$(doveconf -h ssl 2>/dev/null)" = no ]; then
            echo "  (after dovecot ssl is on, a Roundcube on plain localhost:143 is switched to ssl://localhost:993)"
        fi
    fi
    if cp_is_protected_service vsftpd && [ -f /etc/vsftpd.conf ]; then
        any=1; f=/etc/vsftpd.conf
        cp_backup "$f"
        while IFS= read -r kv; do
            [ -n "$kv" ] || continue; k="${kv%%=*}"; v="${kv#*=}"
            cp_act apps "set $k=$v in $f (now: $(cp_conf_get "$f" "$k"))" "no anonymous FTP / keep a transfer log" _apps_vsftpd_set "$f" "$k" "$v"
        done <<< "$(apps_vsftpd_plan "$f")"
        if [ "$(cp_conf_get "$f" ssl_enable | tr '[:lower:]' '[:upper:]')" != YES ]; then
            local crt key
            crt="$(cp_conf_get "$f" rsa_cert_file)"; key="$(cp_conf_get "$f" rsa_private_key_file)"
            if [ -r "${crt:-/usr/share/ssl/certs/vsftpd.pem}" ] && [ -r "${key:-${crt:-/usr/share/ssl/certs/vsftpd.pem}}" ]; then
                cp_act apps "set ssl_enable=YES in $f" "FTP passwords travel in clear text (after this, FTP clients must use TLS)" _apps_vsftpd_set "$f" ssl_enable YES
            else cp_finding apps "vsftpd: ssl_enable is off and no readable certificate is set (rsa_cert_file / rsa_private_key_file) - FTP logins are clear text"; fi
        fi
        cp_finding apps "vsftpd: also check by hand - chroot_local_user=YES (jail users in their home), write_enable only if the README needs uploads, /etc/ftpusers lists root"
    fi
    if cp_is_protected_service nginx && [ -f /etc/nginx/nginx.conf ]; then
        any=1; f=/etc/nginx/nginx.conf
        if ! apps_nginx_tokens_off "$f"; then
            cp_backup "$f"
            cp_act apps "set server_tokens off in $f" "nginx shows its version on every error page and header" _apps_nginx_tokens "$f"
        fi
        for f in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*; do
            [ -f "$f" ] && apps_nginx_weak_tls "$f" || continue
            f="$(readlink -f "$f")"
            cp_backup "$f"
            cp_act apps "ssl_protocols -> TLSv1.2 TLSv1.3 in $f" "SSLv3 / TLS 1.0 / 1.1 are broken" _apps_nginx_tls "$f"
        done
        grep -rsnE '^[[:space:]]*autoindex[[:space:]]+on' /etc/nginx/nginx.conf /etc/nginx/conf.d /etc/nginx/sites-enabled 2>/dev/null | while read -r kv; do
            cp_finding apps "nginx directory listing on: $kv  (set 'autoindex off;' unless the README wants a file listing)"
        done
        grep -sqE '^[[:space:]]*user[[:space:]]+root' /etc/nginx/nginx.conf && cp_finding apps "nginx workers run as ROOT ('user root;' in nginx.conf) - set 'user www-data;' and run: sudo nginx -t && sudo systemctl restart nginx"
    fi
    if { cp_is_protected_service nginx || cp_is_protected_service apache2; }; then
        for f in /etc/php/*/fpm/php.ini; do
            [ -f "$f" ] || continue
            any=1; cp_backup "$f"
            while IFS= read -r kv; do
                [ -n "$kv" ] || continue; k="${kv%%=*}"; v="${kv#*=}"
                cp_act apps "set $k = $v in $f (now: $(cp_conf_get "$f" "$k"))" "PHP hardening" _apps_php_fpm_set "$f" "$k" "$v"
            done <<< "$(apps_php_plan "$f")"
        done
    fi
    if cp_is_protected_service smbd && [ -f /etc/samba/smb.conf ]; then
        any=1; f=/etc/samba/smb.conf
        cp_backup "$f"
        while IFS= read -r kv; do
            [ -n "$kv" ] || continue; k="${kv%%=*}"; v="${kv#*=}"
            cp_act apps "set '$k = $v' in [global] of $f (now: $(ini_get "$f" global "$k"))" "no SMB1, no anonymous listing of users and shares, no empty passwords" _apps_samba_set "$f" "$k" "$v"
        done <<< "$(apps_samba_plan "$f")"
        for k in $(apps_samba_guest_shares "$f"); do
            cp_finding apps "samba share [$k] allows guests (guest ok = yes) - set 'guest ok = no' unless the README wants a public share"
        done
    fi
    if { cp_is_protected_service mysql || cp_is_protected_service mariadb; } && [ -d /etc/mysql ]; then
        any=1
        while read -r f; do
            if apps_mysql_skip_grant "$f"; then
                cp_backup "$f"
                cp_act apps "comment out skip-grant-tables in $f" "the database lets anyone in with no password" _apps_mysql_nogrant "$f"
            fi
            while IFS= read -r kv; do
                [ -n "$kv" ] || continue; k="${kv%%=*}"; v="${kv#*=}"
                cp_backup "$f"
                cp_act apps "set $k = $v in [mysqld] of $f (now: $(ini_get "$f" mysqld "$k"))" "database reachable from the network / LOAD DATA LOCAL reads files (skip if the README needs remote DB access)" _apps_mysql_set "$f" "$k" "$v"
            done <<< "$(apps_mysql_plan "$f")"
        done < <(find /etc/mysql -xdev -type f -name '*.cnf' 2>/dev/null | sort)
        if command -v my_print_defaults >/dev/null && ! my_print_defaults mysqld 2>/dev/null | grep -qE '^--bind[-_]address='; then
            cp_finding apps "mysqld has NO bind-address (listens on every interface) - add 'bind-address = 127.0.0.1' under [mysqld] unless the README needs remote DB access"
        fi
        cp_finding apps "database: by hand - sudo mysql_secure_installation (root password, drop anonymous users + test DB), then review: SELECT user,host FROM mysql.user;"
    fi
    if cp_is_protected_service postfix && command -v postconf >/dev/null; then
        postconf -h mynetworks 2>/dev/null | grep -qE '(^|[ ,])0\.0\.0\.0/0' && \
            cp_finding apps "postfix mynetworks contains 0.0.0.0/0 = OPEN RELAY (anyone can send mail through it) - set mynetworks = 127.0.0.0/8 [::1]/128 in /etc/postfix/main.cf, then: sudo postfix check && sudo systemctl reload postfix"
    fi
    if { cp_is_protected_service named || cp_is_protected_service bind9; } && [ -f /etc/bind/named.conf.options ]; then
        any=1; f=/etc/bind/named.conf.options
        for k in $(apps_bind_plan "$f"); do
            cp_backup "$f"
            cp_act apps "set '$(apps_bind_line "$k")' in options { } of $f" "hides the BIND version / stops anyone copying every DNS record (zone transfer)" _apps_bind_set "$f" "$k"
        done
        grep -rsnE 'allow-transfer[[:space:]]*\{[[:space:]]*any' /etc/bind 2>/dev/null | while read -r kv; do
            cp_finding apps "BIND zone transfer open to ANY host: $kv  (use { none; } or the README's secondary DNS IP)"
        done
        grep -rsnE 'allow-recursion[[:space:]]*\{[[:space:]]*any|allow-update[[:space:]]*\{[[:space:]]*any' /etc/bind 2>/dev/null | while read -r kv; do
            cp_finding apps "BIND open to ANY host: $kv  (open resolver / anyone can change records)"
        done
    fi
    if cp_is_protected_service proftpd && [ -f /etc/proftpd/proftpd.conf ]; then
        any=1; f=/etc/proftpd/proftpd.conf
        while IFS= read -r kv; do
            [ -n "$kv" ] || continue; k="${kv%% *}"; v="${kv#* }"
            cp_backup "$f"
            cp_act apps "set $k $v in $f (now: $(cp_conf_get "$f" "$k"))" "no root FTP logins / users jailed in their home / no version banner" _apps_proftpd_set "$f" "$k" "$v"
        done <<< "$(apps_proftpd_plan "$f")"
        grep -qiE '^[[:space:]]*<Anonymous' "$f" /etc/proftpd/conf.d/*.conf 2>/dev/null && \
            cp_finding apps "proftpd has an <Anonymous> block (anonymous FTP) - comment out the whole <Anonymous ...> ... </Anonymous> block unless the README wants public FTP, then: sudo proftpd -t && sudo systemctl restart proftpd"
    fi
    if cp_is_protected_service pure-ftpd && [ -d /etc/pure-ftpd/conf ]; then
        any=1
        for k in $(apps_pureftpd_plan /etc/pure-ftpd/conf); do
            cp_act apps "write 'yes' to /etc/pure-ftpd/conf/$k" "no anonymous FTP / users jailed in their home" _apps_pureftpd_set /etc/pure-ftpd/conf "$k"
        done
    fi
    [ "$any" = 0 ] && echo "  ok   no README-critical service with app settings here (apache2/nginx/php/postfix/dovecot/vsftpd/samba/mysql/bind/proftpd/pure-ftpd)"
    return 0
}

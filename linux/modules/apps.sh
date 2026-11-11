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
    for kv in "expose_php=Off" "session.cookie_httponly=1"; do
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

# ---------- appliers (validate or restore) ----------
_apps_restore() { local f; for f in "$@"; do [ -e "$CP_RUN/backup$f" ] && cp -a "$CP_RUN/backup$f" "$f"; done; }

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
    [ "$any" = 0 ] && echo "  ok   no README-critical service with app settings here (apache2/postfix/dovecot)"
    return 0
}

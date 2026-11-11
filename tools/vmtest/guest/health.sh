# Health + score helpers for Linux practice VMs (Aeacus scorer). PRACTICE VMs ONLY.
# In a job:  . <(curl -s "$CP_SERVER/g/health.sh"); health 'PASSWORD'; score 150
# Edit CP_HEALTH_SERVICES / CP_HEALTH_USER for the image (defaults: ETH007 Arena, Debian 11 mail server).
CP_HEALTH_SERVICES="${CP_HEALTH_SERVICES:-dovecot postfix apache2 CSSClient}"
CP_HEALTH_USER="${CP_HEALTH_USER:-sadness}"
health() {
    local s pw="${1:-}" u="$CP_HEALTH_USER"
    echo "--- health"
    for s in $CP_HEALTH_SERVICES; do printf '%-10s %s\n' "$s" "$(systemctl is-active "$s")"; done
    pgrep -x phocus >/dev/null && echo "phocus     running" || echo "phocus     NOT RUNNING"
    if [ -n "$pw" ] && command -v doveadm >/dev/null; then
        echo "dovecot login $u: $(doveadm auth test "$u" "$pw" 2>&1 | head -1)"
        echo "imap plaintext login from localhost (what Roundcube does): $(curl -s --max-time 10 -u "$u:$pw" imap://127.0.0.1/ -o /dev/null && echo OK || echo "FAIL rc=$?")"
    fi
    echo "webmail http: $(curl -s -o /dev/null -w '%{http_code}' -H 'Host: mail.inside.out' http://127.0.0.1/)"
    printf 'smtp 25: ';  timeout 12 bash -c 'exec 3<>/dev/tcp/127.0.0.1/25; head -c 40 <&3' 2>&1 | tr -d '\r' | head -1; echo
    echo "ufw: $(ufw status 2>/dev/null | head -1)"
    local today=$(( $(date +%s) / 86400 ))
    awk -F: -v d=$today '$3>=1000 && $3<65534 {print $1}' /etc/passwd | head -3 | while read -r x; do
        getent shadow "$x" | awk -F: -v d=$today -v u="$x" '{e = ($5 != "" && $3 > 0 && $3 + $5 <= d) ? "EXPIRED" : "ok"; print u ": pw age " d-$3 "d max " ($5==""?"-":$5) " -> " e}'
    done
}
# score [SECONDS]: wait up to SECONDS for the report to be rewritten, then print score + fixed items.
score() {
    local r=/opt/aeacus/assets/ScoringReport.html wait="${1:-0}" t0 i=0
    [ -f "$r" ] || { echo "no Aeacus report"; return; }
    if [ "$wait" -gt 0 ]; then
        t0="$(stat -c %Y $r)"
        while [ $i -lt "$wait" ] && [ "$(stat -c %Y $r)" = "$t0" ]; do sleep 5; i=$((i+5)); done
    fi
    sed -e 's/<[^>]*>/\n/g' $r | grep -E 'Report Generated At|points received|penalties assessed|security issues fixed' | sed 's/^[[:space:]]*//'
    sed -e 's/<\/li>/\n/g; s/<[^>]*>//g' $r | grep -oE '[A-Z][^<>]{3,120} - -?[0-9]+ pts' | head -60
}

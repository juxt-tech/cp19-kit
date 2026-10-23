#!/usr/bin/env bash
# Services module under real systemd (run by systemd-test.sh inside the systemd container).
K=/k/linux
PASS=0; FAIL=0
t() { local n="$1"; shift; if "$@" >/dev/null 2>&1; then PASS=$((PASS+1)); echo "  ok   $n"; else FAIL=$((FAIL+1)); echo "  FAIL $n"; fi; }

systemctl enable --now cups.service cups.socket avahi-daemon.service avahi-daemon.socket vsftpd.service >/dev/null 2>&1
t "setup: cups running"   systemctl is-active cups.service
t "setup: vsftpd running" systemctl is-active vsftpd.service

printf 'ADMINS=santa\nUSERS=\nCRITICAL_SERVICES=ftp\n' > /tmp/c.txt   # nickname: ftp must protect vsftpd
bash $K/harden.sh --config /tmp/c.txt --apply --yes --module services > /tmp/s1.txt 2>&1
for u in cups.service cups.socket cups.path avahi-daemon.service avahi-daemon.socket; do
    t "$u disabled"  sh -c "! systemctl is-enabled $u"
    t "$u stopped"   sh -c "! systemctl is-active $u"
done
t "README ftp -> vsftpd still enabled" systemctl is-enabled vsftpd.service
t "README ftp -> vsftpd still running" systemctl is-active vsftpd.service

bash $K/harden.sh --config /tmp/c.txt --apply --yes --module services > /tmp/s2.txt 2>&1
RUN2="$(ls -1d /root/cpkit-runs/* | tail -1)"
t "second run makes 0 changes" sh -c "! grep -q ' | ACTION | ' '$RUN2/log.txt'"

echo "== systemd: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || { echo '--- first run output'; cat /tmp/s1.txt; }
[ "$FAIL" -eq 0 ]

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
t "Ctrl-Alt-Del reboot masked" sh -c "systemctl is-enabled ctrl-alt-del.target | grep -q masked"

bash $K/harden.sh --config /tmp/c.txt --apply --yes --module services > /tmp/s2.txt 2>&1
RUN2="$(ls -1d /root/cpkit-runs/* | tail -1)"
t "second run makes 0 changes" sh -c "! grep -q ' | ACTION | ' '$RUN2/log.txt'"

# apps module under real systemd: the edit must stick AND the critical service must still be running.
sed -i 's/^anonymous_enable=.*/anonymous_enable=YES/' /etc/vsftpd.conf; systemctl restart vsftpd
bash $K/harden.sh --config /tmp/c.txt --apply --yes --module apps > /tmp/a1.txt 2>&1
t "apps: anonymous FTP off"                   grep -qx 'anonymous_enable=NO' /etc/vsftpd.conf
t "apps: vsftpd still running after the edit" systemctl is-active vsftpd.service
bash $K/harden.sh --config /tmp/c.txt --apply --yes --module apps > /tmp/a2.txt 2>&1
RUN3="$(ls -1d /root/cpkit-runs/* | tail -1)"
t "apps: second run makes 0 changes" sh -c "! grep -q ' | ACTION | ' '$RUN3/log.txt'"
# A change the service rejects must be rolled back: an unknown option stops vsftpd from starting.
cp /etc/vsftpd.conf /tmp/vsftpd.good
( source $K/lib/common.sh; source $K/modules/apps.sh; CP_RUN=/tmp/rb; mkdir -p $CP_RUN; cp_backup /etc/vsftpd.conf
  echo 'not_a_real_option=YES' >> /etc/vsftpd.conf; _apps_svc_check vsftpd /etc/vsftpd.conf ) > /tmp/rb.txt 2>&1
t "apps: rejected edit rolled back"           cmp -s /etc/vsftpd.conf /tmp/vsftpd.good
t "apps: vsftpd running after the rollback"   systemctl is-active vsftpd.service
echo "== systemd: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || { echo '--- first run output'; cat /tmp/s1.txt; }
[ "$FAIL" -eq 0 ]

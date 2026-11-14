#!/usr/bin/env bash
# Critical file ownership/permissions. CP category: Uncategorized OS Settings (OS permissions).
# Fixes a short known list; SUID/world-writable scans are REPORT ONLY.

CP_PERMS=(
    "/etc/passwd root root 644"
    "/etc/group root root 644"
    "/etc/shadow root shadow 640"
    "/etc/gshadow root shadow 640"
    "/etc/sudoers root root 440"
    "/etc/crontab root root 600"
    "/etc/ssh/sshd_config root root 600"
    "/boot/grub/grub.cfg root root 600"
    "/etc/passwd- root root 644"
    "/etc/group- root root 644"
    "/etc/shadow- root shadow 640"
    "/etc/gshadow- root shadow 640"
    "/etc/security/opasswd root root 600"
    "/etc/cron.d root root 700"
    "/etc/cron.hourly root root 700"
    "/etc/cron.daily root root 700"
    "/etc/cron.weekly root root 700"
    "/etc/cron.monthly root root 700"
)
# Programs that must never carry the SUID bit: with it, any user gets a root shell (GTFOBins).
# Image makers plant it on find, vim, python, bash, nmap... Removing it never breaks the program.
CP_SUID_NEVER='bash|dash|sh|zsh|ksh|csh|tcsh|fish|find|vim?|view|nano|pico|ed|emacs|python|perl|ruby|lua|php|node|nodejs|awk|gawk|mawk|nawk|sed|less|more|most|cat|tac|head|tail|cut|sort|uniq|cp|mv|dd|tee|env|nice|ionice|timeout|time|xargs|tar|zip|unzip|gzip|bzip2|xz|cpio|rsync|scp|sftp|ftp|wget|curl|nc|ncat|netcat|socat|nmap|tcpdump|strace|ltrace|gdb|make|gcc|git|man|systemctl|journalctl|docker|chmod|chown|chroot|date|base64|base32|xxd|od|hexdump|strings|install|busybox|expect|script|watch|taskset|stdbuf|setarch|flock|unshare|nsenter|capsh|start-stop-daemon|run-parts|apt|apt-get|dpkg|pip|openssl|diff|file|tclsh|wish'
# Pure. Paths on stdin -> those whose file name is on that list (python3.11, vim.basic, nc.traditional too).
suid_never_list() {
    awk -v re="^(${CP_SUID_NEVER})([0-9][0-9.]*)?([.](basic|tiny|nox|gtk|gtk3|athena|traditional|openbsd))?$" \
        '{ n = split($0, a, "/"); if (a[n] ~ re) print }'
}
# Pure. 0 when octal mode CUR grants nothing beyond WANT (600 is fine where 644 is wanted; 666 is not).
perm_within() { [ $(( 0$1 & ~0$2 )) -eq 0 ]; }
# 0 when DIR is world-writable without the sticky bit (anyone can delete or swap other users' files).
dir_needs_sticky() { [ -d "$1" ] && [ ! -k "$1" ] && [ -n "$(find "$1" -maxdepth 0 -perm -0002 2>/dev/null)" ]; }
# Pure. tmpfiles.d lines that re-create /tmp or /var/tmp world-writable WITHOUT the sticky bit at every
# boot (BotForge image) - a chmod alone would not survive a reboot.
tmpfiles_bad_lines() { grep -E '^[dDqQv][[:space:]]+/(var/)?tmp[[:space:]]+0?777([[:space:]]|$)' "$1" 2>/dev/null; }
tmpfiles_fix() { sed -i -E 's#^([dDqQv][[:space:]]+/(var/)?tmp[[:space:]]+)0?777([[:space:]]|$)#\11777\3#' "$1"; }

CP_SUID_OK='^/(usr/)?(s?bin|lib|libexec)/(su|sudo|passwd|chsh|chfn|gpasswd|newgrp|mount|umount|ping|pkexec|fusermount3?|ntfs-3g|unix_chkpwd|pppd|chage|expiry|crontab|ssh-agent|dbus-daemon-launch-helper|polkit-agent-helper-1|Xorg.wrap|ssh-keysign|at|mount.cifs|mount.nfs|vmware-user-suid-wrapper|exim4|dotlockfile)$|/(dbus-1|openssh|polkit-1|xorg|snapd|eject)/'

mod_perms() {
    cp_header "PERMISSIONS  (critical files)"
    local e path own grp mode cur
    for e in "${CP_PERMS[@]}"; do
        read -r path own grp mode <<< "$e"
        [ -e "$path" ] || continue
        getent group "$grp" >/dev/null || grp=root
        cur="$(stat -c '%U:%G:%a' "$path")"
        # stricter than wanted is fine (never loosen a file the image already has tighter)
        if [ "${cur%:*}" = "$own:$grp" ] && perm_within "${cur##*:}" "$mode"; then echo "  ok   $path $cur"
        else cp_act perms "set $path to $own:$grp $mode (now $cur)" "too-open permissions leak or allow editing secrets" \
            sh -c "chown $own:$grp '$path' && chmod $mode '$path'"; fi
    done
    local d f
    for d in /tmp /var/tmp /dev/shm; do
        dir_needs_sticky "$d" && cp_act perms "chmod 1777 $d (now $(stat -c '%a' "$d"))" "no sticky bit: any user can delete or replace other users' files there" chmod 1777 "$d"
    done
    for f in /etc/tmpfiles.d/*.conf; do
        [ -f "$f" ] && [ -n "$(tmpfiles_bad_lines "$f")" ] || continue
        cp_backup "$f"
        cp_act perms "set mode 1777 for /tmp in $f" "this file re-creates /tmp without the sticky bit at every boot" tmpfiles_fix "$f"
    done
    echo "  scanning SUID binaries and world-writable files..."
    while read -r f; do
        cp_act perms "chmod u-s $f (mode $(stat -c '%a' "$f"))" "SUID on this program gives every user a root shell (GTFOBins)" chmod u-s "$f"
    done < <(find / -xdev -type f -perm -4000 2>/dev/null | suid_never_list)
    find / -xdev -type f -perm -4000 2>/dev/null | grep -Ev "$CP_SUID_OK" | while read -r f; do
        cp_finding perms "unusual SUID binary: $f  (GTFOBins? e.g. find/vim/python with SUID = root shell)"
    done
    # Config under /etc is never meant to be world-writable (ETH007 image: dovecot.conf 777): fix it.
    while read -r f; do
        cp_act perms "chmod o-w $f (now $(stat -c '%a' "$f"))" "anyone could rewrite this config" chmod o-w "$f"
    done < <(find /etc -xdev -type f -perm -0002 2>/dev/null)
    # World-writable directories without the sticky bit: anyone can replace files inside
    # (ETH007: /etc/dovecot/conf.d, /etc/dovecot/private, /var/mail). /tmp-style dirs have the sticky bit.
    while read -r f; do
        cp_act perms "chmod o-w $f/ (now $(stat -c '%a' "$f"))" "anyone could replace the files in it" chmod o-w "$f"
    done < <(find /etc /var/mail /var/spool /var/www /opt /srv -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null)
    find /usr /bin /sbin -xdev -type f -perm -0002 2>/dev/null | while read -r f; do
        cp_finding perms "world-writable system file: $f"
    done
    awk -F: '$3>=1000 && $3<65534 {print $6}' /etc/passwd | while read -r h; do
        [ -d "$h" ] || continue
        case "$(stat -c '%a' "$h")" in *7|*6|*3|*2) cp_finding perms "home dir writable by everyone: $h";; esac
    done
    return 0
}

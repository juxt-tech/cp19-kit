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
)

CP_SUID_OK='^/(usr/)?(s?bin|lib|libexec)/(su|sudo|passwd|chsh|chfn|gpasswd|newgrp|mount|umount|ping|pkexec|fusermount3?|ntfs-3g|unix_chkpwd|pppd|chage|expiry|crontab|ssh-agent|dbus-daemon-launch-helper|polkit-agent-helper-1|Xorg.wrap|ssh-keysign|at|mount.cifs|mount.nfs|vmware-user-suid-wrapper|exim4|dotlockfile)$|/(dbus-1|openssh|polkit-1|xorg|snapd|eject)/'

mod_perms() {
    cp_header "PERMISSIONS  (critical files)"
    local e path own grp mode cur
    for e in "${CP_PERMS[@]}"; do
        read -r path own grp mode <<< "$e"
        [ -e "$path" ] || continue
        getent group "$grp" >/dev/null || grp=root
        cur="$(stat -c '%U:%G:%a' "$path")"
        if [ "$cur" = "$own:$grp:$mode" ]; then echo "  ok   $path $cur"
        else cp_act perms "set $path to $own:$grp $mode (now $cur)" "too-open permissions leak or allow editing secrets" \
            sh -c "chown $own:$grp '$path' && chmod $mode '$path'"; fi
    done
    echo "  scanning SUID binaries and world-writable files (report only)..."
    find / -xdev -type f -perm -4000 2>/dev/null | grep -Ev "$CP_SUID_OK" | while read -r f; do
        cp_finding perms "unusual SUID binary: $f  (GTFOBins? e.g. find/vim/python with SUID = root shell)"
    done
    find /etc /usr /bin /sbin -xdev -type f -perm -0002 2>/dev/null | while read -r f; do
        cp_finding perms "world-writable system file: $f"
    done
    awk -F: '$3>=1000 && $3<65534 {print $6}' /etc/passwd | while read -r h; do
        [ -d "$h" ] || continue
        case "$(stat -c '%a' "$h")" in *7|*6|*3|*2) cp_finding perms "home dir writable by everyone: $h";; esac
    done
    return 0
}

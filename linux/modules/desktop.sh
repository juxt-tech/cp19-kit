#!/usr/bin/env bash
# Desktop + browser: automatic login off, screen lock, no USB/CD autorun, Firefox protections back on.
# CP categories: Account Policies / Local Policy (login screen), Application Security (Firefox).
# Ideas from Ripper1004/CyberPatriot-Toolkit (sec_desktop, sec_browser).

# Firefox settings images switch to false. Commenting the line out puts the safe default back.
CP_FF_BAD_PREFS="dom.disable_open_during_load xpinstall.whitelist.required xpinstall.signatures.required extensions.blocklist.enabled browser.safebrowsing.malware.enabled browser.safebrowsing.phishing.enabled browser.safebrowsing.downloads.enabled browser.safebrowsing.downloads.remote.block_dangerous browser.safebrowsing.downloads.remote.block_potentially_unwanted"

_ff_bad_re() {
    local k re=""
    for k in $CP_FF_BAD_PREFS; do re="$re|${k//./\\.}"; done
    printf '^[[:space:]]*(user_pref|pref|lockPref|defaultPref|sticky_pref)\\([[:space:]]*["'"'"'](%s)["'"'"'][[:space:]]*,[[:space:]]*false[[:space:]]*\\)' "${re#|}"
}
# Pure. Lines in a Firefox prefs file that switch a protection off.
ff_bad_pref_lines() { [ -f "$1" ] && grep -nE "$(_ff_bad_re)" "$1"; return 0; }
# Comment those lines out (// in JS files).
ff_fix_prefs() {
    local f="$1" tmp
    tmp="$(mktemp)"
    sed -E "s#($(_ff_bad_re).*)\$#// \\1   // protection back on (cpkit)#" "$f" > "$tmp" && cat "$tmp" > "$f"
    rm -f "$tmp"
}
# Firefox prefs files: every profile under the given homes, plus system-wide pref files.
ff_pref_files() {
    local h d f
    for h in "$@"; do
        for d in "$h"/.mozilla/firefox/*/ "$h"/snap/firefox/common/.mozilla/firefox/*/; do
            [ -d "$d" ] || continue
            for f in "$d"prefs.js "$d"user.js; do [ -f "$f" ] && echo "$f"; done
        done
    done
    for f in /etc/firefox/syspref.js /etc/firefox/pref/*.js /etc/firefox-esr/*.js /usr/lib/firefox*/defaults/pref/*.js \
             /usr/lib/firefox*/browser/defaults/preferences/*.js /usr/lib/firefox*/*.cfg; do
        [ -f "$f" ] && echo "$f"
    done
    return 0
}

# Pure. Display-manager config lines that log someone in with no password.
dm_autologin_lines() {
    [ -f "$1" ] || return 0
    local re='autologin-user[[:space:]]*=[[:space:]]*[^[:space:]]+|autologin-guest[[:space:]]*=[[:space:]]*true|allow-guest[[:space:]]*=[[:space:]]*true|AutomaticLoginEnable[[:space:]]*=[[:space:]]*(true|1)|TimedLoginEnable[[:space:]]*=[[:space:]]*(true|1)'
    # SDDM's autologin is "User=name" (in [Autologin]); that key means nothing in other files
    if [ "${1##*/}" = sddm.conf ] || [[ "$1" == */sddm.conf.d/* ]]; then re="$re|User[[:space:]]*=[[:space:]]*[^[:space:]]+"; fi
    grep -nE "^[[:space:]]*($re)" "$1"
    return 0
}
dm_autologin_fix() {
    local f="$1" tmp sddm=0
    { [ "${f##*/}" = sddm.conf ] || [[ "$f" == */sddm.conf.d/* ]]; } && sddm=1
    tmp="$(mktemp)"
    awk -v sddm="$sddm" '
        /^[ \t]*(autologin-user[ \t]*=[ \t]*[^ \t]+|autologin-guest[ \t]*=[ \t]*true|allow-guest[ \t]*=[ \t]*true)/ { print "#" $0 "   # off (cpkit)"; next }
        /^[ \t]*(AutomaticLoginEnable|TimedLoginEnable)[ \t]*=[ \t]*(true|1)/ { sub(/=.*/, "=false"); print; next }
        sddm == 1 && /^[ \t]*User[ \t]*=[ \t]*[^ \t]+/ { print "#" $0 "   # autologin off (cpkit)"; next }
        { print }' "$f" > "$tmp"
    cat "$tmp" > "$f"; rm -f "$tmp"
}

# Write the dconf files (screen lock + no automount) under ROOT ("" = real system).
CP_DCONF_LOCK_KEYS='[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
idle-activation-enabled=true

[org/gnome/desktop/session]
idle-delay=uint32 300

[org/cinnamon/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0

[org/cinnamon/desktop/session]
idle-delay=uint32 300

[org/mate/screensaver]
lock-enabled=true
idle-activation-enabled=true

[org/mate/desktop/session]
idle-delay=5'
desktop_dconf_media_keys() {
    local s
    for s in org/gnome/desktop/media-handling org/cinnamon/desktop/media-handling org/mate/desktop/media-handling; do
        printf '[%s]\nautomount=false\nautomount-open=false\nautorun-never=true\n\n' "$s"
    done
}
desktop_dconf_locks() {
    local s
    printf '/org/gnome/desktop/screensaver/lock-enabled\n/org/gnome/desktop/screensaver/lock-delay\n/org/gnome/desktop/session/idle-delay\n'
    printf '/org/cinnamon/desktop/screensaver/lock-enabled\n/org/cinnamon/desktop/session/idle-delay\n/org/mate/screensaver/lock-enabled\n'
    for s in org/gnome/desktop/media-handling org/cinnamon/desktop/media-handling org/mate/desktop/media-handling; do
        printf '/%s/automount\n/%s/automount-open\n/%s/autorun-never\n' "$s" "$s" "$s"
    done
}
desktop_dconf_ok() {   # ROOT
    local r="${1:-}"
    grep -qs '^system-db:local' "$r/etc/dconf/profile/user" &&
    [ "$(cat "$r/etc/dconf/db/local.d/00-cpkit-desktop" 2>/dev/null)" = "$(printf '%s\n\n' "$CP_DCONF_LOCK_KEYS"; desktop_dconf_media_keys)" ]
}
desktop_dconf_write() {   # ROOT
    local r="${1:-}"
    mkdir -p "$r/etc/dconf/profile" "$r/etc/dconf/db/local.d/locks"
    [ -n "$CP_RUN" ] && [ -z "$r" ] && { cp_backup /etc/dconf/profile/user; cp_backup /etc/dconf/db/local.d/00-cpkit-desktop; }
    if [ ! -s "$r/etc/dconf/profile/user" ]; then printf 'user-db:user\nsystem-db:local\n' > "$r/etc/dconf/profile/user"
    elif ! grep -q '^system-db:local' "$r/etc/dconf/profile/user"; then echo 'system-db:local' >> "$r/etc/dconf/profile/user"; fi
    { printf '%s\n\n' "$CP_DCONF_LOCK_KEYS"; desktop_dconf_media_keys; } > "$r/etc/dconf/db/local.d/00-cpkit-desktop"
    desktop_dconf_locks > "$r/etc/dconf/db/local.d/locks/00-cpkit-desktop"
    [ -z "$r" ] && command -v dconf >/dev/null && dconf update
    return 0
}

_desktop_install_dconf() { DEBIAN_FRONTEND=noninteractive apt-get install -y dconf-cli; }
_desktop_gdm_hardening() {   # FILE: no remote X / XDMCP
    cp_backup "$1"
    ini_set "$1" security DisallowTCP true; ini_set "$1" xdmcp Enable false
    return 0
}
_desktop_home_dirs() { echo /root; getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 { print $6 }' | sort -u; }

mod_desktop() {
    cp_header "DESKTOP + FIREFOX  (autologin off, screen lock, no autorun, Firefox protections)"
    local f l owner g
    # Automatic / guest login: GDM (Debian/Ubuntu), LightDM (Mint), SDDM (KDE)
    for f in /etc/gdm3/daemon.conf /etc/gdm3/custom.conf /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.d/*.conf \
             /usr/share/lightdm/lightdm.conf.d/*.conf /etc/sddm.conf /etc/sddm.conf.d/*.conf; do
        l="$(dm_autologin_lines "$f")"
        [ -n "$l" ] || continue
        cp_backup "$f"
        cp_act desktop "turn off automatic/guest login in $f ($(echo "$l" | cut -d: -f2- | xargs | cut -c1-80))" "anyone at the keyboard gets a session with no password (skip if README needs autologin)" dm_autologin_fix "$f"
    done
    for g in /etc/gdm3/daemon.conf /etc/gdm3/custom.conf; do
        [ -f "$g" ] || continue
        if [ "$(ini_get "$g" security DisallowTCP)" = true ] && [ "$(ini_get "$g" xdmcp Enable)" != true ]; then echo "  ok   $g: no X over TCP / XDMCP"
        else cp_act desktop "DisallowTCP=true, xdmcp Enable=false in $g" "remote X logins without encryption" _desktop_gdm_hardening "$g"; fi
        break
    done

    # Screen lock + no automount (only where a desktop exists)
    if [ -d /etc/dconf ] || [ -d /usr/share/xsessions ]; then
        command -v dconf >/dev/null || cp_act desktop "apt-get install dconf-cli" "needed to set the screen lock for every user" _desktop_install_dconf
        if desktop_dconf_ok ""; then echo "  ok   screen lock after 5 min + no USB/CD automount (dconf, locked)"
        else cp_act desktop "dconf: lock screen after 5 idle min, no USB/CD automount/autorun, locked for users + dconf update" "an unattended unlocked screen / a planted USB stick" desktop_dconf_write ""; fi
        [ -d /etc/xdg/xfce4 ] && cp_finding desktop "Xfce does not read dconf: set Settings > Screensaver > Lock Screen by hand"
    else echo "  ok   no graphical desktop found (screen lock skipped)"; fi

    # Firefox: protections switched off in prefs files
    local files any=0 homes
    mapfile -t homes < <(_desktop_home_dirs)
    files="$(ff_pref_files "${homes[@]}")"
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        l="$(ff_bad_pref_lines "$f")"
        [ -n "$l" ] || continue
        any=1
        if [ "${f##*/}" = prefs.js ]; then
            owner="$(stat -c %U "$f")"
            if pgrep -u "$owner" -x 'firefox|firefox-esr|firefox-bin' >/dev/null 2>&1; then
                cp_finding desktop "Firefox is OPEN for $owner - close it, then re-run --module desktop ($f turns off: $(echo "$l" | grep -oE '"[a-z._]+"' | xargs))"
                continue
            fi
        fi
        cp_backup "$f"
        cp_act desktop "Firefox protections back on in $f: $(echo "$l" | grep -oE "[\"'][a-z._]+[\"']" | tr -d "\"'" | xargs)" "pop-up blocking, add-on warnings, dangerous-site/download blocking" ff_fix_prefs "$f"
    done <<< "$files"
    [ "$any" = 0 ] && echo "  ok   no Firefox prefs file turns protections off"
    for f in /etc/firefox/policies/policies.json /etc/firefox-esr/policies/policies.json /usr/lib/firefox*/distribution/policies.json; do
        [ -f "$f" ] && cp_finding desktop "Firefox policy file $f - open about:policies and check nothing turns protections off"
    done
    [ -n "$files" ] && cp_finding desktop "Firefox by hand (each user): Settings > Privacy & Security - Block pop-ups, Warn on add-on installs, Block dangerous content, HTTPS-Only mode; remove unknown extensions; update Firefox"
    return 0
}

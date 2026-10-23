#!/usr/bin/env bash
# Prohibited files. CP category: Policy Violation: Prohibited Files.
# REPORT ONLY - deleting before the forensics questions are answered can cost points.

# Drops the kit's own files (run dirs with backups, the downloaded kit) from the report.
# The kit root is skipped only when it is named like the kit, so /home is never hidden.
media_not_kit() {
    local root="${CP_KIT_ROOT:-}"
    case "$(basename "${root:-/x}")" in cp19-kit*|cyberpatriot-kit*) ;; *) root="" ;; esac
    awk -v r="$root" 'index($0, "/root/cpkit-runs/") == 1 { next } r != "" && index($0, r "/") == 1 { next } { print }'
}

mod_media() {
    cp_header "MEDIA / PROHIBITED FILES  (report only - delete by hand AFTER forensics)"
    local n=0 f
    while IFS= read -r f; do
        cp_finding media "media file: $f"; n=$((n+1))
    done < <(find /home /root /srv /opt /var/www /tmp /usr/share/games -xdev -type f \
        \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.avi' -o -iname '*.mkv' -o -iname '*.mov' -o -iname '*.wav' \
           -o -iname '*.flac' -o -iname '*.ogg' -o -iname '*.m4a' -o -iname '*.wma' -o -iname '*.aac' -o -iname '*.m4v' \
           -o -iname '*.flv' -o -iname '*.webm' \) 2>/dev/null | media_not_kit)
    while IFS= read -r f; do
        cp_finding media "image in a home dir: $f"; n=$((n+1))
    done < <(find /home /root -xdev -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' \) \
        -not -path '*/.cache/*' -not -path '*/.local/share/icons/*' -not -path '*/.mozilla/*' 2>/dev/null | media_not_kit)
    while IFS= read -r f; do
        cp_finding media "archive/secret-looking file: $f"; n=$((n+1))
    done < <(find /home /root /srv /opt /var/www -xdev -type f \( -iname '*.zip' -o -iname '*.tar.gz' -o -iname '*.7z' \
        -o -iname '*.rar' -o -iname '*password*' -o -iname '*.kdbx' -o -iname '*creditcard*' -o -iname '*ssn*' \
        -o -iname '*.pcap' \) 2>/dev/null | media_not_kit)
    echo "  $n file(s) listed in findings.txt"
    return 0
}

#!/usr/bin/env bash
# Shared helpers for every Linux module.
# Rules this file enforces for the whole kit:
#   - audit mode (default) never changes anything; it prints [WOULD] lines
#   - apply mode asks y/N per action (unless CP_YES=1), backs files up, logs everything
#   - users/services named in the README config are protected, as is the scoring client

CP_MODE="${CP_MODE:-audit}"     # audit | apply
CP_YES="${CP_YES:-0}"           # 1 = don't prompt (tests only)
CP_RUN="${CP_RUN:-}"            # run directory: log.txt, findings.txt, backup/
CP_ADMINS=""; CP_USERS=""; CP_CRITICAL=""; CP_ALLOWED=""; CP_NEWPASS=""
CP_CRITICAL_ALL=""              # CP_CRITICAL + every alias/unit name it implies
CP_ME="${CP_ME:-}"              # the human running the kit (never removed/demoted)
CP_SCORING_RE='cyberpatriot|cpscor|scoring|aeacus'

# README words -> the unit names they can mean on Mint/Debian/Ubuntu.
declare -A CP_SERVICE_ALIASES=(
    [ssh]="ssh sshd openssh-server" [sshd]="ssh sshd"
    [ftp]="vsftpd proftpd pure-ftpd" [vsftpd]="vsftpd" [proftpd]="proftpd"
    [samba]="smbd nmbd samba" [smb]="smbd nmbd" [smbd]="smbd nmbd"
    [mysql]="mysql mariadb mysqld" [mariadb]="mariadb mysql mysqld" [mysqld]="mysql mariadb mysqld"
    [apache]="apache2 httpd" [apache2]="apache2" [httpd]="apache2 httpd"
    [postgres]="postgresql" [postgresql]="postgresql"
    [bind]="bind9 named" [bind9]="bind9 named" [named]="bind9 named" [dns]="bind9 named"
    [mail]="postfix dovecot" [smtp]="postfix exim4" [cups]="cups cups-browsed" [printing]="cups cups-browsed"
    [nfs]="nfs-server nfs-kernel-server rpcbind" [web]="apache2 nginx" [vnc]="x11vnc vncserver xrdp"
)

# Who is running this? sudo -> SUDO_USER; "sudo su -" -> logname / who am i.
cp_detect_me() {
    local me="${SUDO_USER:-}"
    [ -z "$me" ] || [ "$me" = root ] && me="$(logname 2>/dev/null || true)"
    [ -z "$me" ] || [ "$me" = root ] && me="$(who am i 2>/dev/null | awk '{print $1}')"
    [ "$me" = root ] && me=""
    CP_ME="$me"
}

cp_expand_critical() {
    local c base out=""
    for c in $CP_CRITICAL; do
        base="$(echo "${c%.service}" | tr '[:upper:]' '[:lower:]')"
        out="$out $base ${CP_SERVICE_ALIASES[$base]:-}"
    done
    CP_CRITICAL_ALL="$(echo $out | tr ' ' '\n' | awk 'NF && !seen[$0]++' | xargs)"
}

cp_require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run with sudo:  sudo bash $0" >&2
        exit 1
    fi
}

# Read KEY=value lines. Lists stay space-separated strings.
cp_load_config() {
    local file="$1" key val
    if [ ! -f "$file" ]; then
        echo "Config not found: $file  (copy config/cp-config.example.txt to cp-config.txt and fill it from the README)" >&2
        return 1
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"                      # tolerate Windows line endings
        line="${line#$'\xef\xbb\xbf'}"            # tolerate a UTF-8 BOM (Notepad)
        [[ "$line" =~ ^[[:space:]]*# ]] && continue   # whole-line comments only
        [[ "$line" == *=* ]] || continue
        key="$(echo "${line%%=*}" | tr -d '[:space:]')"
        val="${line#*=}"
        if [ "$key" = NEW_PASSWORD ]; then
            # passwords may contain # ' and spaces: keep exactly, trim only the ends
            val="$(printf '%s' "$val" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
        else
            val="$(printf '%s' "$val" | sed -E 's/[[:space:]]+#.*$//' | tr ',' ' ' | awk '{$1=$1; print}')"   # commas = spaces
        fi
        case "$key" in
            ADMINS) CP_ADMINS="$val" ;;
            USERS) CP_USERS="$val" ;;
            CRITICAL_SERVICES) CP_CRITICAL="$val" ;;
            ALLOWED_SOFTWARE) CP_ALLOWED="$val" ;;
            NEW_PASSWORD) CP_NEWPASS="$val" ;;
            KEEP_RDP|KEEP_SHARES) ;;              # Windows-only keys
            *) echo "  (config: unknown key '$key' ignored)" >&2 ;;
        esac
    done < "$file"
    cp_expand_critical
    return 0
}

# Whole-word membership. cp_in_list ITEM "LIST"
cp_in_list() {
    local item="$1" w
    for w in $2; do [ "$w" = "$item" ] && return 0; done
    return 1
}

cp_is_protected_user() {
    local u="$1" uid
    cp_in_list "$u" "$CP_ADMINS $CP_USERS" && return 0
    [ -n "${SUDO_USER:-}" ] && [ "$u" = "$SUDO_USER" ] && return 0
    [ -n "${CP_ME:-}" ] && [ "$u" = "$CP_ME" ] && return 0
    [ "$u" = "root" ] && return 0
    uid="$(id -u "$u" 2>/dev/null || echo "")"
    # system accounts (UID < 1000) are never removed by the users module
    [ -n "$uid" ] && [ "$uid" -ne 0 ] && [ "$uid" -lt 1000 ] && return 0
    return 1
}

cp_is_protected_service() {
    local s c
    s="$(echo "${1%.service}" | tr '[:upper:]' '[:lower:]')"
    echo "$s" | grep -Eqi "$CP_SCORING_RE" && return 0
    s="${s%.socket}"; s="${s%.path}"
    [ -n "$CP_CRITICAL_ALL" ] || cp_expand_critical
    cp_in_list "$s" "$CP_CRITICAL_ALL" && return 0
    return 1
}

cp_log() {  # MODULE ACTION BEFORE AFTER WHY
    [ -n "$CP_RUN" ] || return 0
    printf '%s | %s | %s | %s -> %s | %s\n' "$(date +%H:%M:%S)" "$1" "$2" "$3" "$4" "$5" >> "$CP_RUN/log.txt"
}

# Copy a file to $CP_RUN/backup<path> the first time it is touched in this run.
cp_backup() {
    local p="$1" dest
    [ -e "$p" ] || return 0
    dest="$CP_RUN/backup$p"
    [ -e "$dest" ] && return 0
    mkdir -p "$(dirname "$dest")"
    cp -a "$p" "$dest"
}

cp_finding() {  # MODULE TEXT
    echo "  [CHECK] $2"
    [ -n "$CP_RUN" ] && printf '[%s] %s\n' "$1" "$2" >> "$CP_RUN/findings.txt"
    return 0
}

# Ask y/N. Returns 0 for yes. CP_YES=1 answers yes.
cp_ask() {
    [ "$CP_YES" = "1" ] && return 0
    local a
    read -r -p "  Apply? [y/N] " a </dev/tty || return 1
    [[ "$a" =~ ^[Yy] ]]
}

# cp_act MODULE "description" "why" command args...
cp_act() {
    local mod="$1" desc="$2" why="$3"; shift 3
    if [ "$CP_MODE" != "apply" ]; then
        echo "  [WOULD] $desc  -- $why"
        return 0
    fi
    echo "  [DO] $desc  -- $why"
    if ! cp_ask; then
        echo "       skipped"
        cp_log "$mod" "SKIP" "$desc" "-" "$why"
        return 0
    fi
    if "$@"; then
        cp_log "$mod" "ACTION" "$desc" "done" "$why"
    else
        echo "       FAILED (see above); continuing"
        cp_log "$mod" "FAILED" "$desc" "error" "$why"
    fi
    return 0
}

cp_header() { echo; echo "===== $1 ====="; }

# Current value of KEY in a "KEY value" / "KEY=value" / "KEY = value" file (uncommented lines only).
cp_conf_get() {
    local file="$1" key="$2"
    [ -f "$file" ] || return 0
    awk -v k="$key" '
        { line=$0; sub(/^[ \t]+/, "", line) }
        line ~ "^" k "([ \t]*=[ \t]*|[ \t]+)" {
            sub("^" k "([ \t]*=[ \t]*|[ \t]+)", "", line); sub(/[ \t]+$/, "", line)
            if (n && line != val) conflict=1
            if (!n) val=line
            n++
        }
        END { if (conflict) print "(conflicting duplicates)"; else if (val != "") print val }' "$file"
}

# Set KEY to VALUE. Replaces every uncommented occurrence; else the first commented one; else
# inserts it above the first "Match" block (sshd) or at the end.
# Returns 0 if changed, 2 if already set. Backs the file up first. SEP defaults to one space.
cp_set_conf() {
    local file="$1" key="$2" value="$3" sep="${4:- }" tmp
    [ "$(cp_conf_get "$file" "$key")" = "$value" ] && return 2
    [ -n "$CP_RUN" ] && cp_backup "$file"
    tmp="$(mktemp)"
    awk -v k="$key" -v v="$value" -v s="$sep" '
        { lines[NR]=$0; l=$0; sub(/^[ \t]+/, "", l)
          if (!matchl && l ~ /^Match[ \t]/) matchl=NR
          if (l ~ "^" k "([ \t]*=|[ \t]+|$)") { live[NR]=1; nlive++ }
          else if (!firstc && l ~ "^#[ \t]*" k "([ \t]*=|[ \t]+|$)") firstc=NR }
        END {
          if (matchl && firstc > matchl) firstc=0      # never land inside a Match block
          done=0
          for (i=1;i<=NR;i++) {
            if (i==matchl && !done && !nlive && !firstc) { print k s v; done=1 }
            if (i in live) { if (!done) { print k s v; done=1 } ; continue }
            if (i==firstc && !nlive) { print k s v; done=1; continue }
            print lines[i]
          }
          if (!done) print k s v
        }' "$file" > "$tmp"
    cat "$tmp" > "$file"; rm -f "$tmp"
    return 0
}

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
CP_SCORING_RE='cyberpatriot|cpscor|scoring|aeacus'

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
        line="${line%%#*}"                        # strip comments
        [[ "$line" == *=* ]] || continue
        key="$(echo "${line%%=*}" | tr -d '[:space:]')"
        val="$(echo "${line#*=}" | xargs)"        # trim + collapse spaces
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
    for c in $CP_CRITICAL; do
        [ "$s" = "$(echo "${c%.service}" | tr '[:upper:]' '[:lower:]')" ] && return 0
    done
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

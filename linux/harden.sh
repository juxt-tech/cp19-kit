#!/usr/bin/env bash
# CyberPatriot Linux hardening kit (Mint 21 / Debian 12 / Ubuntu 22-24).
#
#   sudo bash harden.sh                      # AUDIT: shows what it would change, changes nothing
#   sudo bash harden.sh --apply              # menu; asks y/N before every change
#   sudo bash harden.sh --apply --module users --module passwords
#
# Before you run it: answer the forensics questions, read the README, fill cp-config.txt,
# and take a VMware snapshot. Run one module at a time and snapshot between them.

KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CP_KIT_ROOT="$(dirname "$KIT")"   # media report skips the kit's own download
# shellcheck source=lib/common.sh
source "$KIT/lib/common.sh"
for m in "$KIT"/modules/*.sh; do source "$m"; done

ORDER=(users sources passwords firewall ssh sysctl perms services software updates persistence media)
declare -A WHAT=(
    [users]="accounts + sudo match the README; lock root; guest login off"
    [sources]="re-enable official apt sources + apt-get update (needed before installs)"
    [passwords]="password age/length/complexity/history; lockout after 5 fails"
    [firewall]="ufw on: deny in, allow out, open critical-service ports"
    [ssh]="harden sshd_config (only if ssh is critical)"
    [sysctl]="kernel/network hardening (ASLR, SYN cookies, no redirects)"
    [perms]="fix /etc/shadow, passwd, sudoers perms; list odd SUID files"
    [services]="stop risky services not required by the README"
    [software]="purge hacking tools/games; list recent installs"
    [updates]="enable sources + auto-updates; full upgrade"
    [persistence]="REPORT cron/timers/rc.local/backdoors/hosts"
    [media]="REPORT media + prohibited files (delete by hand later)"
)

usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; echo "Flags: --apply --yes --all --config FILE --module NAME (repeatable)"; echo "Modules: ${ORDER[*]}"; }

CONFIG=""; MODULES=(); ALL=0
while [ $# -gt 0 ]; do
    case "$1" in
        --apply) CP_MODE=apply ;;
        --yes) CP_YES=1 ;;
        --all) ALL=1 ;;
        --config) CONFIG="$2"; shift ;;
        --module) MODULES+=("$2"); shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

cp_require_root

if [ -z "$CONFIG" ]; then
    for c in ./cp-config.txt "$KIT/cp-config.txt" "$KIT/../cp-config.txt"; do [ -f "$c" ] && { CONFIG="$c"; break; }; done
fi
cp_load_config "${CONFIG:-./cp-config.txt}" || exit 1
cp_detect_me
export CP_ME

CP_RUN="/root/cpkit-runs/$(date +%Y%m%d-%H%M%S)"
[ -e "$CP_RUN" ] && CP_RUN="$CP_RUN-$$"
mkdir -p "$CP_RUN"; : > "$CP_RUN/log.txt"; : > "$CP_RUN/findings.txt"
export CP_RUN CP_MODE CP_YES

echo "================================================================"
echo " CyberPatriot Linux kit   mode: $(echo "$CP_MODE" | tr a-z A-Z)"
echo " config : $CONFIG"
echo " admins : $CP_ADMINS      (you: ${CP_ME:-unknown - run with sudo from your own account})"
echo " users  : $CP_USERS"
echo " critical services: ${CP_CRITICAL:-(none)}    allowed software: ${CP_ALLOWED:-(none)}"
echo " run dir: $CP_RUN   (log.txt, findings.txt, backup/)"
echo "================================================================"
if [ "$CP_MODE" = apply ] && [ "$CP_YES" != 1 ]; then
    read -r -p "Forensics questions answered AND VMware snapshot taken? [y/N] " a </dev/tty
    [[ "$a" =~ ^[Yy] ]] || { echo "Do those first. Nothing was changed."; exit 0; }
fi

run_module() {
    local m="$1"
    if ! declare -F "mod_$m" >/dev/null; then echo "unknown module: $m (choose: ${ORDER[*]})"; return; fi
    "mod_$m"
}

if [ ${#MODULES[@]} -gt 0 ]; then
    for m in "${MODULES[@]}"; do run_module "$m"; done
elif [ "$ALL" = 1 ]; then
    for m in "${ORDER[@]}"; do run_module "$m"; done
else
    while true; do
        echo; echo "Modules (recommended order - snapshot between them):"
        i=1; for m in "${ORDER[@]}"; do printf "  %2d) %-12s %s\n" "$i" "$m" "${WHAT[$m]}"; i=$((i+1)); done
        echo "   a) all in order     q) quit"
        read -r -p "Choose: " c </dev/tty || break
        case "$c" in
            q|Q|"") break ;;
            a|A) for m in "${ORDER[@]}"; do run_module "$m"; done ;;
            *[!0-9]*) run_module "$c" ;;
            *) [ "$c" -ge 1 ] && [ "$c" -le ${#ORDER[@]} ] && run_module "${ORDER[$((c-1))]}" ;;
        esac
    done
fi

echo
echo "================================================================"
echo " done. changes made: $(grep -c ' | ACTION | ' "$CP_RUN/log.txt")   findings to review: $(wc -l < "$CP_RUN/findings.txt")"
echo " findings: $CP_RUN/findings.txt     undo files: $CP_RUN/backup/"
[ "$CP_MODE" = audit ] && echo " This was an AUDIT. Re-run with --apply to make changes."
echo "================================================================"
exit 0

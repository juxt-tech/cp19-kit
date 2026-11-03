#!/usr/bin/env bash
# cpkit practice-VM test agent (Linux). PRACTICE VMs ONLY - never on a competition image.
# Installed by linux-bootstrap.sh as systemd unit cpkit-test-agent (root, Restart=always), so a lock
# screen, logout or reboot does not stop it. Pulls jobs from the host, runs each in its own process
# group (timeout + kill), posts results and a heartbeat every 15 s. Needs curl or wget.
S="${CP_SERVER:-}"; [ -n "$S" ] || S='{{SERVER}}'   # filled in by server.py; CP_SERVER overrides (tests)
ROOT="${CP_ROOT:-/var/lib/cpagent}"
ID="${CP_VM:-$(hostname | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._\n-' '-')}"
IDLE="${CP_IDLE:-3}"
VERSION=2
mkdir -p "$ROOT/jobs" "$ROOT/outbox"
exec 9>"$ROOT/lock"
flock -n 9 || exit 0   # already running

log() { echo "$(date +%FT%T) $*" >> "$ROOT/agent.log"; }

# http_get URL OUTFILE -> prints the status code (0 = no connection); headers in OUTFILE.hdr
http_get() {
    if command -v curl >/dev/null 2>&1; then
        curl -s -o "$2" -D "$2.hdr" -w '%{http_code}' --max-time 15 "$1" 2>/dev/null || true
    else
        wget -q -S -O "$2" --timeout=15 --tries=1 "$1" 2>"$2.hdr"
        awk '/^ *HTTP\//{c=$2} END{print c+0}' "$2.hdr"
    fi
}
# http_post NAME FILE -> exit 0 on success
http_post() {
    if command -v curl >/dev/null 2>&1; then
        curl -sf -o /dev/null --max-time 60 -X POST -H 'Content-Type: application/octet-stream' --data-binary "@$2" "$S/$ID/r/$1"
    else
        wget -q -O /dev/null --timeout=60 --tries=1 --header='Content-Type: application/octet-stream' --post-file="$2" "$S/$ID/r/$1"
    fi
}

json_str() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/ /g' | tr -d '\000-\010\013-\037' | awk 'BEGIN{ORS="\\n"} {print}' | sed 's/\\n$//'; }

heartbeat() {   # heartbeat JOB SECS OUTFILE
    local up tail sess
    up=$(awk '{print int($1/60)}' /proc/uptime 2>/dev/null)
    tail=""; [ -n "$3" ] && [ -f "$3" ] && tail=$(tail -n 8 "$3" 2>/dev/null)
    sess=$(who 2>/dev/null | awk '{print $1"@"$2}' | tr '\n' ' ')
    printf '{"time":"%s","vm":"%s","os":"linux","agent":%s,"runas":"%s","uptimeMin":%s,"lastJob":%s,"job":%s,"jobSecs":%s,"sessions":"%s","tail":"%s"}\n' \
        "$(date +%FT%T)" "$ID" "$VERSION" "$(id -un)" "${up:--1}" "$LAST" "${1:-null}" "${2:-0}" "$(json_str "$sess")" "$(json_str "$tail")" > "$ROOT/hb.json"
    http_post hb.json "$ROOT/hb.json" || true
}

flush_outbox() {
    local f
    for f in "$ROOT"/outbox/*; do
        [ -f "$f" ] || continue
        http_post "$(basename "$f")" "$f" && rm -f "$f"
    done
}

save_result() {   # save_result N FILE-WITH-TEXT
    local max=$((8 * 1024 * 1024))
    if [ "$(stat -c %s "$2")" -gt "$max" ]; then
        { echo "[output truncated to the last 8 MB]"; tail -c "$max" "$2"; } > "$ROOT/outbox/out-$1.txt"
    else
        cp "$2" "$ROOT/outbox/out-$1.txt"
    fi
    flush_outbox
}

run_job() {   # run_job N CODEFILE
    local n=$1 code=$2 timeout=3600 job out t0 pid secs status=done ex=-1 next_hb
    t=$(grep -m1 -oE '^[[:space:]]*#[[:space:]]*timeout[[:space:]]*=[[:space:]]*[0-9]+' "$code" | grep -oE '[0-9]+$') && timeout=$t
    job="$ROOT/jobs/cmd-$n.sh"; out="$ROOT/jobs/out-$n.txt"
    {
        echo "CP_SERVER='$S'; CP_VM='$ID'; export CP_SERVER CP_VM"
        echo "up() { local f; f=\$(mktemp); cat > \"\$f\"; if command -v curl >/dev/null; then curl -sf -o /dev/null -X POST --data-binary \"@\$f\" \"\$CP_SERVER/\$CP_VM/r/\$1\"; else wget -q -O /dev/null --post-file=\"\$f\" \"\$CP_SERVER/\$CP_VM/r/\$1\"; fi; rm -f \"\$f\"; }"
        cat "$code"
    } > "$job"
    t0=$(date +%s)
    # 9>&-: the job must not inherit the agent's lock, or an orphaned job blocks the restarted agent
    setsid bash "$job" > "$out" 2>&1 < /dev/null 9>&- &
    pid=$!
    next_hb=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 2
        secs=$(( $(date +%s) - t0 ))
        if [ "$secs" -ge "$timeout" ]; then status="timeout after ${timeout}s"; kill -KILL -- "-$pid" 2>/dev/null; break; fi
        if [ "$(date +%s)" -ge "$next_hb" ]; then
            next_hb=$(( $(date +%s) + 15 ))
            heartbeat "$n" "$secs" "$out"
            if [ "$(http_get "$S/$ID/kill-$n" "$ROOT/kill.tmp")" = 200 ]; then status="killed by host"; kill -KILL -- "-$pid" 2>/dev/null; break; fi
        fi
    done
    wait "$pid" 2>/dev/null; ex=$?
    secs=$(( $(date +%s) - t0 ))
    { echo "#job=$n status=$status exit=$ex secs=$secs"; cat "$out"; } > "$ROOT/jobs/res-$n.txt"
    save_result "$n" "$ROOT/jobs/res-$n.txt"
}

LAST=0; [ -f "$ROOT/last.txt" ] && LAST=$(head -n1 "$ROOT/last.txt")
if [ -f "$ROOT/running.txt" ]; then   # VM or agent restarted mid-job: never re-run it
    n=$(head -n1 "$ROOT/running.txt")
    echo "#job=$n status=interrupted (agent or VM restarted while it ran)" > "$ROOT/jobs/res-$n.txt"
    save_result "$n" "$ROOT/jobs/res-$n.txt"; rm -f "$ROOT/running.txt"
fi
log "agent v$VERSION start as $(id -un) server=$S id=$ID last=$LAST"

next_hb=0
while true; do
    flush_outbox
    code=$(http_get "$S/$ID/next?after=$LAST" "$ROOT/next.tmp")
    if [ "$code" = 200 ]; then
        n=$(awk 'tolower($1)=="x-job:"{gsub("\r","",$2); print $2}' "$ROOT/next.tmp.hdr" | tail -n1)
        if [ -n "$n" ]; then
            echo "$n" > "$ROOT/last.txt"; echo "$n" > "$ROOT/running.txt"
            log "job $n start"; run_job "$n" "$ROOT/next.tmp"
            rm -f "$ROOT/running.txt"; LAST=$n; log "job $n end"; next_hb=0
            continue
        fi
    fi
    if [ "$(date +%s)" -ge "$next_hb" ]; then heartbeat "" 0 ""; next_hb=$(( $(date +%s) + 15 )); fi
    sleep "$IDLE"
done

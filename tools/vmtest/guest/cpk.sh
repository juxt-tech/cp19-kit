# Kit helpers for Linux test jobs. In a job:  source <(curl -s "$CP_SERVER/g/cpk.sh")   (or wget -qO-)
# (CP_SERVER, CP_VM and up come from the agent's job prelude.)
cp_fetch() { if command -v curl >/dev/null 2>&1; then curl -sf "$1" -o "$2"; else wget -qO "$2" "$1"; fi; }

install_kit() {   # install_kit [CONFIG-NAME]
    local cfg="${1:-cp-config.txt}"
    cd / || return
    cp_fetch "$CP_SERVER/f/kit.tgz" /root/cpkit.tgz || { echo "kit.tgz download failed"; return 1; }
    rm -rf /root/cpkit; mkdir -p /root/cpkit
    tar -xzf /root/cpkit.tgz -C /root/cpkit
    cp_fetch "$CP_SERVER/f/$cfg" /root/cpkit/cp-config.txt || { echo "config $cfg download failed"; return 1; }
    echo "kit installed: $(find /root/cpkit -type f | wc -l) files, config $cfg"
}

run_kit() {   # run_kit TAG [harden.sh flags...]   e.g. run_kit apply-users --apply --yes --module users
    local tag=$1 t0 r; shift
    cd /root/cpkit || return
    t0=$(date +%s)
    # The agent is root with no sudo, but the kit protects the user who ran sudo (SUDO_USER/CP_ME).
    # Act as the signed-in team member, like a real "sudo bash harden.sh" from their terminal.
    me=$(who 2>/dev/null | awk '$1!="root"{print $1; exit}')
    SUDO_USER="${me:-}" CP_ME="${me:-}" bash linux/harden.sh --config /root/cpkit/cp-config.txt "$@" > "/root/$tag.txt" 2>&1 < /dev/null
    r=$(ls -1d /root/cpkit-runs/*/ 2>/dev/null | sort | tail -n1)
    [ -n "$r" ] && up "$tag-findings.txt" < "$r/findings.txt"
    [ -n "$r" ] && up "$tag-log.txt" < "$r/log.txt"
    up "$tag.txt" < "/root/$tag.txt"
    echo "### $tag ($(( $(date +%s) - t0 ))s, run dir $r)"
    cat "/root/$tag.txt"
}

get_score() {   # get_score TAG  - uploads the Aeacus report if there is one
    local f
    for f in /opt/aeacus/assets/ScoringReport.html /opt/aeacus/web/assets/ScoringReport.html; do
        [ -f "$f" ] && { up "$1-score.html" < "$f"; echo "score report $1: $(stat -c %y "$f")"; return; }
    done
    echo "no Aeacus score report found (CCS image? check the desktop score report by hand)"
}

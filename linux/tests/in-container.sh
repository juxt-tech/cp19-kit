#!/usr/bin/env bash
# Full scenario inside ONE throwaway container. Kit is mounted read-only at /k.
K=/k/linux
step() { echo; echo "######## $*"; }
fail() { echo "SCENARIO FAIL: $*"; exit 1; }

step "unit tests"
bash $K/tests/unit.sh | tail -1 | grep -q " 0 failed" || { bash $K/tests/unit.sh | grep FAIL; fail "unit"; }
echo "unit ok"

step "plant vulnerabilities"
bash $K/tests/plant-vulns.sh || fail "plant"

step "non-root run must refuse"
setpriv --reuid=65534 --regid=65534 --clear-groups bash $K/harden.sh --config /tmp/cp-config.txt --module users >/tmp/nr.txt 2>&1
rc=$?; [ $rc -eq 1 ] && grep -q "Run with sudo" /tmp/nr.txt || fail "non-root rc=$rc $(cat /tmp/nr.txt)"
echo "non-root refused ok"

step "audit run changes nothing in /etc"
before="$(tar -cf - --sort=name /etc 2>/dev/null | sha256sum)"
CP_SKIP_UPGRADE=1 bash $K/harden.sh --config /tmp/cp-config.txt --yes --all > /tmp/audit.txt 2>&1 || fail "audit exit $(tail -5 /tmp/audit.txt)"
after="$(tar -cf - --sort=name /etc 2>/dev/null | sha256sum)"
[ "$before" = "$after" ] || fail "audit modified /etc"
grep -c "\[WOULD\]" /tmp/audit.txt | sed 's/^/would-actions: /'
grep -q "\[WOULD\] delete user hacker" /tmp/audit.txt || fail "audit did not plan hacker removal"
echo "audit ok"

step "apply run"
CP_SKIP_UPGRADE=1 bash $K/harden.sh --config /tmp/cp-config.txt --apply --yes --all > /tmp/apply.txt 2>&1 || fail "apply exit"
RUN1="$(ls -1d /root/cpkit-runs/* | tail -1)"
grep -E "FAILED|reverted|restored" /tmp/apply.txt && echo "(above failures logged)"
bash $K/tests/verify.sh "$RUN1" || fail "verify"

step "second apply is a no-op"
CP_SKIP_UPGRADE=1 bash $K/harden.sh --config /tmp/cp-config.txt --apply --yes --all > /tmp/apply2.txt 2>&1 || fail "apply2 exit"
RUN2="$(ls -1d /root/cpkit-runs/* | tail -1)"
[ "$RUN1" != "$RUN2" ] || fail "second run reused run dir"
n="$(grep -c ' | ACTION | ' "$RUN2/log.txt" 2>/dev/null || true)"; n="${n:-0}"
[ "$n" -eq 0 ] || { grep ' | ACTION | ' "$RUN2/log.txt"; fail "second apply made $n changes"; }
echo "idempotent ok"
echo; echo "SCENARIO PASS"

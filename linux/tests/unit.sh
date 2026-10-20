#!/usr/bin/env bash
# Pure-function unit tests for the Linux kit. Run inside a container:
#   docker run --rm -v "$PWD":/k debian:12 bash /k/linux/tests/unit.sh
# Every test touches only temp files, never the real system.
KIT="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$KIT/.." && pwd)"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL $1${2:+ :: $2}"; }
eq()   { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$3] got [$2]"; fi; }
yes_() { if "${@:2}"; then ok "$1"; else bad "$1"; fi; }
no_()  { if "${@:2}"; then bad "$1"; else ok "$1"; fi; }

# shellcheck source=../lib/common.sh
source "$KIT/lib/common.sh"
for m in "$KIT"/modules/*.sh; do [ -f "$m" ] && source "$m"; done

T="$(mktemp -d)"
CP_RUN="$T/run"; mkdir -p "$CP_RUN"
CP_MODE=audit; CP_YES=0

echo "== common: config"
cp_load_config "$ROOT/config/cp-config.example.txt"
eq  "ADMINS parsed"            "$CP_ADMINS"   "santa prancer"
eq  "USERS parsed"             "$CP_USERS"    "cupid dasher"
eq  "CRITICAL parsed"          "$CP_CRITICAL" "ssh vsftpd"
eq  "NEW_PASSWORD parsed"      "$CP_NEWPASS"  'Cyb3rP@triot!2026'
no_ "missing config fails"     cp_load_config "$T/nope.txt"

echo "== common: lists and guards"
yes_ "whole word in list"         cp_in_list dasher "$CP_USERS"
no_  "partial word not in list"   cp_in_list das "$CP_USERS"
yes_ "scoring service protected"  cp_is_protected_service cyberpatriot-scorer
yes_ "critical service protected" cp_is_protected_service vsftpd
yes_ "critical match ignores case+.service" cp_is_protected_service VSFTPD.service
no_  "random service not protected" cp_is_protected_service cups
yes_ "listed user protected"      cp_is_protected_user santa
SUDO_USER=operatorx yes_ "invoking sudo user protected" cp_is_protected_user operatorx
no_  "unknown user not protected" cp_is_protected_user hacker

echo "== common: act / backup / finding"
echo original > "$T/f.txt"
out="$(cp_act test "write file" "because test" sh -c "echo changed > '$T/f.txt'")"
eq  "audit act leaves file"       "$(cat "$T/f.txt")" "original"
case "$out" in *"[WOULD]"*) ok "audit act prints [WOULD]";; *) bad "audit act prints [WOULD]" "$out";; esac
CP_MODE=apply; CP_YES=1
cp_act test "write file" "because test" sh -c "echo changed > '$T/f.txt'" >/dev/null
eq  "apply act changes file"      "$(cat "$T/f.txt")" "changed"
yes_ "apply act logged"           grep -q "| test | ACTION | write file -> done | because test" "$CP_RUN/log.txt"
cp_backup "$T/f.txt"; echo again > "$T/f.txt"; cp_backup "$T/f.txt"
eq  "backup keeps first copy"     "$(cat "$CP_RUN/backup$T/f.txt")" "changed"
cp_finding test "look at this"
yes_ "finding recorded"           grep -q "look at this" "$CP_RUN/findings.txt"
CP_MODE=audit; CP_YES=0

# Module tests are appended by later tasks below this line.
for t in "$KIT"/tests/unit-*.sh; do [ -f "$t" ] && source "$t"; done

rm -rf "$T"
echo "== $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

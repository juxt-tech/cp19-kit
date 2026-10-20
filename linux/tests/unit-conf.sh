# Sourced by unit.sh. Tests for cp_conf_get / cp_set_conf (common.sh).
echo "== common: config-file editing"
f="$T/conf"
printf '#PermitRootLogin prohibit-password\nPASS_MAX_DAYS\t99999\nminlen = 6\n' > "$f"
eq "get tab-separated value"      "$(cp_conf_get "$f" PASS_MAX_DAYS)" "99999"
eq "get ' = ' value"              "$(cp_conf_get "$f" minlen)" "6"
eq "commented key reads empty"    "$(cp_conf_get "$f" PermitRootLogin)" ""
cp_set_conf "$f" PermitRootLogin no
yes_ "commented key replaced in place" grep -qx "PermitRootLogin no" "$f"
no_  "old commented line gone"         grep -q "prohibit-password" "$f"
cp_set_conf "$f" PASS_MAX_DAYS 90
yes_ "tab value replaced"             grep -qx "PASS_MAX_DAYS 90" "$f"
cp_set_conf "$f" minlen 10 " = "
yes_ "custom separator kept"          grep -qx "minlen = 10" "$f"
cp_set_conf "$f" MaxAuthTries 4
yes_ "missing key appended"           grep -qx "MaxAuthTries 4" "$f"
before="$(md5sum < "$f")"; cp_set_conf "$f" MaxAuthTries 4; rc=$?
eq "already-set returns 2"            "$rc" "2"
eq "already-set leaves file"          "$(md5sum < "$f")" "$before"
eq "line count stable"                "$(wc -l < "$f")" "4"

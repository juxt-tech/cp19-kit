# Sourced by unit.sh. Config parsing edge cases teammates will hit.
echo "== config: tricky values"
c="$T/tricky.txt"
printf '\xef\xbb\xbfADMINS=santa  prancer\r\n# a comment line\r\nUSERS=dasher\r\nNEW_PASSWORD=Ab#12'"'"'xy Z!\r\nCRITICAL_SERVICES=ssh   # README says ssh\r\n' > "$c"
cp_load_config "$c" 2>/dev/null
eq "BOM does not break the first key"     "$CP_ADMINS" "santa prancer"
eq "# and apostrophe kept in password"    "$CP_NEWPASS" "Ab#12'xy Z!"
eq "inline ' # note' stripped from lists" "$CP_CRITICAL" "ssh"
eq "USERS still parsed"                   "$CP_USERS" "dasher"
cp_load_config "$ROOT/config/cp-config.example.txt"

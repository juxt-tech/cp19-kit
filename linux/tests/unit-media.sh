# Sourced by unit.sh. Media report must not list the kit's own files (backups, run logs, download).
echo "== media: skip the kit's own files"
KIT_ROOT_SAVE="${CP_KIT_ROOT:-}"
CP_KIT_ROOT="/root/cp19-kit-main"
out="$(printf '%s\n' /root/cpkit-runs/20261022-1/backup/home/x/song.mp3 /root/cp19-kit-main/kit.zip /home/cupid/Music/song.mp3 /root/cp19-kit-mainX/a.zip | media_not_kit)"
eq "run dir + kit dir dropped, real files kept" "$(echo "$out" | tr '\n' ' ')" "/home/cupid/Music/song.mp3 /root/cp19-kit-mainX/a.zip "
CP_KIT_ROOT="/home"
eq "kit root not named like the kit is never excluded" "$(printf '/home/cupid/a.mp3\n' | media_not_kit)" "/home/cupid/a.mp3"
CP_KIT_ROOT="$KIT_ROOT_SAVE"

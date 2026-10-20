# Sourced by unit.sh. Tests for plan_services / plan_software (pure).
echo "== services/software: planners"
CP_CRITICAL="vsftpd"; CP_ALLOWED="nmap"
p="$(plan_services "vsftpd.service ssh.service cups.service cyberpatriot-scorer.service")"
has() { case $'\n'"$p"$'\n' in *$'\n'"$2"$'\n'*) ok "$1";; *) bad "$1" "plan was: $(echo "$p" | tr '\n' ';')";; esac; }
hasnt() { case "$p" in *"$2"*) bad "$1" "plan was: $(echo "$p" | tr '\n' ';')";; *) ok "$1";; esac; }
has   "critical bad-list service kept"   "KEEP vsftpd (critical)"
has   "non-critical bad service disabled" "DISABLE cups"
hasnt "ssh not on bad list -> untouched" "ssh"
hasnt "scoring service never touched"    "DISABLE cyberpatriot-scorer"

p="$(plan_software "john nmap firefox netcat-openbsd hydra-gtk")"
has   "hacking tool purged"              "PURGE john"
hasnt "allowed tool skipped"             "nmap"
hasnt "normal app untouched"             "firefox"
has   "netcat-openbsd only reviewed"     "REVIEW netcat-openbsd"
has   "glob entry matches"               "PURGE hydra-gtk"
CP_CRITICAL="ssh vsftpd"; CP_ALLOWED="firefox nmap"

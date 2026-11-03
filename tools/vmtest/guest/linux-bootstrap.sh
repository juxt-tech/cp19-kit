#!/usr/bin/env bash
# Installs the cpkit test agent on a PRACTICE Linux VM (never on a competition image).
# In a terminal in the VM, type ONE of:
#   curl -s 192.168.209.1:8765/l | sudo bash
#   wget -qO- 192.168.209.1:8765/l | sudo bash
# Afterwards the agent runs as root under systemd: lock screen, logout and reboots do not stop it.
# Remove later: sudo systemctl disable --now cpkit-test-agent; sudo rm -rf /var/lib/cpagent /usr/local/sbin/cpkit-test-agent /etc/systemd/system/cpkit-test-agent.service
set -e
S='{{SERVER}}'
[ "$(id -u)" = 0 ] || { echo "run it with sudo"; exit 1; }
if command -v curl >/dev/null 2>&1; then curl -sf "$S/g/linux-agent.sh" -o /usr/local/sbin/cpkit-test-agent
else wget -qO /usr/local/sbin/cpkit-test-agent "$S/g/linux-agent.sh"; fi
chmod 700 /usr/local/sbin/cpkit-test-agent
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    cat > /etc/systemd/system/cpkit-test-agent.service <<EOF
[Unit]
Description=cpkit practice-VM test agent (PRACTICE ONLY)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/sbin/cpkit-test-agent
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable cpkit-test-agent >/dev/null 2>&1
    systemctl restart cpkit-test-agent
    # A suspended VM stops everything; the lock screen is harmless (agent = root service).
    systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target >/dev/null 2>&1 || true
else
    nohup /usr/local/sbin/cpkit-test-agent >/dev/null 2>&1 &
    echo "(no systemd: agent started with nohup - it will NOT survive a reboot)"
fi
printf '\033[32mcpkit test agent installed (id %s, server %s). You can close this terminal.\033[0m\n' \
    "$(hostname | tr '[:upper:]' '[:lower:]')" "$S"

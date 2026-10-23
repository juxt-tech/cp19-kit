#!/usr/bin/env bash
# Services module under a real systemd. --privileged is needed for systemd as PID 1;
# it only affects the Docker Desktop VM's throwaway container.
#   bash linux/tests/systemd-test.sh
cd "$(dirname "$0")/../.." || exit 1
KIT="$(pwd -W 2>/dev/null || pwd)"
docker build -q -t cpkit-systemd linux/tests/systemd >/dev/null || exit 1
cid="$(MSYS_NO_PATHCONV=1 docker run -d --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
      --tmpfs /run --tmpfs /run/lock -v "$KIT":/k:ro cpkit-systemd)" || exit 1
trap 'docker rm -f "$cid" >/dev/null' EXIT
for _ in $(seq 60); do
    st="$(docker exec "$cid" systemctl is-system-running 2>/dev/null)"
    case "$st" in running|degraded) break ;; esac; sleep 1
done
echo "systemd: $st"
MSYS_NO_PATHCONV=1 docker exec "$cid" bash /k/linux/tests/in-systemd.sh

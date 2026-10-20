#!/usr/bin/env bash
# Runs the full scenario on each target distro in a throwaway container.
#   bash linux/tests/run-tests.sh            # all
#   bash linux/tests/run-tests.sh debian:12  # one
# NET_ADMIN is only granted so ufw/iptables work inside the container's own network namespace.
cd "$(dirname "$0")/../.." || exit 1
KIT="$(pwd -W 2>/dev/null || pwd)"
IMAGES=("${@:-linuxmintd/mint21-amd64 debian:12 ubuntu:22.04}")
read -r -a IMAGES <<< "${IMAGES[*]}"
rc=0
for img in "${IMAGES[@]}"; do
    echo "================ $img ================"
    if MSYS_NO_PATHCONV=1 docker run --rm --cap-add NET_ADMIN -v "$KIT":/k:ro "$img" bash /k/linux/tests/in-container.sh > "/tmp/cpkit-test-${img//[:\/]/_}.log" 2>&1; then
        tail -3 "/tmp/cpkit-test-${img//[:\/]/_}.log"
    else
        rc=1; tail -40 "/tmp/cpkit-test-${img//[:\/]/_}.log"
    fi
done
exit $rc

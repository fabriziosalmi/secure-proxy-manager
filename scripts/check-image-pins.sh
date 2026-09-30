#!/usr/bin/env bash
# Assert that an image pinned in more than one place agrees with itself.
#
# deploy/docker-compose.prod.yml pulls tailscale directly, while
# docker-compose.yml builds it from overlay/tailscale/Dockerfile. Dependabot
# updates the Dockerfile — its docker ecosystem reads Dockerfiles and Kubernetes
# YAML, never a compose file — so the compose pin was left behind and drifted
# to v1.80.3 against the Dockerfile's v1.102.5: twenty-two minor versions, and
# 122 fixable HIGH/CRITICAL findings in the image an operator actually deploys,
# against 5 in the one a developer builds.
#
# Same shape as check-version-sync.sh, check-waf-keys.sh and
# check-config-contract.sh: turn a lockstep that exists only in someone's head
# into a check that fails.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

rc=0

# tailscale: FROM in the Dockerfile vs image: in the production compose.
dockerfile_pin=$(sed -nE 's#^FROM[[:space:]]+(tailscale/tailscale:[^[:space:]]+).*#\1#p' \
                   overlay/tailscale/Dockerfile | head -1)
compose_pin=$(sed -nE 's#^[[:space:]]*image:[[:space:]]+(tailscale/tailscale:[^[:space:]]+).*#\1#p' \
                deploy/docker-compose.prod.yml | head -1)

if [ -z "$dockerfile_pin" ] || [ -z "$compose_pin" ]; then
    echo "FAIL: could not read both tailscale pins (Dockerfile='$dockerfile_pin' compose='$compose_pin')" >&2
    rc=1
elif [ "$dockerfile_pin" != "$compose_pin" ]; then
    echo "FAIL: the tailscale pin disagrees with itself" >&2
    echo "  overlay/tailscale/Dockerfile      : $dockerfile_pin" >&2
    echo "  deploy/docker-compose.prod.yml    : $compose_pin" >&2
    echo "  Dependabot only updates the first. Copy it into the second." >&2
    rc=1
else
    echo "OK: the tailscale pin agrees across the Dockerfile and the production compose"
fi

exit $rc

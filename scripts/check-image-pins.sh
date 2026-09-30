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

# playwright: the browsers live in the image, the runner library in package.json,
# and Playwright refuses to start when the two disagree. Dependabot bumps them
# from different ecosystems (docker and npm) and cannot know they are one
# version: #341 moved the image to v1.63.0 while tests/e2e/package.json stayed
# pinned at 1.62.0, and every E2E test failed at 0ms — the suite never started.
# ui/package.json carries the same library and must agree too.
img_pw=$(sed -nE 's#^FROM[[:space:]]+mcr\.microsoft\.com/playwright:v([0-9]+\.[0-9]+)\.[0-9]+.*#\1#p' \
           tests/e2e/Dockerfile | head -1)
e2e_pw=$(sed -nE 's#.*"@playwright/test"[[:space:]]*:[[:space:]]*"[^0-9]*([0-9]+\.[0-9]+)\..*#\1#p' \
           tests/e2e/package.json | head -1)
ui_pw=$(sed -nE 's#.*"@playwright/test"[[:space:]]*:[[:space:]]*"[^0-9]*([0-9]+\.[0-9]+)\..*#\1#p' \
          ui/package.json | head -1)

if [ -z "$img_pw" ] || [ -z "$e2e_pw" ] || [ -z "$ui_pw" ]; then
    echo "FAIL: could not read all three playwright pins (image='$img_pw' e2e='$e2e_pw' ui='$ui_pw')" >&2
    rc=1
elif [ "$img_pw" != "$e2e_pw" ] || [ "$img_pw" != "$ui_pw" ]; then
    echo "FAIL: the playwright version disagrees with itself" >&2
    echo "  tests/e2e/Dockerfile (browsers) : $img_pw" >&2
    echo "  tests/e2e/package.json (runner) : $e2e_pw" >&2
    echo "  ui/package.json (runner)        : $ui_pw" >&2
    echo "  The library and the browsers must be the same minor, or the suite" >&2
    echo "  fails to start and every test reports 0ms." >&2
    rc=1
else
    echo "OK: the playwright version agrees across the image and both package.json ($img_pw)"
fi

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

# go: the images compile with the golang:X.Y in their Dockerfiles, and CI tests
# with setup-go's go-version. When they differed (1.26 in CI, 1.27 in the images)
# the shipped binaries were built by a toolchain the unit tests never ran under.
# Dependabot moves the Dockerfiles; this fails until CI follows.
go_images=$(sed -nE 's#^FROM[[:space:]]+golang:([0-9]+\.[0-9]+)[^[:space:]]*.*#\1#p' \
              backend-go/Dockerfile waf-go/Dockerfile | sort -u)
# Only the setup-go lines marked "# go-toolchain: images" are compared: those are
# the jobs that build and test what ships. The lint and gosec jobs are marked
# "tools" and pinned to what golangci-lint and gosec can type-check (see ci.yml).
go_ci=$(sed -nE "s#^[[:space:]]*go-version:[[:space:]]*'?([0-9]+\\.[0-9]+)'?[[:space:]]*\\# go-toolchain: images[[:space:]]*\$#\\1#p" \
          .github/workflows/ci.yml | sort -u)
if [ -z "$go_images" ] || [ -z "$go_ci" ]; then
    echo "FAIL: could not read the Go versions (images='$go_images' ci='$go_ci')" >&2
    rc=1
elif [ "$(wc -l <<<"$go_images" | tr -d ' ')" != 1 ] || [ "$go_images" != "$go_ci" ]; then
    echo "FAIL: the Go toolchain disagrees between CI and the images" >&2
    echo "  Dockerfiles (golang:)      : $(tr '\n' ' ' <<<"$go_images")" >&2
    echo "  ci.yml (go-toolchain: images) : $(tr '\n' ' ' <<<"$go_ci")" >&2
    echo "  Both images and every CI job must use the same Go minor." >&2
    rc=1
else
    echo "OK: CI and both images use Go $go_images"
fi

# squid floor: the version floor only means something for the Ubuntu release it
# was written for (see proxy/Dockerfile).
ubuntu_from=$(sed -nE 's#^FROM[[:space:]]+ubuntu:([0-9]+\.[0-9]+)[^[:space:]]*.*#\1#p' proxy/Dockerfile | head -1)
floor_for=$(sed -nE 's#^ARG[[:space:]]+SQUID_FLOOR_FOR=([0-9]+\.[0-9]+)[[:space:]]*$#\1#p' proxy/Dockerfile | head -1)
if [ -z "$ubuntu_from" ] || [ -z "$floor_for" ]; then
    echo "FAIL: could not read the proxy base release or SQUID_FLOOR_FOR (from='$ubuntu_from' floor='$floor_for')" >&2
    rc=1
elif [ "$ubuntu_from" != "$floor_for" ]; then
    echo "FAIL: the Squid version floor was written for Ubuntu $floor_for but the proxy image is built FROM ubuntu:$ubuntu_from" >&2
    echo "  Set SQUID_MIN_VERSION to the fixed revision for $ubuntu_from (apt-get changelog squid)" >&2
    echo "  and update SQUID_FLOOR_FOR. Otherwise the floor is below anything the new release ships" >&2
    echo "  and the build can no longer refuse an unpatched Squid." >&2
    rc=1
else
    echo "OK: the Squid floor and the proxy base image are both Ubuntu $ubuntu_from"
fi

exit $rc

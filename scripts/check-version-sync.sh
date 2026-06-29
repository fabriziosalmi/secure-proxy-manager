#!/usr/bin/env bash
# Assert the project version is identical everywhere it is declared, so a release
# can never ship with drifted version metadata. This guards the exact failure
# seen before 3.10.5, where ui/package-lock.json lagged at 3.10.2 while
# package.json/version.go were already at 3.10.5 (the lockfile's version field is
# not updated by `npm ci`).
#
# Sources of truth checked (all must agree):
#   - backend-go/internal/config/version.go  (AppVersion)
#   - ui/package.json                         (version)
#   - ui/package-lock.json                    (top-level version)
#   - CHANGELOG.md                            (latest ## [x.y.z] heading)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

go_v=$(sed -nE 's/.*AppVersion = "([^"]+)".*/\1/p' backend-go/internal/config/version.go | head -1)
pkg_v=$(sed -nE 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' ui/package.json | head -1)
lock_v=$(sed -nE 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' ui/package-lock.json | head -1)
chg_v=$(sed -nE 's/^## \[([0-9]+\.[0-9]+\.[0-9]+)\].*/\1/p' CHANGELOG.md | head -1)

printf 'version.go=%s  package.json=%s  package-lock.json=%s  CHANGELOG=%s\n' \
  "$go_v" "$pkg_v" "$lock_v" "$chg_v"

rc=0
for pair in "package.json:$pkg_v" "package-lock.json:$lock_v" "CHANGELOG:$chg_v"; do
  name=${pair%%:*}; val=${pair#*:}
  if [ "$val" != "$go_v" ]; then
    echo "ERROR: $name version ($val) != version.go ($go_v)" >&2
    rc=1
  fi
done
[ -n "$go_v" ] || { echo "ERROR: could not read AppVersion from version.go" >&2; rc=1; }

if [ "$rc" -ne 0 ]; then
  echo "Version drift detected — bump all four together (or run scripts/bump-version.sh)." >&2
  exit 1
fi
echo "OK: all version declarations agree on $go_v"

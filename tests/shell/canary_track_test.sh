#!/usr/bin/env bash
# scripts/canary.sh aligns to what CANARY_TRACK names, against a real git
# repository: main (the default) moves to origin/main; release moves to the
# newest vX.Y.Z tag in numeric order, never to a release candidate, an
# mcp-v* tag or main ahead of the release, and does not move while that is
# still the newest. Either way the tracked lists the backend exports survive
# the reset. compose and curl are stubs that pass.
#
# Usage: tests/shell/canary_track_test.sh
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
REPO=$(pwd)
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ✗ %s\n     %s\n" "$1" "${2:-}"; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"

cat > "$T/bin/compose" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  "ps proxy --format {{.Health}}") echo healthy ;;
  ps*) printf 'proxy running\nwaf running\n' ;;
esac
exit 0
EOF
cat > "$T/bin/curl" <<'EOF'
#!/usr/bin/env bash
case "$*" in *"/api/health"*) echo '{"status":"healthy","version":"9.9.9"}'; exit 0 ;; esac
code=405; case "$*" in *"/login"*) code=403 ;; esac
case "$*" in *'%header{x-squid-error}'*) printf '%s ' "$code" ;; *) printf '%s' "$code" ;; esac
exit 0
EOF
chmod +x "$T/bin/compose" "$T/bin/curl"

# Upstream: v3.9.0, v3.10.0, v3.10.1-rc1, mcp-v9.0.0, then main ahead of all.
# v3.9.0 sorts after v3.10.0 as text. config/domain_blacklist.txt is tracked,
# as the repository's fixture is.
g() { git -C "$T/src" -c user.name=t -c user.email=t@t "$@"; }
git init -q -b main "$T/src"
mkdir -p "$T/src/config"
for v in 3.9.0 3.10.0 3.10.1-rc1 mcp-9.0.0 main; do
  printf '%s\n' "$v" > "$T/src/VERSION"
  echo fixture.example > "$T/src/config/domain_blacklist.txt"
  g add -A; g commit -q -m "$v"
  case "$v" in main) ;; mcp-*) g tag "mcp-v${v#mcp-}" ;; *) g tag "v$v" ;; esac
done
git clone -q --bare "$T/src" "$T/upstream.git"

deploy() { # a deployment cloned at an older release, with a live list
  rm -rf "$T/d"
  git clone -q "$T/upstream.git" "$T/d"
  git -C "$T/d" -c advice.detachedHead=false checkout -q -B main v3.9.0
  printf 'live1.example\nlive2.example\n' > "$T/d/config/domain_blacklist.txt"
}
canary() { # track (empty = default) -> exit code; output in $T/out
  (cd "$T/d" && PATH="$T/bin:$PATH" COMPOSE="$T/bin/compose" CANARY_STATE="$T/state.json" \
    PROBE_RETRY_DELAY=0 CANARY_TRACK="${1:-}" bash "$REPO/scripts/canary.sh" > "$T/out" 2>&1)
}
at() { cat "$T/d/VERSION"; }

deploy; canary release; rc=$?
[ "$rc" -eq 0 ] && [ "$(at)" = 3.10.0 ] && grep -q 'newest release: v3.10.0' "$T/out" && grep -q '"track":"release"' "$T/state.json" \
  && ok "release: the newest vX.Y.Z (not v3.9.0 by text, not the rc, not mcp-v*, not main)" \
  || bad "release: the newest release" "rc=$rc at=$(at) $(tail -3 "$T/out" | tr '\n' ' ')"
[ "$(at)" = 3.10.0 ] && [ "$(cat "$T/d/config/domain_blacklist.txt")" = "$(printf 'live1.example\nlive2.example')" ] \
  && ok "release: the live list survives the reset" || bad "release: the live list survives" "$(cat "$T/d/config/domain_blacklist.txt")"

canary release; rc=$?
[ "$rc" -eq 0 ] && grep -q 'already at' "$T/out" && [ "$(at)" = 3.10.0 ] \
  && ok "release: no newer release, no move" || bad "release: no move" "rc=$rc $(head -3 "$T/out" | tr '\n' ' ')"

deploy; canary; rc=$?
[ "$rc" -eq 0 ] && [ "$(at)" = main ] && grep -q '"track":"main"' "$T/state.json" \
  && ok "default: origin/main, as before" || bad "default: origin/main" "rc=$rc at=$(at)"

deploy; canary nightly; rc=$?
[ "$rc" -ne 0 ] && [ "$(at)" = 3.9.0 ] && grep -q "CANARY_TRACK must be main or release, not 'nightly'" "$T/state.json" \
  && ok "an unknown track: refused, nothing moves" || bad "unknown track" "rc=$rc at=$(at) $(cat "$T/state.json")"

# A remote with no release tag at all: refused, never aligned to main instead.
git -C "$T/upstream.git" tag -l 'v*' | xargs -n1 git -C "$T/upstream.git" tag -d >/dev/null
deploy 2>/dev/null; git -C "$T/d" tag -l 'v*' | xargs -n1 git -C "$T/d" tag -d >/dev/null; canary release; rc=$?
[ "$rc" -ne 0 ] && grep -q 'no release tag' "$T/state.json" \
  && ok "release with no release tag: refused, not aligned to main" || bad "release with no release tag" "rc=$rc $(cat "$T/state.json")"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

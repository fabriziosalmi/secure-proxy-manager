#!/usr/bin/env bash
# scripts/canary.sh aligns to what CANARY_TRACK names, against a real git
# repository: main (the default) moves to origin/main; release moves to the
# newest vX.Y.Z tag in numeric order, never to a release candidate, an
# mcp-v* tag or main ahead of the release, and does not move while that is
# still the newest. Either way the tracked lists the backend exports survive
# the reset. compose and curl are stubs that pass.
#
# The release track follows the installer's rule (deploy/install.sh,
# published_release): a tag whose five images are not in the registry is
# skipped, and named, at most twice; a registry that cannot be asked stops the
# canary where it is. The stub curl plays ghcr.io: every image is published
# unless $T/missing names it, and nothing answers while $T/registry_down exists.
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
export REGISTRY_STATE="$T"
cat > "$T/bin/curl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *"ghcr.io/token"*) [ -e "$REGISTRY_STATE/registry_down" ] && exit 7; echo '{"token":"t"}'; exit 0 ;;
  *"ghcr.io/v2/"*)
    if [ -e "$REGISTRY_STATE/registry_down" ]; then printf 000; exit 7; fi
    while read -r m; do case "$*" in *"$m"*) printf 404; exit 0 ;; esac; done < <(cat "$REGISTRY_STATE/missing" 2>/dev/null)
    printf 200; exit 0 ;;
esac
case "$*" in *"/api/health"*) echo '{"status":"healthy","version":"9.9.9"}'; exit 0 ;; esac
code=405; case "$*" in *"/login"*) code=403 ;; esac
case "$*" in *'%header{x-squid-error}'*) printf '%s ' "$code" ;; *) printf '%s' "$code" ;; esac
exit 0
EOF
chmod +x "$T/bin/compose" "$T/bin/curl"

# Upstream: v3.8.0, v3.9.0, v3.10.0, v3.10.1-rc1, mcp-v9.0.0, then main ahead of all.
# v3.9.0 sorts after v3.10.0 as text. config/domain_blacklist.txt is tracked,
# as the repository's fixture is.
g() { git -C "$T/src" -c user.name=t -c user.email=t@t "$@"; }
git init -q -b main "$T/src"
mkdir -p "$T/src/config" "$T/src/deploy"
# The deployment carries its own installer, as a real checkout does: the
# release track must read that one, not one next to wherever the script runs.
cp "$REPO/deploy/install.sh" "$T/src/deploy/install.sh"
for v in 3.8.0 3.9.0 3.10.0 3.10.1-rc1 mcp-9.0.0 main; do
  printf '%s\n' "$v" > "$T/src/VERSION"
  echo fixture.example > "$T/src/config/domain_blacklist.txt"
  g add -A; g commit -q -m "$v"
  case "$v" in main) ;; mcp-*) g tag "mcp-v${v#mcp-}" ;; *) g tag "v$v" ;; esac
done
git clone -q --bare "$T/src" "$T/upstream.git"

deploy() { # [release, default v3.9.0] a deployment cloned at an older release, with a live list
  rm -rf "$T/d"
  git clone -q "$T/upstream.git" "$T/d"
  git -C "$T/d" -c advice.detachedHead=false checkout -q -B main "${1:-v3.9.0}"
  printf 'live1.example\nlive2.example\n' > "$T/d/config/domain_blacklist.txt"
}
# git, but its first $GIT_FETCH_FAILS fetches fail as a DNS blip does
# ("Could not resolve host"); everything else goes to the real git.
export REAL_GIT; REAL_GIT=$(command -v git)
mkdir -p "$T/gitstub"
cat > "$T/gitstub/git" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = fetch ] && [ "${GIT_FETCH_FAILS:-0}" -gt 0 ]; then
  n=$(cat "$GIT_FETCH_COUNT" 2>/dev/null || echo 0)
  if [ "$n" -lt "$GIT_FETCH_FAILS" ]; then
    echo $((n + 1)) > "$GIT_FETCH_COUNT"
    echo "fatal: unable to access 'https://github.invalid/repo.git/': Could not resolve host: github.invalid" >&2
    exit 128
  fi
fi
exec "$REAL_GIT" "$@"
EOF
chmod +x "$T/gitstub/git"
export GIT_FETCH_COUNT="$T/fetch_count"

canary() { # track (empty = default) -> exit code; output in $T/out
  # As the systemd unit runs it: a copy outside the checkout (so a reset
  # cannot rewrite the running script), started in the deployment directory.
  mkdir -p "$T/run"; install -m 755 "$REPO/scripts/canary.sh" "$T/run/spm-canary.sh"
  rm -f "$GIT_FETCH_COUNT"
  (cd "$T/d" && PATH="$T/gitstub:$T/bin:$PATH" COMPOSE="$T/bin/compose" CANARY_STATE="$T/state.json" \
    PROBE_RETRY_DELAY=0 FETCH_RETRY_DELAY=0 CANARY_TRACK="${1:-}" "$T/run/spm-canary.sh" > "$T/out" 2>&1)
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

# The newest release without one of its images: the canary aligns to the one
# before and says which tag it skipped and why.
echo 'secure-proxy-manager-waf/manifests/v3.10.0' > "$T/missing"
deploy v3.8.0; canary release; rc=$?
[ "$rc" -eq 0 ] && [ "$(at)" = 3.9.0 ] && grep -q 'Skipping v3.10.0.*waf' "$T/out" \
  && ok "release: v3.10.0 without its waf image, aligned to v3.9.0, v3.10.0 named as skipped" \
  || bad "release: newest without its images" "rc=$rc at=$(at) $(tail -4 "$T/out" | tr '\n' ' ')"

# Three releases in a row without their images: refused, nothing moves.
printf '%s\n' secure-proxy-manager-dns/manifests/v3.10.0 secure-proxy-manager-web/manifests/v3.9.0 \
  secure-proxy-manager-proxy/manifests/v3.8.0 > "$T/missing"
deploy v3.8.0; canary release; rc=$?
[ "$rc" -ne 0 ] && [ "$(at)" = 3.8.0 ] && grep -q 'none of the newest releases has all its images published' "$T/state.json" \
  && ok "release: no published release among the newest three, refused, nothing moves" \
  || bad "release: none published" "rc=$rc at=$(at) $(cat "$T/state.json")"
rm -f "$T/missing"

# The registry cannot be asked: refused, never aligned to an older release.
touch "$T/registry_down"
deploy v3.8.0; canary release; rc=$?
[ "$rc" -ne 0 ] && [ "$(at)" = 3.8.0 ] && grep -q 'could not ask the registry' "$T/state.json" \
  && ok "release: registry unreachable, refused, nothing moves" \
  || bad "release: registry unreachable" "rc=$rc at=$(at) $(cat "$T/state.json")"
rm -f "$T/registry_down"

# A fetch that fails as a DNS blip does is retried: a one-second resolver
# outage left a release-track run red with nothing moved.
deploy; GIT_FETCH_FAILS=1 canary release; rc=$?
[ "$rc" -eq 0 ] && [ "$(at)" = 3.10.0 ] && [ "$(cat "$GIT_FETCH_COUNT" 2>/dev/null)" = 1 ] && grep -q 'retrying' "$T/out" \
  && ok "release: a fetch that fails once is retried, and the run aligns" \
  || bad "release: fetch retried" "rc=$rc at=$(at) fails=$(cat "$GIT_FETCH_COUNT" 2>/dev/null) $(tail -4 "$T/out" | tr '\n' ' ')"
deploy; GIT_FETCH_FAILS=2 canary; rc=$?
[ "$rc" -eq 0 ] && [ "$(at)" = main ] && [ "$(cat "$GIT_FETCH_COUNT" 2>/dev/null)" = 2 ] \
  && ok "main: a fetch that fails twice is retried, and the run aligns" \
  || bad "main: fetch retried" "rc=$rc at=$(at) $(tail -4 "$T/out" | tr '\n' ' ')"
# A fetch that keeps failing is refused after FETCH_ATTEMPTS, nothing moves.
deploy v3.8.0; GIT_FETCH_FAILS=9 canary release; rc=$?
[ "$rc" -ne 0 ] && [ "$(at)" = 3.8.0 ] && [ "$(cat "$GIT_FETCH_COUNT" 2>/dev/null)" = 3 ] \
  && grep -q 'git fetch of the release tags failed 3 times' "$T/state.json" \
  && ok "release: a fetch that fails 3 times is refused, nothing moves" \
  || bad "release: fetch keeps failing" "rc=$rc at=$(at) fails=$(cat "$GIT_FETCH_COUNT" 2>/dev/null) $(cat "$T/state.json")"

# A remote with no release tag at all: refused, never aligned to main instead.
git -C "$T/upstream.git" tag -l 'v*' | xargs -n1 git -C "$T/upstream.git" tag -d >/dev/null
deploy 2>/dev/null; git -C "$T/d" tag -l 'v*' | xargs -n1 git -C "$T/d" tag -d >/dev/null; canary release; rc=$?
[ "$rc" -ne 0 ] && grep -q 'no release tag' "$T/state.json" \
  && ok "release with no release tag: refused, not aligned to main" || bad "release with no release tag" "rc=$rc $(cat "$T/state.json")"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

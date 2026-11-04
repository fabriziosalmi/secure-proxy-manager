#!/usr/bin/env bash
# deploy/install.sh installs, or updates to, the newest release tag rather than
# main, whose compose file can be ahead of the release images it pulls. This
# sources the installer's functions and runs them against a local repository
# with release tags, a release candidate, an mcp-v* tag and a main ahead of
# them all.
#
# Usage: tests/shell/install_release_test.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n     %s\n' "$1" "${2:-}"; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The upstream: v3.9.0, v3.10.0, v3.10.1-rc1, mcp-v9.0.0, then main ahead.
# v3.9.0 sorts after v3.10.0 as text; the installer must not pick it.
git init -q -b main "$WORK/src"
commit() { # version
  printf '%s\n' "$1" > "$WORK/src/VERSION"
  git -C "$WORK/src" add VERSION
  git -C "$WORK/src" -c user.name=t -c user.email=t@t commit -q -m "$1"
}
for v in 3.9.0 3.10.0 3.10.1-rc1 mcp-9.0.0 main; do
  commit "$v"
  case "$v" in
    main) ;;
    mcp-*) git -C "$WORK/src" tag "mcp-v${v#mcp-}" ;;
    *) git -C "$WORK/src" tag "v$v" ;;
  esac
done
git clone -q --bare "$WORK/src" "$WORK/upstream.git"
UPSTREAM="file://$WORK/upstream.git"

# Run a snippet with the installer's functions, against the local upstream.
# The installer's set -e is turned off so a snippet can print a status; the
# installer itself calls release_tag as TAG=$(release_tag) || exit 1.
run() {
  bash -c "
    source '$ROOT/deploy/install.sh'
    set +e
    REPO='$UPSTREAM'
    $1
  " 2>&1
}

echo "── which release ──"
got="$(run 'release_tag')"
[ "$got" = v3.10.0 ] && ok "the newest release, in numeric order (not v3.9.0, not the rc, not mcp-v*)" \
  || bad "the newest release" "got: $got"

got="$(SPM_VERSION=v3.9.0 run 'release_tag')"
[ "$got" = v3.9.0 ] && ok "SPM_VERSION picks an older release" || bad "SPM_VERSION picks an older release" "got: $got"

got="$(SPM_VERSION=v9.9.9 run 'release_tag; echo "rc=$?"')"
grep -q 'rc=1' <<<"$got" && grep -q 'v9.9.9 was not found' <<<"$got" \
  && ok "SPM_VERSION that does not exist: refused, named" || bad "SPM_VERSION that does not exist" "got: $got"

got="$(SPM_VERSION=main run 'release_tag; echo "rc=$?"')"
grep -q 'rc=1' <<<"$got" && grep -q 'must be a release tag' <<<"$got" \
  && ok "SPM_VERSION=main: refused, main is not a release" || bad "SPM_VERSION=main" "got: $got"

got="$(bash -c "source '$ROOT/deploy/install.sh'; REPO='file://$WORK/missing.git'; TAG=\$(release_tag) || echo \"stopped, TAG=[\$TAG]\"" 2>&1)"
grep -q 'stopped, TAG=\[\]' <<<"$got" && grep -q 'Could not read the releases' <<<"$got" \
  && ok "upstream unreachable: fails, does not fall back to main" || bad "upstream unreachable" "got: $got"

echo "── fresh install ──"
got="$(run "git -c advice.detachedHead=false clone -q --depth 1 -b \"\$(release_tag)\" \"\$REPO\" '$WORK/fresh' && cat '$WORK/fresh/VERSION'")"
[ "$got" = 3.10.0 ] && ok "the clone is the release's content" || bad "fresh clone" "got: $got"

echo "── update ──"
# An install made by the previous installer: a shallow clone of main.
git clone -q --depth 1 -b main "$UPSTREAM" "$WORK/old"
got="$(run "cd '$WORK/old' && checkout_release v3.10.0 && cat VERSION && git symbolic-ref -q HEAD || echo detached")"
[ "$got" = "$(printf '3.10.0\ndetached')" ] && ok "a clone of main moves to the release, detached" \
  || bad "a clone of main moves to the release" "got: $got"

got="$(run "cd '$WORK/old' && checkout_release v3.10.0 && cat VERSION")"
[ "$got" = 3.10.0 ] && ok "running it again at the same release changes nothing" || bad "same release again" "got: $got"

got="$(run "cd '$WORK/old' && checkout_release v3.9.0 && cat VERSION")"
[ "$got" = 3.9.0 ] && ok "SPM_VERSION to an older release moves there" || bad "older release" "got: $got"

printf 'edited\n' > "$WORK/old/VERSION"
got="$(run "cd '$WORK/old' && checkout_release v3.10.0; echo \"rc=\$?\"; cat VERSION")"
grep -q 'rc=1' <<<"$got" && grep -qx 'edited' <<<"$got" \
  && ok "a local edit to a file the release changes: refused, the edit is kept" || bad "local edit" "got: $got"

echo ""
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

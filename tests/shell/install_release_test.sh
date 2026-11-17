#!/usr/bin/env bash
# deploy/install.sh installs, or updates to, the newest release tag rather than
# main, whose compose file can be ahead of the release images it pulls. This
# sources the installer's functions and runs them against a local repository
# with release tags, a release candidate, an mcp-v* tag and a main ahead of
# them all.
#
# A release is installed only when its five images are in the registry: the
# git tag exists from the moment it is pushed, the images only at the end of
# the release run, and never when a gate fails. image_manifest_status is the
# installer's one call to the registry; a stub replaces it here, and the real
# one runs against a stub curl. Nothing here uses the network.
#
# Usage: tests/shell/install_release_test.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n     %s\n' "$1" "${2:-}"; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The upstream: v3.7.0, v3.8.0, v3.9.0, v3.10.0, v3.10.1-rc1, mcp-v9.0.0,
# then main ahead. v3.9.0 sorts after v3.10.0 as text; the installer must not
# pick it.
git init -q -b main "$WORK/src"
commit() { # version
  printf '%s\n' "$1" > "$WORK/src/VERSION"
  git -C "$WORK/src" add VERSION
  git -C "$WORK/src" -c user.name=t -c user.email=t@t commit -q -m "$1"
}
for v in 3.7.0 3.8.0 3.9.0 3.10.0 3.10.1-rc1 mcp-9.0.0 main; do
  commit "$v"
  case "$v" in
    main) ;;
    mcp-*) git -C "$WORK/src" tag "mcp-v${v#mcp-}" ;;
    *) git -C "$WORK/src" tag "v$v" ;;
  esac
done
git clone -q --bare "$WORK/src" "$WORK/upstream.git"
UPSTREAM="file://$WORK/upstream.git"

# The registry, stubbed: every image is published unless MISSING names it
# ("tag:image" words), and asking fails for ERROR ("tag:image" words, or all).
# Each question is logged to $ASKED.
export ASKED="$WORK/asked"
cat > "$WORK/registry_stub.sh" <<'EOF'
image_manifest_status() { # image tag
  printf '%s:%s\n' "$2" "$1" >> "$ASKED"
  case " ${ERROR:-} " in *" all "*|*" $2:$1 "*) echo "curl: (7) Failed to connect to ghcr.io" >&2; return 2 ;; esac
  case " ${MISSING:-} " in *" $2:$1 "*) return 1 ;; esac
  return 0
}
EOF

# Run a snippet with the installer's functions, against the local upstream.
# The installer's set -e is turned off so a snippet can print a status; the
# installer itself calls release_tag as TAG=$(release_tag) || exit 1.
run() {
  bash -c "
    source '$ROOT/deploy/install.sh'
    source '$WORK/registry_stub.sh'
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

echo "── published images ──"
: > "$ASKED"
got="$(run 'release_tag')"
asked="$(sort "$ASKED" | tr '\n' ' ')"
[ "$got" = v3.10.0 ] && [ "$asked" = "v3.10.0:backend v3.10.0:dns v3.10.0:proxy v3.10.0:waf v3.10.0:web " ] \
  && ok "all five images published: the newest release, after asking for each of them" \
  || bad "all five images published" "got: $got; asked: $asked"

: > "$ASKED"
got="$(MISSING='v3.10.0:waf' run 'TAG=$(release_tag) || echo stopped; echo "TAG=$TAG"')"
grep -qx 'TAG=v3.9.0' <<<"$got" && grep -q 'WARN.*Skipping v3.10.0.*waf' <<<"$got" \
  && ok "one image missing on the newest release: falls back to v3.9.0, and says v3.10.0 was skipped and why" \
  || bad "one image missing on the newest release" "got: $got"

: > "$ASKED"
got="$(ERROR=all run 'TAG=$(release_tag) || echo "stopped, TAG=[$TAG]"')"
grep -q 'stopped, TAG=\[\]' <<<"$got" && grep -q 'Could not ask' <<<"$got" && ! grep -q '^v3\.9\.0:' "$ASKED" \
  && ok "registry unreachable: stops with an error, never asks about an older release" \
  || bad "registry unreachable" "got: $got; asked: $(tr '\n' ' ' < "$ASKED")"

: > "$ASKED"
got="$(MISSING='v3.10.0:waf' ERROR='v3.10.0:dns' run 'TAG=$(release_tag) || echo "stopped, TAG=[$TAG]"')"
grep -q 'stopped, TAG=\[\]' <<<"$got" && ! grep -q '^v3\.9\.0:' "$ASKED" \
  && ok "one image missing and another unanswered: stops, does not fall back" \
  || bad "one image missing and another unanswered" "got: $got"

# What the installer does with it, in its own order: TAG=$(release_tag) ||
# exit 1, then checkout_release. With the registry down an update stops
# before the clone moves, so nothing changes on disk.
git clone -q --depth 1 -b v3.9.0 "$UPSTREAM" "$WORK/inst" 2>/dev/null
got="$(cd "$WORK/inst" && ERROR=all bash -c "source '$ROOT/deploy/install.sh'; source '$WORK/registry_stub.sh'; REPO='$UPSTREAM'; TAG=\$(release_tag) || exit 1; checkout_release \"\$TAG\"; echo moved" 2>&1; echo "rc=$?"; cat "$WORK/inst/VERSION")"
grep -q 'rc=1' <<<"$got" && ! grep -q moved <<<"$got" && grep -qx 3.9.0 <<<"$got" \
  && ok "registry unreachable on an update: exits 1, the installed clone stays at v3.9.0" \
  || bad "registry unreachable on an update" "got: $got"
# shellcheck disable=SC2016 # the installer's own text, not an expansion
check_line=$(grep -n 'TAG=$(release_tag) || exit 1' "$ROOT/deploy/install.sh" | cut -d: -f1)
# shellcheck disable=SC2016
move_line=$(grep -n 'checkout_release "$TAG"' "$ROOT/deploy/install.sh" | cut -d: -f1)
[ -n "$check_line" ] && [ -n "$move_line" ] && [ "$check_line" -lt "$move_line" ] \
  && ok "the installer decides the release (line $check_line) before the clone moves (line $move_line)" \
  || bad "the release is decided before the clone moves" "release_tag at ${check_line:-?}, checkout_release at ${move_line:-?}"

: > "$ASKED"
got="$(MISSING='v3.10.0:dns v3.9.0:web v3.8.0:proxy' run 'TAG=$(release_tag) || echo "stopped, TAG=[$TAG]"')"
grep -q 'stopped, TAG=\[\]' <<<"$got" && grep -q 'Skipping v3.10.0' <<<"$got" && grep -q 'Skipping v3.9.0' <<<"$got" \
  && grep -q 'Skipping v3.8.0' <<<"$got" && ! grep -q '^v3\.7\.0:' "$ASKED" \
  && ok "three releases in a row without their images: stops, never tries a fourth" \
  || bad "three releases without their images" "got: $got; asked: $(cut -d: -f1 "$ASKED" | sort -u | tr '\n' ' ')"

: > "$ASKED"
got="$(SPM_VERSION=v3.9.0 MISSING='v3.9.0:backend' run 'TAG=$(release_tag) || echo "stopped, TAG=[$TAG]"')"
grep -q 'stopped, TAG=\[\]' <<<"$got" && grep -q 'v3.9.0.*backend' <<<"$got" && [ -s "$ASKED" ] && ! grep -qv '^v3\.9\.0:' "$ASKED" \
  && ok "SPM_VERSION without its images: refused, never falls back to another release" \
  || bad "SPM_VERSION without its images" "got: $got; asked: $(tr '\n' ' ' < "$ASKED")"

echo "── the registry request ──"
# The real image_manifest_status, against a stub curl: an anonymous pull token,
# then a HEAD of the manifest. 200 is published, 404 is not, anything else
# (no answer, 401, 5xx, no token) is an error, never "not published".
mkdir -p "$WORK/bin"
export CURL_LOG="$WORK/curl.log"
cat > "$WORK/bin/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$CURL_LOG"
case "$*" in
  *"/token?"*) [ "${CURL_TOKEN:-ok}" = ok ] || exit 7; printf '{"token":"anon-token"}' ;;
  *"/v2/"*) if [ "$CURL_CODE" = none ]; then printf '000'; exit 7; fi; printf '%s' "$CURL_CODE" ;;
  *) exit 99 ;;
esac
EOF
chmod +x "$WORK/bin/curl"
status() { # manifest answer [token answer] -> what image_manifest_status returns
  : > "$CURL_LOG"
  PATH="$WORK/bin:$PATH" CURL_CODE="$1" CURL_TOKEN="${2:-ok}" bash -c "
    source '$ROOT/deploy/install.sh'; set +e
    image_manifest_status waf v3.10.0; echo \"rc=\$?\"" 2>&1
}
while read -r code want what; do
  got="$(status "$code")"
  grep -qx "rc=$want" <<<"$got" && ok "manifest answer $code: $what" || bad "manifest answer $code: $what" "got: $got"
done <<'EOF'
200 0 published
404 1 not published
none 2 no answer is an error
503 2 a 503 is an error
401 2 a 401 is an error
EOF
got="$(status 200 fail)"
grep -qx 'rc=2' <<<"$got" && ok "no pull token: an error, not 'not published'" || bad "no pull token" "got: $got"
status 200 >/dev/null
grep -q -- '-I .*Authorization: Bearer anon-token.*https://ghcr.io/v2/fabriziosalmi/secure-proxy-manager-waf/manifests/v3.10.0' "$CURL_LOG" \
  && grep -q 'https://ghcr.io/token?.*scope=repository:fabriziosalmi/secure-proxy-manager-waf:pull' "$CURL_LOG" \
  && ok "asks ghcr.io anonymously: a pull token, then a HEAD of the waf manifest for v3.10.0" \
  || bad "the request to ghcr.io" "$(cat "$CURL_LOG")"

echo ""
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

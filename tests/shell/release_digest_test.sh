#!/usr/bin/env bash
# scripts/select-scanned-digest.sh against fake artifact directories, as
# actions/download-artifact lays them out in publish
# (DIR/digest-<image>-<attempt>/digest), and the wiring in multi-arch.yml.
#
# Each build-scan leg uploads its scanned digest as digest-<image>-<attempt>.
# A full "Re-run all jobs" sees the artifacts of every earlier attempt next to
# its own, and the download keeps one artifact per name by artifact id, which
# is not an attempt order: with one name per image, a full rerun could publish
# the digest an earlier attempt built instead of the one it just scanned. With
# the attempt in the name, publish picks the highest attempt per image, so a
# full rerun uses its own digests and a rerun of only the failed publish legs
# still finds the earlier attempt's.
#
# Usage: tests/shell/release_digest_test.sh
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ✗ %s\n     %s\n" "$1" "${2:-}"; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

IMAGES="web backend waf proxy dns"
d() { # a fake digest, distinct per tag
  if command -v sha256sum >/dev/null; then h=$(printf '%s' "$1" | sha256sum); else h=$(printf '%s' "$1" | shasum -a 256); fi
  printf 'sha256:%s' "${h%% *}"
}
put() { # dir image attempt tag
  mkdir -p "$1/digest-$2-$3"
  printf '%s\n' "$(d "$4")" > "$1/digest-$2-$3/digest"
}
fresh() { rm -rf "$T/dl"; mkdir -p "$T/dl"; }
sel() { # image total -> digest on stdout, rc
  bash scripts/select-scanned-digest.sh "$T/dl" "$1" "$2" 2>"$T/err"
}

# One attempt, five images: each image gets its own digest.
fresh; for i in $IMAGES; do put "$T/dl" "$i" 1 "a1$i"; done
out=$(sel web 5); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "$(d a1web)" ] && ok "a first attempt publishes the digest it scanned" || bad "first attempt" "rc=$rc out=$out err=$(cat "$T/err")"
out=$(sel dns 5); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "$(d a1dns)" ] && ok "each image reads its own digest" || bad "each image reads its own digest" "rc=$rc out=$out"

# Full rerun: attempts 1 and 2 of every image are both downloaded.
fresh; for i in $IMAGES; do put "$T/dl" "$i" 1 "a1$i"; put "$T/dl" "$i" 2 "a2$i"; done
out=$(sel backend 5); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "$(d a2backend)" ] && ok "a full rerun publishes the digest it just built and scanned, not attempt 1's" || bad "full rerun uses its own digest" "rc=$rc out=$out err=$(cat "$T/err")"

# Rerun of the failed jobs only: build-scan web failed its scan in attempt 1
# and passed in attempt 2; the other four keep their attempt-1 artifact.
fresh; for i in $IMAGES; do put "$T/dl" "$i" 1 "a1$i"; done; put "$T/dl" web 2 "a2web"
out=$(sel web 5); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "$(d a2web)" ] && ok "a rerun leg's new digest wins for its image" || bad "rerun leg's digest" "rc=$rc out=$out"
out=$(sel proxy 5); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "$(d a1proxy)" ] && ok "a rerun of only the failed jobs still finds the earlier attempt's digests" || bad "earlier attempt found" "rc=$rc out=$out err=$(cat "$T/err")"

# Publish alone rerun in attempt 3: every digest is from attempt 1 or 2.
fresh; for i in $IMAGES; do put "$T/dl" "$i" 1 "a1$i"; put "$T/dl" "$i" 2 "a2$i"; done
out=$(sel waf 5); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "$(d a2waf)" ] && ok "a publish-only rerun takes the newest attempt that scanned the image" || bad "publish-only rerun" "rc=$rc out=$out"

# Attempts are compared as numbers: 10 is newer than 9.
fresh; for i in $IMAGES; do put "$T/dl" "$i" 9 "a9$i"; done; put "$T/dl" dns 10 "a10dns"
out=$(sel dns 5); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "$(d a10dns)" ] && ok "attempt 10 is newer than attempt 9" || bad "numeric attempt order" "rc=$rc out=$out"

# An image whose name starts with another's is not mistaken for it.
fresh; for i in web backend waf proxy; do put "$T/dl" "$i" 1 "a1$i"; done; put "$T/dl" web-ui 2 "a2webui"
out=$(sel web 5); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "$(d a1web)" ] && ok "digest-web-ui-2 is not a digest of web" || bad "prefix image" "rc=$rc out=$out"

# A missing image fails every leg, including those whose digest is there.
fresh; for i in web backend waf proxy; do put "$T/dl" "$i" 1 "a1$i"; done
out=$(sel web 5); rc=$?
[ "$rc" -ne 0 ] && [ -z "$out" ] && grep -q '4 digests' "$T/err" && ok "four scanned images for five publish legs fails" || bad "missing image fails" "rc=$rc out=$out err=$(cat "$T/err")"

# Extra attempts of the same image do not stand in for a missing one.
fresh; for i in web backend waf proxy; do put "$T/dl" "$i" 1 "a1$i"; done; put "$T/dl" web 2 "a2web"
out=$(sel web 5); rc=$?
[ "$rc" -ne 0 ] && [ -z "$out" ] && ok "two attempts of web do not count as two images" || bad "attempts counted as images" "rc=$rc out=$out"

# An image publish does not know.
fresh; for i in $IMAGES extra; do put "$T/dl" "$i" 1 "a1$i"; done
out=$(sel web 5); rc=$?
[ "$rc" -ne 0 ] && [ -z "$out" ] && ok "six scanned images for five publish legs fails" || bad "extra image fails" "rc=$rc out=$out"

# The count matches but this leg's image is not among them.
fresh; for i in web backend waf proxy other; do put "$T/dl" "$i" 1 "a1$i"; done
out=$(sel dns 5); rc=$?
[ "$rc" -ne 0 ] && [ -z "$out" ] && grep -q 'no scanned digest for dns' "$T/err" && ok "a leg with no digest of its own fails" || bad "own digest missing" "rc=$rc out=$out err=$(cat "$T/err")"

# An artifact name without an attempt is not guessed at.
# All five images have an attempt, so only the name check can refuse it.
fresh; for i in $IMAGES; do put "$T/dl" "$i" 1 "a1$i"; done; mkdir -p "$T/dl/digest-dns"; d a1dns > "$T/dl/digest-dns/digest"
out=$(sel web 5); rc=$?
[ "$rc" -ne 0 ] && [ -z "$out" ] && ok "an artifact named without its attempt fails" || bad "unnamed attempt fails" "rc=$rc out=$out"

# What the artifact holds must be a sha256 digest.
fresh; for i in $IMAGES; do put "$T/dl" "$i" 1 "a1$i"; done; printf 'latest\n' > "$T/dl/digest-web-1/digest"
out=$(sel web 5); rc=$?
[ "$rc" -ne 0 ] && [ -z "$out" ] && ok "a digest file that holds a tag fails" || bad "non-digest fails" "rc=$rc out=$out"

# An artifact directory without its digest file.
fresh; for i in $IMAGES; do put "$T/dl" "$i" 1 "a1$i"; done; put "$T/dl" web 2 "a2web"; rm "$T/dl/digest-web-2/digest"
out=$(sel web 5); rc=$?
[ "$rc" -ne 0 ] && [ -z "$out" ] && ok "the newest attempt's artifact without a digest file fails, not falls back" || bad "empty newest artifact" "rc=$rc out=$out"

# The choice must not depend on the order the directory lists its
# artifacts: the attempt-order cases run again with find's output sorted one
# way and then the other, so "the first one found" fails in at least one.
realfind=$(command -v find)
for order in "" r; do
  mkdir -p "$T/bin$order"
  printf '#!/usr/bin/env bash\n"%s" "$@" | LC_ALL=C sort -z%s\n' "$realfind" "$order" > "$T/bin$order/find"
  chmod +x "$T/bin$order/find"
  how="listing sorted${order:+ in reverse}"
  fresh; for i in $IMAGES; do put "$T/dl" "$i" 1 "a1$i"; put "$T/dl" "$i" 2 "a2$i"; done
  out=$(PATH="$T/bin$order:$PATH" sel backend 5); rc=$?
  [ "$rc" -eq 0 ] && [ "$out" = "$(d a2backend)" ] && ok "a full rerun publishes attempt 2's digest ($how)" || bad "full rerun ($how)" "rc=$rc out=$out err=$(cat "$T/err")"
  fresh; for i in $IMAGES; do put "$T/dl" "$i" 1 "a1$i"; done; put "$T/dl" web 9 "a9web"; put "$T/dl" web 10 "a10web"
  out=$(PATH="$T/bin$order:$PATH" sel web 5); rc=$?
  [ "$rc" -eq 0 ] && [ "$out" = "$(d a10web)" ] && ok "attempt 10 wins over attempt 9 ($how)" || bad "attempt 10 over 9 ($how)" "rc=$rc out=$out err=$(cat "$T/err")"
done

# The workflow uploads one artifact per image and attempt, and publish reads
# it through this script, with the job total as the expected count.
wf=.github/workflows/multi-arch.yml
grep -qF 'name: digest-${{ matrix.image }}-${{ github.run_attempt }}' "$wf" \
  && ok "build-scan names its artifact with the run attempt" || bad "artifact name carries the attempt" "$(grep -n 'name: digest-' "$wf")"
grep -qF 'overwrite: true' "$wf" \
  && bad "no artifact is overwritten" "$(grep -n 'overwrite' "$wf")" || ok "no artifact is overwritten"
grep -qF 'pattern: digest-*' "$wf" \
  && ok "publish downloads every attempt's digests" || bad "publish downloads digest-*" ""
grep -qE 'bash scripts/select-scanned-digest\.sh "\$DIGESTS" "\$IMG" "\$JOB_TOTAL"' "$wf" \
  && ok "publish selects the digest with this script" || bad "publish uses the script" "$(grep -n 'select-scanned' "$wf")"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

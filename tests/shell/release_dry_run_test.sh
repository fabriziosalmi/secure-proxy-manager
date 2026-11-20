#!/usr/bin/env bash
# What a release dry run (workflow_dispatch of .github/workflows/multi-arch.yml)
# runs, and what it must never run.
#
# Never: a step that signs, tags or mirrors runs only for a vX.Y.Z tag
# (env.RELEASE == 'true'), so a dry run cannot move a tag or sign a digest.
#
# Always, dry run included: cosign is installed (publish and spm binaries) and
# Docker Hub is logged in to when its credentials exist, and the dry run
# verifies the current release's :latest with scripts/cosign-verify.sh. Before
# this, the dry run skipped all three, so a broken cosign-installer or Docker
# Hub login would first show on the tag, where a fix needs another release.
#
# scripts/cosign-verify.sh is tested against a stub cosign.
#
# Usage: tests/shell/release_dry_run_test.sh
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ✗ %s\n     %s\n" "$1" "${2:-}"; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
WF=.github/workflows/multi-arch.yml

# Every step of the workflow as "job<TAB>name<TAB>if<TAB>uses+run", one line each.
python3 -I - "$WF" > "$T/steps" <<'PY'
import re, sys
job = None; step = None; out = []
def flush():
    if step is not None:
        out.append("\t".join([job or "", step.get("name", ""), step.get("if", ""), " ".join(step.get("body", []))]))
in_jobs = False
for line in open(sys.argv[1]):
    s = line.rstrip("\n")
    if s.startswith("jobs:"):
        in_jobs = True; continue
    if not in_jobs:
        continue
    m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", s)
    if m:
        flush(); step = None; job = m.group(1); continue
    m = re.match(r"^      - (name|uses|run): ?(.*)$", s)
    if m:
        flush(); step = {"body": []}
        if m.group(1) == "name": step["name"] = m.group(2).strip()
        else: step["body"].append(m.group(2))
        continue
    if step is None:
        continue
    m = re.match(r"^        if: (.*)$", s)
    if m:
        step["if"] = m.group(1).strip(); continue
    if re.match(r"^        (uses|run):", s) or re.match(r"^ {10,}\S", s):
        step["body"].append(s.strip())
flush()
print("\n".join(out))
PY
[ -s "$T/steps" ] && ok "multi-arch.yml parsed: $(wc -l < "$T/steps" | tr -d ' ') steps" || bad "parse" "no steps"

# Never in a dry run: sign, tag, mirror.
# A step counts by what it runs as well as by its name: cosign-sign*.sh,
# cosign sign, or imagetools create (which writes a tag).
mut='tolower($2) ~ /^(sign|tag the|mirror)/ || $4 ~ /cosign-sign|cosign sign|imagetools create/'
unguarded=$(awk -F'\t' "($mut) && \$3 !~ /env\\.RELEASE == .true./ {print \$1\": \"\$2\" (if: \"\$3\")\"}" "$T/steps")
n=$(awk -F'\t' "$mut" "$T/steps" | wc -l | tr -d ' ')
[ "$n" -ge 5 ] && [ -z "$unguarded" ] \
  && ok "all $n sign, tag and mirror steps run only for a release tag" \
  || bad "sign, tag and mirror are release-only" "found $n; unguarded: $unguarded"

# Always: cosign installed in publish and spm binaries.
inst=$(awk -F'\t' '$2 == "Install cosign" {print $1"|"$3}' "$T/steps")
[ "$(printf '%s\n' "$inst" | grep -c .)" -eq 2 ] && ! printf '%s' "$inst" | grep -q 'RELEASE' \
  && ok "cosign is installed in both jobs that sign, on a dry run too" \
  || bad "cosign installed on a dry run" "$inst"

# Docker Hub login: whenever the credentials exist, release or not.
hub=$(awk -F'\t' '$2 == "Login to Docker Hub" {print $3}' "$T/steps")
printf '%s' "$hub" | grep -q "steps.dh.outputs.enabled == 'true'" && ! printf '%s' "$hub" | grep -q 'RELEASE' \
  && ok "Docker Hub is logged in to on a dry run when its credentials exist" \
  || bad "Docker Hub login on a dry run" "if: $hub"

# The dry run verifies the current release with the installed cosign.
v=$(awk -F'\t' '$3 ~ /env\.RELEASE != .true./ && $4 ~ /cosign-verify\.sh/ {print $1"|"$4}' "$T/steps")
printf '%s' "$v" | grep -q 'publish|' && printf '%s' "$v" | grep -qF '${IMAGE}:latest' \
  && printf '%s' "$v" | grep -qF 'secure-proxy-manager:${IMG}-latest' \
  && ok "the publish dry run verifies the current release's :latest on GHCR and Docker Hub" \
  || bad "dry run verifies the current release" "$v"
cv=$(awk -F'\t' '$1 == "cli-assets" && $3 ~ /env\.RELEASE != .true./ && $4 ~ /cosign version/' "$T/steps")
[ -n "$cv" ] && ok "the spm binaries dry run runs the installed cosign" || bad "spm binaries dry run runs cosign" "none"

# scripts/cosign-verify.sh against a stub cosign.
mkdir -p "$T/bin"
cat > "$T/bin/cosign" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
case "$1" in
  version) exit 0 ;;
  verify) [ -e "$STUB_DIR/unsigned" ] && exit 1; exit 0 ;;
esac
exit 3
STUB
chmod +x "$T/bin/cosign"
export STUB_LOG="$T/log" STUB_DIR="$T"
out=$(PATH="$T/bin:$PATH" bash scripts/cosign-verify.sh ghcr.io/o/r:latest 2>&1); rc=$?
[ "$rc" -eq 0 ] && grep -q -- '--certificate-oidc-issuer https://token.actions.githubusercontent.com' "$T/log" \
  && ok "a signed reference verifies, against the release workflow identity" || bad "signed verifies" "rc=$rc $out $(cat "$T/log" 2>/dev/null)"
touch "$T/unsigned"
out=$(PATH="$T/bin:$PATH" bash scripts/cosign-verify.sh ghcr.io/o/r:latest 2>&1); rc=$?
[ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q '::error::' \
  && ok "an unsigned reference fails with an error annotation" || bad "unsigned fails" "rc=$rc $out"
rm -f "$T/unsigned"
mkdir -p "$T/empty"; ln -sf "$(command -v bash)" "$T/empty/bash"
out=$(PATH="$T/empty" "$T/empty/bash" scripts/cosign-verify.sh ghcr.io/o/r:latest 2>&1); rc=$?
[ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'cosign is not installed' \
  && ok "no cosign on PATH fails, saying cosign is not installed" || bad "missing cosign fails" "rc=$rc $out"

# One identity everywhere it is written.
id_sign=$(sed -nE "s/^identity='(.*)'$/\1/p" scripts/cosign-sign.sh)
id_verify=$(sed -nE "s/^identity='(.*)'$/\1/p" scripts/cosign-verify.sh)
[ -n "$id_sign" ] && [ "$id_sign" = "$id_verify" ] && grep -qF -- "$id_sign" SECURITY.md \
  && ok "cosign-verify.sh checks the identity cosign-sign.sh and SECURITY.md name" \
  || bad "one identity" "sign='$id_sign' verify='$id_verify'"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

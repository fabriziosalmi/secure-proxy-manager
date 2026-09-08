#!/usr/bin/env bash
# Branch protection for `main`, as a reviewed file instead of a memory of clicks.
#
# The protection on main used to be a shell: required_status_checks existed with
# `strict: true` and an EMPTY context list, force pushes were allowed, and no
# pull request was required. So "up to date with main" was enforced against
# nothing, and a red CI never blocked a merge — the only thing standing between
# a broken main and a merge was whoever was reading the check list.
#
# Keeping the desired state in .github/branch-protection.json means it can be
# reviewed in a PR, diffed against reality, and restored after someone relaxes
# it "just for a minute".
#
#   scripts/branch-protection.sh verify   # diff live state against the file (default)
#   scripts/branch-protection.sh apply    # write the file's state to GitHub
#
# apply needs a token with `repo` admin scope: `gh auth refresh -s admin:repo`.
set -uo pipefail

REPO="${REPO:-fabriziosalmi/secure-proxy-manager}"
BRANCH="${BRANCH:-main}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DESIRED="$DIR/.github/branch-protection.json"
API="repos/$REPO/branches/$BRANCH/protection"

command -v gh >/dev/null || { echo "gh CLI not found" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 2; }
[ -f "$DESIRED" ] || { echo "missing $DESIRED" >&2; exit 2; }

# normalize reduces a protection document — either the desired file or the
# live API response, whose shape differs — to the same comparable form.
normalize() {
  python3 -c '
import json, sys
d = json.load(sys.stdin)

def flag(v):
    # The API wraps booleans as {"enabled": bool}; the request body uses plain bools.
    return v.get("enabled") if isinstance(v, dict) else bool(v)

rsc = d.get("required_status_checks") or {}
# The API returns both the modern "checks" list and the legacy "contexts";
# compare on the names only.
if rsc.get("checks"):
    contexts = sorted(c["context"] for c in rsc["checks"])
else:
    contexts = sorted(rsc.get("contexts") or [])

pr = d.get("required_pull_request_reviews")
out = {
    "pull_request_required": pr is not None,
    "required_approving_review_count": (pr or {}).get("required_approving_review_count"),
    "dismiss_stale_reviews": (pr or {}).get("dismiss_stale_reviews"),
    "strict_up_to_date": rsc.get("strict"),
    "required_checks": contexts,
    "enforce_admins": flag(d.get("enforce_admins")),
    "required_linear_history": flag(d.get("required_linear_history")),
    "allow_force_pushes": flag(d.get("allow_force_pushes")),
    "allow_deletions": flag(d.get("allow_deletions")),
    "required_conversation_resolution": flag(d.get("required_conversation_resolution")),
    "lock_branch": flag(d.get("lock_branch")),
}
json.dump(out, sys.stdout, indent=2, sort_keys=True)
print()
'
}

case "${1:-verify}" in
  apply)
    echo "applying $DESIRED to $REPO@$BRANCH ..."
    gh api --method PUT "$API" --input "$DESIRED" >/dev/null || {
      echo "PUT failed — the token needs admin scope: gh auth refresh -s admin:repo" >&2
      exit 1
    }
    echo "applied. re-verifying:"
    exec "$0" verify
    ;;
  verify)
    live="$(gh api "$API" 2>/dev/null)" || {
      echo "cannot read protection on $REPO@$BRANCH (needs admin scope, or none is set)" >&2
      exit 1
    }
    a="$(printf '%s' "$live" | normalize)"
    b="$(normalize < "$DESIRED")"
    if [ "$a" = "$b" ]; then
      echo "OK: branch protection on $REPO@$BRANCH matches .github/branch-protection.json"
      printf '%s\n' "$b"
      exit 0
    fi
    echo "DRIFT: live protection does not match .github/branch-protection.json"
    diff -u <(printf '%s\n' "$b") <(printf '%s\n' "$a") | sed '1,2d'
    echo
    echo "run: scripts/branch-protection.sh apply"
    exit 1
    ;;
  *)
    echo "usage: $0 [verify|apply]" >&2
    exit 2
    ;;
esac

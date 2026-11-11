#!/usr/bin/env bash
# The nightly report jobs in .github/workflows/ci.yml must depend on every
# other job. A job left out of `needs` fails without a report: E2E
# (production compose), the UI layout tests and slopless were missing, so a
# red run of any one of them alone opened no issue.
#
# Usage: scripts/check-nightly-needs.sh [workflow]
set -euo pipefail
WF="${1:-.github/workflows/ci.yml}"
python3 - "$WF" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
body = text.split("\njobs:\n", 1)[1]
jobs = re.findall(r"^  ([a-z0-9-]+):\s*$", body, re.M)
reporters = [j for j in jobs if j.startswith("nightly-")]
others = set(j for j in jobs if j not in reporters)
if not reporters:
    sys.exit(f"ERROR: no nightly-* job in {sys.argv[1]}")
bad = False
for r in reporters:
    block = re.search(rf"^  {r}:\s*\n(.*?)(?=^  [a-z0-9-]+:\s*$|\Z)", body, re.M | re.S).group(1)
    m = re.search(r"^    needs:\s*\[(.*?)\]", block, re.M | re.S)
    needs = set(n.strip() for n in m.group(1).replace("\n", " ").split(",") if n.strip()) if m else set()
    missing, unknown = sorted(others - needs), sorted(needs - others)
    if missing or unknown:
        bad = True
        print(f"ERROR: {r}: missing {missing or 'none'}, unknown {unknown or 'none'}")
if bad:
    sys.exit(1)
print(f"OK: {', '.join(reporters)} depend on all {len(others)} other jobs")
PY

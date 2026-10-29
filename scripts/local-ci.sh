#!/usr/bin/env bash
# Local equivalent of .github/workflows/ci.yml for a tree that cannot run
# GitHub Actions (such as a GHSA private advisory fork). Runs every gate,
# records pass/fail per step, never stops early, and exits non-zero if any
# gate failed.
#
# The suites wipe config/, data/ and logs/ and tests/ci-e2e.sh rewrites .env,
# so it runs only in a linked worktree (git worktree add), never in the
# checkout a deployment runs from. SPM_LOCAL_CI_ALLOW_RESET=1 accepts any
# other disposable checkout, such as a fresh clone kept for testing.
#
# Usage: scripts/local-ci.sh [worktree] [log_dir]
set -u

# Started from a git hook or git rebase -x, git exports GIT_DIR and friends:
# every git call below would then act on that repository, not on the target.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_PREFIX

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEFAULT_W=$(cd "$SCRIPT_DIR/.." && pwd)
W=${1:-$DEFAULT_W}
if ! W=$(cd "$W" 2>/dev/null && pwd); then
  echo "error: worktree directory not found: ${1:-$DEFAULT_W}" >&2
  exit 1
fi
L=${2:-${TMPDIR:-/tmp}/spm-local-ci-$(date +%Y%m%d-%H%M%S)}

LOCK_DIR="${SPM_LOCAL_CI_LOCK_DIR:-${TMPDIR:-/tmp}/spm-local-ci.lock}"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  holder_pid=$(cat "$LOCK_DIR/pid" 2>/dev/null || echo "unknown")
  # A run killed by SIGKILL or a closed terminal never reaches the EXIT trap.
  # Its lock names a process that is gone: take the lock over.
  if [ "$holder_pid" != "unknown" ] && ! kill -0 "$holder_pid" 2>/dev/null &&
    rm -rf "$LOCK_DIR" && mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "note: removed a stale lock left by pid $holder_pid, which no longer runs." >&2
  else
    echo "error: another local-ci.sh run holds the lock at $LOCK_DIR (pid: $holder_pid)." >&2
    echo "Wait for it to finish, or if a previous run crashed, remove it with: rm -rf \"$LOCK_DIR\"" >&2
    exit 1
  fi
fi
echo "$$" > "$LOCK_DIR/pid"
trap 'rm -rf "$LOCK_DIR"' EXIT

mkdir -p "$L"
cd "$W" || exit 1
RES="$L/results.txt"
: > "$RES"

# A linked worktree has its own git dir under the main repository's
# .git/worktrees/; in the main checkout the two are the same directory.
git_dir=$(git rev-parse --absolute-git-dir 2>/dev/null) || git_dir=""
common_dir=$(cd "$(git rev-parse --git-common-dir 2>/dev/null || echo .)" 2>/dev/null && pwd -P) || common_dir=""
git_dir=$(cd "$git_dir" 2>/dev/null && pwd -P) || git_dir=""
if [ -z "$git_dir" ] || { [ "$git_dir" = "$common_dir" ] && [ "${SPM_LOCAL_CI_ALLOW_RESET:-0}" != "1" ]; }; then
  echo "error: $W is not a linked git worktree. The suites wipe config/, data/ and logs/" >&2
  echo "and rewrite .env, so this script refuses a checkout that may hold a deployment." >&2
  echo "Run it in one: git worktree add ../spm-ci HEAD && scripts/local-ci.sh ../spm-ci" >&2
  echo "For a disposable clone, set SPM_LOCAL_CI_ALLOW_RESET=1." >&2
  exit 1
fi

# Test hook (tests/shell/local_ci_lock_test.sh): stop after the lock and the
# worktree check, before any gate.
if [ "${SPM_LOCAL_CI_DRY_RUN:-0}" = "1" ]; then
  sleep "${SPM_LOCAL_CI_HOLD_SECONDS:-1}"
  echo "done" >> "$RES"
  cat "$RES"
  exit 0
fi

# Defense in depth: if a test script ever calls sudo without -n from a shell
# with a terminal, sudo waits for a password on /dev/tty and hangs the run. A
# shim first in PATH forces non-interactive sudo (-n) so any such call fails at
# once and triggers the script's fallback.
SHIM="$L/.sudo-shim"
mkdir -p "$SHIM"
printf '#!/bin/sh\nexec /usr/bin/sudo -n "$@"\n' > "$SHIM/sudo"
chmod +x "$SHIM/sudo"
export PATH="$SHIM:$PATH"

FAILURES=0

step() { # name, command...
  local name=$1
  shift
  local log
  log="$L/$(echo "$name" | tr ' /()' '____').log"
  local t0=$SECONDS
  printf '==> [gate] %s\n' "$name"
  # Defense in depth: stdin from /dev/null ensures a subprocess started from a
  # background job of an interactive shell never reads /dev/tty and gets
  # stopped by SIGTTIN/SIGTTOU.
  if "$@" </dev/null >"$log" 2>&1; then
    local line
    line="PASS  $(printf '%-38s' "$name") $((SECONDS - t0))s"
    echo "$line" | tee -a "$RES"
  else
    local line
    line="FAIL  $(printf '%-38s' "$name") $((SECONDS - t0))s  (log: $log)"
    echo "$line" | tee -a "$RES"
    FAILURES=$((FAILURES + 1))
  fi
}

export GOFLAGS=-p=2

# Stack runs leave state in config/, data/ and logs/, much of it gitignored
# (dnsmasq.d/blocklist.hosts, ssl_db, *.pos offsets, the SQLite file), which
# plain git clean -fd keeps: a later smoke then starts on the previous run's
# blacklist and log offsets. This runs only inside a worktree.
reset_state() {
  git checkout -q -- config logs && git clean -fdxq config data logs && git checkout -q -- config logs
}
reset_state

# The shell suites build their images only when absent (build_if_missing), so a
# tag left by another branch is reused silently and tests old code. Rebuild
# every image a suite names from this worktree.
rebuild_test_images() {
  docker build -q -t spm-waf-test waf-go/ >/dev/null &&
    docker build -q -t spm-dns-test dns/ >/dev/null &&
    docker build -q -t spm-backend-test backend-go/ >/dev/null
}
rebuild_test_images

step "go backend test+vet"   bash -c 'cd backend-go && go vet ./... && go test -race -count=1 ./...'
step "go waf test+vet"       bash -c 'cd waf-go && go vet ./... && go test -race -count=1 ./...'
step "golangci backend"      docker run --rm -v "$W:/repo" -w /repo/backend-go golangci/golangci-lint:v2.12.2 golangci-lint run --timeout 5m
step "golangci waf"          docker run --rm -v "$W:/repo" -w /repo/waf-go golangci/golangci-lint:v2.12.2 golangci-lint run --timeout 5m
step "gosec backend (go 1.26 as CI)" docker run --rm -v "$W/backend-go:/src:ro" -w /src -e GOTOOLCHAIN=local golang:1.26 sh -c 'go install github.com/securego/gosec/v2/cmd/gosec@v2.22.4 >/dev/null 2>&1 && /go/bin/gosec -quiet -severity medium -confidence medium ./...'
step "ui tsc+vitest+eslint+build" bash -c 'cd ui && npm ci --no-audit --no-fund >/dev/null && npx tsc --noEmit && npx vitest run && npx eslint src && npm run build'
step "ui layout (playwright)"    bash -c 'cd ui && npx playwright install chromium >/dev/null && npm run test:layout'
step "version sync"          bash scripts/check-version-sync.sh
step "image pins"            bash scripts/check-image-pins.sh
step "config contract"       bash scripts/check-config-contract.sh
step "shellcheck"            docker run --rm -v "$W:/mnt" -w /mnt koalaman/shellcheck:v0.11.0 --severity=warning proxy/*.sh deploy/*.sh scripts/*.sh tests/*.sh tests/shell/*.sh
step "python tests"          uv run --no-project --with pytest==8.4.2 --with 'mcp>=2.0.0,<3.0.0' --with 'httpx>=0.27,<1.0.0' python -I -m pytest tests/python -q -p no:cacheprovider
step "ruff"                  uvx ruff@0.14.2 check proxy/ mcp/
step "proxy image build"     docker build -q -t spm-proxy-test proxy/
step "squid config generation" bash tests/shell/generate_squid_conf_test.sh spm-proxy-test
step "squid access policy matrix" bash tests/shell/squid_acl_matrix_test.sh spm-proxy-test
step "web TLS entrypoint"    bash tests/shell/ui_tls_entrypoint_test.sh
step "restore drill"         bash tests/shell/restore_test.sh
step "adversarial suite"     bash tests/adversarial/run.sh
reset_state
step "e2e compose smoke"     bash tests/ci-e2e.sh
# Separate jobs on GitHub: the smoke run leaves proxy status files in config/,
# which the Playwright suite (no proxy) must not see.
reset_state
step "e2e playwright"        bash -c 'docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner; rc=$?; docker compose -f docker-compose.test.yml down -v >/dev/null 2>&1; exit $rc'
reset_state
step "compose images build"  env COMPOSE_PROJECT_NAME=spmlocalci docker compose build web backend waf proxy dns
for img in web backend waf proxy dns; do
  step "trivy own image $img" docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v spm-trivy-cache:/root/.cache aquasec/trivy:0.69.3 image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress "spmlocalci-$img:latest"
done
echo "done" >> "$RES"
printf '\n=== Local CI Results (%s) ===\n' "$RES"
cat "$RES"
[ "$FAILURES" -eq 0 ]

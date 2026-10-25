#!/usr/bin/env bash
# Measure the backend's start-up: wall time and peak memory of each step, under
# the compose limits, against a database the size of a real deployment's.
#
# What it does, from the repository root:
#   1. builds the helper (scripts/measure-backend-startup/) and, unless -I is
#      given, the backend image from backend-go/;
#   2. generates the fixture with TestGenerateLargeDB (backend-go/internal/
#      database/largedb_test.go), unless -f names one;
#   3. per run: copies the fixture into a fresh volume, starts the backend with
#      --memory/--cpus as compose sets them (read-only root, tmpfs /tmp,
#      cap-drop ALL), samples its cgroup every 50 ms from a separate container
#      (so the sampler's memory is not counted as the backend's), waits for
#      "HTTP server starting", keeps sampling for -a seconds, stops it;
#   4. prints, per run, each "startup step" log line (and the background
#      integrity check) with its duration and the peak anonymous memory while
#      it ran, then the start-to-HTTP time, the whole-run peak and oom_kill.
#
# Usage:
#   scripts/measure-backend-startup.sh [-r runs] [-l logs] [-d domains] [-i ips]
#       [-f fixture.db] [-I image] [-m memory] [-c cpus] [-a seconds] [-n] [-o dir]
#
#   -r  runs (default 3)
#   -l -d -i  fixture rows: proxy_logs, domain_blacklist, ip_blacklist
#       (default 1000000 640000 50000, about 440 MiB; smoke test: -l 20000 -d 10000 -i 1000)
#   -f  use this fixture instead of generating one (it is copied, never written)
#   -I  measure this image instead of building backend-go/
#   -m -c  backend limits (default 128m and 0.25, the docker-compose.yml values)
#   -a  seconds to keep sampling after the HTTP server starts (default 120: the
#       full integrity check begins 30 s after start and takes about a minute
#       on the default fixture at 0.25 CPU)
#   -n  no swap: --memory-swap equal to --memory, as on a host without swap.
#       Without it Docker's default applies, as under compose.
#   -o  output directory (default .measure-startup/, gitignored); each
#       invocation writes <dir>/<timestamp>/run<N>/{log,samples.csv,state,t0}
#       and report.txt
#
# Columns of the report: anon_MiB is the cgroup's anonymous memory (what the
# OOM killer cannot reclaim), rssA_MiB the process's RssAnon, cgcur_MiB the
# cgroup's memory.current (file cache included, so it sits at the limit), swap
# the cgroup's memory.swap.current.
#
# Needs: docker with cgroup v2 (Docker Desktop, OrbStack, Linux). Every
# container it starts has a memory cap; on exit (success, failure or Ctrl-C)
# it removes every container, volume and image it created and the work
# directory with the fixture, and keeps only the run outputs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT=$(pwd)

RUNS=3 LOGS=1000000 DOMAINS=640000 IPS=50000 FIXTURE="" IMAGE="" MEM=128m CPUS=0.25
AFTER_READY=120 NOSWAP="" OUTBASE="$ROOT/.measure-startup"
while getopts "r:l:d:i:f:I:m:c:a:no:h" opt; do
  case "$opt" in
    r) RUNS=$OPTARG ;;
    l) LOGS=$OPTARG ;;
    d) DOMAINS=$OPTARG ;;
    i) IPS=$OPTARG ;;
    f) FIXTURE=$OPTARG ;;
    I) IMAGE=$OPTARG ;;
    m) MEM=$OPTARG ;;
    c) CPUS=$OPTARG ;;
    a) AFTER_READY=$OPTARG ;;
    n) NOSWAP=1 ;;
    o) OUTBASE=$OPTARG ;;
    *) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 2 ;;
  esac
done

# The toolchain and base images the backend's own Dockerfile pins, so the
# helper and the fixture are built with what the image is built with.
GOLANG=$(sed -nE 's#^FROM[[:space:]]+(golang:[^[:space:]]+)[[:space:]]+AS[[:space:]]+builder.*#\1#p' backend-go/Dockerfile | head -1)
ALPINE=$(sed -nE 's#^FROM[[:space:]]+(alpine:[^[:space:]]+).*#\1#p' backend-go/Dockerfile | head -1)
[ -n "$GOLANG" ] && [ -n "$ALPINE" ] || { echo "cannot read the golang and alpine pins from backend-go/Dockerfile" >&2; exit 1; }

STAMP=$(date +%Y%m%d-%H%M%S)
OUT="$OUTBASE/$STAMP"
WORK="$OUTBASE/work-$STAMP"
P="spm-measure-$$"
BUILT_IMAGE=""
mkdir -p "$OUT" "$WORK/fixture"

cleanup() {
  local c v
  for c in $(docker ps -aq --filter "name=^$P-"); do docker rm -f "$c" >/dev/null 2>&1 || true; done
  for v in $(docker volume ls -q --filter "name=^$P-"); do docker volume rm "$v" >/dev/null 2>&1 || true; done
  [ -n "$BUILT_IMAGE" ] && docker rmi "$BUILT_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "building the helper"
docker run --rm --name "$P-build" --memory 1g -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
  -v "$ROOT/scripts/measure-backend-startup:/src:ro" -v "$WORK:/out" -w /src "$GOLANG" \
  go build -o /out/measure . >/dev/null

if [ -z "$IMAGE" ]; then
  echo "building the backend image from backend-go/"
  BUILT_IMAGE="$P-backend:local"
  docker build -q -t "$BUILT_IMAGE" backend-go >/dev/null
  IMAGE=$BUILT_IMAGE
fi

if [ -z "$FIXTURE" ]; then
  echo "generating the fixture: $LOGS logs, $DOMAINS domains, $IPS ips"
  docker run --rm --name "$P-fixture" --memory 1g -e CGO_ENABLED=0 -e GOFLAGS="-buildvcs=false -mod=readonly" \
    -e SPM_LARGE_DB=/out/proxy_manager.db -e SPM_LARGE_DB_LOGS="$LOGS" \
    -e SPM_LARGE_DB_DOMAINS="$DOMAINS" -e SPM_LARGE_DB_IPS="$IPS" \
    -v "$ROOT/backend-go:/src:ro" -v "$WORK/fixture:/out" -w /src "$GOLANG" \
    go test ./internal/database -run '^TestGenerateLargeDB$' -count=1 -timeout 30m -v 2>&1 \
    | grep -E 'wrote |FAIL|panic' || { echo "fixture generation failed" >&2; exit 1; }
  FIXTURE="$WORK/fixture/proxy_manager.db"
fi
[ -f "$FIXTURE" ] || { echo "no fixture at $FIXTURE" >&2; exit 1; }
FIXDIR=$(cd "$(dirname "$FIXTURE")" && pwd)
FIXNAME=$(basename "$FIXTURE")

SWAP_ARGS=()
[ -n "$NOSWAP" ] && SWAP_ARGS=(--memory-swap "$MEM")

# Wall clock in milliseconds (macOS date has no %N); the log timestamps it is
# compared with come from the Docker daemon, on the same clock.
now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time() * 1000'; }

run_once() {
  local n=$1 dir="$OUT/run$1" b="$P-r$1" id ready="" st
  mkdir -p "$dir"
  for v in data config logs; do docker volume create "$b-$v" >/dev/null; done
  docker run --rm --name "$b-copy" --memory 64m -v "$b-data:/data" -v "$FIXDIR:/src:ro" "$ALPINE" \
    sh -c "cp '/src/$FIXNAME' /data/proxy_manager.db && sync"
  docker create --name "$b-backend" --memory "$MEM" ${SWAP_ARGS[@]+"${SWAP_ARGS[@]}"} --cpus "$CPUS" \
    --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
    -v "$b-data:/data" -v "$b-config:/config" -v "$b-logs:/logs" \
    -e BASIC_AUTH_USERNAME=admin -e BASIC_AUTH_PASSWORD=Measure-Startup-9x \
    -e SECRET_KEY=5f2b0c3e9a8d7f6e5d4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a291807f6e \
    -e PROXY_URL=http://127.0.0.1:9 -e WAF_URL=http://127.0.0.1:9 \
    "$IMAGE" >/dev/null
  id=$(docker inspect -f '{{.Id}}' "$b-backend")
  docker run -d --name "$b-sampler" --pid=host --memory 32m \
    -v /sys/fs/cgroup:/cg:ro -v "$WORK:/m:ro" "$ALPINE" /m/measure sample /cg "$id" 50 >/dev/null
  sleep 1
  now_ms > "$dir/t0"
  docker start "$b-backend" >/dev/null
  # Wait for the HTTP server, the process to exit, or 20 minutes.
  for _ in $(seq 1 2400); do
    if docker logs "$b-backend" 2>&1 | grep -q '"HTTP server starting"'; then ready=1; break; fi
    st=$(docker inspect -f '{{.State.Status}}' "$b-backend")
    [ "$st" = "running" ] || break
    sleep 0.5
  done
  [ -n "$ready" ] && sleep "$AFTER_READY"
  docker inspect -f 'status={{.State.Status}} oom_killed={{.State.OOMKilled}} exit={{.State.ExitCode}}' "$b-backend" > "$dir/state"
  docker stop -t 10 "$b-backend" >/dev/null 2>&1 || true
  sleep 0.5
  docker logs -t "$b-backend" > "$dir/log" 2>&1
  docker logs "$b-sampler" > "$dir/samples.csv" 2>&1
  docker rm -f "$b-backend" "$b-sampler" >/dev/null 2>&1 || true
  for v in data config logs; do docker volume rm "$b-$v" >/dev/null 2>&1 || true; done
  echo "run $n: $(cat "$dir/state")"
}

for n in $(seq 1 "$RUNS"); do run_once "$n"; done

dirs=()
for n in $(seq 1 "$RUNS"); do dirs+=("/o/run$n"); done
docker run --rm --name "$P-report" --memory 64m -v "$OUT:/o:ro" -v "$WORK:/m:ro" "$ALPINE" \
  /m/measure report "${dirs[@]}" | tee "$OUT/report.txt"
echo "outputs: $OUT"

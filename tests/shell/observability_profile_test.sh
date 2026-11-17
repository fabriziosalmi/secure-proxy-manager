#!/usr/bin/env bash
# Verify that the observability profile in docker-compose.yml starts cleanly,
# Prometheus loads its configuration and sees the backend:5000 and waf:8080
# scrape targets, promtool validates the alert rules in /etc/prometheus/rules,
# and Grafana starts with the provisioned Prometheus datasource and the
# Proxy cache dashboard.
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

PASS=0; FAIL=0
G="\033[0;32m"; R="\033[0;31m"; N="\033[0m"
ok()  { PASS=$((PASS+1)); printf "  ${G}✓${N} %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ${R}✗${N} %s\n     %s\n" "$1" "${2:-}"; }

PROJ="spmobs$$"
ADMIN_PW="obs-admin-$$-pass"
OVERRIDE="$(mktemp "${TMPDIR:-/tmp}/spm-obs-override.XXXXXX.yml")"

cleanup() {
  COMPOSE_PROJECT_NAME="$PROJ" GRAFANA_ADMIN_PASSWORD="$ADMIN_PW" \
    docker compose -f docker-compose.yml -f "$OVERRIDE" --profile observability down -v >/dev/null 2>&1 || true
  docker rm -f secure-proxy-manager-prometheus secure-proxy-manager-grafana >/dev/null 2>&1 || true
  rm -f "$OVERRIDE"
  # When ./infra is absent (base reproduction), Docker creates host directories
  # for the missing bind-mount sources; remove them if prometheus.yml is a dir.
  if [ -d infra/prometheus/prometheus.yml ]; then
    rm -rf infra
  fi
}
trap cleanup EXIT

cat >"$OVERRIDE" <<'EOF'
services:
  prometheus:
    deploy:
      resources:
        limits:
          cpus: '0.25'
          memory: 256M
  grafana:
    deploy:
      resources:
        limits:
          cpus: '0.25'
          memory: 512M
EOF
# Grafana gets 512M. At 256M, on one GitHub runner image (ubuntu-26.04
# 20261111.82.6, kernel 7.0.0-1016-aws, Docker 29.4.2), the kernel killed
# Grafana 13.3.0 for memory at every start (an oom event and exit 137, nine
# times in a row), while the same test passed on the other runner image. The
# compose files set no memory limit on Grafana: the cap is this test's own.

echo "── observability profile (prometheus + grafana) ──"
TEST_START="$(date +%s)"
UP_OUT="$(COMPOSE_PROJECT_NAME="$PROJ" GRAFANA_ADMIN_PASSWORD="$ADMIN_PW" \
  docker compose -f docker-compose.yml -f "$OVERRIDE" --profile observability up -d prometheus grafana 2>&1)"
UP_RC=$?
if [ "$UP_RC" -eq 0 ]; then
  ok "docker compose --profile observability up -d prometheus grafana"
else
  bad "docker compose --profile observability up -d prometheus grafana" "$UP_OUT"
  printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
  exit 1
fi

prom_ready=0
for _ in $(seq 1 30); do
  if docker exec secure-proxy-manager-prometheus wget -qO- http://127.0.0.1:9090/-/ready >/dev/null 2>&1; then
    prom_ready=1
    break
  fi
  sleep 1
done
if [ "$prom_ready" -eq 1 ]; then
  ok "prometheus is ready on :9090"
else
  bad "prometheus is ready on :9090" "$(docker logs secure-proxy-manager-prometheus 2>&1 | tail -10)"
fi

# Grafana took over 40 s to answer on a GitHub runner (2026-11-14): its
# health and datasource checks failed while the dashboard check, which waits,
# passed. It gets up to 120 s, and every Grafana check waits for its answer.
graf_ready=0
for _ in $(seq 1 120); do
  if docker exec secure-proxy-manager-grafana wget -qO- http://127.0.0.1:3000/api/health >/dev/null 2>&1; then
    graf_ready=1
    break
  fi
  sleep 1
done
# How the Grafana container ended, when it did not come up: a container that
# restarts with no error in its log was killed, and OOMKilled says whether by
# the memory limit this test sets.
# OOMKilled and ExitCode describe the current run only: after a restart they
# read false and 0 even when every earlier run was killed for memory, so the
# kills are counted from Docker's oom events since the test started.
grafana_state() {
  local ooms
  ooms=$(docker events --since "$TEST_START" --until "$(date +%s)" \
    --filter container=secure-proxy-manager-grafana --filter event=oom --format '{{.Action}}' 2>/dev/null | grep -c oom)
  echo "Restarts=$(docker inspect -f '{{.RestartCount}}' secure-proxy-manager-grafana 2>&1)" \
    "Status=$(docker inspect -f '{{.State.Status}}' secure-proxy-manager-grafana 2>&1)" \
    "oom_kills=$ooms" \
    "memory=$(docker stats --no-stream --format '{{.MemUsage}}' secure-proxy-manager-grafana 2>&1)" \
    "peak=$(docker exec secure-proxy-manager-grafana cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo n/a)"
}
# Why Grafana stopped, when it restarts with exit code 0 and no OOM (seen on
# one GitHub runner image only, 2026-11-16): what Docker saw happen to the
# container (die with its exit code, kill with its signal, oom), the lines in
# which Grafana says it is shutting down or failed, across every restart, and
# the runner's kernel and Docker.
grafana_diagnosis() {
  echo "     runner: kernel $(uname -r), docker $(docker version --format '{{.Server.Version}}' 2>&1), cgroup $(docker info --format '{{.CgroupDriver}} v{{.CgroupVersion}}' 2>&1)"
  echo "     state: $(docker inspect -f 'StartedAt={{.State.StartedAt}} FinishedAt={{.State.FinishedAt}} Error={{.State.Error}}' secure-proxy-manager-grafana 2>&1)"
  echo "     docker events (die, kill, oom, stop):"
  docker events --since "$TEST_START" --until "$(date +%s)" \
    --filter container=secure-proxy-manager-grafana \
    --filter event=die --filter event=kill --filter event=oom --filter event=stop \
    --format '       {{.Action}} exitCode={{index .Actor.Attributes "exitCode"}} signal={{index .Actor.Attributes "signal"}}' 2>&1 | head -40
  echo "     grafana log, shutdown and errors:"
  docker logs secure-proxy-manager-grafana 2>&1 \
    | grep -iE 'shutdown|shutting down|stopp|signal|terminat|level=(error|crit)|panic|fatal' | head -40 | sed 's/^/       /'
}
if [ "$graf_ready" -eq 1 ]; then
  ok "grafana is healthy on :3000"
else
  bad "grafana is healthy on :3000" "$(grafana_state) $(docker logs secure-proxy-manager-grafana 2>&1 | tail -10)"
  grafana_diagnosis
fi
echo "  grafana: $(grafana_state)"

TARGETS_JSON="$(docker exec secure-proxy-manager-prometheus wget -qO- http://127.0.0.1:9090/api/v1/targets 2>&1 || true)"
if printf '%s' "$TARGETS_JSON" | grep -q 'http://backend:5000/metrics'; then
  ok "prometheus target backend:5000/metrics is configured"
else
  bad "prometheus target backend:5000/metrics is configured" "$TARGETS_JSON"
fi
if printf '%s' "$TARGETS_JSON" | grep -q 'http://waf:8080/metrics'; then
  ok "prometheus target waf:8080/metrics is configured"
else
  bad "prometheus target waf:8080/metrics is configured" "$TARGETS_JSON"
fi

RULES_OUT="$(docker exec secure-proxy-manager-prometheus promtool check rules /etc/prometheus/rules/spm.rules.yml 2>&1)"
if [ $? -eq 0 ]; then
  ok "promtool check rules /etc/prometheus/rules/spm.rules.yml"
else
  bad "promtool check rules /etc/prometheus/rules/spm.rules.yml" "$RULES_OUT"
fi

DS_JSON=""
for _ in $(seq 1 20); do
  DS_JSON="$(docker exec secure-proxy-manager-grafana wget -qO- "http://admin:${ADMIN_PW}@127.0.0.1:3000/api/datasources" 2>&1 || true)"
  printf '%s' "$DS_JSON" | grep -q '"type":"prometheus"' && break
  sleep 1
done
if printf '%s' "$DS_JSON" | grep -q '"type":"prometheus"'; then
  ok "grafana provisioned the prometheus datasource"
else
  bad "grafana provisioned the prometheus datasource" "$DS_JSON"
fi

# The dashboard provider and its one dashboard: an error in the JSON or in
# the provider leaves Grafana healthy and the dashboard missing, so its uid is
# asked for, not the health endpoint.
DASH_JSON=""
for _ in $(seq 1 20); do
  DASH_JSON="$(docker exec secure-proxy-manager-grafana wget -qO- "http://admin:${ADMIN_PW}@127.0.0.1:3000/api/dashboards/uid/spm-cache" 2>&1 || true)"
  printf '%s' "$DASH_JSON" | grep -q '"title":"Proxy cache"' && break
  sleep 1
done
if printf '%s' "$DASH_JSON" | grep -q '"title":"Proxy cache"' && printf '%s' "$DASH_JSON" | grep -q '"provisioned":true'; then
  ok "grafana provisioned the Proxy cache dashboard (uid spm-cache)"
else
  bad "grafana provisioned the Proxy cache dashboard (uid spm-cache)" "$(printf '%s' "$DASH_JSON" | head -c 300) $(docker logs secure-proxy-manager-grafana 2>&1 | grep -i 'provision' | tail -5)"
fi

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

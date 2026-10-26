#!/usr/bin/env bash
# Verify that the observability profile in docker-compose.yml starts cleanly,
# Prometheus loads its configuration and sees the backend:5000 and waf:8080
# scrape targets, promtool validates the alert rules in /etc/prometheus/rules,
# and Grafana starts with the provisioned Prometheus datasource.
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
          memory: 256M
EOF

echo "── observability profile (prometheus + grafana) ──"
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

graf_ready=0
for _ in $(seq 1 40); do
  if docker exec secure-proxy-manager-grafana wget -qO- http://127.0.0.1:3000/api/health >/dev/null 2>&1; then
    graf_ready=1
    break
  fi
  sleep 1
done
if [ "$graf_ready" -eq 1 ]; then
  ok "grafana is healthy on :3000"
else
  bad "grafana is healthy on :3000" "$(docker logs secure-proxy-manager-grafana 2>&1 | tail -10)"
fi

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

DS_JSON="$(docker exec secure-proxy-manager-grafana wget -qO- "http://admin:${ADMIN_PW}@127.0.0.1:3000/api/datasources" 2>&1 || true)"
if printf '%s' "$DS_JSON" | grep -q '"type":"prometheus"'; then
  ok "grafana provisioned the prometheus datasource"
else
  bad "grafana provisioned the prometheus datasource" "$DS_JSON"
fi

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

#!/usr/bin/env bash
# CI end-to-end smoke test.
#
# Brings the full stack up with `docker compose` and checks the core path that
# the build-only CI never exercised — exactly the things that broke a fresh
# deploy of v3.4.6 and shipped green:
#   - all five services reach a healthy state (volume perms, dnsmasq dir,
#     backend boot, blacklist watchdog)
#   - the forward proxy can actually reach the internet (egress network)
#   - a blacklisted host is blocked (watchdog → Squid reconfigure)
#   - proxied traffic flows through to the dashboard (Squid log readability)
#   - administrative actions are recorded in the audit log
#
# Run from the repository root: `bash tests/ci-e2e.sh`.
set -uo pipefail

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }

AUTH='admin:CiE2ePass2026xyz'
API='http://127.0.0.1:5001'
PROXY='http://127.0.0.1:3128'
EXPECT_SERVICES=5 # web, backend, waf, dns, proxy (tailscale is profile-gated)

cleanup() {
  echo "── teardown ──"
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f .env
}
trap cleanup EXIT

dump_logs() {
  echo "──────── docker compose ps ────────"
  docker compose ps || true
  echo "──────── docker compose logs (tail) ────────"
  docker compose logs --no-color --tail 60 || true
}

echo "── writing CI .env ──"
SECRET="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cat > .env <<EOF
BASIC_AUTH_USERNAME=admin
BASIC_AUTH_PASSWORD=CiE2ePass2026xyz
SECRET_KEY=${SECRET}
CORS_ALLOWED_ORIGINS=http://127.0.0.1:8011
PROXY_HOST=proxy
PROXY_PORT=3128
PROXY_CONTAINER_NAME=secure-proxy-manager-proxy
PROXY_BIND_IP=0.0.0.0
EOF

# Ensure the bind-mounted runtime directories are writable by the containers.
# ./data and ./logs are created by compose (root-owned, fine), but ./config is
# checked out as the CI user, so a container whose effective UID differs (e.g.
# under userns-remap) cannot rewrite the blacklist files the proxy reads. This
# mirrors the prep an operator does before a real deploy.
echo "── preparing writable runtime dirs ──"
mkdir -p config config/dnsmasq.d data logs
chmod -R a+rwX config data logs 2>/dev/null || true

echo "── docker compose up -d --build ──"
if ! docker compose up -d --build; then
  echo "compose up failed"
  dump_logs
  exit 1
fi

echo "── waiting for ${EXPECT_SERVICES} services to become healthy (max 300s) ──"
deadline=$((SECONDS + 300))
while :; do
  healthy=$(docker compose ps --format '{{.Health}}' 2>/dev/null | grep -c '^healthy$' || true)
  echo "  healthy=${healthy}/${EXPECT_SERVICES}  (${SECONDS}s)"
  [ "${healthy}" -ge "${EXPECT_SERVICES}" ] && break
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    echo "TIMEOUT waiting for services to become healthy"
    dump_logs
    exit 1
  fi
  sleep 5
done
ok "all ${EXPECT_SERVICES} services healthy"

echo "── core smoke ──"

# Backend API reachable + authenticated.
code=$(curl -s -m 10 -u "$AUTH" -o /dev/null -w '%{http_code}' "$API/api/status")
[ "$code" = 200 ] && ok "backend /api/status (200)" || bad "backend /api/status (got $code)"

# Forward-proxy egress — HTTP and HTTPS. example.com is a stable target.
hc=$(curl -s -m 20 -x "$PROXY" -o /dev/null -w '%{http_code}' http://example.com/)
[ "$hc" = 200 ] && ok "proxy HTTP egress (200)" || bad "proxy HTTP egress (got $hc)"
sc=$(curl -s -m 20 -x "$PROXY" -o /dev/null -w '%{http_code}' https://example.com/)
[ "$sc" = 200 ] && ok "proxy HTTPS egress (200)" || bad "proxy HTTPS egress (got $sc)"

# Live blacklist reload. Block a normally-reachable domain and confirm it stops
# being reachable. We test a domain that DOES resolve (example.org) so the
# result distinguishes "blocked" from "never resolved": without the block it is
# 200, and a block makes it non-200 — whether that is 403 (Squid ACL, once the
# watchdog has synced the list) or a blackhole/connect failure (DNS layer).
base_code=$(curl -s -m 20 -x "$PROXY" -o /dev/null -w '%{http_code}' http://example.org/)
curl -s -m 10 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d '{"domain":"example.org"}' "$API/api/domain-blacklist" >/dev/null
sleep 10
bc=$(curl -s -m 20 -x "$PROXY" -o /dev/null -w '%{http_code}' http://example.org/)
if [ "$base_code" = 200 ] && [ "$bc" != 200 ]; then
  ok "blacklisted domain blocked (example.org: 200 -> $bc)"
else
  bad "blacklist did not block (baseline=$base_code, after=$bc)"
fi

# Log pipeline — generate some proxied traffic, then the dashboard must count it
# (this fails if the backend cannot read Squid's access.log).
for _ in 1 2 3 4 5; do curl -s -m 15 -x "$PROXY" -o /dev/null http://example.com/ || true; done
sleep 5
total=$(curl -s -m 10 -u "$AUTH" "$API/api/dashboard/summary" | grep -o '"total_requests":[0-9]*' | grep -o '[0-9]*' | head -1)
if [ "${total:-0}" -gt 0 ] 2>/dev/null; then
  ok "log pipeline feeds dashboard (total_requests=${total})"
else
  bad "log pipeline empty (total_requests=${total:-0})"
fi

# Audit log — the blacklist add above must be recorded.
if curl -s -m 10 -u "$AUTH" "$API/api/audit-log?limit=10" | grep -q 'add_domain_blacklist'; then
  ok "audit log records the action"
else
  bad "audit log missing the action"
fi

echo
echo "── result: ${PASS} passed, ${FAIL} failed ──"
if [ "${FAIL}" -gt 0 ]; then
  dump_logs
  exit 1
fi

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
ok()   { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; }

AUTH='admin:CiE2ePass2026xyz'
API='http://127.0.0.1:5001'
PROXY='http://127.0.0.1:3128'
EXPECT_SERVICES=5 # web, backend, waf, dns, proxy (tailscale is profile-gated)

# E2E_PROD=1 runs the production compose the way deploy/install.sh deploys it:
# deploy/docker-compose.prod.yml copied to compose.prod.yml at the repository
# root and selected with COMPOSE_FILE, on images already built and tagged with
# SPM_IMAGE_TAG (no --build, nothing pulled). Without it, the development
# compose is built from source as before.
if [ "${E2E_PROD:-0}" = 1 ]; then
  : "${SPM_IMAGE_TAG:?E2E_PROD=1 needs SPM_IMAGE_TAG naming the prebuilt images}"
  export SPM_IMAGE_TAG
  cp deploy/docker-compose.prod.yml compose.prod.yml
  export COMPOSE_FILE=compose.prod.yml
  UP_ARGS=(up -d --pull never)
  echo "── production compose, images tagged ${SPM_IMAGE_TAG} ──"
else
  UP_ARGS=(up -d --build)
fi

cleanup() {
  echo "── teardown ──"
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f .env
  [ "${E2E_PROD:-0}" = 1 ] && rm -f compose.prod.yml
  return 0
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

# Ensure the bind-mounted runtime directories are usable by the containers.
# ./config (blacklist files the proxy rewrites) and ./data (SQLite) need broad
# write because container effective UIDs differ from the CI checkout user.
#
# ./logs is DELIBERATELY NOT made world-writable: it is owned by a non-container
# UID (0755), exactly like a real host where the proxy creates the log files as
# its own user. This forces the dns/proxy containers to use their capabilities
# (CAP_DAC_OVERRIDE) + correct user to write there — making `chmod -R a+rwX logs`
# here is precisely what hid the 3.10.3–3.10.5 dns "cannot open log: Permission
# denied" regression from CI while real deploys broke. Keep it restrictive so
# this class of bug fails the build.
echo "── preparing writable runtime dirs ──"
mkdir -p config config/dnsmasq.d data logs
chmod -R a+rwX config data 2>/dev/null || true
sudo -n chown -R 65534:65534 logs 2>/dev/null || chown -R 65534:65534 logs 2>/dev/null || true
chmod 0755 logs 2>/dev/null || true

echo "── docker compose ${UP_ARGS[*]} ──"
if ! docker compose "${UP_ARGS[@]}"; then
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

# Live blacklist reload. Domains are blocked by the dnsmasq sinkhole (answer
# 0.0.0.0), not by a Squid ACL. This used to blacklist ci-block.invalid, which
# never resolves, and expect 403: the request failed with 503 whether or not
# the blacklist worked, so the check could never pass and proved nothing. It
# now blacklists a host that resolves. The control resolves it through dnsmasq
# rather than fetching it through the proxy: a fetch would put it in Squid's
# HTTP cache, and cached objects of a blacklisted domain are still served
# (TCP_MEM_HIT), which the sinkhole cannot stop because no DNS lookup happens.
BLOCK_HOST='example.net'
pre=$(docker compose exec -T dns nslookup "$BLOCK_HOST" 127.0.0.1 2>/dev/null | awk '/^Address/ && !/#53/ {print $NF}' | head -1)
case "$pre" in
  ""|0.0.0.0|::) bad "control: ${BLOCK_HOST} does not resolve before it is blacklisted (${pre:-none})" ;;
  *)             ok "control: ${BLOCK_HOST} resolves before it is blacklisted ($pre)" ;;
esac
curl -s -m 10 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"domain\":\"${BLOCK_HOST}\"}" "$API/api/domain-blacklist" >/dev/null
synced=0
for _ in $(seq 1 15); do # up to ~30s
  if docker exec secure-proxy-manager-proxy \
       grep -q "$BLOCK_HOST" /etc/squid/blacklists/domain/local.txt 2>/dev/null; then
    synced=1
    break
  fi
  sleep 2
done
[ "$synced" = 1 ] && ok "watchdog synced the blacklist into Squid" \
                  || bad "watchdog did not sync the blacklist within 30s"

# Whether Squid then actually denies the request (403) is a secondary,
# best-effort check: `squid -k reconfigure` reliably re-reads the dstdomain ACL
# file on a real host (opti10/Proxmox returns 403), but in the GitHub-runner
# container it does not pick up the change within the window, so this is a
# WARN, not a gate. The gating signal above is that the watchdog synced the
# file — that is the deploy-critical piece. (Follow-up: Squid reconfigure ACL
# reload behaviour under the CI runtime.)
sinkholed=0
for _ in $(seq 1 20); do # up to ~40s
  ans=$(docker compose exec -T dns nslookup "$BLOCK_HOST" 127.0.0.1 2>/dev/null | awk '/^Address/ && !/#53/ {print $NF}' | head -1)
  [ "$ans" = 0.0.0.0 ] && { sinkholed=1; break; }
  sleep 2
done
[ "$sinkholed" = 1 ] && ok "dnsmasq sinkholes the blacklisted host (0.0.0.0)" \
                     || bad "dnsmasq does not sinkhole ${BLOCK_HOST} (answer: ${ans:-none})"
bc=$(curl -s -m 20 -x "$PROXY" -o /dev/null -w '%{http_code}' "http://${BLOCK_HOST}/")
[ "$bc" != 200 ] && ok "blacklisted host no longer served through the proxy (got $bc)" \
                 || bad "blacklisted host still served through the proxy (200)"

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

# ── Egress default-deny destination allowlist ────────────────────────────────
# Allowlist example.com + enable default-deny via the API (exercises the new Go
# export + toggle), reload-config to restart the proxy so startup.sh injects the
# rule, then assert the allowlisted host is reachable and another is denied.
# Runs last: default-deny changes proxy behaviour for everything after it.
echo "── egress allowlist (default-deny) ──"
curl -s -m 10 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d '{"entry":"example.com","description":"e2e allow"}' "$API/api/egress-allowlist" >/dev/null
curl -s -m 10 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d '{"egress_default_deny":"true"}' "$API/api/settings" >/dev/null
curl -s -m 30 -u "$AUTH" -X POST "$API/api/maintenance/reload-config" >/dev/null

# reload-config restarts the proxy. Poll a real proxied request to the
# allowlisted host: a 200 means the proxy is back up AND enforcing (squidclient
# mgr:info is an unreliable readiness probe right after a restart).
ac=000
for _ in $(seq 1 60); do
  ac=$(docker exec secure-proxy-manager-proxy \
        curl -s -m 10 -x http://127.0.0.1:3128 -o /dev/null -w '%{http_code}' http://example.com/ 2>/dev/null || echo 000)
  case "$ac" in 200|301|302) break ;; esac
  sleep 2
done
case "$ac" in
  200|301|302) ok "proxy recovered; allowlisted destination reachable (example.com → $ac)" ;;
  *)           bad "allowlisted destination unreachable after default-deny (example.com → $ac)" ;;
esac

# reload-config is now asynchronous: the backend writes a .reload-squid trigger
# and the in-container watchdog regenerates the config + reconfigures squid (the
# docker-decouple replaced the old "restart the proxy container" path). The
# "example.com → 200" probe above does not gate on that regen (example.com is
# reachable regardless), so poll for the injected rule instead of grepping once.
rule_found=0
for _ in $(seq 1 20); do
  if docker exec secure-proxy-manager-proxy \
       grep -q 'http_access deny localnet !egress_dst_allow' /etc/squid/squid.conf 2>/dev/null; then
    rule_found=1; break
  fi
  sleep 2
done
[ "$rule_found" = 1 ] && ok "default-deny rule injected into squid.conf" \
                      || bad "default-deny rule missing from squid.conf"

# A non-allowlisted destination must be denied. The probe used to run inside
# the proxy container against 127.0.0.1, i.e. from localhost, which the
# default-deny exempts by design, so it got 200 and could only WARN. It now
# connects to the container's own non-loopback address, a localnet source,
# like a LAN client. Retry to absorb the reconfigure window.
lan_probe() { # url -> status, from a localnet source
  docker exec secure-proxy-manager-proxy sh -c \
    'ip=$(hostname -i | awk "{print \$1}"); curl -s -m 10 -x "http://$ip:3128" -o /dev/null -w "%{http_code}" "$1"' _ "$1" 2>/dev/null || echo 000
}
dc=000
for _ in $(seq 1 15); do
  dc=$(lan_probe http://example.org/)
  [ "$dc" = 403 ] && break
  sleep 2
done
[ "$dc" = 403 ] && ok "non-allowlisted destination denied to a LAN client (example.org → 403)" \
                || bad "non-allowlisted destination not denied to a LAN client (example.org → $dc)"
ac_lan=$(lan_probe http://example.com/)
case "$ac_lan" in
  200|301|302) ok "allowlisted destination reachable for a LAN client (example.com → $ac_lan)" ;;
  *)           bad "allowlisted destination unreachable for a LAN client (example.com → $ac_lan)" ;;
esac

echo
echo "── result: ${PASS} passed, ${FAIL} failed ──"
if [ "${FAIL}" -gt 0 ]; then
  dump_logs
  exit 1
fi

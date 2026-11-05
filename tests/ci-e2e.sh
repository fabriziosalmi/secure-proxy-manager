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

# The SSL-bump CA key and the certificate database are in the proxy's own
# /ssl mount. /config is shared, and the backend (root, proxy group) and dns
# (root, CAP_DAC_OVERRIDE) read whatever sits there.
docker compose exec -T proxy test -f /ssl/ssl_key.pem \
  && ok "the CA key is in the proxy's /ssl" || bad "the CA key is in the proxy's /ssl"
for svc in backend dns waf web; do
  seen=$(docker compose exec -T "$svc" sh -c 'for f in /config/ssl_key.pem /config/ssl_db /ssl; do [ -e "$f" ] && echo "$f"; done' 2>&1)
  [ -z "$seen" ] && ok "$svc cannot reach the CA key or the certificate database" \
    || bad "$svc reaches the CA material: $seen"
done
grep -q '"key_isolated":true' config/ssl_ca_status.json 2>/dev/null \
  && ok "the proxy reports the CA key isolated" || bad "the proxy reports the CA key isolated"

# What a device fetches through nginx, with no login: the PAC file, which no
# longer sends a browser around a proxy that is down; the CA certificate,
# byte for byte the proxy's; its fingerprint in /api/client-setup; /setup.
pac=$(curl -s -m 10 http://127.0.0.1:8011/wpad.dat | grep 'return "PROXY')
[ "$pac" = '  return "PROXY 127.0.0.1:3128";' ] && ok "the PAC file has no DIRECT fallback" \
  || bad "the PAC file has no DIRECT fallback (got: $pac)"
served=$(curl -s -m 10 http://127.0.0.1:8011/ca.crt | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
proxy_fp=$(openssl x509 -in config/ssl_cert.pem -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
[ -n "$proxy_fp" ] && [ "$served" = "$proxy_fp" ] && ok "/ca.crt on port 80, without a login, is the proxy's CA" \
  || bad "/ca.crt is the proxy's CA (served: $served, proxy: $proxy_fp)"
described=$(curl -sk -m 10 https://127.0.0.1:8443/api/client-setup | python3 -c 'import json,sys; print((json.load(sys.stdin)["data"]["ca"] or {}).get("sha256",""))' 2>/dev/null)
[ -n "$proxy_fp" ] && [ "$described" = "$proxy_fp" ] && ok "/api/client-setup, without a login, gives the CA fingerprint" \
  || bad "/api/client-setup gives the CA fingerprint (got: $described)"
code=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/setup)
[ "$code" = 200 ] && ok "/setup is served without a login (200)" || bad "/setup is served without a login (got $code)"

# Forward-proxy egress — HTTP and HTTPS. example.com is a stable target.
hc=$(curl -s -m 20 -x "$PROXY" -o /dev/null -w '%{http_code}' http://example.com/)
[ "$hc" = 200 ] && ok "proxy HTTP egress (200)" || bad "proxy HTTP egress (got $hc)"
sc=$(curl -s -m 20 -x "$PROXY" -o /dev/null -w '%{http_code}' https://example.com/)
[ "$sc" = 200 ] && ok "proxy HTTPS egress (200)" || bad "proxy HTTPS egress (got $sc)"

# Client groups, end to end: a pasted list set to groups only leaves the
# global lists and the DNS sinkhole; a group whose member is this client gets
# its rules in Squid (backend export, verified sync, regeneration) and blocks
# the list's domain for it; deleting the group takes the rules out again.
GROUP_HOST='e2e-group.example'
curl -s -m 10 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"type\":\"domain\",\"content\":\"${GROUP_HOST}\"}" "$API/api/blacklists/import" >/dev/null
gsrc=$(curl -s -m 10 -u "$AUTH" "$API/api/domain-blacklist/sources" | python3 -c '
import json, sys
rows = [s for s in json.load(sys.stdin)["data"] if s.get("kind") == "paste" and s.get("id")]
print(max(s["id"] for s in rows) if rows else "")' 2>/dev/null)
curl -s -m 10 -u "$AUTH" -X PUT -H 'Content-Type: application/json' -d '{"scope":"groups"}' \
  "$API/api/domain-blacklist/sources/${gsrc}/scope" >/dev/null
curl -s -m 20 -x "$PROXY" -o /dev/null http://example.com/
me=$(docker compose exec -T proxy tail -n 1 /var/log/squid/access.log 2>/dev/null | awk '{print $3}')
gid=$(curl -s -m 10 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"e2e\",\"members\":[\"${me}\"],\"lists\":[${gsrc:-0}]}" "$API/api/client-groups" \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["data"]["id"])' 2>/dev/null)
applied=0
for _ in $(seq 1 20); do # up to ~40s
  if docker compose exec -T proxy grep -qxF "http_access deny spm_g${gid} spm_s${gsrc}_domain spm_r_group_list" /etc/squid/squid.conf 2>/dev/null \
     && docker compose exec -T proxy grep -qxF "$GROUP_HOST" "/etc/squid/groups/s${gsrc}_domain.txt" 2>/dev/null; then
    applied=1; break
  fi
  sleep 2
done
[ -n "$gid" ] && [ -n "$me" ] && [ "$applied" = 1 ] \
  && ok "a client group reaches Squid: its list copied verified, its rule generated (member ${me})" \
  || bad "a client group did not reach Squid within 40s (group ${gid:-none}, source ${gsrc:-none}, member ${me:-none})"
docker compose exec -T proxy grep -qxF "$GROUP_HOST" /etc/squid/blacklists/domain/local.txt 2>/dev/null \
  && bad "a groups-only list reached the global domain list" || ok "a groups-only list stays out of the global domain list"
grep -q " ${GROUP_HOST}$" config/dnsmasq.d/blocklist.hosts 2>/dev/null \
  && bad "a groups-only list reached the DNS sinkhole" || ok "a groups-only list stays out of the DNS sinkhole"
gc=$(curl -s -m 20 -x "$PROXY" -o /dev/null -w '%{http_code}' "http://${GROUP_HOST}/")
greason=$(docker compose exec -T proxy tail -n 1 /var/log/squid/access.log 2>/dev/null | awk '{print $12}')
[ "$gc" = 403 ] && [ "$greason" = group_list ] && ok "the group's member is denied the list's domain (403 group_list)" \
  || bad "the group's member got ${gc} (${greason:-no reason}) for ${GROUP_HOST}, want 403 group_list"
curl -s -m 10 -u "$AUTH" -X DELETE "$API/api/client-groups/${gid:-0}" >/dev/null
gone=0
for _ in $(seq 1 20); do
  docker compose exec -T proxy grep -q "spm_g${gid} " /etc/squid/squid.conf 2>/dev/null || { gone=1; break; }
  sleep 2
done
[ "$gone" = 1 ] && ok "deleting the group takes its rules out of Squid" || bad "the deleted group's rules are still in squid.conf after 40s"

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
# file on a real host (a real deployment returns 403), but in the GitHub-runner
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
# (this fails if the backend cannot read Squid's access.log). These requests
# come from the Docker host, through the bridge gateway, which the backend
# counts as the stack's own traffic once its classifier knows the stack's
# subnets (backend-go/internal/sources, refreshed 30 s after start): counted
# as clients before that, as internal after. The check used to read
# total_requests only, the clients, and passed only when it ran within those
# 30 s; both counts together are what the backend read.
for _ in 1 2 3 4 5; do curl -s -m 15 -x "$PROXY" -o /dev/null http://example.com/ || true; done
sleep 5
summary=$(curl -s -m 10 -u "$AUTH" "$API/api/dashboard/summary")
total=$(printf '%s' "$summary" | python3 -c 'import json, sys; d = json.load(sys.stdin)["data"]; print(d["total_requests"] + d["last_24h_internal_requests"])' 2>/dev/null)
if [ "${total:-0}" -ge 5 ] 2>/dev/null; then
  ok "log pipeline feeds dashboard (${total} requests, clients and the stack's own)"
else
  bad "log pipeline empty (${total:-0} requests, clients and the stack's own; want at least the 5 just made)"
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
echo "── service token (INTERNAL_ALERT_TOKEN unset in this .env) ──"
# The backend generates the token into the volume it shares with the WAF, so
# with the variable empty the backend still reaches the WAF management API and
# the WAF still has a credential for its alerts. Without it the first answered
# 403 (proxied as 502) and the second logged "no backend alert credential".
wc=$(curl -s -m 10 -u "$AUTH" -o /dev/null -w '%{http_code}' "$API/api/waf/categories")
[ "$wc" = "200" ] && ok "backend reaches the WAF management API with the generated token (200)" \
                   || bad "backend reaches the WAF management API with the generated token (got $wc)"
curl -s -m 20 -x "$PROXY" -o /dev/null "http://example.com/?q=1%27%20UNION%20SELECT%20password%20FROM%20users--" || true
sleep 3
if docker compose logs waf 2>&1 | grep -q 'no backend alert credential'; then
  bad "the WAF has a credential for its alerts (it logged: no backend alert credential)"
else
  ok "the WAF has a credential for its alerts"
fi

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

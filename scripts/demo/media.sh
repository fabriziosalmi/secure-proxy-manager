#!/usr/bin/env bash
# Regenerates the README screenshot and the docs tour video from a fresh,
# local stack with synthetic traffic, so no real client, address or browsing
# history ever reaches a published image.
#
#   bash scripts/demo/media.sh            # screenshot + video
#
# What it does:
#   1. writes a throwaway .env (demo credentials, local only) and starts the
#      stack from this checkout;
#   2. attaches the proxy to a separate network, 192.168.88.0/24, where three
#      client containers browse through it. The stack's own networks count as
#      internal and the dashboard hides them; these clients count as devices;
#   3. adds a few blacklist entries and sends requests the WAF blocks, so the
#      pages have blocks with their rules;
#   4. runs scripts/demo/capture.mjs in the Playwright image on the stack's
#      network: docs/screenshots/dashboard.png and, through ffmpeg,
#      docs/public/demo/tour.mp4 with its poster frame tour-poster.jpg;
#   5. tears everything down and restores config/, data/ and logs/.
#
# Needs docker and ffmpeg. Run it in a worktree: step 5 deletes the
# gitignored runtime state under config/, data/ and logs/.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

USER_NAME="admin"
PASS="DemoOnly$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
LAN=spmdemo-lan
PROXY_LAN_IP=192.168.88.2
PROXY_CTR=secure-proxy-manager-proxy
OUT_PNG=docs/screenshots/dashboard.png
OUT_MP4=docs/public/demo/tour.mp4
OUT_POSTER=docs/public/demo/tour-poster.jpg
WORK="$(mktemp -d)"
PW_IMAGE=spm-demo-pw

if docker ps --format '{{.Names}}' | grep -qx "$PROXY_CTR"; then
  echo "another stack already runs $PROXY_CTR; stop it first" >&2
  exit 1
fi
command -v ffmpeg >/dev/null || { echo "ffmpeg is required" >&2; exit 1; }

reset_state() {
  git checkout -q -- config logs
  git clean -fdxq config data logs
  git checkout -q -- config logs
}

cleanup() {
  echo "── teardown ──"
  docker rm -f spmdemo-laptop spmdemo-phone spmdemo-tv >/dev/null 2>&1 || true
  docker network disconnect "$LAN" "$PROXY_CTR" >/dev/null 2>&1 || true
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm "$LAN" >/dev/null 2>&1 || true
  rm -f .env
  reset_state
  # DEMO_DEBUG_DIR keeps what the capture wrote (failed.png on a failure).
  if [ -n "${DEMO_DEBUG_DIR:-}" ]; then mkdir -p "$DEMO_DEBUG_DIR" && cp -R "$WORK"/. "$DEMO_DEBUG_DIR"/ 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

reset_state
cat > .env <<EOF
BASIC_AUTH_USERNAME=${USER_NAME}
BASIC_AUTH_PASSWORD=${PASS}
SECRET_KEY=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
CORS_ALLOWED_ORIGINS=http://127.0.0.1:8011
PROXY_HOST=proxy
PROXY_PORT=3128
PROXY_CONTAINER_NAME=${PROXY_CTR}
PROXY_BIND_IP=127.0.0.1
INTERNAL_ALERT_TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
EOF
mkdir -p config config/dnsmasq.d data logs
chmod -R a+rwX config data 2>/dev/null || true

echo "── starting the stack ──"
docker compose up -d --build >/dev/null
for _ in $(seq 1 60); do
  [ "$(docker compose ps --format '{{.Health}}' | grep -c '^healthy$')" -ge 5 ] && break
  sleep 5
done
[ "$(docker compose ps --format '{{.Health}}' | grep -c '^healthy$')" -ge 5 ] || { echo "stack not healthy" >&2; docker compose ps; exit 1; }

API=http://127.0.0.1:5001/api
AUTH="${USER_NAME}:${PASS}"
api() { # method path json: fails loudly, a silent seed makes a misleading image
  local code
  code=$(curl -s -m 20 -o /dev/null -w '%{http_code}' -u "$AUTH" -H 'Content-Type: application/json' -X "$1" -d "$3" "$API/$2")
  [ "$code" = 200 ] || { echo "seed failed: $1 $2 -> $code" >&2; exit 1; }
}

echo "── settings and blacklist entries ──"
# A fresh install opens on the setup wizard; the demo shows the dashboard.
api POST settings '{"wizard_completed":"true"}'
for d in doubleclick.net googlesyndication.com adservice.google.com tracking.example.net; do
  api POST domain-blacklist "{\"domain\":\"$d\",\"description\":\"Ads and tracking (demo)\"}"
done
api POST ip-blacklist '{"ip":"198.51.100.0/24","description":"Known scanner range (demo)"}'
sleep 8 # the watchdog syncs the lists into Squid and the DNS sinkhole

echo "── demo LAN and clients ──"
docker network create --subnet 192.168.88.0/24 "$LAN" >/dev/null
docker network connect --ip "$PROXY_LAN_IP" "$LAN" "$PROXY_CTR"
client() { # name ip script
  docker run -d --name "spmdemo-$1" --network "$LAN" --ip "$2" --memory 64m \
    --entrypoint /bin/sh curlimages/curl:8.11.1 -c "$3" >/dev/null
}
P="http://${PROXY_LAN_IP}:3128"
BROWSE="for i in 1 2 3 4 5 6; do
  for u in https://www.wikipedia.org https://github.com https://www.debian.org http://example.com http://neverssl.com https://www.mozilla.org https://doubleclick.net https://googlesyndication.com; do
    curl -s -o /dev/null -m 10 -x $P \"\$u\"; sleep 1
  done
done"
ATTACK="for i in 1 2 3; do
  curl -s -o /dev/null -m 10 -x $P \"http://example.com/search?q=1%27%20OR%20%271%27%3D%271\"
  curl -s -o /dev/null -m 10 -x $P \"http://example.com/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E\"
  curl -s -o /dev/null -m 10 --path-as-is -x $P \"http://example.com/../../etc/passwd\"
  curl -s -o /dev/null -m 10 -x $P http://198.51.100.7/
  sleep 3
done"
client laptop 192.168.88.10 "$BROWSE"
client phone  192.168.88.11 "$BROWSE"
client tv     192.168.88.12 "$ATTACK; $BROWSE"
echo "  waiting for the clients to finish (about 90 s)"
for _ in $(seq 1 60); do
  [ -z "$(docker ps -q --filter name=spmdemo-)" ] && break
  sleep 5
done
sleep 10 # the log tailer reads the last lines

echo "── capture ──"
docker build -q -t "$PW_IMAGE" tests/e2e >/dev/null
NET="$(docker inspect "$(docker compose ps -q web)" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' | tr ' ' '\n' | grep '_frontend$')"
# The dashboard names the proxy by the host the browser used: give it the
# name a home network would, not the container's.
WEB_IP="$(docker inspect "$(docker compose ps -q web)" --format "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}")"
docker run --rm --network "$NET" --memory 2g --add-host "spm.home.arpa:$WEB_IP" \
  -e DEMO_USER="$USER_NAME" -e DEMO_PASS="$PASS" \
  -v "$PWD/scripts/demo/capture.mjs:/tests/capture.mjs:ro" -v "$WORK:/out" \
  "$PW_IMAGE" node capture.mjs https://spm.home.arpa:8443 /out
cp "$WORK/dashboard.png" "$OUT_PNG"
ffmpeg -loglevel error -y -i "$WORK/tour.webm" -c:v libx264 -preset slow -crf 30 \
  -pix_fmt yuv420p -movflags +faststart -an "$OUT_MP4"
# The frame the docs page shows before the video plays.
ffmpeg -loglevel error -y -ss 2 -i "$OUT_MP4" -frames:v 1 -q:v 4 "$OUT_POSTER"
ls -l "$OUT_PNG" "$OUT_MP4" "$OUT_POSTER"

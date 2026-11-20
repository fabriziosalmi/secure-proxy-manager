#!/usr/bin/env bash
# The spm-mcp image (mcp/Dockerfile) builds and runs: the Python its FROM lines
# name, every locked dependency installed and consistent (pip check), the
# server as a non-root user, and the stdio entrypoint answering an MCP
# initialize. No workflow built this image before, so a bump of its Python
# base went green without anyone building it.
#
# It needs no backend: the redirect check points SPM_URL at a local stub that
# answers 301, and the startup error must name where it points. That check
# uses --network host, so it runs on a Linux Docker host.
#
# Usage: tests/shell/mcp_image_test.sh   (MCP_IMAGE=name reuses a built image)
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ✗ %s\n     %s\n" "$1" "${2:-}"; }
T=$(mktemp -d); STUB_PID=""
cleanup() { [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
finish() { printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"; [ "$FAIL" -eq 0 ]; }

IMAGE="${MCP_IMAGE:-spm-mcp:test}"
if [ -z "${MCP_IMAGE:-}" ]; then
  if docker build -q -t "$IMAGE" mcp > "$T/build" 2>&1; then
    ok "mcp/Dockerfile builds"
  else
    bad "mcp/Dockerfile builds" "$(tail -25 "$T/build")"; finish; exit 1
  fi
fi
run() { docker run --rm --entrypoint "$1" "$IMAGE" "${@:2}"; }

want=$(sed -nE 's/^FROM python:([0-9]+\.[0-9]+)-slim.*/\1/p' mcp/Dockerfile | sort -u)
got=$(run python -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>&1)
[ -n "$want" ] && [ "$got" = "$want" ] \
  && ok "runs Python $got, the version its FROM lines name" \
  || bad "Python version" "FROM says '$want', the image runs '$got'"

uid=$(run id -u 2>&1)
[ "$uid" = 1000 ] && ok "runs as the non-root user (uid 1000)" || bad "non-root user" "id -u: $uid"

out=$(run python -m pip check 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "every installed package has what it requires (pip check)" || bad "pip check" "$out"

pv=$(sed -nE 's/^version = "([^"]+)"/\1/p' mcp/pyproject.toml)
out=$(run python -c 'import importlib.metadata as m, spm_mcp, mcp, httpx, pydantic_core, rpds, cryptography, cffi; print(m.version("spm-mcp"))' 2>&1)
[ -n "$pv" ] && [ "$out" = "$pv" ] \
  && ok "spm-mcp $pv and its compiled dependencies import" \
  || bad "imports" "got '$out', pyproject says '$pv'"

# The entrypoint answers an MCP initialize over stdio. stdin stays open for a
# few seconds: closing it at once can end the server before it answers.
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ci","version":"0"}}}'
out=$({ printf '%s\n' "$init"; sleep 10; } | timeout 60 docker run -i --rm \
  -e SPM_URL=http://127.0.0.1:9 -e SPM_TOKEN=spm_ci_token "$IMAGE" 2>"$T/err")
printf '%s' "$out" | grep -q '"id":1' && printf '%s' "$out" | grep -q '"serverInfo"' \
  && printf '%s' "$out" | grep -q '"secure-proxy-manager"' \
  && ok "the spm-mcp entrypoint answers an MCP initialize over stdio" \
  || bad "initialize over stdio" "out=$out err=$(tail -5 "$T/err")"

# A server that redirects: the startup error names where it points and says
# what to set, from inside the image.
cat > "$T/stub.py" <<'EOF'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header("Location", "https://127.0.0.1:8443" + self.path)
        self.end_headers()
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 -I "$T/stub.py" "$port" & STUB_PID=$!
for _ in $(seq 1 50); do
  curl -s -o /dev/null "http://127.0.0.1:$port/" && break
  sleep 0.1
done
out=$(docker run --rm --network host -e SPM_URL="http://127.0.0.1:$port" -e SPM_TOKEN=spm_ci_token \
  --entrypoint python "$IMAGE" -c '
from spm_mcp.server import SPMServer
try:
    SPMServer().tools()
    print("no error")
except RuntimeError as e:
    print(e)' 2>&1)
printf '%s' "$out" | grep -qF 'redirected to https://127.0.0.1:8443/api/openapi.json (301)' \
  && printf '%s' "$out" | grep -qF 'set SPM_URL' \
  && ok "behind a redirect, the startup error names its target and says to set SPM_URL" \
  || bad "redirect at startup" "$out"

finish

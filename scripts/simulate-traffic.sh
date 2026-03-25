#!/bin/bash
# Simulate proxy traffic for testing the Secure Proxy Manager
# Usage: ./simulate-traffic.sh [PROXY_HOST] [PROXY_PORT] [ROUNDS]
# Example: ./simulate-traffic.sh 192.168.1.100 3128 3

PROXY_HOST="${1:-localhost}"
PROXY_PORT="${2:-3128}"
ROUNDS="${3:-2}"
PROXY="http://${PROXY_HOST}:${PROXY_PORT}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# Domains to hit (expected: allowed)
ALLOWED_DOMAINS=(
  "http://example.com"
  "http://httpbin.org/get"
  "http://ifconfig.me"
  "http://neverssl.com"
  "http://detectportal.firefox.com/success.txt"
  "http://www.google.com"
  "http://github.com"
  "http://cloudflare.com"
  "http://ubuntu.com"
  "http://debian.org"
)

# Domains expected to be blocked (if added to blacklist beforehand)
# These will just generate DENIED entries if blacklisted
POTENTIALLY_BLOCKED=(
  "http://ads.example.com"
  "http://tracker.example.net"
  "http://malware-test.example.org"
)

# Direct IPs (expected: blocked by Squid direct-IP rule)
DIRECT_IPS=(
  "http://1.1.1.1"
  "http://8.8.8.8"
  "http://93.184.216.34"
)

curl_req() {
  local url="$1"
  local label="$2"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    --proxy "$PROXY" \
    --max-time 8 \
    --connect-timeout 5 \
    "$url" 2>/dev/null)
  local exit_code=$?

  if [ $exit_code -ne 0 ] || [ "$status" = "000" ]; then
    echo -e "  ${RED}FAIL${NC}  $label (curl error / timeout)"
  elif [ "$status" = "403" ] || [ "$status" = "407" ]; then
    echo -e "  ${YELLOW}DENY${NC}  $label (HTTP $status)"
  elif [ "$status" -ge 200 ] && [ "$status" -lt 400 ]; then
    echo -e "  ${GREEN} OK ${NC}  $label (HTTP $status)"
  else
    echo -e "  ${CYAN}MISC${NC}  $label (HTTP $status)"
  fi
}

echo "=========================================="
echo " Secure Proxy Manager — Traffic Simulator"
echo "=========================================="
echo " Proxy : $PROXY"
echo " Rounds: $ROUNDS"
echo "=========================================="

for round in $(seq 1 "$ROUNDS"); do
  echo ""
  echo -e "${CYAN}--- Round $round / $ROUNDS ---${NC}"

  echo ""
  echo "[ Allowed domains ]"
  for url in "${ALLOWED_DOMAINS[@]}"; do
    curl_req "$url" "$url"
    sleep 0.3
  done

  echo ""
  echo "[ Direct IP access (should be blocked) ]"
  for url in "${DIRECT_IPS[@]}"; do
    curl_req "$url" "$url"
    sleep 0.3
  done

  echo ""
  echo "[ Potentially blocked domains ]"
  for url in "${POTENTIALLY_BLOCKED[@]}"; do
    curl_req "$url" "$url"
    sleep 0.3
  done

  [ "$round" -lt "$ROUNDS" ] && sleep 1
done

echo ""
echo "=========================================="
echo " Done. Check the Logs page in the UI."
echo "=========================================="

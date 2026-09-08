#!/usr/bin/env bash
# SECURE-TEST-01. generate_squid_conf.sh is 633 lines and the sole producer of
# squid.conf: it injects the IP and domain blocking ACLs, the egress
# default-deny with its fail-closed fallback, the SSL-bump block and the ICAP
# wiring. Nothing verified any of it — the only exercise was indirect, through
# a compose-up e2e whose most meaningful assertion is a warning rather than a
# gate. This runs the real generator against fixture /config states inside the
# real proxy image and asserts on the squid.conf it produces, including that
# squid itself will parse it.
#
# Usage: tests/shell/generate_squid_conf_test.sh [image]
set -uo pipefail

IMAGE="${1:-spm-proxy-test}"
PASS=0; FAIL=0
G="\033[0;32m"; R="\033[0;31m"; N="\033[0m"
ok()   { PASS=$((PASS+1)); printf "  ${G}✓${N} %s\n" "$1"; }
bad()  { FAIL=$((FAIL+1)); printf "  ${R}✗${N} %s\n     %s\n" "$1" "${2:-}"; }

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "building $IMAGE from proxy/ ..."
  docker build -q -t "$IMAGE" proxy/ >/dev/null || { echo "build failed"; exit 1; }
fi

# Run the generator inside the image against a fixture /config, then print the
# resulting squid.conf. Extra shell can be supplied to seed the fixture.
generate() {
  local seed="$1"
  docker run --rm --entrypoint /bin/bash "$IMAGE" -c "
    set -e
    mkdir -p /config /etc/squid
    $seed
    /usr/local/bin/generate_squid_conf.sh >/tmp/gen.log 2>&1 || { echo '__GENERATOR_FAILED__'; cat /tmp/gen.log; exit 0; }
    cat /etc/squid/squid.conf
  " 2>/dev/null
}

# Does squid itself accept the config the generator produced?
parses() {
  local seed="$1"
  docker run --rm --entrypoint /bin/bash "$IMAGE" -c "
    set -e
    mkdir -p /config /etc/squid
    $seed
    /usr/local/bin/generate_squid_conf.sh >/dev/null 2>&1 || exit 1
    /usr/sbin/squid -k parse >/tmp/parse.log 2>&1 || { cat /tmp/parse.log; exit 1; }
  " >/dev/null 2>&1
}

echo "── baseline (no toggles) ──"
conf="$(generate 'true')"
case "$conf" in *__GENERATOR_FAILED__*) bad "generator runs" "$conf";; *) ok "generator runs";; esac
grep -q 'http_port' <<<"$conf"        && ok "http_port present"        || bad "http_port present"
grep -q 'acl localnet src 10.0.0.0/8' <<<"$conf" && ok "localnet ACL present" || bad "localnet ACL present"
grep -q 'http_access deny all' <<<"$conf" && ok "terminating deny present"  || bad "terminating deny present"
grep -q 'icap_service service_req' <<<"$conf" && ok "ICAP REQMOD wired"     || bad "ICAP REQMOD wired"
grep -q 'bypass=0' <<<"$conf"         && ok "REQMOD fails closed (bypass=0)" || bad "REQMOD fails closed (bypass=0)"
parses 'true' && ok "squid -k parse accepts it" || bad "squid -k parse accepts it"

echo "── egress default-deny ON ──"
conf="$(generate 'touch /config/egress_default_deny; : > /config/dst_allow_ip.txt; : > /config/dst_allow_domain.txt')"
grep -q 'http_access deny localnet !egress_dst_allow' <<<"$conf" \
  && ok "deny rule injected" || bad "deny rule injected" "the egress fail-closed rule is missing"
n=$(grep -c 'http_access deny localnet !egress_dst_allow' <<<"$conf")
[ "$n" = 1 ] && ok "deny rule injected exactly once" || bad "deny rule injected exactly once" "found $n"
parses 'touch /config/egress_default_deny; : > /config/dst_allow_ip.txt; : > /config/dst_allow_domain.txt' \
  && ok "parses with egress deny on" || bad "parses with egress deny on"

echo "── SSL bump ON ──"
conf="$(generate 'touch /config/ssl_bump_enabled')"
grep -q 'ssl_bump' <<<"$conf" && ok "ssl_bump directives injected" || bad "ssl_bump directives injected"
n=$(grep -c '^ssl_bump bump all' <<<"$conf")
[ "$n" -le 1 ] && ok "ssl_bump block not duplicated" || bad "ssl_bump block not duplicated" "found $n"

echo "── GUI whitelist set ──"
conf="$(generate 'export GUI_IP_WHITELIST=192.168.1.5')"
n=$(grep -c 'acl gui_override dst' <<<"$conf")
[ "$n" -le 1 ] && ok "gui_override ACL defined at most once" \
                || bad "gui_override ACL defined at most once" "found $n — duplicate ACL definition"

echo "── offline mode ON ──"
conf="$(generate 'touch /config/offline_mode_enabled')"
n=$(grep -c '^offline_mode on' <<<"$conf")
[ "$n" -le 1 ] && ok "offline_mode not appended twice" || bad "offline_mode not appended twice" "found $n"

echo "── injection: a hostile /config must not become squid config ──"
conf="$(generate 'printf "SQUID_PORT=3128\nEVIL=\$(touch /tmp/pwned)\n" > /config/squid_settings.env')"
grep -q 'pwned' <<<"$conf" && bad "safe_source rejects command substitution" || ok "safe_source rejects command substitution"

echo "── boot path: startup.sh sources the generator and must survive it ──"
# SECURE-ARCH-01. startup.sh used to carry a byte-identical copy of the
# generator (407 of its 490 lines) and was deduplicated down to the boot-only
# steps, leaving the generator as the single producer of squid.conf. That makes
# the source at the top of startup.sh load-bearing in a way it was not before:
# a bare `exit` in the generator now terminates the whole entrypoint. It did,
# once — the container reached neither the swap init nor supervisord, and came
# up with no squid and no watchdog while every earlier assertion here still
# passed, because they all invoke the generator as a subprocess. These run the
# real entrypoint instead.
boot="$(docker run --rm --cap-add NET_ADMIN --entrypoint /bin/bash "$IMAGE" -c '
  sed -i "s|^exec /usr/bin/supervisord.*|echo __REACHED_SUPERVISORD__|" /startup.sh
  /startup.sh 2>&1
  echo "__STARTUP_RC__=$?"
' 2>/dev/null)"
grep -q '__REACHED_SUPERVISORD__' <<<"$boot" \
  && ok "startup.sh runs to the supervisord hand-off" \
  || bad "startup.sh runs to the supervisord hand-off" "the entrypoint stopped early — sourcing the generator must return, not exit"
grep -q '__STARTUP_RC__=0' <<<"$boot" && ok "startup.sh exits 0" || bad "startup.sh exits 0"
grep -q 'Configuration syntax is valid' <<<"$boot" \
  && ok "boot validates its own squid.conf" || bad "boot validates its own squid.conf"

# Executed as a subprocess (the watchdog's contract) it must still exit 0, and
# sourced (startup.sh's contract) it must hand control back.
docker run --rm --entrypoint /bin/bash "$IMAGE" -c '
  mkdir -p /config /etc/squid
  /usr/local/bin/generate_squid_conf.sh >/dev/null 2>&1' >/dev/null 2>&1 \
  && ok "generator exits 0 when executed" || bad "generator exits 0 when executed"
srcd="$(docker run --rm --entrypoint /bin/bash "$IMAGE" -c '
  mkdir -p /config /etc/squid
  . /usr/local/bin/generate_squid_conf.sh >/dev/null 2>&1
  echo "__AFTER_SOURCE__=$?"' 2>/dev/null)"
grep -q '__AFTER_SOURCE__=0' <<<"$srcd" \
  && ok "generator returns 0 when sourced" \
  || bad "generator returns 0 when sourced" "sourcing it killed the caller"

echo "── startup.sh stays deduplicated ──"
# The duplication is what ARCH-01 removed; catch it coming back.
dup="$(docker run --rm --entrypoint /bin/bash "$IMAGE" -c '
  echo "lines=$(wc -l < /startup.sh)"
  echo "mutations=$(grep -cE ">>? /etc/squid/squid\\.conf( |$)" /startup.sh)"' 2>/dev/null)"
n=$(sed -n 's/^lines=//p' <<<"$dup")
[ "${n:-999}" -lt 150 ] && ok "startup.sh is boot-only (<150 lines, is $n)" \
                        || bad "startup.sh is boot-only" "grown back to $n lines"
m=$(sed -n 's/^mutations=//p' <<<"$dup")
[ "${m:-1}" = 0 ] && ok "startup.sh writes no squid.conf of its own" \
                  || bad "startup.sh writes no squid.conf of its own" "found $m heredoc writes"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

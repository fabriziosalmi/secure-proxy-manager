#!/usr/bin/env bash
# Proxy login from an LDAP directory, against a real OpenLDAP
# (tests/fixtures/openldap): the generator writes the LDAP block from the
# files the backend writes, and Squid, with the image's own helpers, runs it.
# The block is taken from the generated squid.conf and run in a minimal Squid,
# so no WAF or DNS container is needed. Checks: a user with the right
# password gets in, a wrong password, an unknown user and no credentials get
# 407, a member of no group gets 403 once a group is set, and the search
# account's password is neither in squid.conf nor on the helper's command
# line. The search account's DN has spaces, as on Active Directory.
#
# Usage: tests/shell/proxy_login_ldap_test.sh [proxy image]
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

IMAGE="${1:-spm-proxy-test}"
LDAP_IMAGE=spm-openldap-test
NET="spmldap$$"
PASS=0; FAIL=0
G="\033[0;32m"; R="\033[0;31m"; N="\033[0m"
ok()  { PASS=$((PASS+1)); printf "  ${G}✓${N} %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ${R}✗${N} %s\n     %s\n" "$1" "${2:-}"; }

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -q -t "$IMAGE" proxy/ >/dev/null || { echo "proxy image build failed"; exit 1; }
docker build -q -t "$LDAP_IMAGE" tests/fixtures/openldap/ >/dev/null || { echo "openldap image build failed"; exit 1; }

cleanup() { docker rm -f "$NET-ldap" "$NET-squid" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; }
trap cleanup EXIT
docker network create "$NET" >/dev/null
docker run -d --name "$NET-ldap" --network "$NET" "$LDAP_IMAGE" >/dev/null
for _ in $(seq 1 60); do docker logs "$NET-ldap" 2>&1 | grep -q "openldap ready" && break; sleep 1; done
docker logs "$NET-ldap" 2>&1 | grep -q "openldap ready" && ok "OpenLDAP is up with its seed" || { bad "OpenLDAP is up" "$(docker logs "$NET-ldap" 2>&1 | tail -5)"; exit 1; }

# run_squid GROUP: generate the LDAP block (with GROUP, or none when empty)
# and run it in a minimal Squid named $NET-squid.
run_squid() {
  local group="$1"
  docker rm -f "$NET-squid" >/dev/null 2>&1
  docker run -d --name "$NET-squid" --network "$NET" --entrypoint /bin/bash "$IMAGE" -c "
    set -e
    mkdir -p /config /etc/squid /secrets
    touch /config/proxy_auth_enabled /config/proxy_auth_ldap
    printf 'bind-pass-123' > /secrets/ldap_bind_password
    chown root:proxy /secrets/ldap_bind_password; chmod 0640 /secrets/ldap_bind_password
    printf 'LDAP_URL=ldap://$NET-ldap\nLDAP_BIND_DN=cn=Proxy Bind,ou=Service Accounts,dc=example,dc=com\nLDAP_USER_BASE=ou=people,dc=example,dc=com\nLDAP_USER_FILTER=(uid=%%s)\n' > /secrets/ldap.conf
    if [ -n '$group' ]; then printf 'LDAP_GROUP=$group\nLDAP_GROUP_BASE=ou=groups,dc=example,dc=com\nLDAP_GROUP_FILTER=(&(cn=%%g)(member=%%u))\n' >> /secrets/ldap.conf; fi
    /usr/local/bin/generate_squid_conf.sh >/tmp/gen.log 2>&1
    {
      echo 'http_port 3128'
      echo 'pid_filename /tmp/sq.pid'
      echo 'cache deny all'
      echo 'acl localhost src 127.0.0.1/32'
      echo 'acl spm_r_proxy_auth annotate_transaction spm_reason=proxy_auth'
      echo 'acl spm_r_proxy_auth_unset annotate_transaction spm_reason=proxy_auth_unset'
      grep -E '^(auth_param|acl authenticated|acl spm_ldap_group|external_acl_type spm_ldap_group|http_access deny !localhost spm_r_proxy_auth)' /etc/squid/squid.conf
      echo 'http_access allow all'
      echo 'access_log stdio:/tmp/access.log'
      echo 'cache_log stdio:/tmp/cache.log'
    } > /tmp/sq.conf
    cp /etc/squid/squid.conf /tmp/generated.conf
    touch /tmp/access.log /tmp/cache.log; chmod 666 /tmp/access.log /tmp/cache.log
    exec squid -N -f /tmp/sq.conf" >/dev/null
  for _ in $(seq 1 30); do
    docker exec "$NET-squid" sh -c 'grep -q "Accepting HTTP" /tmp/cache.log' 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

# code ARGS...: the status a client gets through the proxy.
code() {
  docker run --rm --network "$NET" --entrypoint curl "$IMAGE" -s -o /dev/null -m 25 -w '%{http_code}' \
    -x "http://$NET-squid:3128" "$@" http://example.com/
}

echo "── LDAP, no group ──"
run_squid "" && ok "Squid starts with the generated LDAP block" || bad "Squid starts" "$(docker logs "$NET-squid" 2>&1 | tail -5)"
[ "$(code -U alice:alice-pass-123)" != "407" ] && ok "alice, right password: let in" || bad "alice, right password: let in"
[ "$(code -U bob:bob-pass-123)" != "407" ] && ok "bob, right password, no group set: let in" || bad "bob, right password: let in"
[ "$(code -U alice:wrong)" = "407" ] && ok "a wrong password: 407" || bad "a wrong password: 407"
[ "$(code -U nobody:x)" = "407" ] && ok "an unknown user: 407" || bad "an unknown user: 407"
[ "$(code)" = "407" ] && ok "no credentials: 407" || bad "no credentials: 407"
docker exec "$NET-squid" grep -q 'bind-pass-123' /tmp/generated.conf && bad "the search password is not in squid.conf" || ok "the search password is not in squid.conf"
argv="$(docker exec "$NET-squid" sh -c 'for p in /proc/[0-9]*; do c=$(tr "\0" " " < $p/cmdline 2>/dev/null); case "$c" in *basic_ldap_auth*) echo "$c";; esac; done' | head -1)"
case "$argv" in
  *"-D cn=Proxy Bind,ou=Service Accounts,dc=example,dc=com -W /secrets/ldap_bind_password"*) ok "the helper gets the DN with spaces as one argument and the password as a file" ;;
  *) bad "the helper's arguments" "$argv" ;;
esac
case "$argv" in *bind-pass-123*) bad "the search password is not on the helper's command line" "$argv" ;; *) ok "the search password is not on the helper's command line" ;; esac

echo "── LDAP, members of proxy-users only ──"
run_squid "proxy-users" && ok "Squid starts with the group rule" || bad "Squid starts with the group rule" "$(docker logs "$NET-squid" 2>&1 | tail -5)"
[ "$(code -U alice:alice-pass-123)" != "407" ] && [ "$(code -U alice:alice-pass-123)" != "403" ] && ok "alice, a member: let in" || bad "alice, a member: let in"
[ "$(code -U bob:bob-pass-123)" = "403" ] && ok "bob, right password, not a member: 403" || bad "bob, not a member: 403" "$(code -U bob:bob-pass-123)"
[ "$(code -U alice:wrong)" = "407" ] && ok "a wrong password: still 407" || bad "a wrong password: still 407"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

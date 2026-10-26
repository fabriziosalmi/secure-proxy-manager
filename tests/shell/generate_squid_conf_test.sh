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
  docker run --rm --memory 256m --entrypoint /bin/bash "$IMAGE" -c "
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
  docker run --rm --memory 256m --entrypoint /bin/bash "$IMAGE" -c "
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
# The watchdog's localhost fetch of the cache manager (cache statistics) is
# neither logged as client traffic nor sent to the WAF. A LAN client's attempt
# at the manager is still both: the ACL needs localhost AND manager.
grep -q '^acl spm_self_mgr all-of localhost manager$' <<<"$conf" \
  && ok "spm_self_mgr is localhost AND manager" || bad "spm_self_mgr is localhost AND manager" "$(grep spm_self_mgr <<<"$conf")"
grep -q '^access_log daemon:/var/log/squid/access.log spm !spm_self_mgr spm_has_request$' <<<"$conf" \
  && ok "the access log leaves out the watchdog's manager fetch" || bad "the access log leaves out the watchdog's manager fetch" "$(grep '^access_log' <<<"$conf")"
# The backend's health probe connects and closes without a request; Squid
# would log that as error:transaction-end-before-headers every 30 s.
grep -q '^acl spm_has_request has request$' <<<"$conf" \
  && ok "the access log leaves out connections that sent no request" || bad "the access log leaves out connections that sent no request" "$(grep spm_has_request <<<"$conf")"
for svc in service_req service_resp; do
  first="$(grep -m1 "^adaptation_access $svc " <<<"$conf")"
  [ "$first" = "adaptation_access $svc deny spm_self_mgr" ] \
    && ok "$svc: the manager fetch is exempt before allow all" || bad "$svc: the manager fetch is exempt before allow all" "first rule: $first"
done
grep -q 'Strict-Transport-Security' <<<"$conf" \
  && bad "no HSTS is injected into third-party responses" "reply_header_add Strict-Transport-Security is back" \
  || ok "no HSTS is injected into third-party responses"

echo "── egress default-deny ON ──"
conf="$(generate 'touch /config/egress_default_deny; : > /config/dst_allow_ip.txt; : > /config/dst_allow_domain.txt')"
grep -q 'http_access deny localnet !egress_dst_allow' <<<"$conf" \
  && ok "deny rule injected" || bad "deny rule injected" "the egress fail-closed rule is missing"
n=$(grep -c 'http_access deny localnet !egress_dst_allow' <<<"$conf")
[ "$n" = 1 ] && ok "deny rule injected exactly once" || bad "deny rule injected exactly once" "found $n"
parses 'touch /config/egress_default_deny; : > /config/dst_allow_ip.txt; : > /config/dst_allow_domain.txt' \
  && ok "parses with egress deny on" || bad "parses with egress deny on"

echo "── every access rule records its reason ──"
# The block statistics are built from the spm_reason note each rule sets
# (squid_acl_matrix_test.sh asserts the logged value per rule). A rule added
# without its spm_r_* ACL would decide requests that are then logged with the
# previous rule's note or none, so every http_access line must carry one, with
# every policy toggle on.
conf="$(generate 'touch /config/egress_default_deny /config/proxy_auth_enabled /config/content_filtering_enabled /config/time_restrictions_enabled
  printf "%s\n" "\\.exe(\\?.*)?\$" > /config/blocked_file_types.txt; printf "TIME_START=08:00\nTIME_END=18:00\n" > /config/time_restrictions.conf
  export BASIC_AUTH_USERNAME=u BASIC_AUTH_PASSWORD=p')"
n_rules=$(grep -c '^http_access ' <<<"$conf")
unlabelled="$(grep '^http_access ' <<<"$conf" | grep -v ' spm_r_[a-z_]*\( \|$\)')"
[ "$n_rules" -gt 20 ] && [ -z "$unlabelled" ] \
  && ok "all $n_rules http_access rules name a reason" \
  || bad "every http_access rule names a reason" "rules without one: ${unlabelled:-none} (of $n_rules)"
grep -q '^http_access deny !localhost spm_r_proxy_auth !authenticated$' <<<"$conf" \
  && ok "the auth ACL stays last on its rule (407), the reason before it" \
  || bad "the auth ACL stays last on its rule" "$(grep 'authenticated' <<<"$conf" | grep http_access)"
# The fail-closed lists gate denies every client: its denials are logged as
# lists_unverified, not folded into other with the cache manager and deny all.
grep -qx 'http_access deny spm_lists_gate spm_r_lists_unverified' <<<"$conf" \
  && grep -qx 'acl spm_r_lists_unverified annotate_transaction spm_reason=lists_unverified' <<<"$conf" \
  && ok "the lists gate records the reason lists_unverified" \
  || bad "the lists gate records the reason lists_unverified" "$(grep 'spm_lists_gate\|lists_unverified' <<<"$conf")"
grep -qF '%{spm_reason}note %{X-SPM-Reason}adapt::<last_h' <<<"$conf" \
  && ok "the spm logformat carries the reason fields" || bad "the spm logformat carries the reason fields"
# The backend writes each extension as typed (\.exe$); a server answers
# /x.EXE as readily, so the ACL must ignore case (squid_acl_matrix_test.sh
# asserts the 403 for .EXE and .Exe).
grep -qxF 'acl blocked_extensions urlpath_regex -i "/config/blocked_file_types.txt"' <<<"$conf" \
  && ok "the blocked-extensions ACL ignores case" \
  || bad "the blocked-extensions ACL ignores case" "$(grep 'acl blocked_extensions' <<<"$conf")"

echo "── proxy login ──"
# Login on with no user to check against fails closed: one deny for every
# client but localhost, no auth helper, and a record the backend reads.
# Behaviour (status and logged reason per client): squid_acl_matrix_test.sh.
login_state() { # seed -> "<deny rules> <auth rules> <helper lines> <status>"
  docker run --rm --memory 256m --entrypoint /bin/bash "$IMAGE" -c "
    mkdir -p /config /etc/squid; $1
    /usr/local/bin/generate_squid_conf.sh >/tmp/gen.log 2>&1
    printf '%s %s %s %s\n' \
      \"\$(grep -c '^http_access deny !localhost spm_r_proxy_auth_unset\$' /etc/squid/squid.conf)\" \
      \"\$(grep -c '^http_access deny !localhost spm_r_proxy_auth !authenticated\$' /etc/squid/squid.conf)\" \
      \"\$(grep -c '^auth_param basic program' /etc/squid/squid.conf)\" \
      \"\$(sed -n 's/.*\"state\":\"\\([a-z_]*\\)\".*/\\1/p' /config/proxy_auth_status.json)\"" 2>/dev/null
}
bcrypt_line='u:$2a$10$0/zCMOoBoSRv/VuMO1g5zODMGanOhND6qkcI5nC/TugytJ4K7zLAm'
got="$(login_state 'touch /config/proxy_auth_enabled')"
[ "$got" = "1 0 0 no_credentials" ] && ok "login on, no password file: every client refused, recorded" || bad "login on, no password file: fail closed" "got: $got"
got="$(login_state "touch /config/proxy_auth_enabled; echo '# comment only' > /config/proxy_users.htpasswd")"
[ "$got" = "1 0 0 no_credentials" ] && ok "login on, password file with no user: fail closed" || bad "login on, password file with no user: fail closed" "got: $got"
got="$(login_state "touch /config/proxy_auth_enabled; printf '# marker\n%s\n' '$bcrypt_line' > /config/proxy_users.htpasswd")"
[ "$got" = "0 1 1 enforced" ] && ok "login on, a user in the file: login required, recorded" || bad "login on, a user in the file: login required" "got: $got"
got="$(login_state "printf '%s\n' '$bcrypt_line' > /config/proxy_users.htpasswd")"
[ "$got" = "0 0 0 off" ] && ok "login off: no login rule, even with a file left behind" || bad "login off: no login rule" "got: $got"
got="$(login_state 'touch /config/proxy_auth_enabled; export BASIC_AUTH_USERNAME=u BASIC_AUTH_PASSWORD=workaround-pass-1')"
[ "$got" = "0 1 1 enforced" ] && ok "login on, BASIC_AUTH_* passed by hand: file created from them" || bad "login on, BASIC_AUTH_* passed by hand" "got: $got"
parses 'touch /config/proxy_auth_enabled' && ok "parses with login on and no credentials" || bad "parses with login on and no credentials"

echo "── SSL bump ON ──"
conf="$(generate 'touch /config/ssl_bump_enabled')"
grep -q 'ssl_bump' <<<"$conf" && ok "ssl_bump directives injected" || bad "ssl_bump directives injected"
n=$(grep -c '^ssl_bump bump all' <<<"$conf")
[ "$n" -le 1 ] && ok "ssl_bump block not duplicated" || bad "ssl_bump block not duplicated" "found $n"
# The certificate database used to stay empty ("Cannot create /config/ssl_db"),
# so Squid stopped as soon as SSL-bump was on: run it, do not just parse it.
bump="$(docker run --rm --memory 256m --entrypoint /bin/bash "$IMAGE" -c '
  mkdir -p /config /etc/squid /var/spool/squid /var/log/squid /run/squid
  touch /config/ssl_bump_enabled
  /usr/local/bin/generate_squid_conf.sh >/tmp/gen1.log 2>&1
  [ -f /config/ssl_db/index.txt ] && echo db=ok || echo db=missing
  grep -h "Cannot create" /tmp/gen1.log
  chown -R proxy:proxy /var/spool/squid /var/log/squid /run/squid
  squid -z -N >/dev/null 2>&1; rm -f /run/squid/squid.pid
  # 124 = still running when timeout stopped it after 8 s.
  timeout 8 squid -N -d1 >/tmp/sq.log 2>&1; echo "squid_rc=$?"
  grep -m1 -E "FATAL|crashing too rapidly" /tmp/sq.log
  /usr/local/bin/generate_squid_conf.sh >/tmp/gen2.log 2>&1
  grep -q "Using existing SSL certificate database" /tmp/gen2.log && echo reuse=ok || echo reuse=no
' 2>/dev/null)"
grep -q 'db=ok' <<<"$bump" && ok "SSL-bump: the certificate database is created" || bad "SSL-bump: the certificate database is created" "$bump"
grep -q 'reuse=ok' <<<"$bump" && ok "SSL-bump: an existing database is kept" || bad "SSL-bump: an existing database is kept" "$bump"
grep -q 'squid_rc=124' <<<"$bump" && ! grep -qE 'FATAL|crashing' <<<"$bump" \
  && ok "SSL-bump: Squid runs (the certificate helper does not crash)" || bad "SSL-bump: Squid runs" "$bump"

echo "── GUI whitelist set ──"
# GUI_IP_WHITELIST names extra client SOURCES. It must not create a destination
# ACL or an allow rule of its own (the old gui_override did both, ahead of the
# port checks); its entries join localnet. Behaviour: squid_acl_matrix_test.sh.
conf="$(generate 'export GUI_IP_WHITELIST="192.168.1.5,100.64.0.0/10 not-an-ip"')"
grep -q 'gui_override' <<<"$conf" \
  && bad "GUI whitelist creates no destination ACL" "gui_override is back" \
  || ok "GUI whitelist creates no destination ACL"
grep -qF 'acl localnet src "/etc/squid/extra_clients.txt"' <<<"$conf" \
  && ok "extra client sources join localnet" || bad "extra client sources join localnet"
extra="$(docker run --rm --memory 256m --entrypoint /bin/bash "$IMAGE" -c '
  mkdir -p /config /etc/squid; export GUI_IP_WHITELIST="192.168.1.5,100.64.0.0/10 not-an-ip"
  /usr/local/bin/generate_squid_conf.sh >/dev/null 2>&1; cat /etc/squid/extra_clients.txt' 2>/dev/null)"
[ "$extra" = "$(printf '192.168.1.5\n100.64.0.0/10')" ] \
  && ok "comma/space entries parsed, invalid entry dropped" \
  || bad "comma/space entries parsed, invalid entry dropped" "got: $(tr '\n' ' ' <<<"$extra")"

echo "── offline mode ON ──"
conf="$(generate 'touch /config/offline_mode_enabled')"
n=$(grep -c '^offline_mode on' <<<"$conf")
[ "$n" -le 1 ] && ok "offline_mode not appended twice" || bad "offline_mode not appended twice" "found $n"

echo "── an empty value its pattern allows is accepted ──"
# The backend writes EXTRA_SSL_PORTS= by default; it was refused with a warning
# on every boot of every default install.
empty="$(docker run --rm --memory 256m --entrypoint /bin/bash "$IMAGE" -c '
  mkdir -p /config /etc/squid
  printf "SQUID_PORT=3128\nSQUID_CACHE_MB=1000\nSQUID_MEM_MB=256\nEXTRA_SSL_PORTS=\n" > /config/squid_settings.env
  /usr/local/bin/generate_squid_conf.sh 2>&1 | grep -c "WARNING: /config/squid_settings.env"
' 2>/dev/null)"
[ "$empty" = "0" ] && ok "default squid_settings.env loads without a warning" || bad "default squid_settings.env loads without a warning" "$empty warning(s)"

echo "── injection: nothing in a /config settings file is executed ──"
# The previous check grepped squid.conf for "pwned", which says nothing about
# whether a command RAN, and safe_source did run "KEY=value command": a space
# in EXTRA_SSL_PORTS executed the rest of the value as root. This asserts on
# the side effect, inside the container, for every file the generator reads.
ran="$(docker run --rm --memory 256m --entrypoint /bin/bash "$IMAGE" -c '
  mkdir -p /config /etc/squid
  printf "SQUID_PORT=3128\nEXTRA_SSL_PORTS=8443 touch /tmp/ran-ssl\nEVIL=\$(touch /tmp/ran-subst)\nSQUID_MEM_MB=64;touch /tmp/ran-semi\nPATH=/nowhere\n" > /config/squid_settings.env
  touch /config/bandwidth_limits_enabled
  printf "BW_LIMIT_MBPS=10\nBW_PER_USER_KBPS=0\nPATH=/config\nIFS=x\n" > /config/bandwidth_limits.conf
  touch /config/time_restrictions_enabled
  printf "TIME_START=08:00 touch /tmp/ran-time\nTIME_END=18:00\n" > /config/time_restrictions.conf
  /usr/local/bin/generate_squid_conf.sh >/tmp/gen.log 2>&1; echo "rc=$?"
  ls /tmp/ran-* 2>/dev/null
  grep -c "^acl SSL_ports port 8443" /etc/squid/squid.conf
  grep -c "^http_port 3128" /etc/squid/squid.conf
  grep -c "^delay_pools 1" /etc/squid/squid.conf
  grep -c "allowed_hours" /etc/squid/squid.conf
  /usr/sbin/squid -k parse >/dev/null 2>&1 && echo parse=ok || echo parse=fail
' 2>/dev/null)"
case "$ran" in *"/tmp/ran-"*) bad "no settings value is executed" "ran: $(grep /tmp/ran- <<<"$ran" | tr '\n' ' ')";; *) ok "no settings value is executed";; esac
grep -q '^rc=0' <<<"$ran" && ok "the generator still completes" || bad "the generator still completes" "$ran"
grep -q 'parse=ok' <<<"$ran" && ok "the result still parses (PATH and IFS were not replaced)" || bad "the result still parses" "$ran"
[ "$(sed -n 3p <<<"$ran")" = "1" ] && ok "a valid http_port survives next to hostile keys" || bad "a valid http_port survives next to hostile keys" "$ran"
[ "$(sed -n 4p <<<"$ran")" = "1" ] && ok "bandwidth limits still apply with PATH/IFS lines in the file" || bad "bandwidth limits still apply" "$ran"
[ "$(sed -n 5p <<<"$ran")" = "0" ] && ok "a time value with a trailing command is refused, not half-applied" || bad "a time value with a trailing command is refused" "$ran"

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
boot="$(docker run --rm --memory 256m --cap-add NET_ADMIN --entrypoint /bin/bash "$IMAGE" -c '
  sed -i "s|^exec /usr/bin/supervisord.*|echo __REACHED_SUPERVISORD__|" /startup.sh
  /startup.sh 2>&1
  echo "__STARTUP_RC__=$?"
' 2>/dev/null)"
grep -q '__REACHED_SUPERVISORD__' <<<"$boot" \
  && ok "startup.sh runs to the supervisord hand-off" \
  || bad "startup.sh runs to the supervisord hand-off" "the entrypoint stopped early — sourcing the generator must return, not exit"
grep -q '__STARTUP_RC__=0' <<<"$boot" && ok "startup.sh exits 0" || bad "startup.sh exits 0"

echo "── boot path: a config that does not parse is never replaced by a weaker one ──"
# The old fallback copied squid.conf.base over a config that failed to parse:
# no dns_nameservers, no egress default-deny, no SSL bump, no proxy auth, and a
# healthy container. An extras file that does not parse is now dropped (the
# rest of the generated config, filtering included, stays), and nothing else
# is ever substituted.
bad_extras="$(docker run --rm --memory 256m --cap-add NET_ADMIN --entrypoint /bin/bash "$IMAGE" -c '
  mkdir -p /config; touch /config/egress_default_deny
  echo "this_is_not_a_directive 1" > /config/custom_squid_extra.conf
  sed -i "s|^exec /usr/bin/supervisord.*|echo __REACHED_SUPERVISORD__|" /startup.sh
  /startup.sh 2>&1
  echo "__STARTUP_RC__=$?"
  grep -c "this_is_not_a_directive" /etc/squid/squid.conf
  grep -c "egress_dst_allow" /etc/squid/squid.conf
' 2>/dev/null)"
grep -q 'regenerating WITHOUT /config/custom_squid_extra.conf' <<<"$bad_extras" \
  && ok "an extras file that does not parse is dropped, loudly" \
  || bad "an extras file that does not parse is dropped, loudly" "$(tail -5 <<<"$bad_extras")"
grep -q '__REACHED_SUPERVISORD__' <<<"$bad_extras" && ok "Squid still starts without the broken extras" || bad "Squid still starts without the broken extras"
[ "$(tail -2 <<<"$bad_extras" | head -1)" = "0" ] && ok "the broken directive is not in the running config" || bad "the broken directive is not in the running config"
[ "$(tail -1 <<<"$bad_extras")" != "0" ] && ok "the egress default-deny survives the retry" || bad "the egress default-deny survives the retry" "the fallback lost filtering"
grep -q 'falling back to base' <<<"$bad_extras" && bad "no fallback to the unfiltered base config" || ok "no fallback to the unfiltered base config"
grep -q 'Configuration syntax is valid' <<<"$boot" \
  && ok "boot validates its own squid.conf" || bad "boot validates its own squid.conf"

echo "── boot log: no Squid command runs before the config exists ──"
# /etc/squid is a tmpfs in the compose stack: nothing is there at boot until
# the generator writes it. Three comments in the generator's unquoted heredoc
# quoted Squid commands in backticks, so the shell ran them: a clean boot
# logged "FATAL: Unable to open configuration file" three times, and on a
# running proxy every regeneration rotated the logs, reconfigured Squid and
# started a second one. The boot runs as compose runs it (tmpfs /etc/squid).
clean="$(docker run --rm --cap-add NET_ADMIN --tmpfs /etc/squid --entrypoint /bin/bash "$IMAGE" -c '
  sed -i "s|^exec /usr/bin/supervisord.*|echo __REACHED_SUPERVISORD__|" /startup.sh
  /startup.sh 2>&1' 2>/dev/null)"
n_fatal=$(grep -c 'FATAL' <<<"$clean")
grep -q '__REACHED_SUPERVISORD__' <<<"$clean" && [ "$n_fatal" = 0 ] \
  && ok "a clean boot logs no FATAL line" \
  || bad "a clean boot logs no FATAL line" "$n_fatal FATAL line(s): $(grep -m3 FATAL <<<"$clean")"
# The generator itself never runs Squid: startup.sh and the watchdog parse and
# reconfigure after it has written the file. A recorder stands in for squid.
calls="$(docker run --rm --entrypoint /bin/bash "$IMAGE" -c '
  mkdir -p /config
  printf "#!/bin/sh\necho \"\$*\" >> /tmp/squid-calls\n" > /usr/sbin/squid
  /usr/local/bin/generate_squid_conf.sh >/dev/null 2>&1
  SQUID_CONF=/etc/squid/squid.conf.next /usr/local/bin/generate_squid_conf.sh >/dev/null 2>&1
  if [ -f /tmp/squid-calls ]; then wc -l < /tmp/squid-calls; else echo 0; fi' 2>/dev/null)"
[ "$calls" = 0 ] && ok "the generator runs no Squid command (boot and watchdog runs)" \
  || bad "the generator runs no Squid command" "squid was run ${calls:-?} time(s)"

echo "── the lists are copied only when the backend's manifest vouches for them ──"
# The generator copied /config/*.txt into Squid's ACL directories with cp, at
# boot and on every watchdog regeneration, without the manifest check the
# watchdog applies: a torn export became the live ACL. It now copies through
# the watchdog's sync. lists_case SETUP prints, one per line: the IP blacklist
# ACL, the IP whitelist ACL, the domain blacklist, the gate (lines), whether
# squid parses, and the refusal / gate / legacy lines of the log.
lists_case() {
  docker run --rm --entrypoint /bin/bash "$IMAGE" -c '
    mkdir -p /config /etc/squid
    sha() { sha256sum "$1" | cut -d" " -f1; }
    manifest() { # every list with its current checksum, then NAME=SHA overrides
      local f s sep="" body=""
      for f in ip_blacklist ip_whitelist domain_blacklist dst_allow_ip dst_allow_domain; do
        s=$(sha /config/$f.txt)
        for kv in "$@"; do [ "${kv%%=*}" = "$f.txt" ] && s="${kv#*=}"; done
        body="$body$sep\"$f.txt\": {\"sha256\": \"$s\", \"bytes\": 0}"; sep=", "
      done
      printf "{\"version\": 1, \"generated_at\": 1, \"files\": {%s}}\n" "$body" > /config/lists.manifest.json
    }
    for f in ip_blacklist ip_whitelist domain_blacklist dst_allow_ip dst_allow_domain; do : > /config/$f.txt; done
    printf "203.0.113.9\n198.51.100.7\n" > /config/ip_blacklist.txt
    printf "192.0.2.10\n" > /config/ip_whitelist.txt
    printf "evil.example\n" > /config/domain_blacklist.txt
    torn=$(printf "%064d" 0)
    '"$1"'
    echo "ipbl=$(tr "\n" " " < /etc/squid/blacklists/ip/local.txt)"
    echo "ipwl=$(tr "\n" " " < /etc/squid/whitelists/ip/local.txt)"
    echo "dombl=$(tr "\n" " " < /etc/squid/blacklists/domain/local.txt)"
    echo "gate=$(wc -l < /etc/squid/lists_gate.txt)"
    /usr/sbin/squid -k parse >/dev/null 2>&1 && echo parse=ok || echo parse=fail
    grep -h -o -E "REFUSED [^:]*|CRITICAL: no verified copy|no lists manifest" /tmp/gen*.log | sort -u
  ' 2>/dev/null
}
gen='/usr/local/bin/generate_squid_conf.sh > /tmp/gen.log 2>&1'

out="$(lists_case "manifest; $gen")"
grep -qx 'ipbl=198.51.100.7 203.0.113.9 ' <<<"$out" && grep -qx 'gate=0' <<<"$out" && grep -qx 'parse=ok' <<<"$out" \
  && ! grep -q REFUSED <<<"$out" \
  && ok "match: every list is copied and the gate is open" || bad "match: every list is copied and the gate is open" "$out"

out="$(lists_case "manifest ip_blacklist.txt=\$torn; printf '203.0.113.9\n198.51.' > /config/ip_blacklist.txt; $gen")"
grep -qx 'ipbl=' <<<"$out" && grep -qx 'gate=1' <<<"$out" && grep -qx 'parse=ok' <<<"$out" \
  && grep -q 'REFUSED /config/ip_blacklist.txt' <<<"$out" && grep -q 'CRITICAL: no verified copy' <<<"$out" \
  && ok "boot, torn IP blacklist: not loaded, the gate closes (fail closed)" \
  || bad "boot, torn IP blacklist: not loaded, the gate closes" "$out"
grep -qx 'ipwl=192.0.2.10 ' <<<"$out" && grep -qx 'dombl=evil.example ' <<<"$out" \
  && ok "boot, torn IP blacklist: the lists that match are still copied" \
  || bad "boot, torn IP blacklist: the lists that match are still copied" "$out"

out="$(lists_case "manifest domain_blacklist.txt=\$torn; $gen")"
grep -qx 'dombl=' <<<"$out" && grep -qx 'gate=1' <<<"$out" \
  && ok "boot, mismatched domain blacklist: not loaded, the gate closes" \
  || bad "boot, mismatched domain blacklist: not loaded, the gate closes" "$out"

out="$(lists_case "manifest ip_whitelist.txt=\$torn; $gen")"
grep -qx 'ipwl=' <<<"$out" && grep -qx 'gate=0' <<<"$out" && grep -q 'REFUSED /config/ip_whitelist.txt' <<<"$out" \
  && ok "boot, mismatched allowlist: starts empty (allows less), the gate stays open" \
  || bad "boot, mismatched allowlist: starts empty, the gate stays open" "$out"

out="$(lists_case "$gen")"
grep -qx 'ipbl=198.51.100.7 203.0.113.9 ' <<<"$out" && grep -qx 'gate=0' <<<"$out" && grep -q 'no lists manifest' <<<"$out" \
  && ok "no manifest (a backend that predates it): copied unverified, with a warning" \
  || bad "no manifest: copied unverified, with a warning" "$out"

out="$(lists_case "echo '{not json' > /config/lists.manifest.json; $gen")"
grep -qx 'ipbl=' <<<"$out" && grep -qx 'gate=1' <<<"$out" \
  && ok "unreadable manifest: nothing is trusted, the gate closes" \
  || bad "unreadable manifest: nothing is trusted, the gate closes" "$out"

out="$(lists_case "manifest; $gen; printf '10.9.9.9\n' > /config/ip_blacklist.txt; touch -d '+1 min' /config/ip_blacklist.txt
  SQUID_CONF=/etc/squid/squid.conf.next /usr/local/bin/generate_squid_conf.sh > /tmp/gen2.log 2>&1")"
grep -qx 'ipbl=198.51.100.7 203.0.113.9 ' <<<"$out" && grep -qx 'gate=0' <<<"$out" && grep -q 'REFUSED /config/ip_blacklist.txt' <<<"$out" \
  && ok "regeneration, mismatched IP blacklist: the verified copy is kept, the gate stays open" \
  || bad "regeneration, mismatched IP blacklist: the verified copy is kept" "$out"

# Executed as a subprocess (the watchdog's contract) it must still exit 0, and
# sourced (startup.sh's contract) it must hand control back.
docker run --rm --memory 256m --entrypoint /bin/bash "$IMAGE" -c '
  mkdir -p /config /etc/squid
  /usr/local/bin/generate_squid_conf.sh >/dev/null 2>&1' >/dev/null 2>&1 \
  && ok "generator exits 0 when executed" || bad "generator exits 0 when executed"
srcd="$(docker run --rm --memory 256m --entrypoint /bin/bash "$IMAGE" -c '
  mkdir -p /config /etc/squid
  . /usr/local/bin/generate_squid_conf.sh >/dev/null 2>&1
  echo "__AFTER_SOURCE__=$?"' 2>/dev/null)"
grep -q '__AFTER_SOURCE__=0' <<<"$srcd" \
  && ok "generator returns 0 when sourced" \
  || bad "generator returns 0 when sourced" "sourcing it killed the caller"

echo "── startup.sh stays deduplicated ──"
# The duplication is what ARCH-01 removed; catch it coming back.
dup="$(docker run --rm --memory 256m --entrypoint /bin/bash "$IMAGE" -c '
  echo "lines=$(wc -l < /startup.sh)"
  echo "mutations=$(grep -cE ">>? /etc/squid/squid\\.conf( |$)" /startup.sh)"' 2>/dev/null)"
n=$(sed -n 's/^lines=//p' <<<"$dup")
[ "${n:-999}" -lt 150 ] && ok "startup.sh is boot-only (<150 lines, is $n)" \
                        || bad "startup.sh is boot-only" "grown back to $n lines"
m=$(sed -n 's/^mutations=//p' <<<"$dup")
[ "${m:-1}" = 0 ] && ok "startup.sh writes no squid.conf of its own" \
                  || bad "startup.sh writes no squid.conf of its own" "found $m heredoc writes"

echo "── cross-language: the watchdog's acknowledgement must decode as Go int64 ──"
# SECURE-API-01 / SECURE-TEST-01. The backend decodes .reload-squid.result into
# a struct whose trigger_mtime is int64, and Go's encoding/json refuses ANY JSON
# float for an integer field — including one with a .0 fraction. The producer is
# Python, where os.path.getmtime returns a float, so for the life of the feature
# every acknowledgement failed to parse and the reload endpoint could answer only
# "pending". The Go test could not catch it because it built its fixture with
# json.Marshal from an int64 — the one shape that cannot disagree with itself.
# This asserts the REAL producer's output, in the real image.
ack="$(docker run --rm --memory 256m -v "$PWD/proxy/blacklist_watchdog.py:/w.py:ro" --entrypoint sh "$IMAGE" -c '
  mkdir -p /config
  python3 - <<PYEOF
import time
g = {}
exec(open("/w.py").read().split("def main()")[0], g)
open("/config/.reload-squid", "w").write(str(int(time.time())))
g["write_result"]("reload-squid", g["trigger_stamp"]("/config/.reload-squid", 0), 0, 0)
print(open("/config/.reload-squid.result").read().strip())
PYEOF' 2>/dev/null | tail -1)"
case "$ack" in
  *'"trigger_mtime":'*[0-9].[0-9]*) bad "trigger_mtime is emitted as a float" "$ack" ;;
  *'"trigger_mtime":'*[0-9]*)       ok  "trigger_mtime is emitted as an integer" ;;
  *)                                bad "watchdog produced no acknowledgement" "$ack" ;;
esac
case "$ack" in
  *'"applied": true'*|*'"applied":true'*) ok "acknowledgement reports applied" ;;
  *)                                      bad "acknowledgement reports applied" "$ack" ;;
esac

echo "── documentation: the claims that are mechanically checkable ──"
# SECURE-DOC-01. This repository already proves it can gate doc-code agreement:
# the API catalogue is walked from the live router with a test asserting the two
# agree, and the version is gated across four files. Prose had no such gate, and
# this audit found three statements describing the previous release — all of them
# about the proxy container or its CA, which is what an operator reads when
# enforcement is misbehaving. These are the claims a script can check.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

grep -q 'generate_squid_conf.sh` is the \*\*sole producer\*\*' "$repo_root/docs/guide/architecture.md" \
  && ok "architecture.md names the real producer of squid.conf" \
  || bad "architecture.md names the real producer of squid.conf" "it still attributes generation to startup.sh"

if grep -qE 'startup\.sh.*generates .squid\.conf' "$repo_root/docs/guide/architecture.md"; then
  bad "architecture.md no longer attributes generation to startup.sh" "the old claim is still present"
else
  ok "architecture.md no longer attributes generation to startup.sh"
fi

# The CA lifetime is a number in two places; they must agree.
gen_days="$(grep -oE '\-days [0-9]+' "$repo_root/proxy/generate_squid_conf.sh" | head -1 | awk '{print $2}')"
if [ -n "$gen_days" ] && grep -q "\*\*${gen_days} days\*\*" "$repo_root/DEPLOYMENT.md"; then
  ok "DEPLOYMENT.md states the CA lifetime the generator uses (${gen_days} days)"
else
  bad "DEPLOYMENT.md states the CA lifetime the generator uses" "generator says ${gen_days:-?} days"
fi

# The code points at a rotation procedure; it has to exist.
if grep -q 'See DEPLOYMENT.md "Rotating the SSL-bump CA"' "$repo_root/proxy/generate_squid_conf.sh"; then
  grep -q '^### Rotating the SSL-bump CA' "$repo_root/DEPLOYMENT.md" \
    && ok "the rotation procedure the code cites exists" \
    || bad "the rotation procedure the code cites exists" "generate_squid_conf.sh points at a section that is not in DEPLOYMENT.md"
fi

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

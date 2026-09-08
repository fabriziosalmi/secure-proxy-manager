#!/bin/bash

# ── What this script does, and what it does NOT ──────────────────────────────
# Everything that BUILDS squid.conf lives in generate_squid_conf.sh, which is
# sourced below. 407 of this file's 490 lines used to be a byte-identical copy
# of that generator: the helper block, and the entire 285-line mutation block.
# Because the generator is sourced first and its copy then ran AGAIN here, the
# unguarded mutations were applied twice — offline_mode appended twice, the
# gui_override ACL defined twice — and, worse, every security-relevant edit had
# to land in two files or the boot path and the watchdog reload path diverged.
#
# That was not hypothetical: at the time this was removed, startup.sh still
# carried a 3650-day CA and an htpasswd -bc invocation that put the admin
# password in argv, both already fixed in the generator. They were inert only
# because the generator ran first and the guards saw the files already present.
#
# This file is now boot-only: stop any previous squid, install the transparent
# proxy rules, generate the config once, prepare directories and permissions,
# and hand off to supervisord (SECURE-ARCH-01).

# ── Stop any existing Squid ──────────────────────────────────────────────────

if [ -f /run/squid.pid ]; then
    pid=$(cat /run/squid.pid)
    if ps -p $pid > /dev/null 2>&1; then
        kill $pid
        sleep 2
    fi
    rm -f /run/squid.pid
fi
pkill -15 squid 2>/dev/null || true
sleep 2

# ── iptables for transparent proxy ──────────────────────────────────────────
# Idempotent: -C checks whether the rule already exists before -A appends it, so
# a `docker restart` (which reuses the netns) does not stack duplicate REDIRECT
# rules on every boot.

iptables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3128 2>/dev/null || \
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3128
iptables -t nat -C PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 3128 2>/dev/null || \
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 3128

# ── Generate Squid configuration ─────────────────────────────────────────────
# Sourced, not executed: the generator also defines the helper functions the
# validation and verification steps below call. It returns (not exits) so that
# control comes back here — see the tail of generate_squid_conf.sh. The status
# is advisory; the authoritative check is the `squid -k parse` below, which
# validates the artefact rather than the exit code.

. /usr/local/bin/generate_squid_conf.sh
gen_status=$?
if [ "$gen_status" -ne 0 ]; then
    echo "WARNING: squid config generation returned $gen_status; validating anyway"
fi

# ── Blacklist watchdog (live reload + log readability) ───────────────────────
# The watchdog is shipped as /usr/local/bin/blacklist_watchdog.py and is
# registered statically in squid-supervisor.conf, so supervisord starts it on
# boot. It keeps /config blacklist files synced into the Squid ACL dirs (live
# reload via `squid -k reconfigure`) and re-asserts 0644 on the Squid logs so
# the backend container can tail them. Nothing to generate here at runtime.

# ── Prepare directories and permissions ──────────────────────────────────────

mkdir -p /var/log/squid /var/spool/squid /run/squid /var/run/squid /var/log/supervisor
chown -R proxy:proxy /var/log/squid /var/spool/squid /run/squid /var/run/squid
# Log files must be world-readable so the backend container (different UID)
# can tail access.log for analytics without requiring a shared group or
# elevated privileges.
chmod 755 /var/log/squid
chmod 755 /run/squid /var/run/squid
touch /run/squid/squid.pid /run/squid.pid
chown proxy:proxy /run/squid/squid.pid /run/squid.pid

# ── Initialize swap directories ─────────────────────────────────────────────

su - proxy -s /bin/bash -c "/usr/sbin/squid -z"
sleep 2

# ── Validate configuration ──────────────────────────────────────────────────

echo "Validating Squid configuration..."
if /usr/sbin/squid -k parse; then
    echo "Configuration syntax is valid."
else
    echo "Configuration has errors, falling back to base..."
    [ ! -f /etc/squid/squid.conf.backup ] && cp /etc/squid/squid.conf /etc/squid/squid.conf.backup
    cp /etc/squid/squid.conf.base /etc/squid/squid.conf
    ensure_ip_blocking_rules /etc/squid/squid.conf
fi

# ── Final verification ──────────────────────────────────────────────────────

echo "Configuration verification:"
verify_config_feature "Direct IP blocking"      "acl direct_ip_url"
verify_config_feature "Cache configuration"      "cache_dir ufs"
verify_config_feature "Local network access"     "acl localnet src"
verify_config_feature "IP blacklist"             "acl ip_blacklist"
verify_config_feature "Domain blacklist"         "acl domain_blacklist"
verify_config_feature "Connection timeout"       "connect_timeout"
verify_config_feature "DNS timeout"              "dns_timeout"
verify_config_feature "Logging"                  "debug_options"

# ── Start supervisor ────────────────────────────────────────────────────────

echo "Starting supervisor..."
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf

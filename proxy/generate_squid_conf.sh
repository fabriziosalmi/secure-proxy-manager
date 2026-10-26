#!/bin/bash
# The file this run writes. The watchdog points it at a scratch path, checks
# that Squid parses the result, and only then moves it into place; boot
# writes the live file directly.
SQUID_CONF="${SQUID_CONF:-/etc/squid/squid.conf}"

# ── Helper functions ─────────────────────────────────────────────────────────

ensure_ip_blocking_rules() {
    local conf="$1"
    local needs_acls=false
    local needs_deny=false

    if ! grep -q "acl direct_ip_url" "$conf" || ! grep -q "acl direct_ip_host" "$conf"; then
        needs_acls=true
    fi
    if ! grep -q "http_access deny direct_ip_url" "$conf" || ! grep -q "http_access deny direct_ip_host" "$conf"; then
        needs_deny=true
    fi

    if $needs_acls || $needs_deny; then
        echo "Adding missing direct IP blocking rules..."
        cat >> "$conf" << 'EOL'

# ==== CRITICAL SECURITY RULES (auto-added by startup) ====
acl direct_ip_url url_regex -i ^https?://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)
acl direct_ip_host dstdom_regex -i ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$
acl direct_ipv6_url url_regex -i ^https?://\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\]
acl direct_ipv6_host dstdom_regex -i ^\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\]$

http_access allow ip_whitelist spm_r_none
http_access deny direct_ip_url spm_r_direct_ip
http_access deny direct_ip_host spm_r_direct_ip
http_access deny direct_ipv6_url spm_r_direct_ip
http_access deny direct_ipv6_host spm_r_direct_ip
http_access deny CONNECT direct_ip_host spm_r_direct_ip
http_access deny CONNECT direct_ipv6_host spm_r_direct_ip
# ==== END CRITICAL SECURITY RULES ====
EOL
        echo "Direct IP blocking rules added."
    else
        echo "Direct IP blocking rules already present."
    fi
}

# insert_policy BLOCK: place access-policy lines at the @@SPM_POLICY@@ marker,
# ahead of every allow rule. Squid stops at the first http_access line that
# matches, so a restriction appended to the end of the file (after "deny all",
# behind "allow localnet") is never evaluated: proxy auth, time restrictions and
# content filtering were all written that way and none of them took effect.
# The block travels through the environment, not awk -v, so backslashes in it
# are not reinterpreted. Fails if the marker is gone rather than appending.
insert_policy() {
    local conf="$SQUID_CONF" tmp
    if ! grep -qF '# @@SPM_POLICY@@' "$conf"; then
        echo "CRITICAL: policy marker missing from $conf; refusing to append access rules where Squid would ignore them" >&2
        return 1
    fi
    tmp="$(mktemp)"
    SPM_BLOCK="$1" awk 'index($0, "# @@SPM_POLICY@@") == 1 { print ENVIRON["SPM_BLOCK"] } { print }' "$conf" > "$tmp" \
        && cat "$tmp" > "$conf"
    rm -f "$tmp"
}

# Squid's ACL lists are written by blacklist_watchdog.py, the same code the
# watchdog runs after every sync, so boot and reload cannot disagree:
# - normalize_ip_lists collapses the IP lists to the smallest set of networks.
#   Squid warns once per entry another entry covers, and aborts at startup
#   past 1000 such messages (a 50,772-entry import kept it in a restart loop).
# - refresh_domain_acl derives the domain ACL from the synced list: exact names
#   (a "*." prefix is a literal to dstdomain and never matched), each once,
#   empty above SPM_SQUID_DOMAIN_ACL_MAX entries (the dnsmasq sinkhole still
#   applies).
SPM_LISTS="${SPM_LISTS:-/usr/local/bin/blacklist_watchdog.py}"
normalize_ip_lists() {
    python3 -I "$SPM_LISTS" --normalize ip "$@" \
        || echo "WARNING: could not normalize the IP lists; Squid may refuse to start on a list with overlapping entries"
}
refresh_domain_acl() {
    if ! python3 -I "$SPM_LISTS" --normalize domain-acl; then
        echo "WARNING: could not write Squid's domain ACL: Squid denies no domain itself, only the DNS sinkhole does"
        : > /etc/squid/blacklists/domain/squid.txt
    fi
}

verify_config_feature() {
    local label="$1"
    local pattern="$2"
    if grep -q "$pattern" "$SQUID_CONF"; then
        echo "  [ok] $label"
    else
        echo "  [--] $label (may be disabled)"
    fi
}

# load_settings FILE KEY=REGEX...: assign the listed keys from FILE's
# KEY=VALUE lines, each only when its whole value matches its regex, with
# printf -v. Nothing in the file is executed and no other variable can be set.
#
# This replaced safe_source, which SOURCED the file as root after two checks
# that allowed spaces: "EXTRA_SSL_PORTS=8443 pkill squid" passed both and ran
# pkill, and "BW_PER_USER_KBPS=0" followed by "PATH=/config" passed and
# replaced PATH for the rest of the generator. Values reach these files from
# the settings API and from a restored backup.
load_settings() {
    local file="$1"; shift
    [ -f "$file" ] || return 0
    local line key val spec re
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|\#*) continue ;; esac
        key="${line%%=*}"
        val="${line#*=}"
        if [ "$key" = "$line" ]; then
            echo "WARNING: $file: ignoring a line that is not KEY=VALUE"
            continue
        fi
        re=""
        for spec in "$@"; do
            if [ "${spec%%=*}" = "$key" ]; then re="${spec#*=}"; break; fi
        done
        if [ -z "$re" ]; then
            echo "WARNING: $file: ignoring unknown key '$key'"
        # %s\n, not %s: grep reads no line at all from an empty value, so a
        # pattern that allows empty (EXTRA_SSL_PORTS) refused the default.
        elif printf '%s\n' "$val" | grep -Eqx -- "$re"; then
            printf -v "$key" '%s' "$val"
        else
            echo "WARNING: $file: ignoring $key, its value is not of the form $re"
        fi
    done < "$file"
}

# ── Directory setup ──────────────────────────────────────────────────────────

mkdir -p /etc/squid/blacklists/ip /etc/squid/blacklists/domain /etc/squid/whitelists/ip
mkdir -p /config/ssl_db
# ssl_db must be writable by the proxy user (squid SSL bump) and readable by
# the backend health checker — 750 with proxy ownership is the safe minimum.
chown proxy:proxy /config/ssl_db
chmod 750 /config/ssl_db

# ── SSL certificates ────────────────────────────────────────────────────────

# Reject the CA private key that was historically committed to this repository.
# Any deployment still carrying it shares one public keypair with every other
# user of the project, so anyone with the repo could forge certificates and MITM
# all SSL-bumped TLS. If we detect that exact keypair (matched by modulus, so it
# survives PEM re-encoding), delete it and the cert DB it signed so a fresh,
# unique CA is generated below.
KNOWN_BAD_KEY_MODULUS_SHA256="b3443bfd0d20cec31e7a87eb77d7ebd6864253037091c69bf1d069368e089c31"
if [ -f /config/ssl_key.pem ]; then
    current_modulus_sha256="$(openssl rsa -in /config/ssl_key.pem -noout -modulus 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}')"
    if [ "$current_modulus_sha256" = "$KNOWN_BAD_KEY_MODULUS_SHA256" ]; then
        echo "SECURITY: detected the known-compromised committed CA key: deleting and regenerating a unique CA." >&2
        rm -f /config/ssl_key.pem /config/ssl_cert.pem
        rm -rf /config/ssl_db/* 2>/dev/null || true
    fi
fi

if [ ! -f /config/ssl_cert.pem ] || [ ! -f /config/ssl_key.pem ]; then
    echo "Generating SSL certificates for HTTPS filtering..."
    # umask 077 in a subshell so the key is NEVER created world-readable. The
    # chmod below used to be the only protection, and it runs two commands
    # later — an interruption in between left a 0644 private key on a
    # bind-mounted host directory permanently, because the next boot sees both
    # files present and skips this whole block (SECURE-SEC-05).
    (umask 077; openssl genrsa -out /config/ssl_key.pem 2048)
    # 825 days, not 3650. A ten-year CA with no rotation procedure outlives the
    # deployment: if it leaks there is no rehearsed way back, and every client
    # has it installed. 825 days is the CA/Browser Forum maximum for a leaf and
    # a lifetime an operator will actually be prompted to replace
    # (SECURE-SEC-03). See DEPLOYMENT.md "Rotating the SSL-bump CA".
    openssl req -new -key /config/ssl_key.pem -x509 -days 825 -out /config/ssl_cert.pem \
        -subj "/C=US/ST=CA/L=SanFrancisco/O=SecureProxy/CN=secure-proxy.local"
    chmod 400 /config/ssl_key.pem
    chmod 444 /config/ssl_cert.pem
    echo "SSL certificates generated."
else
    echo "Using existing SSL certificates."
fi

# security_file_certgen -c creates the database (index.txt, size, certs/) and
# refuses a directory that already exists, which /config/ssl_db always is by
# here (created above). It was called on that directory, failed with "Cannot
# create /config/ssl_db" and left it empty, while this script printed
# "initialized"; with SSL-bump on, the certificate helper then crashed and
# Squid stopped ("sslcrtd_program helpers are crashing too rapidly"). The test
# also looked for a db/ subdirectory the tool never creates. The database is
# built beside the directory and moved in.
if [ ! -f /config/ssl_db/index.txt ]; then
    echo "Initializing SSL certificate database..."
    rm -rf /config/ssl_db.new
    if /usr/lib/squid/security_file_certgen -c -s /config/ssl_db.new -M 4MB >/dev/null \
        && rm -rf /config/ssl_db/* && mv /config/ssl_db.new/* /config/ssl_db/; then
        chown -R proxy:proxy /config/ssl_db
        echo "SSL certificate database initialized."
    else
        echo "WARNING: the SSL certificate database could not be created; SSL-bump will not work"
    fi
    rm -rf /config/ssl_db.new
else
    echo "Using existing SSL certificate database."
fi

# ── Empty blacklist placeholders ─────────────────────────────────────────────

touch /etc/squid/blacklists/ip/local.txt
touch /etc/squid/blacklists/domain/local.txt
touch /etc/squid/whitelists/ip/local.txt
# Rewritten from GUI_IP_WHITELIST below on every generation, so unsetting the
# variable removes the sources it added.
: > /etc/squid/extra_clients.txt
# Squid's copy of the domain blacklist; filled by refresh_domain_acl below.
touch /etc/squid/blacklists/domain/squid.txt

# ── Read dynamic settings from backend DB (via config files written on save) ─

# SECURE-REL-02. WAF_FAIL_OPEN governed only panics INSIDE the WAF process; an
# unreachable WAF container was decided here, by a hardcoded bypass=0, which no
# setting reached. So an operator who set WAF_FAIL_OPEN=1 — explicitly trading
# security for availability — still lost all proxying when the WAF died, which
# is the failure they were guarding against. One switch now governs both.
# Default stays 0: fail closed.
case "$(printf '%s' "${WAF_FAIL_OPEN:-0}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes) ICAP_REQMOD_BYPASS=1
                echo "WAF_FAIL_OPEN=1: an unreachable WAF will ALLOW traffic (availability over security)" ;;
    *)          ICAP_REQMOD_BYPASS=0 ;;
esac

SQUID_PORT="${PROXY_PORT:-3128}"
SQUID_CACHE_MB="${PROXY_CACHE_SIZE_MB:-2000}"
SQUID_MEM_MB="${PROXY_MEMORY_CACHE_MB:-256}"

# Allow override via /config/squid_settings.env (written by backend on settings save)
load_settings /config/squid_settings.env \
    'SQUID_PORT=[0-9]{1,5}' \
    'SQUID_CACHE_MB=[0-9]{1,7}' \
    'SQUID_MEM_MB=[0-9]{1,6}' \
    'EXTRA_SSL_PORTS=([0-9]{1,5}([ ,]+[0-9]{1,5})*)?'

echo "Squid settings: port=${SQUID_PORT} cache=${SQUID_CACHE_MB}MB mem=${SQUID_MEM_MB}MB extra_ssl=${EXTRA_SSL_PORTS:-none}"

# ── Generate base Squid configuration ────────────────────────────────────────

# /etc/squid is a tmpfs at runtime: copy the stock templates from
# /usr/share/squid/errors/en first (for non-error templates such as
# ERR_DIR_LISTING and error-details.txt), then overwrite the error templates
# with the SPM pages staged in /opt/squid-error-pages.
mkdir -p /etc/squid/error-pages \
    || echo "WARNING: failed to create /etc/squid/error-pages"
if [ -d /usr/share/squid/errors/en ]; then
    cp -a /usr/share/squid/errors/en/. /etc/squid/error-pages/ 2>/dev/null \
        || echo "WARNING: failed to copy stock error templates from /usr/share/squid/errors/en"
else
    echo "WARNING: stock error directory /usr/share/squid/errors/en is missing"
fi
if [ -d /opt/squid-error-pages ]; then
    cp -a /opt/squid-error-pages/. /etc/squid/error-pages/ 2>/dev/null \
        || echo "WARNING: failed to copy SPM error pages from /opt/squid-error-pages"
else
    echo "WARNING: SPM error directory /opt/squid-error-pages is missing"
fi

echo "Setting up Squid configuration..."
# The delimiter is unquoted so that ${SQUID_PORT} and the other settings
# expand, which means a backtick or a dollar-parenthesis anywhere below,
# comments included, is a command the shell RUNS. Three comments quoted Squid
# commands in backticks: every generation ran "squid -k rotate", "squid" and
# "squid -k reconfigure". At boot, before the file existed, each printed
# "FATAL: Unable to open configuration file"; on a running proxy every reload
# rotated the logs, reconfigured Squid on the previous file and started a
# second Squid (measured on 7.7). Quote commands with single quotes here.
cat > /etc/squid/squid.conf.base << CONFEOF
http_port ${SQUID_PORT}
visible_hostname secure-proxy
pid_filename /run/squid/squid.pid

# Access control lists
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7
acl localnet src fe80::/10
# Extra client sources from GUI_IP_WHITELIST (one per line, may be empty).
# They join localnet, so every rule that governs a LAN client governs them too.
acl localnet src "/etc/squid/extra_clients.txt"

# SSL/HTTPS related ACLs
acl SSL_ports port 443
acl SSL_ports port 8443
acl Safe_ports port 80
acl Safe_ports port 443
# port 21 (FTP) intentionally NOT a Safe_port — we do not proxy FTP, and the
# FTP gateway is the Squidbleed (CVE-2026-47729) attack surface. See ftp_proto.
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777

# Blacklists and whitelists
# Domain blocking is handled at L3 by dnsmasq (DNS blackhole → 0.0.0.0)
# Only IP blocking remains at L7 in Squid. Both lists are DESTINATION lists:
# the blacklist used to be a src ACL that also exempted LAN clients, so it could
# not block a destination for anyone.
acl ip_blacklist dst "/etc/squid/blacklists/ip/local.txt"
acl ip_whitelist dst "/etc/squid/whitelists/ip/local.txt"

# Direct IP access detection
acl direct_ip_url url_regex -i ^https?://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)
acl direct_ip_host dstdom_regex -i ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$
acl direct_ipv6_url url_regex -i ^https?://\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\]
acl direct_ipv6_host dstdom_regex -i ^\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\]$

# HTTP method definitions
acl CONNECT method CONNECT

# Block reasons. An annotate_transaction ACL always matches; its only effect is
# to set the spm_reason note, which the spm logformat writes to the access log
# and the backend stores as the request's block reason. Every deny rule below
# ends with the one naming it, so the note records the rule that matched, not
# a guess from the status code: a Squid deny and a WAF block both log 403, and
# a request to a sinkholed name used to log 503. Every allow rule ends with
# spm_r_none, which clears a note set by a rule that was evaluated but did not
# deny (the proxy-auth rule, whose auth ACL has to stay last). The vocabulary
# is shared with backend-go/internal/workers/log_tailer.go.
acl spm_r_none annotate_transaction spm_reason=none
acl spm_r_protocol_policy annotate_transaction spm_reason=protocol_policy
acl spm_r_port_policy annotate_transaction spm_reason=port_policy
acl spm_r_source_gate annotate_transaction spm_reason=source_gate
acl spm_r_ip_blacklist annotate_transaction spm_reason=ip_blacklist
acl spm_r_domain_blacklist annotate_transaction spm_reason=domain_blacklist
acl spm_r_domain_blacklist_dns annotate_transaction spm_reason=domain_blacklist_dns
acl spm_r_proxy_auth annotate_transaction spm_reason=proxy_auth
acl spm_r_proxy_auth_unset annotate_transaction spm_reason=proxy_auth_unset
acl spm_r_time_restriction annotate_transaction spm_reason=time_restriction
acl spm_r_content_filter annotate_transaction spm_reason=content_filter
acl spm_r_direct_ip annotate_transaction spm_reason=direct_ip
acl spm_r_egress_policy annotate_transaction spm_reason=egress_policy
acl spm_r_lists_unverified annotate_transaction spm_reason=lists_unverified
acl spm_r_other annotate_transaction spm_reason=other

# Protocol guard: Squid's built-in FTP gateway is the Squidbleed
# (CVE-2026-47729) out-of-bounds-read surface. We never proxy FTP, so match and
# deny the FTP scheme outright (denied first in the access rules below).
acl ftp_proto proto FTP

# Local network destinations (proxy UI, backend — should not be blocked as "direct IP")
# NOTE: 172.16.0.0/12 intentionally excluded — Docker internal networks use that range
# There is no URL-regex twin of this ACL any more: "^https?://10\." matched any
# HOSTNAME starting with "10.", so 10.anything.example was allowed to any
# public address, past the direct-IP rules and the egress default-deny. A
# literal LAN IP is already matched by dst.
acl local_dst dst 10.0.0.0/8 192.168.0.0/16

# HTTP method policy: positive allowlist (Safe_methods) + explicit dangerous-method
# denylist for clearer audit logs. Anything not in Safe_methods is denied below
# alongside the rest of the access rules.
acl Safe_methods method GET HEAD POST OPTIONS CONNECT
acl Dangerous_methods method PUT DELETE PATCH TRACE TRACK
http_access deny Dangerous_methods spm_r_protocol_policy
http_access deny !Safe_methods spm_r_protocol_policy

# Access rules
http_access deny ftp_proto spm_r_protocol_policy
http_access deny !Safe_ports spm_r_port_policy

# Who may use the proxy at all. Every allow rule below is scoped by destination
# only, so without this gate a client from ANY address could tunnel into the
# LAN (CONNECT local_dst) or relay through it. Nothing below may come before it.
http_access deny !localnet !localhost spm_r_source_gate

# The cache manager lists every in-flight request with its client and URL.
# Local stats only.
http_access allow localhost manager spm_r_none
http_access deny manager spm_r_other
# The watchdog reads the info page from localhost once a minute for the cache
# statistics. That request is not client traffic: it is kept out of the access
# log the statistics are built from and out of the WAF (measured on 7.7: with
# the WAF down and REQMOD fail-closed, the request got no answer until curl
# gave up after 10 s, logged NONE_NONE_ABORTED/000).
acl spm_self_mgr all-of localhost manager

# Fail closed while a blocklist has no verified copy. The lists are copied only
# when they match the manifest the backend writes after them; one refused at
# boot has no previous copy to keep (/etc/squid is a tmpfs), and Squid without
# its blocklist would let everything through. The gate file then holds every
# address and every client request is denied here, until the watchdog copies a
# verified list; it is empty otherwise. Written by blacklist_watchdog.py
# (save_lists_state). Logged with the reason lists_unverified.
acl spm_lists_gate src "/etc/squid/lists_gate.txt"
http_access deny spm_lists_gate spm_r_lists_unverified

http_access deny ip_blacklist spm_r_ip_blacklist

# Blacklisted domains are sinkholed by dnsmasq. They are also denied here
# while the list is small enough for Squid to hold, because the sinkhole alone
# does not stop a domain that was visited before it was blacklisted: Squid
# serves it from its DNS cache and, for anything it already has, from its HTTP
# cache (TCP_MEM_HIT), with no lookup at all. This rule runs before the cache.
# The file is derived from the list by refresh_domain_acl: its exact names up
# to SPM_SQUID_DOMAIN_ACL_MAX entries, empty above that (measured at 0.5 CPU:
# 100k entries cost about 36 MB and a 1.5 s reconfigure, 250k about 80 MB and
# 3.5 s (about 1.4 s of refused requests while it reloads), 1M about 200 MB and
# 13 s, 5.5M exhausted the 512 MB limit).
acl domain_blacklist dstdomain "/etc/squid/blacklists/domain/squid.txt"
http_access deny domain_blacklist spm_r_domain_blacklist

# A blacklisted name that is not in Squid's own copy above (the list is over
# SPM_SQUID_DOMAIN_ACL_MAX) is still sinkholed by dnsmasq, which answers
# 0.0.0.0 and ::. Squid used to try to connect to that address and log
# TCP_TUNNEL/503 or TCP_MISS/503: the client got a connection error instead of
# the block page and the statistics counted nothing. A dst ACL matches the
# address the name resolves to, so the sinkhole answer itself is denied here.
# It costs no extra lookup: ip_blacklist above is a dst ACL too, so the name
# is already resolved (and in Squid's ipcache) by the time this rule runs.
acl dns_sinkhole dst 0.0.0.0 ::
http_access deny dns_sinkhole spm_r_domain_blacklist_dns

# @@SPM_POLICY@@ (proxy auth, time restrictions and content filtering are
# inserted here, ahead of every allow rule; see insert_policy)

http_access allow CONNECT local_dst spm_r_none
http_access deny CONNECT !SSL_ports spm_r_port_policy

# Allow whitelisted + local network destinations before blocking direct IPs
http_access allow ip_whitelist spm_r_none
http_access allow local_dst spm_r_none

http_access deny direct_ip_url spm_r_direct_ip
http_access deny direct_ip_host spm_r_direct_ip
http_access deny direct_ipv6_url spm_r_direct_ip
http_access deny direct_ipv6_host spm_r_direct_ip
http_access deny CONNECT direct_ip_host spm_r_direct_ip
http_access deny CONNECT direct_ipv6_host spm_r_direct_ip
http_access allow localnet spm_r_none
http_access allow localhost spm_r_none
http_access deny all spm_r_other

# Caching
cache_mem ${SQUID_MEM_MB} MB
maximum_object_size_in_memory 512 KB
memory_replacement_policy lru
cache_replacement_policy heap LFUDA
cache_dir ufs /var/spool/squid ${SQUID_CACHE_MB} 16 256
maximum_object_size 100 MB
coredump_dir /var/spool/squid

# Connection performance tuning
client_persistent_connections on
server_persistent_connections on
pipeline_prefetch on
dns_v4_first on
request_body_max_size 10 MB
reply_body_max_size 200 MB
max_filedesc 65535

# Refresh patterns — base (conservative)
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320

# Cache manager: reachable from localhost only (http_access above).
cachemgr_passwd none info menu

# Custom branded error pages
error_directory /etc/squid/error-pages

# ICAP WAF
icap_enable on
icap_send_client_ip on
icap_send_client_username on
icap_client_username_encode off
icap_client_username_header X-Client-Username
icap_preview_enable on
icap_preview_size 4096
icap_service service_req reqmod_precache bypass=${ICAP_REQMOD_BYPASS} icap://waf:1344/waf
adaptation_access service_req deny spm_self_mgr
adaptation_access service_req allow all
icap_service service_resp respmod_precache bypass=1 icap://waf:1344/waf
adaptation_access service_resp deny spm_self_mgr
adaptation_access service_resp allow all

# Logging: keep volume growth bounded: lower verbosity, disable the noisy
# store log, and keep 5 rotations (a daily 'squid -k rotate' is triggered by the
# blacklist watchdog sidecar).
debug_options ALL,1
logfile_rotate 5
# Custom 'spm' logformat = the 10 stock 'squid' fields IN EXACT ORDER (the
# backend's parseSquidLine is positional and requires >=10 of them, so these must
# not change) + an 11th field carrying the WAF correlation id. The WAF stamps
# X-WAF-Event-Id on the 403 it returns via ICAP REQMOD; %{...}<h reads it from the
# reply headers. Allowed requests carry no such header → Squid logs '-' there,
# which parseSquidLine treats as empty (issue #107).
# 12th field: the spm_reason note set by the access rule that decided the
# request (see the spm_r_* ACLs). 13th field: the X-SPM-Reason header of the
# last ICAP response, which the WAF sets to "waf" on every block it returns. It
# is read from the ICAP reply, not the HTTP one, so an upstream server cannot
# forge it. Both log '-' when absent. Measured on Squid 7.7: docs/design/block-reasons.md.
logformat spm %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt %{X-WAF-Event-Id}<h %{spm_reason}note %{X-SPM-Reason}adapt::<last_h
# A connection that closes before it sends a request has nothing to log, yet
# Squid logs it as "NONE_NONE/000 - error:transaction-end-before-headers"
# (measured on 7.7). The backend's proxy health probe is exactly that: it
# connects and closes, every 30 s per open UI tab, and the access log the
# product analyses filled with its rows. Only transactions with a request are
# logged; a request Squid cannot parse is still one ("- / NONE_NONE/400").
acl spm_has_request has request
access_log daemon:/var/log/squid/access.log spm !spm_self_mgr spm_has_request
cache_log /var/log/squid/cache.log
cache_store_log none

# Timeouts
connect_timeout 30 seconds
dns_timeout 5 seconds

# Squid caches a DNS answer for its TTL, up to positive_dns_ttl (6 hours by
# default), and 'squid -k reconfigure' does not clear that cache. Domains are
# blocked by the dnsmasq sinkhole, so a domain that had just been visited kept
# being served from the cached address after it was blacklisted (measured:
# example.org still 200 after dnsmasq answered 0.0.0.0, and after a
# reconfigure). dnsmasq is local, so a one-minute cap costs nothing and bounds
# how long a newly blacklisted domain stays reachable.
positive_dns_ttl 1 minute

# ── Protocol Hardening ───────────────────────────────────────────────────────

# Strip internal topology from outbound requests
via off
forwarded_for delete
request_header_access X-Forwarded-For deny all

# No HSTS injection. It was added to every proxied response: over plain HTTP
# browsers ignore it (RFC 6797 8.1), and with SSL bump on it told every client
# that every third-party site and all its subdomains are HTTPS-only for a
# year, which outlives the proxy and breaks HTTP-only subdomains.


# Strip Expect: 100-continue (anti-smuggling)
request_header_access Expect deny all

# Strip non-standard outbound headers (reduce attack surface)
request_header_access X-Forwarded-Host deny all
request_header_access X-Forwarded-Proto deny all
request_header_access Proxy-Connection deny all

# Limit request body size (10MB default, prevents exfiltration of large dumps)
request_body_max_size 10 MB

# Limit request header size (prevents header-based buffer overflow/exfil)
request_header_max_size 64 KB

# Outbound TLS hardening — disable obsolete protocols, prefer modern ciphers.
# Applies to direct CONNECT tunneling and (when enabled) SSL-bump origin
# connections. NO_SSLv3,NO_TLSv1,NO_TLSv1_1 covers the obsolete versions;
# we keep TLSv1.2+TLSv1.3 for compatibility with the long tail of older
# legitimate origins. Cipher list mandates ECDHE forward secrecy + AEAD.
tls_outgoing_options options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1 cipher=ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!3DES:!RC4

CONFEOF

# ── Apply generated config, then append custom extras ────────────────────────

cp /etc/squid/squid.conf.base "$SQUID_CONF"

# Append custom directives (extras only — do NOT override the entire config).
# Migration: if old custom_squid.conf exists, rename to custom_squid_extra.conf.
if [ -f /config/custom_squid.conf ] && [ ! -f /config/custom_squid_extra.conf ]; then
    echo "Migrating custom_squid.conf → custom_squid_extra.conf (append-only mode)"
    mv /config/custom_squid.conf /config/custom_squid_extra.conf
fi
# A complete squid.conf is not an "extra". The legacy config/custom_squid.conf
# that shipped in the repository was one, and through the migration above it
# was appended to every generated config: a second http_port, cache_dir,
# access_log and ICAP service, plus a second rule set after "deny all".
if [ -f /config/custom_squid_extra.conf ] && \
   grep -qE '^[[:space:]]*(http_port|https_port|icap_service|cache_dir|access_log)([[:space:]]|$)' /config/custom_squid_extra.conf; then
    echo "WARNING: /config/custom_squid_extra.conf looks like a full squid.conf (it defines http_port, icap_service, cache_dir or access_log), so it is NOT appended. Keep only extra directives in it."
elif [ -f /config/custom_squid_extra.conf ] && [ "${SPM_SKIP_EXTRAS:-0}" = 1 ]; then
    echo "WARNING: SPM_SKIP_EXTRAS=1, so /config/custom_squid_extra.conf is NOT applied"
elif [ -f /config/custom_squid_extra.conf ]; then
    echo "Appending custom directives from /config/custom_squid_extra.conf"
    echo "" >> "$SQUID_CONF"
    echo "# ── Custom extras (from custom_squid_extra.conf) ──" >> "$SQUID_CONF"
    cat /config/custom_squid_extra.conf >> "$SQUID_CONF"
fi

# ── Ensure critical security rules are present ──────────────────────────────

ensure_ip_blocking_rules "$SQUID_CONF"

# ── Extra SSL Ports (from Settings > extra_ssl_ports) ──────────────────────
if [ -n "$EXTRA_SSL_PORTS" ]; then
    echo "Adding extra SSL ports: $EXTRA_SSL_PORTS"
    for p in ${EXTRA_SSL_PORTS//,/ }; do
        # Validate: must be a number 1-65535
        if echo "$p" | grep -qE '^[0-9]+$' && [ "$p" -ge 1 ] && [ "$p" -le 65535 ]; then
            if ! grep -q "acl SSL_ports port $p" "$SQUID_CONF"; then
                sed -i "/^acl SSL_ports port 8443/a acl SSL_ports port $p" "$SQUID_CONF"
                echo "  Added SSL_port $p"
            fi
        else
            echo "  Skipping invalid port: $p"
        fi
    done
fi

# ── GUI_IP_WHITELIST: extra client SOURCES allowed to use the proxy ─────────
# This used to emit "acl gui_override dst ..." plus allow rules ahead of the
# port checks, which is the opposite of what DEPLOYMENT.md documents: it made
# the listed address a destination ANY source could CONNECT to on any port,
# and gave the listed client nothing. Each entry is now validated and written
# to the file the localnet ACL reads. Commas and spaces both separate entries.
if [ -n "$GUI_IP_WHITELIST" ]; then
    for entry in $(printf '%s' "$GUI_IP_WHITELIST" | tr ',' ' '); do
        if printf '%s' "$entry" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$|^[0-9a-fA-F:]*:[0-9a-fA-F:]*(/[0-9]{1,3})?$'; then
            echo "$entry" >> /etc/squid/extra_clients.txt
            echo "  Extra proxy client source: $entry"
        else
            echo "  Skipping invalid GUI_IP_WHITELIST entry: $entry"
        fi
    done
fi

# ── Egress destination allowlist (default-deny) — conditional on toggle ──────
# When /config/egress_default_deny exists, a localnet client may reach ONLY
# destinations in the allowlists (IP/CIDR via `dst`, domain via `dstdomain`);
# anything else falls through to the final "deny all". This flips the forward
# proxy from default-allow-destination to default-deny-destination — the basis
# for a sovereign / EU-strict egress. Allowed IPs (ip_whitelist, a dst ACL:
# destinations, not sources) and local infrastructure (local_dst) are allowed
# earlier and stay reachable.
# The allowlist files always exist (managed by the backend + watchdog); only the
# enforcement rule is gated by the toggle, so removing the toggle restores the
# prior default-allow behaviour.
mkdir -p /etc/squid/allowlists/dst_ip /etc/squid/allowlists/dst_domain
touch /etc/squid/allowlists/dst_ip/local.txt /etc/squid/allowlists/dst_domain/local.txt

if [ -f /config/egress_default_deny ]; then
    echo "Egress default-deny ENABLED: localnet reaches only allowlisted destinations"
    # ACLs: destination IP/CIDR allowlist + destination domain allowlist. Inject
    # once, at the first "acl CONNECT" (Squid evaluates the first matching
    # http_access rule, so the first rule block is authoritative).
    sed -i '0,/^acl CONNECT method CONNECT$/s|^acl CONNECT method CONNECT$|acl CONNECT method CONNECT\nacl egress_dst_allow_ip dst "/etc/squid/allowlists/dst_ip/local.txt"\nacl egress_dst_allow_dom dstdomain "/etc/squid/allowlists/dst_domain/local.txt"|' "$SQUID_CONF"
    # Deny any localnet client whose destination is in neither allowlist,
    # immediately before the first catch-all "http_access allow localnet".
    sed -i '0,/^http_access allow localnet spm_r_none$/s|^http_access allow localnet spm_r_none$|http_access deny localnet !egress_dst_allow_ip !egress_dst_allow_dom spm_r_egress_policy\nhttp_access allow localnet spm_r_none|' "$SQUID_CONF"

    # FAIL-CLOSED VERIFICATION. The toggle promises default-deny egress; a silent
    # default-allow (e.g. if the anchors above drifted and the sed no-op'd) would
    # be a security regression, not a cosmetic one. If the precise deny rule did
    # not land, retry with a whitespace-tolerant anchor; if it still isn't there,
    # neutralise the catch-all localnet allow so non-allowlisted egress falls
    # through to the final "http_access deny all" (hard fail-closed) rather than
    # leaking open.
    DENY_RULE='http_access deny localnet !egress_dst_allow_ip !egress_dst_allow_dom spm_r_egress_policy'
    if ! grep -qF "$DENY_RULE" "$SQUID_CONF"; then
        echo "WARNING: egress deny rule not injected via primary anchor; applying tolerant fallback"
        grep -qF 'acl egress_dst_allow_ip dst' "$SQUID_CONF" || \
            sed -i 's|^[[:space:]]*acl CONNECT method CONNECT.*|&\nacl egress_dst_allow_ip dst "/etc/squid/allowlists/dst_ip/local.txt"\nacl egress_dst_allow_dom dstdomain "/etc/squid/allowlists/dst_domain/local.txt"|' "$SQUID_CONF"
        # Insert the deny immediately before any localnet allow (leading/internal
        # whitespace and trailing tokens tolerated). "&" re-emits the matched
        # allow line after.
        sed -i "s|^[[:space:]]*http_access[[:space:]]\\+allow[[:space:]]\\+localnet.*|${DENY_RULE}\\n&|" "$SQUID_CONF"
    fi
    if ! grep -qF "$DENY_RULE" "$SQUID_CONF"; then
        echo "CRITICAL: could not enforce egress default-deny; denying ALL localnet egress (fail-closed)"
        sed -i 's|^[[:space:]]*http_access[[:space:]]\+allow[[:space:]]\+localnet.*|# egress default-deny: enforcement injection failed, fail-closed\nhttp_access deny localnet spm_r_egress_policy|' "$SQUID_CONF"
    else
        echo "Egress default-deny enforcement rule verified present"
    fi
fi

# ── SSL Bump (HTTPS Inspection) — conditional on toggle file ─────────────

if [ -f /config/ssl_bump_enabled ]; then
    echo "SSL Bump ENABLED: injecting HTTPS interception config"

    # Replace http_port with https_port + ssl-bump
    sed -i 's/^http_port 3128$/http_port 3128 ssl-bump \\\n  cert=\/config\/ssl_cert.pem \\\n  key=\/config\/ssl_key.pem \\\n  generate-host-certificates=on \\\n  dynamic_cert_mem_cache_size=4MB/' "$SQUID_CONF"

    # Add ssl_bump directives before the first http_access line
    SSL_BUMP_BLOCK=$(cat <<'SSLEOF'

# ── SSL Bump (HTTPS Inspection) ────────────────────────────────────────────
sslcrtd_program /usr/lib/squid/security_file_certgen -s /config/ssl_db -M 4MB
sslcrtd_children 3 startup=1 idle=1

# Peek at TLS ClientHello to get SNI, then bump (intercept) the connection
acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all

# Upstream TLS certificate verification — only allow errors for the
# locally-generated proxy CA, not arbitrary invalid/expired certs.
# sslproxy_cert_error deny all   (default — Squid rejects bad upstream certs)
# Note: removed blanket DONT_VERIFY_PEER to prevent MITM on upstream connections.

SSLEOF
)
    # Insert before the first "http_access" line
    sed -i "/^http_access/i\\${SSL_BUMP_BLOCK}" "$SQUID_CONF" 2>/dev/null || \
        echo "$SSL_BUMP_BLOCK" >> "$SQUID_CONF"

    echo "SSL Bump config injected. WAF can now inspect HTTPS content."
else
    echo "SSL Bump disabled (no /config/ssl_bump_enabled file)"
fi

# ── Aggressive Caching (toggle via settings) ────────────────────────────────

if [ -f /config/aggressive_caching_enabled ]; then
    echo "Aggressive caching ENABLED: adding override-expire refresh patterns"
    cat >> "$SQUID_CONF" << 'CACHEEOF'

# ── Aggressive caching (override-expire for static assets) ──
refresh_pattern -i \.(jpg|jpeg|png|gif|ico|svg|webp|woff|woff2|ttf|eot|css|js)$ 10080 90% 518400 override-expire override-lastmod reload-into-ims
refresh_pattern -i \.(rpm|deb|tar|gz|bz2|xz|zip|tgz|pkg)$ 1440 90% 10080 override-expire
refresh_pattern -i \.(mp4|mp3|avi|mkv|flac|ogg|webm)$ 10080 80% 518400 override-expire
CACHEEOF
else
    echo "Aggressive caching disabled (default conservative refresh patterns)"
fi

# ── Cache Bypass Domains (from settings) ────────────────────────────────────

if [ -f /config/cache_bypass_domains.txt ] && [ -s /config/cache_bypass_domains.txt ]; then
    echo "Cache bypass domains found: adding no_cache rules"
    echo "" >> "$SQUID_CONF"
    echo "# ── Cache bypass domains ──" >> "$SQUID_CONF"
    echo "acl cache_bypass_domains dstdomain \"/config/cache_bypass_domains.txt\"" >> "$SQUID_CONF"
    echo "cache deny cache_bypass_domains" >> "$SQUID_CONF"
    echo "Cache bypass configured for $(wc -l < /config/cache_bypass_domains.txt) domains"
fi

# ── Proxy Authentication (Basic Auth for proxy users) ──────────────────────
# The password file is written by the backend when proxy credentials are saved
# in Settings, Clients and access, Login (a bcrypt line per user). The
# BASIC_AUTH_* block below is kept for an operator who passes those variables
# to this container by hand; no shipped compose file does.
#
# The outcome is written to PROXY_AUTH_STATUS for the backend, which shows it
# on the dashboard: off, enforced, or no_credentials (login is on and there is
# no usable password file, so every client is refused).

PROXY_AUTH_STATUS="${PROXY_AUTH_STATUS:-/config/proxy_auth_status.json}"
PROXY_USERS_FILE=/config/proxy_users.htpasswd

write_proxy_auth_status() { # state users
    local tmp
    tmp="$(mktemp "${PROXY_AUTH_STATUS}.XXXXXX" 2>/dev/null)" || return 0
    printf '{"version":1,"state":"%s","users":%d,"written_at":%d}\n' "$1" "$2" "$(date +%s)" > "$tmp" \
        && chmod 0644 "$tmp" && mv -f "$tmp" "$PROXY_AUTH_STATUS"
    rm -f "$tmp" 2>/dev/null
    return 0
}

# proxy_users_count: the user lines basic_ncsa_auth would read ("name:hash",
# no comment, no blank). Zero means the helper would accept nobody.
proxy_users_count() {
    [ -f "$PROXY_USERS_FILE" ] || { echo 0; return; }
    grep -cE '^[^#[:space:]:][^:]*:[^[:space:]]+' "$PROXY_USERS_FILE" 2>/dev/null || true
}

if [ -f /config/proxy_auth_enabled ]; then
    echo "Proxy authentication ENABLED: requiring Basic Auth for proxy access"
    # An operator who passes BASIC_AUTH_USERNAME/PASSWORD to this container by
    # hand gets the file created from them, once, when it does not exist.
    if [ ! -f /config/proxy_users.htpasswd ]; then
        if [ -n "$BASIC_AUTH_USERNAME" ] && [ -n "$BASIC_AUTH_PASSWORD" ]; then
            # SECURE-SEC-02: the password goes in on STDIN, never as an argv
            # element. The previous `htpasswd -b ... "$BASIC_AUTH_PASSWORD"`
            # (and its `openssl passwd -apr1 "$..."` fallback) put the plaintext
            # in /proc/<pid>/cmdline for the life of the call, readable by
            # anything sharing the PID namespace — and this is the credential
            # that authenticates the whole management API, not a proxy-only one.
            #
            # SECURE-SEC-04: -6 is SHA-512 crypt. The previous -apr1 is a
            # 1000-iteration MD5 construction with no work factor, for the same
            # password the dashboard protects with bcrypt. htpasswd is not
            # installed in this image at all, so the -apr1 fallback was in fact
            # the ONLY path ever taken; openssl is the single path now rather
            # than a fallback behind a command that does not exist.
            # squid's basic_ncsa_auth verifies crypt(3) formats, $6$ included.
            umask 077
            printf '%s:%s\n' "$BASIC_AUTH_USERNAME" \
                "$(printf '%s' "$BASIC_AUTH_PASSWORD" | openssl passwd -6 -stdin)" \
                > /config/proxy_users.htpasswd
            echo "Created proxy auth file from BASIC_AUTH_USERNAME"
        fi
    fi
    proxy_users="$(proxy_users_count)"
    if [ "${proxy_users:-0}" -gt 0 ]; then
        # basic_ncsa_auth runs as the proxy user, and the umask above leaves the
        # file root:root 0600, so the helper could not open it and refused every
        # credential. Group-readable for proxy, on every generation, so a file
        # created by an earlier version is repaired too.
        chown root:proxy /config/proxy_users.htpasswd
        chmod 0640 /config/proxy_users.htpasswd
        # localhost is exempt (the container's own probes). authenticated stays
        # the LAST acl on the line: Squid answers 407 only when the rule that
        # denies is decided by an auth acl, otherwise the client gets a 403 and
        # is never asked for credentials. That is why spm_r_proxy_auth comes
        # before it rather than after: it is evaluated for every request that
        # reaches this rule, denied or not, and the allow rule that admits an
        # authenticated request clears it again (spm_r_none).
        insert_policy '# ── Proxy Authentication (Basic Auth) ──
auth_param basic program /usr/lib/squid/basic_ncsa_auth /config/proxy_users.htpasswd
auth_param basic realm Secure Proxy Manager
auth_param basic credentialsttl 8 hours
auth_param basic casesensitive on
acl authenticated proxy_auth REQUIRED
http_access deny !localhost spm_r_proxy_auth !authenticated' || { return 1 2>/dev/null || exit 1; }
        echo "Proxy auth configured with $proxy_users users"
        write_proxy_auth_status enforced "$proxy_users"
    else
        # Fail closed. Login is on and there is no user the helper could
        # accept, so leaving the auth rule out would let every client browse
        # without signing in while this script reported login as enabled.
        # Every client is refused instead (403, reason proxy_auth_unset) until
        # credentials are set; localhost stays exempt for the container's own
        # probes, as it is from the login itself.
        echo "WARNING: proxy login is on but no proxy credentials are set ($PROXY_USERS_FILE has no user): every client is refused until you set them in Settings, Clients and access, Login" >&2
        insert_policy '# ── Proxy login is on and no proxy credentials are set: refuse every client ──
http_access deny !localhost spm_r_proxy_auth_unset' || { return 1 2>/dev/null || exit 1; }
        write_proxy_auth_status no_credentials 0
    fi
else
    echo "Proxy authentication disabled (open for localnet)"
    write_proxy_auth_status off 0
fi

# ── Content Filtering (block downloads by file extension) ──────────────────

if [ -f /config/content_filtering_enabled ] && [ -f /config/blocked_file_types.txt ] && [ -s /config/blocked_file_types.txt ]; then
    echo "Content filtering ENABLED: blocking file types"
    # -i: the backend writes each extension as typed (\.exe$), and a server
    # serves /setup.EXE or /setup.Exe as readily as /setup.exe. Without it the
    # match was case-sensitive and only the lower-case spelling was refused.
    # The patterns themselves are unchanged: anchored to the end of the path.
    insert_policy '# ── Content filtering (blocked file extensions) ──
acl blocked_extensions urlpath_regex -i "/config/blocked_file_types.txt"
http_access deny blocked_extensions spm_r_content_filter' || { return 1 2>/dev/null || exit 1; }
    echo "Content filtering configured for $(wc -l < /config/blocked_file_types.txt) extensions"
else
    echo "Content filtering disabled"
fi

# ── Time-Based Access Restrictions ─────────────────────────────────────────

if [ -f /config/time_restrictions_enabled ] && [ -f /config/time_restrictions.conf ]; then
    echo "Time-based access restrictions ENABLED"
    load_settings /config/time_restrictions.conf \
        'TIME_START=([01][0-9]|2[0-3]):[0-5][0-9]' \
        'TIME_END=([01][0-9]|2[0-3]):[0-5][0-9]'
    if [ -z "${TIME_START:-}" ] || [ -z "${TIME_END:-}" ]; then
        echo "WARNING: time restrictions are enabled but /config/time_restrictions.conf has no valid TIME_START/TIME_END, so the restriction is NOT applied"
    else
    # Parse HH:MM into HH and MM
    START_H=$(echo "$TIME_START" | cut -d: -f1)
    START_M=$(echo "$TIME_START" | cut -d: -f2)
    END_H=$(echo "$TIME_END" | cut -d: -f1)
    END_M=$(echo "$TIME_END" | cut -d: -f2)
    insert_policy "# ── Time-based access restrictions ──
acl allowed_hours time MTWHFAS ${START_H}:${START_M}-${END_H}:${END_M}
http_access deny !allowed_hours localnet spm_r_time_restriction" || { return 1 2>/dev/null || exit 1; }
    echo "Access allowed only ${TIME_START}-${TIME_END}"
    fi
else
    echo "Time-based access restrictions disabled"
fi

# ── Bandwidth Throttling (Squid delay_pools) ──────────────────────────────

if [ -f /config/bandwidth_limits_enabled ] && [ -f /config/bandwidth_limits.conf ]; then
    echo "Bandwidth throttling ENABLED"
    load_settings /config/bandwidth_limits.conf \
        'BW_LIMIT_MBPS=[0-9]{1,6}' \
        'BW_PER_USER_KBPS=[0-9]{1,9}'
    # Convert Mbps to bytes/sec for aggregate, Kbps to bytes/sec for per-user
    AGG_BYTES=$(( ${BW_LIMIT_MBPS:-100} * 125000 ))
    USER_BYTES=${BW_PER_USER_KBPS:-0}
    if [ "$USER_BYTES" -gt 0 ] 2>/dev/null; then
        USER_BYTES=$(( USER_BYTES * 125 ))
    else
        USER_BYTES=-1
    fi
    cat >> "$SQUID_CONF" << BWEOF

# ── Bandwidth throttling ──
delay_pools 1
delay_class 1 2
delay_access 1 allow localnet
delay_parameters 1 ${AGG_BYTES}/${AGG_BYTES} ${USER_BYTES}/${USER_BYTES}
BWEOF
    echo "Bandwidth: aggregate=${BW_LIMIT_MBPS}Mbps per-user=${BW_PER_USER_KBPS}Kbps"
else
    echo "Bandwidth throttling disabled"
fi

# ── Offline Mode / Serve Stale Cache ────────────────────────────────────────

if [ -f /config/offline_mode_enabled ]; then
    echo "Offline mode ENABLED: serving stale cached content"
    cat >> "$SQUID_CONF" << 'OFFEOF'

# ── Offline mode: serve stale cache when origin is unreachable ──
offline_mode on
refresh_pattern . 525600 100% 525600 override-expire override-lastmod reload-into-ims ignore-reload ignore-no-store ignore-private
OFFEOF
fi

# ── Inject dnsmasq as DNS resolver (resolve container IP dynamically) ────────

# DNS: use dnsmasq for domain blackhole. Resolve WAF IP at boot time
# and replace the hostname in ICAP config so Squid doesn't need DNS for WAF.
DNS_IP=$(getent hosts dns 2>/dev/null | awk '{print $1}')
WAF_IP=$(getent hosts waf 2>/dev/null | awk '{print $1}')

if [ -n "$DNS_IP" ]; then
    if ! grep -q "dns_nameservers" "$SQUID_CONF"; then
        # Ensure newline before appending (fixes concatenation with last line)
        echo "" >> "$SQUID_CONF"
        echo "dns_nameservers $DNS_IP" >> "$SQUID_CONF"
    fi
    echo "DNS resolver: dnsmasq at $DNS_IP"
fi

# Replace 'waf' hostname with resolved IP in ICAP config (avoid DNS loop)
if [ -n "$WAF_IP" ]; then
    sed -i "s|icap://waf:|icap://$WAF_IP:|g" "$SQUID_CONF"
    echo "ICAP WAF: resolved waf → $WAF_IP"
fi

# ── Custom error pages (only for ACL denies, not replacing all errors) ────────

if [ -f /etc/squid/error-pages/ERR_ACCESS_DENIED ] && ! grep -q "deny_info" "$SQUID_CONF"; then
    echo "deny_info ERR_ACCESS_DENIED all" >> "$SQUID_CONF"
    # Copy our custom page as the default Squid error page location
    cp /etc/squid/error-pages/ERR_ACCESS_DENIED /usr/share/squid/errors/en/ERR_ACCESS_DENIED 2>/dev/null || true
    echo "Custom block page enabled for ACL denies"
fi

# ── Copy the lists from the config volume, verified ─────────────────────────
# Through the watchdog's own sync (blacklist_watchdog.py --sync-lists), at boot
# and on every regeneration: each list is copied only if its bytes match the
# manifest the backend writes after the lists. These were plain cp calls, so a
# torn or partial export became the live ACL at boot, and on any regeneration
# replaced the verified copy the watchdog had loaded. A refused list keeps the
# copy Squid holds; at boot there is none, an allowlist starts empty (allows
# less) and a blocklist closes the gate above (denies every client) until the
# watchdog copies a verified one. No manifest at all (a backend that predates
# it) copies without verification, with a warning, as the watchdog does.
if ! python3 -I "$SPM_LISTS" --sync-lists; then
    echo "CRITICAL: the lists could not be synced; Squid denies every client request until the watchdog syncs them" >&2
    echo all > /etc/squid/lists_gate.txt
fi
normalize_ip_lists /etc/squid/blacklists/ip/local.txt /etc/squid/whitelists/ip/local.txt /etc/squid/allowlists/dst_ip/local.txt
refresh_domain_acl

# Exit status must reflect whether the CONFIG was generated, not whether the
# last optional file happened to exist. Without this the script exited 1
# whenever /config/dst_allow_domain.txt was absent — the normal case on a fresh
# install and whenever the egress allowlist is empty — because the final
# `[ -f ... ] && cp` short-circuits and its test result becomes the exit status.
# Callers that check the return code (the watchdog now refuses to reconfigure
# on a failed generation, SECURE-ERR-07) would otherwise treat every successful
# run as a failure and never apply a change.
#
# `return` when sourced, `exit` when executed. This script has two callers with
# two invocation styles: the watchdog runs it as a subprocess, while startup.sh
# SOURCES it (it shares the helper functions). A bare `exit 0` terminates the
# sourcing shell — it silently killed startup.sh right here, before the
# directory setup, the swap init and the supervisord exec, so the container
# came up with no squid and no watchdog at all.
return 0 2>/dev/null || exit 0

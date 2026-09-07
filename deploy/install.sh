#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════════╗
# ║  Secure Proxy Manager — One-Click Installer                      ║
# ║  Usage: curl -fsSL https://raw.githubusercontent.com/            ║
# ║    fabriziosalmi/secure-proxy-manager/main/deploy/install.sh|bash║
# ╚═══════════════════════════════════════════════════════════════════╝
set -euo pipefail

REPO="https://github.com/fabriziosalmi/secure-proxy-manager.git"
INSTALL_DIR="/opt/secure-proxy-manager"
BRANCH="main"

C='\033[0;36m'; G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; N='\033[0m'; B='\033[1m'

info()  { printf "${C}[INFO]${N} %s\n" "$1"; }
ok()    { printf "${G}[OK]${N}   %s\n" "$1"; }
warn()  { printf "${Y}[WARN]${N} %s\n" "$1"; }
fail()  { printf "${R}[FAIL]${N} %s\n" "$1"; exit 1; }

# ── Host port preflight ───────────────────────────────────────────────
# A port already taken on the host is the most common reason a fresh install
# does not come up, and it is invisible: `docker compose up -d` reports the bind
# failure per container and the health wait then times out with a generic
# warning about services still starting (#231).
#
# The ports are read from the compose file rather than hardcoded, so this stays
# correct when the file changes.

published_ports() {
    # Host ports this compose file publishes, as "<bind address><TAB><port>".
    # Handles "80:8011", "127.0.0.1:5001:5000" and the substitution
    # "${PROXY_BIND_IP:-0.0.0.0}:3128:3128", whose default contains colons and
    # has to be resolved before splitting on them.
    sed -n 's/^[[:space:]]*-[[:space:]]*"\([^"]*\)".*/\1/p' "$1" \
    | sed -e 's/\${[A-Za-z_][A-Za-z0-9_]*:-\([^}]*\)}/\1/g' \
          -e 's/\${[A-Za-z_][A-Za-z0-9_]*}/0.0.0.0/g' \
    | grep -E '^[0-9.]*:?[0-9]+:[0-9]+(\/(tcp|udp))?$' \
    | sed 's:/.*::' \
    | awk -F: '
        {
            if (NF >= 3) { addr = $1; port = $2 }
            else         { addr = "0.0.0.0"; port = $1 }
            if (port ~ /^[0-9]+$/) print addr "\t" port
        }' \
    | sort -u -k2,2n || true
}

listening_snapshot() {
    # `ss` is present on any current Debian or RHEL; netstat is the fallback for
    # older hosts. Both are read once rather than per port.
    if command -v ss >/dev/null 2>&1; then
        ss -lntp 2>/dev/null
    elif command -v netstat >/dev/null 2>&1; then
        netstat -lntp 2>/dev/null
    fi
}

check_ports() {
    local compose_file="$1" snapshot conflicts=0 addr port holder
    snapshot=$(listening_snapshot)
    if [ -z "$snapshot" ]; then
        warn "Neither ss nor netstat is available — skipping the port check"
        return 0
    fi
    while IFS="$(printf '\t')" read -r addr port; do
        [ -n "$port" ] || continue
        # Column 4 of both tools is the local address; match on the port at its
        # end so 80 does not match 8080. The process column, when the tool
        # reports one, says what is holding it.
        holder=$(printf '%s\n' "$snapshot" | awk -v suffix=":$port" '
            NR > 1 && $4 ~ suffix"$" { print; exit }')
        if [ -n "$holder" ]; then
            conflicts=$((conflicts + 1))
            printf "${R}[PORT]${N} %s:%s is already in use\n" "$addr" "$port"
            printf "        %s\n" "$(printf '%s' "$holder" | tr -s ' ')"
        fi
    done <<PORTS
$(published_ports "$compose_file")
PORTS
    if [ "$conflicts" -gt 0 ]; then
        echo ""
        warn "Free the ports above, or change the host side of the mapping in"
        warn "  ${INSTALL_DIR}/docker-compose.yml, then run this installer again."
        warn "A web server on the host is the usual cause: systemctl stop nginx"
        warn "Set SKIP_PORT_CHECK=1 to install anyway."
        if [ "${SKIP_PORT_CHECK:-0}" = "1" ]; then
            warn "SKIP_PORT_CHECK=1 set — continuing despite the conflicts"
        else
            fail "$conflicts port conflict(s)"
        fi
    else
        ok "All published ports are free"
    fi
}


echo ""
printf "${C}╔═══════════════════════════════════════════════════════════╗${N}\n"
printf "${C}║${N}  ${B}Secure Proxy Manager — Installer${N}                       ${C}║${N}\n"
printf "${C}╚═══════════════════════════════════════════════════════════╝${N}\n"
echo ""

# ── Check root ────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || fail "Please run as root: sudo bash install.sh"

# ── Check OS ──────────────────────────────────────────────────────────
info "Detecting OS..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    ok "OS: $PRETTY_NAME"
else
    warn "Could not detect OS — continuing anyway"
fi

# ── Install Docker if missing ─────────────────────────────────────────
if command -v docker &>/dev/null; then
    ok "Docker: $(docker --version | head -1)"
else
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
    ok "Docker installed"
fi

# ── Install Docker Compose plugin if missing ──────────────────────────
if docker compose version &>/dev/null; then
    ok "Docker Compose: $(docker compose version --short)"
else
    info "Installing Docker Compose plugin..."
    apt-get update -qq && apt-get install -y -qq docker-compose-plugin 2>/dev/null \
        || yum install -y docker-compose-plugin 2>/dev/null \
        || fail "Could not install Docker Compose plugin"
    ok "Docker Compose installed"
fi

# ── Install git if missing ────────────────────────────────────────────
if ! command -v git &>/dev/null; then
    info "Installing git..."
    apt-get install -y -qq git 2>/dev/null || yum install -y git 2>/dev/null
fi

# ── Clone or update repo ─────────────────────────────────────────────
if [ -d "$INSTALL_DIR" ]; then
    info "Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull --ff-only origin "$BRANCH"
    cp deploy/docker-compose.prod.yml docker-compose.yml
    ok "Updated to latest"
else
    info "Cloning repository..."
    git clone --depth 1 -b "$BRANCH" "$REPO" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    cp deploy/docker-compose.prod.yml docker-compose.yml
    ok "Cloned to $INSTALL_DIR"
fi

# ── Generate .env if missing ─────────────────────────────────────────
if [ ! -f .env ]; then
    info "Generating .env with random credentials..."
    ADMIN_USER="admin"
    # Alphanumeric (no +/=) so it is typeable into a Basic-Auth dialog; still
    # ~119 bits of entropy. SECRET_KEY stays full-length hex (never typed).
    ADMIN_PASS=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20)
    SECRET_KEY=$(openssl rand -hex 32)

    cat > .env <<EOF
# Auto-generated by install.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ)
BASIC_AUTH_USERNAME=${ADMIN_USER}
BASIC_AUTH_PASSWORD=${ADMIN_PASS}
SECRET_KEY=${SECRET_KEY}
CORS_ALLOWED_ORIGINS=https://localhost:8443

# HTTPS: uncomment for Let's Encrypt (requires public domain + port 80)
# LETSENCRYPT_DOMAIN=
# LETSENCRYPT_EMAIL=

# WPAD: set to server LAN IP for browser auto-proxy discovery
# PROXY_IP=

# WAF: comma-separated categories to disable
# WAF_DISABLED_CATEGORIES=
EOF

    ok "Credentials generated"
    echo ""
    printf "  ${B}Username:${N} ${ADMIN_USER}\n"
    printf "  ${B}Password:${N} ${ADMIN_PASS}\n"
    echo ""
    warn "Save these credentials! They are also stored in ${INSTALL_DIR}/.env"
    echo ""
else
    ok ".env already exists — keeping current credentials"
fi

# ── Build and start ──────────────────────────────────────────────────
info "Pulling pre-built containers from GitHub Container Registry (GHCR)..."
docker compose pull --quiet

# Back up the data volume before launching new images that may run a DB
# migration (no-op on a fresh install). Keep the 3 most recent backups.
if [ -d data ]; then
    backup="data.bak.$(date +%Y%m%d-%H%M%S)"
    cp -a data "$backup" && ok "Backed up data/ -> ${backup}"
    ls -1dt data.bak.* 2>/dev/null | tail -n +4 | xargs -r rm -rf
fi

info "Checking host ports..."
check_ports docker-compose.yml

info "Starting services..."
docker compose up -d

# A container that cannot bind its port is left in a created or exited state,
# and a later `docker compose up -d` sees no change to the configuration and
# leaves it exactly as it is. That is why freeing the port was not enough in
# #231 and --force-recreate was needed. Recreate them here instead of leaving
# the operator to work it out from a health check that merely times out.
stuck=$(docker compose ps -a --format '{{.Service}} {{.State}}' 2>/dev/null \
        | awk '$2 != "running" { print $1 }' | tr '\n' ' ')
if [ -n "${stuck// /}" ]; then
    warn "Not running after start: ${stuck}"
    info "Recreating them (a container that failed to bind stays down otherwise)..."
    docker compose up -d --force-recreate
fi

# ── Wait for healthy ─────────────────────────────────────────────────
info "Waiting for services to be healthy..."
for _ in $(seq 1 30); do
    if curl -sk --max-time 2 https://localhost:8443/api/health 2>/dev/null | grep -q '"healthy"'; then
        break
    fi
    sleep 2
done

# ── Verify ───────────────────────────────────────────────────────────
if curl -sk --max-time 5 https://localhost:8443/api/health 2>/dev/null | grep -q '"healthy"'; then
    ok "Backend API healthy!"
else
    warn "Backend still starting — check: docker compose ps"
fi

# Smoke-test the actual product — the forward proxy — not just the API. This is
# what catches a proxy-side capability/permission regression the API check misses.
if docker compose exec -T proxy curl -s --max-time 8 -x http://127.0.0.1:3128 \
        -o /dev/null -w '%{http_code}' http://www.gstatic.com/generate_204 2>/dev/null | grep -q '204'; then
    ok "Forward proxy egress working (port 3128)"
else
    warn "Proxy egress not confirmed yet — check: docker compose logs proxy"
fi

# Surface every container's health so a silently-unhealthy one is visible.
echo ""
docker compose ps

# ── Print access info ────────────────────────────────────────────────
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo ""
printf "${G}╔═══════════════════════════════════════════════════════════╗${N}\n"
printf "${G}║${N}  ${B}Installation Complete!${N}                                   ${G}║${N}\n"
printf "${G}╠═══════════════════════════════════════════════════════════╣${N}\n"
printf "${G}║${N}                                                           ${G}║${N}\n"
printf "${G}║${N}  Dashboard:  ${B}https://${LOCAL_IP}:8443${N}                   ${G}║${N}\n"
printf "${G}║${N}  Proxy:      ${B}${LOCAL_IP}:3128${N}                            ${G}║${N}\n"
printf "${G}║${N}  API Docs:   ${B}https://${LOCAL_IP}:8443/api/docs${N}           ${G}║${N}\n"
printf "${G}║${N}                                                           ${G}║${N}\n"
printf "${G}║${N}  Configure your devices to use proxy ${B}${LOCAL_IP}:3128${N}    ${G}║${N}\n"
printf "${G}║${N}  Accept the self-signed cert on first visit.              ${G}║${N}\n"
printf "${G}║${N}                                                           ${G}║${N}\n"
printf "${G}╚═══════════════════════════════════════════════════════════╝${N}\n"
echo ""

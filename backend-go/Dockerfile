# ── stage 1: build ───────────────────────────────────────────────────────────
FROM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

WORKDIR /src
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# GIT_SHA is injected so an artefact can be traced to its tree. Without it the
# binary carried only a hand-maintained AppVersion, so every commit between two
# releases produced an indistinguishable binary (SECURE-BLD-02).
ARG GIT_SHA=unknown
RUN go build -trimpath \
    -ldflags="-s -w -X github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config.GitCommit=${GIT_SHA}" \
    -o /bin/server ./cmd/server

# ── stage 2: runtime ──────────────────────────────────────────────────────────
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# docker-cli was removed: no Go code invokes it, the compose files do not mount
# /var/run/docker.sock into this container, and shipping a host-root-equivalent
# client for a capability the service does not have pre-installs an escalation
# path for any future change that mounts the socket (SECURE-BLD-01).
# Distribution packages are installed without a version constraint. That is a
# deliberate trade-off: pinning an exact apk/apt version breaks the build the
# moment the repository rotates it, which for a project that rebuilds on every
# release costs more than it buys. The consequence is accepted and bounded —
# a rebuild of a tagged release resolves different package versions than the
# one that was published and signed, so a rebuild cannot be used to verify the
# original (SECURE-BLD-03).
#
# Where a package DOES carry security weight the version is asserted after
# install instead: see proxy/Dockerfile, which fails the build if squid-openssl
# is older than its CVE floor.
RUN apk add --no-cache ca-certificates

COPY --from=builder /bin/server /server

RUN mkdir -p /data /config /logs

EXPOSE 5000
# Runs as root, like the sibling proxy/dns/waf containers. The intended
# deployment target is nested/unprivileged LXC (Proxmox), where:
#   - bind-mounted ./data and ./config are owned by the host's root and are
#     not writable by an unprivileged UID, so a non-root server cannot create
#     the SQLite DB or the encryption key;
#   - dropping privileges via su-exec/gosu fails ("setgroups: Operation not
#     permitted") because CAP_SETGID is unavailable;
# (The docker.sock clause that used to be listed here is gone: the socket is
# not mounted into this container and no code calls the Docker API.)
# Running as root is the reliable, portable choice here; harden with
# userns-remap at the daemon level if a non-root server is required.
ENTRYPOINT ["/server"]

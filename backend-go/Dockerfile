# ── stage 1: build ───────────────────────────────────────────────────────────
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

WORKDIR /src
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /bin/server ./cmd/server

# ── stage 2: runtime ──────────────────────────────────────────────────────────
FROM alpine:3.21@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

RUN apk add --no-cache ca-certificates docker-cli

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
#   - the docker.sock used to reconfigure Squid is root-owned.
# Running as root is the reliable, portable choice here; harden with
# userns-remap at the daemon level if a non-root server is required.
ENTRYPOINT ["/server"]

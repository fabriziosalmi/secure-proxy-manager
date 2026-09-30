# Pin: golang 1.24.2 alpine 3.21 (2025-04)
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# GIT_SHA is injected so a running WAF can say which commit it was built from
# (/health and waf_build_info); -trimpath keeps the builder's paths out of the
# binary. Same treatment as the backend image.
ARG GIT_SHA=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.GitCommit=${GIT_SHA}" \
    -o waf-server .

# Pin: alpine 3.21.3 (2025-03)
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk --no-cache add ca-certificates tzdata \
    && addgroup -g 1000 waf && adduser -u 1000 -G waf -s /bin/sh -D waf

WORKDIR /app
COPY --from=builder /app/waf-server .
RUN chown waf:waf /app/waf-server

# Persistent, writable sink for the traffic feature log (issue #112). Created
# owned by waf so that when the empty `waf-traffic` named volume is first mounted
# here, Docker seeds it with waf:waf ownership — writable by the non-root process
# even under a read_only root filesystem, and surviving restarts (unlike the
# /tmp tmpfs fallback). WAF_TRAFFIC_LOG_PATH points the logger at this dir.
RUN mkdir -p /var/lib/waf && chown waf:waf /var/lib/waf

USER waf

EXPOSE 1344
EXPOSE 8080

CMD ["./waf-server"]

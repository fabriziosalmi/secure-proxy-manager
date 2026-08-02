# Pin: golang 1.24.2 alpine 3.21 (2025-04)
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o waf-server .

# Pin: alpine 3.21.3 (2025-03)
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
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

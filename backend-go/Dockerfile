# ── stage 1: build ───────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /src
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /bin/server ./cmd/server

# ── stage 2: runtime ──────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates docker-cli \
    && adduser -D -u 1000 app

COPY --from=builder /bin/server /server

# Create dirs that will be mounted as volumes
RUN mkdir -p /data /config /logs && chown -R app:app /data /config /logs

USER app
EXPOSE 5000
ENTRYPOINT ["/server"]

# ── stage 1: build ───────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /src
# Pure-Go SQLite driver: no CGO needed.
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /bin/server ./cmd/server

# ── stage 2: runtime ──────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /bin/server /server

# Non-root UID (65532 = nonroot in distroless).
USER 65532:65532

EXPOSE 5000
ENTRYPOINT ["/server"]

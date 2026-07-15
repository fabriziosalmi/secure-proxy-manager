# Pin: golang 1.24.2 alpine 3.21 (2025-04)
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o waf-server .

# Pin: alpine 3.21.3 (2025-03)
FROM alpine:3.21.3@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
RUN apk --no-cache add ca-certificates tzdata \
    && addgroup -g 1000 waf && adduser -u 1000 -G waf -s /bin/sh -D waf

WORKDIR /app
COPY --from=builder /app/waf-server .
RUN chown waf:waf /app/waf-server

USER waf

EXPOSE 1344
EXPOSE 8080

CMD ["./waf-server"]

# Pin: golang 1.24.2 alpine 3.21 (2025-04)
FROM golang:1.24.2-alpine3.21 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o waf-server .

# Pin: alpine 3.21.3 (2025-03)
FROM alpine:3.21.3
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/waf-server .

EXPOSE 1344
EXPOSE 8080

CMD ["./waf-server"]

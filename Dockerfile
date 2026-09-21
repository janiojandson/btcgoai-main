# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=1.0.0" \
    -o /worker ./cmd/worker

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /worker /app/worker

ENV HUB_URL=https://puzzleradar-production.up.railway.app \
    WORKER_NAME="" \
    LANES=1024 \
    LOG_LEVEL=info \
    HARDWARE_TYPE="CPU_GO_MONTGOMERY"

EXPOSE 8080

ENTRYPOINT ["/app/worker"]
FROM docker.io/library/golang:latest AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o fluxgate ./cmd/fluxgate

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates sqlite3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/fluxgate /usr/local/bin/fluxgate
ENTRYPOINT ["fluxgate"]

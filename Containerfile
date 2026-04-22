# Base image digests pinned for reproducibility.
# To update: docker pull <image>, then docker inspect --format '{{index .RepoDigests 0}}'
# Last pinned: 2026-04-22
FROM docker.io/library/golang:1.26.1@sha256:cd78d88e00afadbedd272f977d375a6247455f3a4b1178f8ae8bbcb201743a8a AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o fluxgate ./cmd/fluxgate

FROM docker.io/library/debian:bookworm-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates sqlite3 && rm -rf /var/lib/apt/lists/* && \
    useradd -r -u 1001 -s /usr/sbin/nologin fluxgate
COPY --from=builder /build/fluxgate /usr/local/bin/fluxgate
USER fluxgate
ENTRYPOINT ["fluxgate"]

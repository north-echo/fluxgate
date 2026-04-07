FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /fluxgate ./cmd/fluxgate

FROM alpine:3.21
RUN apk add --no-cache ca-certificates git
COPY --from=build /fluxgate /usr/local/bin/fluxgate
ENTRYPOINT ["fluxgate"]

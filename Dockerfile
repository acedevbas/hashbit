FROM golang:1.22-alpine AS builder

# CGO is required for anacrolix/go-libutp (C++ reference μTP implementation).
# Without libutp the fingerprint API can only probe TCP peers and misses
# ~30% of residential-NAT seeders that talk μTP exclusively. The builder
# stage installs g++/musl-dev; the runtime stage adds libstdc++.
RUN apk add --no-cache git gcc g++ musl-dev

WORKDIR /src
ENV GOFLAGS="-mod=mod"

# copy module files first for better caching
COPY go.mod ./
COPY go.sum* ./
RUN go mod download 2>/dev/null || true

COPY . .
RUN go mod tidy
# -ldflags="-s -w" strips debug info; cgo keeps runtime symbols it needs.
# GOOS=linux is explicit so cross-builds from macOS/Windows produce
# linux/amd64 without surprises.
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /out/server ./cmd/server


FROM alpine:3.19
# libstdc++ is the runtime counterpart of the builder's g++. musl's dynamic
# loader resolves it at /usr/lib/libstdc++.so.6 on startup. Without this
# the container exits immediately with "Error loading shared library".
RUN apk add --no-cache ca-certificates tzdata curl libstdc++ \
    && adduser -D -u 10001 app

WORKDIR /app
COPY --from=builder /out/server /app/server

USER app
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/app/server"]

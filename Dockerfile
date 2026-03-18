# HiVoid cross-build Dockerfile
# Targets:
#   Windows amd64/386 → .exe (static)
#   Linux   amd64/386 → binary (static)
#
# Output naming: hivoid-core-{OS}-{arch}-{role}-{version}.zip
#   role = Client | Server

FROM golang:1.26-alpine AS base

WORKDIR /src

RUN apk add --no-cache \
    git ca-certificates tzdata musl-dev file zip

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .


# ── Dev stages ───────────────────────────────────────────────────────────────
FROM base AS dev-server
ENTRYPOINT ["go", "run", "./cmd/server"]
CMD ["--help"]

FROM base AS dev-client
ENTRYPOINT ["go", "run", "./cmd/client"]
CMD ["--help"]


# ── Builder ───────────────────────────────────────────────────────────────────
# Pass version at build time:
#   docker build --build-arg VERSION=1.2.3 ...
# Defaults to "dev" if not supplied.
FROM base AS builder

ARG VERSION=v0.4.0

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eux && \
    mkdir -p /dist && \
    export GOFLAGS="-trimpath" && \
    export CGO_ENABLED=0 && \
    export LDFLAGS="-s -w" && \
    \
    # ── Windows amd64 ──────────────────────────────────────────────────────
    echo "Building Windows amd64 Client ..." && \
    GOOS=windows GOARCH=amd64 go build \
        -ldflags "${LDFLAGS}" \
        -o /tmp/hivoid-core.exe \
        ./cmd/client && \
    zip /dist/hivoid-core-windows-amd64-Client-${VERSION}.zip \
        -j /tmp/hivoid-core.exe && \
    rm /tmp/hivoid-core.exe && \
    \
    echo "Building Windows amd64 Server ..." && \
    GOOS=windows GOARCH=amd64 go build \
        -ldflags "${LDFLAGS}" \
        -o /tmp/hivoid-core.exe \
        ./cmd/server && \
    zip /dist/hivoid-core-windows-amd64-Server-${VERSION}.zip \
        -j /tmp/hivoid-core.exe && \
    rm /tmp/hivoid-core.exe && \
    \
    # ── Windows 386 ────────────────────────────────────────────────────────
    echo "Building Windows 386 Client ..." && \
    GOOS=windows GOARCH=386 go build \
        -ldflags "${LDFLAGS}" \
        -o /tmp/hivoid-core.exe \
        ./cmd/client && \
    zip /dist/hivoid-core-windows-386-Client-${VERSION}.zip \
        -j /tmp/hivoid-core.exe && \
    rm /tmp/hivoid-core.exe && \
    \
    echo "Building Windows 386 Server ..." && \
    GOOS=windows GOARCH=386 go build \
        -ldflags "${LDFLAGS}" \
        -o /tmp/hivoid-core.exe \
        ./cmd/server && \
    zip /dist/hivoid-core-windows-386-Server-${VERSION}.zip \
        -j /tmp/hivoid-core.exe && \
    rm /tmp/hivoid-core.exe && \
    \
    # ── Linux amd64 ────────────────────────────────────────────────────────
    echo "Building Linux amd64 Client ..." && \
    GOOS=linux GOARCH=amd64 go build \
        -ldflags "${LDFLAGS}" \
        -o /tmp/hivoid-core \
        ./cmd/client && \
    zip /dist/hivoid-core-linux-amd64-Client-${VERSION}.zip \
        -j /tmp/hivoid-core && \
    rm /tmp/hivoid-core && \
    \
    echo "Building Linux amd64 Server ..." && \
    GOOS=linux GOARCH=amd64 go build \
        -ldflags "${LDFLAGS}" \
        -o /tmp/hivoid-core \
        ./cmd/server && \
    zip /dist/hivoid-core-linux-amd64-Server-${VERSION}.zip \
        -j /tmp/hivoid-core && \
    rm /tmp/hivoid-core && \
    \
    # ── Linux 386 ──────────────────────────────────────────────────────────
    echo "Building Linux 386 Client ..." && \
    GOOS=linux GOARCH=386 go build \
        -ldflags "${LDFLAGS}" \
        -o /tmp/hivoid-core \
        ./cmd/client && \
    zip /dist/hivoid-core-linux-386-Client-${VERSION}.zip \
        -j /tmp/hivoid-core && \
    rm /tmp/hivoid-core && \
    \
    echo "Building Linux 386 Server ..." && \
    GOOS=linux GOARCH=386 go build \
        -ldflags "${LDFLAGS}" \
        -o /tmp/hivoid-core \
        ./cmd/server && \
    zip /dist/hivoid-core-linux-386-Server-${VERSION}.zip \
        -j /tmp/hivoid-core && \
    rm /tmp/hivoid-core && \
    \
    echo "===== ARTIFACTS =====" && \
    ls -lh /dist


# ── Final image (scratch – only the zips) ────────────────────────────────────
FROM scratch AS artifacts
COPY --from=builder /dist /

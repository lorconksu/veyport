# Build args allow CI to override private DHI base images with public equivalents
ARG NODE_IMAGE=dhi.io/node:25-debian13-dev
ARG GO_IMAGE=dhi.io/golang:1.26.3-debian13-dev

# Stage 1: Build frontend (DHI hardened Node)
FROM ${NODE_IMAGE} AS frontend
WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: Build Hub + Agent binaries (DHI hardened Go)
FROM ${GO_IMAGE} AS backend
# Ensure gcc and libc6-dev are present for CGO/SQLite (no-op if already installed in DHI image)
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/* || true
WORKDIR /app

# Copy proto module (shared dependency)
COPY proto/ proto/

# Build Hub (needs CGO for SQLite)
COPY hub/ hub/
COPY --from=frontend /app/web/dist hub/web/dist
ARG VERSION=dev
RUN cd hub && CGO_ENABLED=1 go build -ldflags="-s -w -X github.com/wyiu/veyport/hub/internal/server.Version=${VERSION}" -o /out/veyport ./cmd/veyport/

# Build Agent (pure Go, cross-compile for linux/amd64 and linux/arm64)
COPY agent/ agent/
RUN cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /out/veyport-agent-linux-amd64 ./cmd/veyport-agent/
RUN cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o /out/veyport-agent-linux-arm64 ./cmd/veyport-agent/
RUN sha256sum /out/veyport-agent-linux-amd64 | awk '{print $1}' > /out/veyport-agent-linux-amd64.sha256
RUN sha256sum /out/veyport-agent-linux-arm64 | awk '{print $1}' > /out/veyport-agent-linux-arm64.sha256

# Stage 3: Minimal runtime (Wolfi — glibc-based, fast CVE patching, no systemd/ncurses/tar)
FROM cgr.dev/chainguard/wolfi-base:latest
# Wolfi pins core packages in /etc/apk/world, so request patched glibc builds explicitly.
RUN apk add --no-cache ca-certificates-bundle tzdata \
    "glibc>=2.43-r7" \
    "glibc-locale-posix>=2.43-r7" \
    "ld-linux>=2.43-r7" \
    "libcrypt1>=2.43-r7" && \
    adduser -D -s /bin/false veyport && \
    mkdir -p /data && chown veyport:veyport /data

WORKDIR /app

COPY --from=backend /out/veyport /app/veyport
COPY --from=backend /out/veyport-agent-linux-amd64 /app/veyport-agent-linux-amd64
COPY --from=backend /out/veyport-agent-linux-arm64 /app/veyport-agent-linux-arm64
COPY --from=backend /out/veyport-agent-linux-amd64.sha256 /app/veyport-agent-linux-amd64.sha256
COPY --from=backend /out/veyport-agent-linux-arm64.sha256 /app/veyport-agent-linux-arm64.sha256
COPY hub/static/install.sh /app/static/install.sh

RUN chown -R veyport:veyport /app
USER veyport

VOLUME /data
EXPOSE 8081 9090

ENTRYPOINT ["/app/veyport"]
CMD ["--addr", ":8081", "--grpc-addr", ":9090", "--db", "/data/veyport.db", "--agent-bin-dir", "/app"]

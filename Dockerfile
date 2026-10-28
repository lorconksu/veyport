# Build args allow CI to override private DHI base images with public equivalents
ARG NODE_IMAGE=dhi.io/node:25-debian13-dev
ARG GO_IMAGE=dhi.io/golang:1.26.10-debian13-dev
ARG RUNTIME_IMAGE=cgr.dev/chainguard/wolfi-base:latest

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
RUN if ! command -v gcc >/dev/null 2>&1; then \
      apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*; \
    fi
WORKDIR /app

# Copy proto module (shared dependency)
COPY proto/ proto/

# Build Hub (needs CGO for SQLite)
COPY hub/ hub/
COPY --from=frontend /app/web/dist hub/web/dist
ARG VERSION=dev
ARG REVISION=unknown
# Keep Go symbol metadata so exact-binary vulnerability scans can distinguish
# installed vulnerable packages from unused module metadata.
RUN cd hub && CGO_ENABLED=1 go build -ldflags="-X github.com/wyiu/veyport/hub/internal/server.Version=${VERSION} -X github.com/wyiu/veyport/hub/internal/server.Revision=${REVISION}" -o /out/veyport ./cmd/veyport/

# Build Agent (pure Go, cross-compile for linux/amd64 and linux/arm64)
COPY agent/ agent/
RUN cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/veyport-agent-linux-amd64 ./cmd/veyport-agent/
RUN cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/veyport-agent-linux-arm64 ./cmd/veyport-agent/
RUN sha256sum /out/veyport-agent-linux-amd64 | awk '{print $1}' > /out/veyport-agent-linux-amd64.sha256
RUN sha256sum /out/veyport-agent-linux-arm64 | awk '{print $1}' > /out/veyport-agent-linux-arm64.sha256

# Build vey CLI connector (pure Go, cross-compile for linux+darwin, amd64+arm64).
# Mirrors `make build-vey` (see Makefile) so the hub can serve it from
# --agent-bin-dir at GET /install/cli/{os}/{arch}.
COPY cli/ cli/
RUN cd cli && CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -ldflags="-X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/vey-linux-amd64 ./cmd/vey/
RUN cd cli && CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -ldflags="-X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/vey-linux-arm64 ./cmd/vey/
RUN cd cli && CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/vey-darwin-amd64 ./cmd/vey/
RUN cd cli && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/vey-darwin-arm64 ./cmd/vey/
RUN for bin in vey-linux-amd64 vey-linux-arm64 vey-darwin-amd64 vey-darwin-arm64; do \
        sha256sum /out/$bin | awk '{print $1}' > /out/$bin.sha256; \
    done

# Optional services are separately runnable targets and release artifacts.
RUN cd hub && for service in ingest export; do for arch in amd64 arm64; do \
      CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -ldflags="-X main.version=${VERSION}" \
        -o /out/veyport-audit-$service-linux-$arch ./cmd/veyport-audit-$service/; \
    done; done
RUN for bin in /out/veyport /out/veyport-audit-*-linux-*; do \
      sha256sum "$bin" | awk '{print $1}' > "$bin.sha256"; \
    done

RUN cd hub && go run ./cmd/artifact-manifest --directory /out --version "${VERSION}" --revision "${REVISION}"

# Stage 3: Minimal runtime (Wolfi — glibc-based, fast CVE patching, no systemd/ncurses/tar)
FROM ${RUNTIME_IMAGE} AS runtime-base
# Wolfi pins core packages in /etc/apk/world, so request patched glibc builds explicitly.
RUN apk add --no-cache ca-certificates-bundle tzdata \
    "glibc>=2.43-r7" \
    "glibc-locale-posix>=2.43-r7" \
    "ld-linux>=2.43-r7" \
    "libcrypt1>=2.43-r7" && \
    adduser -D -s /bin/false veyport && \
    mkdir -p /data && chown veyport:veyport /data

WORKDIR /app

FROM scratch AS artifacts
COPY --from=backend /out/ /

FROM runtime-base AS audit-ingest
ARG VERSION=dev
ARG REVISION=unknown
ARG TARGETARCH
LABEL org.opencontainers.image.version=${VERSION} org.opencontainers.image.revision=${REVISION}
COPY --from=backend /out/veyport-audit-ingest-linux-${TARGETARCH} /app/veyport-audit-ingest
USER veyport
ENTRYPOINT ["/app/veyport-audit-ingest"]

FROM runtime-base AS audit-export
ARG VERSION=dev
ARG REVISION=unknown
ARG TARGETARCH
LABEL org.opencontainers.image.version=${VERSION} org.opencontainers.image.revision=${REVISION}
COPY --from=backend /out/veyport-audit-export-linux-${TARGETARCH} /app/veyport-audit-export
USER veyport
ENTRYPOINT ["/app/veyport-audit-export"]

FROM runtime-base AS veyport
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.version=${VERSION} org.opencontainers.image.revision=${REVISION}

COPY --from=backend /out/veyport /app/veyport
COPY --from=backend /out/artifact-manifest.json /app/artifact-manifest.json
COPY --from=backend /out/veyport-agent-linux-amd64 /app/veyport-agent-linux-amd64
COPY --from=backend /out/veyport-agent-linux-arm64 /app/veyport-agent-linux-arm64
COPY --from=backend /out/veyport-agent-linux-amd64.sha256 /app/veyport-agent-linux-amd64.sha256
COPY --from=backend /out/veyport-agent-linux-arm64.sha256 /app/veyport-agent-linux-arm64.sha256
COPY --from=backend /out/vey-linux-amd64 /app/vey-linux-amd64
COPY --from=backend /out/vey-linux-arm64 /app/vey-linux-arm64
COPY --from=backend /out/vey-darwin-amd64 /app/vey-darwin-amd64
COPY --from=backend /out/vey-darwin-arm64 /app/vey-darwin-arm64
COPY --from=backend /out/vey-linux-amd64.sha256 /app/vey-linux-amd64.sha256
COPY --from=backend /out/vey-linux-arm64.sha256 /app/vey-linux-arm64.sha256
COPY --from=backend /out/vey-darwin-amd64.sha256 /app/vey-darwin-amd64.sha256
COPY --from=backend /out/vey-darwin-arm64.sha256 /app/vey-darwin-arm64.sha256
COPY hub/static/install.sh /app/static/install.sh

RUN chown -R veyport:veyport /app
USER veyport

VOLUME /data
EXPOSE 8081 9090 2222

ENTRYPOINT ["/app/veyport"]
CMD ["--addr", ":8081", "--grpc-addr", ":9090", "--db", "/data/veyport.db", "--agent-bin-dir", "/app"]

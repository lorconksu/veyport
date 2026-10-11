.PHONY: dev-hub dev-web dev-web-lan build build-web embed-web build-hub build-agent build-vey build-audit artifact-manifest test test-hub test-agent test-cli test-proto vet clean proto

# All binaries share the same linker-stamped version.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
REVISION ?= $(shell git rev-parse HEAD)

# Development (run these in separate terminals)
dev-hub:
	cd hub && go run ./cmd/veyport/ --dev --addr :8080

dev-web:
	cd web && npm run dev

dev-web-lan:
	scripts/dev-web-local-https.sh

# Proto generation
proto:
	protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       proto/veyport/v1/agent.proto

# Build production binary (frontend embedded)
build: artifact-manifest

build-web:
	cd web && npm run build

embed-web: build-web
	rm -rf hub/web/dist
	mkdir -p hub/web
	cp -r web/dist hub/web/dist

build-hub: embed-web proto
	cd hub && go build -ldflags "-X github.com/wyiu/veyport/hub/internal/server.Version=$(VERSION)" -o ../bin/veyport ./cmd/veyport/

build-agent: proto
	cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o ../bin/veyport-agent-linux-amd64 ./cmd/veyport-agent/
	cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o ../bin/veyport-agent-linux-arm64 ./cmd/veyport-agent/

# Optional archive services are artifacts; the default deployment starts none.
build-audit: proto
	cd hub && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o ../bin/veyport-audit-ingest-linux-amd64 ./cmd/veyport-audit-ingest/
	cd hub && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o ../bin/veyport-audit-ingest-linux-arm64 ./cmd/veyport-audit-ingest/
	cd hub && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o ../bin/veyport-audit-export-linux-amd64 ./cmd/veyport-audit-export/
	cd hub && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o ../bin/veyport-audit-export-linux-arm64 ./cmd/veyport-audit-export/

artifact-manifest: build-hub build-agent build-vey build-audit
	python3 scripts/release/artifacts.py --directory bin --version "$(VERSION)" --revision "$(REVISION)" --smoke

# vey CLI connector: cross-compiled, CGO-disabled, version-stamped binaries.
# Max size (plan.md performance goal): 15 MB per platform.
VEY_MAX_BYTES := 15728640

build-vey:
	cd cli && CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o ../bin/vey-linux-amd64 ./cmd/vey/
	cd cli && CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o ../bin/vey-linux-arm64 ./cmd/vey/
	cd cli && CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o ../bin/vey-darwin-amd64 ./cmd/vey/
	cd cli && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o ../bin/vey-darwin-arm64 ./cmd/vey/
	@for bin in bin/vey-linux-amd64 bin/vey-linux-arm64 bin/vey-darwin-amd64 bin/vey-darwin-arm64; do \
		size=$$(stat -c%s "$$bin" 2>/dev/null || stat -f%z "$$bin" 2>/dev/null || wc -c < "$$bin"); \
		if [ "$$size" -gt "$(VEY_MAX_BYTES)" ]; then \
			echo "FAIL: $$bin is $$size bytes, exceeds $(VEY_MAX_BYTES) byte (15 MB) limit"; \
			exit 1; \
		fi; \
		echo "$$bin: $$size bytes"; \
	done

# Test
test: test-hub test-agent test-cli test-proto

test-hub:
	cd hub && go test ./...

test-agent:
	cd agent && go test ./...

test-cli:
	cd cli && go test ./...

test-proto:
	cd proto && go test ./...

vet:
	cd hub && go vet ./...
	cd agent && go vet ./...
	cd cli && go vet ./...
	cd proto && go vet ./...

clean:
	rm -rf bin/ web/dist/ hub/web/dist/ hub/veyport

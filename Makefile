.PHONY: dev-hub dev-web dev-web-lan build test clean proto

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
build: build-web embed-web proto build-agent build-hub

build-web:
	cd web && npm run build

embed-web:
	rm -rf hub/web/dist
	mkdir -p hub/web
	cp -r web/dist hub/web/dist

build-hub:
	cd hub && go build -o ../bin/veyport ./cmd/veyport/

build-agent:
	cd agent && GOOS=linux GOARCH=amd64 go build -o ../bin/veyport-agent-linux-amd64 ./cmd/veyport-agent/
	cd agent && GOOS=linux GOARCH=arm64 go build -o ../bin/veyport-agent-linux-arm64 ./cmd/veyport-agent/

# Test
test: test-hub test-agent

test-hub:
	cd hub && go test ./...

test-agent:
	cd agent && go test ./...

clean:
	rm -rf bin/ web/dist/ hub/web/dist/ hub/veyport

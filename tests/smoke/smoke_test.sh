#!/bin/bash
set -euo pipefail

# Ensure we're at repo root
cd "$(dirname "$0")/../.."

CONTAINER_NAME="veyport-smoke-$$"
IMAGE_NAME="veyport-smoke:$$"
HTTP_PORT=18081
GRPC_PORT=19090

cleanup() {
    echo "==> Cleaning up..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Building Docker image..."
docker build ${BUILD_ARGS:-} -t "$IMAGE_NAME" .

echo "==> Starting container..."
docker run -d \
    --name "$CONTAINER_NAME" \
    -p "$HTTP_PORT:8081" \
    -p "$GRPC_PORT:9090" \
    "$IMAGE_NAME"

echo "==> Waiting for container..."
for i in $(seq 1 30); do
    if curl -sf "http://localhost:$HTTP_PORT/api/auth/status" > /dev/null 2>&1; then
        echo "    Ready after ${i}s"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "    FAILED: not ready after 30s"
        docker logs "$CONTAINER_NAME"
        exit 1
    fi
    sleep 1
done

PASS=0
FAIL=0

check() {
    local name="$1"
    echo -n "==> $name... "
    if eval "$2"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
}

check "Auth status returns JSON" \
    'curl -sf "http://localhost:$HTTP_PORT/api/auth/status" | python3 -c "import json,sys; d=json.load(sys.stdin); assert \"initialized\" in d"'

check "Not initialized" \
    'curl -sf "http://localhost:$HTTP_PORT/api/auth/status" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"initialized\"] == False"'

check "SPA serves HTML" \
    'curl -sf "http://localhost:$HTTP_PORT/dashboard" | grep -qi "<!doctype html>"'

check "Register first user" \
    'curl -sf -X POST "http://localhost:$HTTP_PORT/api/auth/register" -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"email\":\"admin@test.com\",\"password\":\"SmokeTest!2026\"}" | python3 -c "import json,sys; d=json.load(sys.stdin); assert \"setup_token\" in d"'

check "Not initialized until TOTP complete" \
    'curl -sf "http://localhost:$HTTP_PORT/api/auth/status" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"initialized\"] == False, \"expected not initialized before TOTP setup\""'

check "No container restarts" \
    '[[ $(docker inspect "$CONTAINER_NAME" --format="{{.RestartCount}}") == "0" ]]'

check "No panic/fatal in logs" \
    '! docker logs "$CONTAINER_NAME" 2>&1 | grep -qiE "panic|fatal"'

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[[ $FAIL -eq 0 ]] || exit 1

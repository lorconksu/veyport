#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="$ROOT_DIR/.dev-certs"
KEY_FILE="$CERT_DIR/vite-local.key"
CERT_FILE="$CERT_DIR/vite-local.crt"
HOST="${VITE_DEV_HOST:-0.0.0.0}"
PORT="${VITE_DEV_PORT:-5173}"

detect_api_target() {
  if [[ -n "${VITE_API_PROXY_TARGET:-}" ]]; then
    printf '%s\n' "$VITE_API_PROXY_TARGET"
    return
  fi

  if curl -fsS --max-time 2 http://127.0.0.1:8081/api/auth/status >/dev/null 2>&1; then
    printf '%s\n' "http://127.0.0.1:8081"
    return
  fi

  printf '%s\n' "http://127.0.0.1:8080"
}

build_san() {
  local san="DNS:localhost,IP:127.0.0.1,IP:::1"
  local ip

  for ip in $(hostname -I 2>/dev/null || true); do
    san="$san,IP:$ip"
  done

  printf '%s\n' "$san"
}

mkdir -p "$CERT_DIR"

if [[ ! -f "$KEY_FILE" || ! -f "$CERT_FILE" ]]; then
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days 365 \
    -nodes \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=$(build_san)" >/dev/null 2>&1
fi

API_TARGET="$(detect_api_target)"

cat <<EOF
Starting Vite with HTTPS for local LAN testing.

URL:        https://$(hostname -I 2>/dev/null | awk '{print $1}'):$PORT/
API proxy:  $API_TARGET
Cert:       $CERT_FILE

Browsers will show a warning for this self-signed cert. Accept it for local testing.
Do not use plain HTTP for login testing; Secure auth cookies will not persist.
EOF

cd "$ROOT_DIR/web"
VITE_API_PROXY_TARGET="$API_TARGET" \
VITE_HTTPS_KEY_FILE="$KEY_FILE" \
VITE_HTTPS_CERT_FILE="$CERT_FILE" \
npm run dev -- --host "$HOST" --port "$PORT"

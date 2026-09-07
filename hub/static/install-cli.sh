#!/bin/sh
set -eu

# Veyport CLI Installer
# Usage: curl -fsSL {{.BaseURL}}/install/cli.sh | sh
#
# Unlike the agent installer (install.sh), this script takes no arguments:
# the hub renders its own base URL into the one-liner via text/template, and
# there is no token to pass — the CLI authenticates later via `vey login`
# (specs/006-cli-install-script/proposal.md). It is also deliberately not
# `curl | sudo sh`: the CLI does not need root, so a user-level install is
# the default and sudo is only offered, never assumed.
#
# POSIX sh only (this is piped to `sh`, which may be dash on Debian/Ubuntu):
# no bashisms, no arrays, no [[ ]], no `local`.

BASE_URL="{{.BaseURL}}"

# Validate the templated URL before it is used anywhere. The hub validates
# its own public base URL server-side too, but a script that trusts its own
# template blindly is one bad env var away from a broken/hostile URL.
if ! echo "$BASE_URL" | grep -qE '^https?://[a-zA-Z0-9.:/_-]+$'; then
  echo "ERROR: invalid hub base URL: $BASE_URL" >&2
  exit 1
fi

# --- Detect platform ---
OS_RAW=$(uname -s)
case "$OS_RAW" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *)
    echo "ERROR: unsupported platform: $OS_RAW (only Linux and macOS are supported)" >&2
    exit 1
    ;;
esac

ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
  x86_64)          ARCH=amd64 ;;
  aarch64|arm64)   ARCH=arm64 ;;
  *)
    echo "ERROR: unsupported architecture: $ARCH_RAW (only amd64 and arm64 are supported)" >&2
    exit 1
    ;;
esac

# --- Download to a scratch dir; verify before anything is installed ---
WORK_DIR=$(mktemp -d)
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

BIN_URL="${BASE_URL}/install/cli/${OS}/${ARCH}"
SHA_URL="${BIN_URL}/sha256"

echo "==> Downloading vey (${OS}-${ARCH})..."
curl -fsSL "$BIN_URL" -o "${WORK_DIR}/vey"
curl -fsSL "$SHA_URL" -o "${WORK_DIR}/vey.sha256"

echo "==> Verifying checksum..."
EXPECTED_SHA=$(awk '{print $1}' "${WORK_DIR}/vey.sha256")
if ! echo "$EXPECTED_SHA" | grep -qE '^[a-fA-F0-9]{64}$'; then
  echo "ERROR: hub returned an invalid checksum for ${OS}-${ARCH}" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA=$(sha256sum "${WORK_DIR}/vey" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA=$(shasum -a 256 "${WORK_DIR}/vey" | awk '{print $1}')
else
  echo "ERROR: neither sha256sum nor shasum is available; cannot verify checksum" >&2
  exit 1
fi

if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
  echo "ERROR: checksum verification failed" >&2
  echo "  expected: $EXPECTED_SHA" >&2
  echo "  actual:   $ACTUAL_SHA" >&2
  exit 1
fi
echo "    checksum OK."

chmod +x "${WORK_DIR}/vey"

# --- Detect an existing install (for the upgrade message) ---
OLD_VERSION=""
if command -v vey >/dev/null 2>&1; then
  OLD_VERSION=$(vey --version 2>/dev/null || true)
fi

# --- Install: prefer /usr/local/bin, offer sudo, else fall back to user bin ---
INSTALL_DIR="/usr/local/bin"

if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "${WORK_DIR}/vey" "${INSTALL_DIR}/vey"
elif command -v sudo >/dev/null 2>&1 && [ -t 0 ]; then
  echo "==> ${INSTALL_DIR} is not writable; requesting sudo to install there..."
  if sudo install -m 0755 "${WORK_DIR}/vey" "${INSTALL_DIR}/vey"; then
    :
  else
    echo "==> sudo install failed; falling back to \$HOME/.local/bin"
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
    install -m 0755 "${WORK_DIR}/vey" "${INSTALL_DIR}/vey"
  fi
else
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
  install -m 0755 "${WORK_DIR}/vey" "${INSTALL_DIR}/vey"
fi

INSTALLED_PATH="${INSTALL_DIR}/vey"

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "NOTE: ${INSTALL_DIR} is not on your PATH. Add this to your shell profile:"
    echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac

# `vey --version` prints "vey vX.Y.Z-..."; use its output verbatim rather
# than prefixing another "vey" (T-verify finding: "Installed vey vey ...").
NEW_VERSION=$("$INSTALLED_PATH" --version 2>/dev/null || echo "vey (version unknown)")

echo ""
if [ -n "$OLD_VERSION" ]; then
  echo "==> Upgraded: ${OLD_VERSION} -> ${NEW_VERSION}"
else
  echo "==> Installed ${NEW_VERSION}"
fi
echo ""
echo "Next step:"
echo "    vey --hub ${BASE_URL} login"

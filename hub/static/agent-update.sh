#!/usr/bin/env bash
# One-time update bootstrap for existing enrolled Linux/systemd agents.
# This deliberately does not invoke the enrollment installer.
set -euo pipefail
umask 077

fail() { printf 'Agent update refused: %s\n' "$*" >&2; exit 1; }
hub=''
ticket=''
while (($#)); do
  case "$1" in
    --hub) (($# >= 2)) || fail 'missing --hub value'; hub="$2"; shift 2 ;;
    --ticket) (($# >= 2)) || fail 'missing --ticket value'; ticket="$2"; shift 2 ;;
    *) fail 'only --hub and --ticket are accepted' ;;
  esac
done
[[ ${EUID} -eq 0 ]] || fail 'run this command with sudo'
printf 'Manual bootstrap precondition: user file/log clients and agent sessions must be closed, all admitted work finished, and idle verified through direct SSH. The one-use Hub ticket records the administrator idle assertion.\n'
hub_expression='^https://[][a-zA-Z0-9._:-]+/?$'
[[ "$hub" =~ $hub_expression ]] || fail 'an explicit configured HTTPS Hub is required'
hub="${hub%/}"
[[ "$ticket" =~ ^[a-zA-Z0-9_-]{32,512}$ ]] || fail 'invalid one-use update ticket'
[[ $(uname -s) == Linux ]] || fail 'only Linux/systemd installations are supported'
[[ -d /run/systemd/system ]] || fail 'systemd is required'
for tool in curl sha256sum stat od sed mktemp wc cat chmod tr rm uname; do command -v "$tool" >/dev/null || fail "required tool is missing: $tool"; done

private_file() {
  [[ -f "$1" && ! -L "$1" ]] || fail 'the enrolled installation contains an unsafe file'
  [[ $(stat -c '%u:%a:%h' -- "$1") == '0:600:1' ]] || fail 'enrolled identity files must be root-owned with mode 0600'
}
for dir in /usr /usr/local /usr/local/bin /etc /etc/veyport /etc/veyport/tls; do
  [[ -d "$dir" && ! -L "$dir" ]] || fail 'the enrolled installation contains an unsafe directory'
  [[ $(stat -c '%u' -- "$dir") == 0 ]] || fail 'installation directories must be root-owned'
  mode=$(stat -c '%a' -- "$dir")
  # Octal group/other digits 0, 1, 4 and 5 omit the write bit. Padding also
  # handles short modes; this is exactly the traditional mode & 0022 test.
  protected_mode_expression='^[0-7]*[0145][0145]$'
  [[ "00$mode" =~ $protected_mode_expression ]] || fail 'installation directories must not be group or world writable'
done
[[ $(stat -c '%a' -- /etc/veyport/tls) == 700 ]] || fail 'TLS directory must have mode 0700'
private_file /etc/veyport/agent.conf
private_file /etc/veyport/tls/client.key
private_file /etc/veyport/tls/client.crt
private_file /etc/veyport/tls/ca.crt
[[ -f /usr/local/bin/veyport-agent && ! -L /usr/local/bin/veyport-agent ]] || fail 'canonical enrolled agent binary is required'
[[ $(stat -c '%u' -- /usr/local/bin/veyport-agent) == 0 ]] || fail 'agent binary must be root-owned'

# The enrolled config writer uses unescaped host:port values. Reject ambiguous
# encodings here; the candidate also validates the complete JSON before use.
enrolled=$(sed -n 's/^[[:space:]]*"hub_url"[[:space:]]*:[[:space:]]*"\([^"\\]*\)"[,[:space:]]*$/\1/p' /etc/veyport/agent.conf)
[[ -n "$enrolled" && "$enrolled" != *$'\n'* ]] || fail 'could not read one canonical enrolled Hub address'
configured_host="${enrolled%:*}"
authority="${hub#https://}"
if [[ "$authority" == '['* ]]; then public_host="${authority%%]*}]"; else public_host="${authority%%:*}"; fi
[[ "$public_host" == "$configured_host" ]] || fail 'HTTPS source differs from the enrolled Hub'
machine_arch=$(uname -m)
case "$machine_arch" in
  x86_64)
    arch=amd64
    machine='3e 00'
    ;;
  aarch64|arm64)
    arch=arm64
    machine='b7 00'
    ;;
  *) fail 'unsupported Linux architecture' ;;
esac

workdir=$(mktemp -d /usr/local/bin/.veyport-agent-bootstrap-XXXXXXXX)
chmod 700 "$workdir"
trap 'rm -rf -- "$workdir"' EXIT
# HTTPS verification stays enabled. Redirects, proxy-supplied source changes,
# oversized files, stalled requests, and non-2xx responses are rejected.
curl --disable --fail --silent --show-error --proto '=https' --max-redirs 0 --connect-timeout 10 --max-time 30 --max-filesize 65536 --output "$workdir/metadata" "$hub/install/metadata/agent/linux/$arch"
[[ $(wc -c < "$workdir/metadata") -le 65536 ]] || fail 'update metadata is oversized'
metadata=$(cat "$workdir/metadata")
string_field() {
  local key="$1" expression
  expression='"'"$key"'"[[:space:]]*:[[:space:]]*"([^"\\]*)"'
  [[ "$metadata" =~ $expression ]] || fail "missing update metadata: $key"
  printf '%s' "${BASH_REMATCH[1]}"
}
version=$(string_field version)
revision=$(string_field revision)
sha=$(string_field sha256)
path=$(string_field path)
[[ $(string_field component) == agent && $(string_field os) == linux && $(string_field arch) == "$arch" ]] || fail 'update metadata platform differs'
bytes_expression='"bytes"[[:space:]]*:[[:space:]]*([0-9]+)'
[[ "$metadata" =~ $bytes_expression ]] || fail 'missing update byte count'
bytes="${BASH_REMATCH[1]}"
[[ "$bytes" =~ ^[1-9][0-9]{0,8}$ ]] && ((bytes <= 134217728)) || fail 'invalid update byte count'
[[ "$sha" =~ ^[0-9a-f]{64}$ && "$revision" =~ ^[0-9a-f]{40,64}$ && "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([+-][a-zA-Z0-9.-]+)?$ ]] || fail 'invalid update release identity'
[[ "$path" == "/install/linux/$arch" ]] || fail 'update artifact path differs from the fixed platform path'
curl --disable --fail --silent --show-error --proto '=https' --max-redirs 0 --connect-timeout 10 --max-time 120 --max-filesize "$bytes" --output "$workdir/candidate" "$hub$path"
[[ $(wc -c < "$workdir/candidate") == "$bytes" ]] || fail 'update artifact is truncated'
read -r actual_sha _ < <(sha256sum -- "$workdir/candidate")
[[ "$actual_sha" == "$sha" ]] || fail 'update artifact checksum differs'
header=$(od -An -tx1 -N6 "$workdir/candidate" | tr -s ' ' | sed 's/^ //;s/ $//')
[[ "$header" == '7f 45 4c 46 02 01' ]] || fail 'update artifact is not a supported ELF binary'
actual_machine=$(od -An -tx1 -j18 -N2 "$workdir/candidate" | tr -s ' ' | sed 's/^ //;s/ $//')
[[ "$actual_machine" == "$machine" ]] || fail 'update artifact ELF architecture differs'
chmod 700 "$workdir/candidate"
printf 'Verified Hub agent artifact %s (%s). Authorizing the enrolled update.\n' "$version" "$revision"
"$workdir/candidate" --update-bootstrap "$ticket" --update-hub "$hub"

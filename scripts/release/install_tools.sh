#!/usr/bin/env bash
# Download pinned official tool releases and verify their published SHA256.
set -euo pipefail
tool="${1:?tool required}"
destination="${2:?private tool directory required}"
case "$tool" in
  actionlint) repository=rhysd/actionlint; version=1.7.12; archive=actionlint_1.7.12_linux_amd64.tar.gz; checksums=actionlint_1.7.12_checksums.txt ;;
  grype) repository=anchore/grype; version=0.110.0; archive=grype_0.110.0_linux_amd64.tar.gz; checksums=grype_0.110.0_checksums.txt ;;
  syft) repository=anchore/syft; version=1.42.3; archive=syft_1.42.3_linux_amd64.tar.gz; checksums=syft_1.42.3_checksums.txt ;;
  gitleaks) repository=gitleaks/gitleaks; version=8.30.1; archive=gitleaks_8.30.1_linux_x64.tar.gz; checksums=gitleaks_8.30.1_checksums.txt ;;
  *) echo "unsupported pinned tool" >&2; exit 1 ;;
esac
mkdir -p "$destination"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
base="https://github.com/$repository/releases/download/v$version"
curl --fail --silent --show-error --location --connect-timeout 10 --max-time 120 "$base/$archive" -o "$temporary/$archive"
curl --fail --silent --show-error --location --connect-timeout 10 --max-time 120 "$base/$checksums" -o "$temporary/checksums.txt"
awk -v name="$archive" '$2 == name {print $0}' "$temporary/checksums.txt" > "$temporary/selected.sha256"
test "$(wc -l < "$temporary/selected.sha256")" -eq 1
(cd "$temporary" && sha256sum --check selected.sha256)
tar -xzf "$temporary/$archive" -C "$temporary" "$tool"
install -m 0755 "$temporary/$tool" "$destination/$tool"

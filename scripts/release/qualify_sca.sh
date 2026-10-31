#!/usr/bin/env bash
# Fresh equivalent-scope scans run once; report export does not rerun them.
set -euo pipefail
candidate_manifest="${1:?candidate inventory required}"
private="${2:?private evidence directory required}"
delivery="${3:?original delivery bytes required}"
scanner="${4:?pinned Snyk executable required}"
python_environment="${5:?resolved pinned pip environment required}"
candidate_id="run-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
common=(--root . --revision "${GITHUB_SHA:?}" --candidate-id "$candidate_id" --artifact-manifest "$candidate_manifest" --scanner "$scanner")
# Retain every scope's evidence even if an independent scope fails.
failed=0
python3 scripts/security/snyk.py source "${common[@]}" --python "$python_environment" --output "$private/source-sca" || failed=1
for target in veyport audit-ingest audit-export; do
  native="$(mktemp -d)"
  trap 'rm -rf "$native"' EXIT
  skopeo copy --override-os linux --override-arch amd64 --preserve-digests \
    "oci-archive:$delivery/$target.oci.tar" "oci-archive:$native/native.oci.tar"
  archive_hash="$(sha256sum "$native/native.oci.tar" | cut -d ' ' -f 1)"
  digest="sha256:$(sha256sum "$delivery/reports/$target.native.manifest.json" | cut -d ' ' -f 1)"
  python3 scripts/security/snyk.py image "${common[@]}" --image "$target" \
    --archive "$native/native.oci.tar" --archive-sha256 "$archive_hash" --native-manifest-digest "$digest" \
    --output "$private/image-$target" || failed=1
  rm -rf "$native"
  trap - EXIT
done
exit "$failed"

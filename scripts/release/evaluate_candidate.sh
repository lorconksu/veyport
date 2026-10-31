#!/usr/bin/env bash
set -euo pipefail
manifest="${1:?candidate manifest required}"
private="${2:?private reports required}"
output="${3:?decision output required}"
args=()
for path in "$private/source-sca/assessment.json" "$private/image-veyport/assessment.json" "$private/image-audit-ingest/assessment.json" "$private/image-audit-export/assessment.json" "$private/native.json" "$private/source-sast.json"; do
  args+=(--report "$path")
done
python3 scripts/release/release_policy.py "${args[@]}" --candidate-id "run-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}" --revision "${GITHUB_SHA:?}" --artifact-manifest-sha256 "$(sha256sum "$manifest" | cut -d ' ' -f 1)" --output "$output"

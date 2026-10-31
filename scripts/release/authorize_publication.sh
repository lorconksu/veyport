#!/usr/bin/env bash
# Every failure exits before the caller can mutate a public registry or release.
set -euo pipefail
root="${1:?private runner directory required}"
python3 scripts/release/evidence_manifest.py --verify --expected-sha256 "$(cat "$root/evidence-manifest.sha256")" --directory "$root/evidence-files" --delivery "$root/delivery" --security "$root/security" --candidate "$root/candidate.json" --workflow "${SOURCE_WORKFLOW:?}" --version "${VERSION:?}" --manifest "$root/evidence-manifest.json"
python3 scripts/release/candidate.py verify-files --directory "$root/delivery" --manifest "$root/candidate.json"
python3 scripts/release/candidate.py verify-qualification --manifest "$root/candidate.json" --public-key "$root/ssdf-keys/candidate.pem" --receipt "$root/security/native.json.receipt.json"
bash scripts/release/evaluate_candidate.sh "$root/candidate.json" "$root/security" "$root/publication-decision.json"
python3 infra/evidence-collector/evidence.py wait-receipt --repository "${GITHUB_REPOSITORY:?}" --run-id "${GITHUB_RUN_ID:?}" --attempt "${GITHUB_RUN_ATTEMPT:?}" --revision "${GITHUB_SHA:?}" --manifest-sha256 "$(cat "$root/evidence-manifest.sha256")" --public-key "$root/ssdf-keys/archive.pem" --timeout 60 > "$root/archive-receipt.json"

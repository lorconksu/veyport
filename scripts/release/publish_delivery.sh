#!/usr/bin/env bash
# Publish only the checksummed OCI archives that already passed every gate.
set -euo pipefail
delivery="${1:?verified public artifact directory required}"
tag="${2:?validated immutable tag required}"
version="${3:?validated version required}"
prototype="${4:?true or false required}"
revision="${5:?exact source revision required}"
test "$prototype" = true || test "$prototype" = false
(cd "$delivery" && sha256sum --check DELIVERY_SHA256SUMS)
python3 "$(dirname "${BASH_SOURCE[0]}")/git_tag.py" ensure "$tag" "$revision" "${GITHUB_REPOSITORY:?repository required}"
for target in veyport audit-ingest audit-export; do
  repository=yiucloud/veyport
  if [ "$target" != veyport ]; then repository="yiucloud/veyport-$target"; fi
  destination="docker.io/$repository:$tag"
  expected="$(cat "$delivery/reports/$target.digest")"
  error_file="$(mktemp)"
  if existing="$(skopeo inspect --raw "docker://$destination" 2>"$error_file" | sha256sum | awk '{print "sha256:" $1}')"; then
    # An existing immutable tag is reusable only when it already has these bytes.
    test "$existing" = "$expected"
  else
    # Authentication, network and server errors do not establish tag absence.
    if ! grep -Eq 'manifest unknown|name unknown|manifest_unknown|NAME_UNKNOWN' "$error_file"; then
      rm -f "$error_file"
      echo "registry could not establish immutable tag absence" >&2
      exit 1
    fi
    skopeo copy --all --preserve-digests "oci-archive:$delivery/$target.oci.tar" "docker://$destination"
  fi
  rm -f "$error_file"
  actual="$(skopeo inspect --raw "docker://$destination" | sha256sum | awk '{print "sha256:" $1}')"
  test "$actual" = "$expected"
  printf '%s@%s\n' "docker.io/$repository" "$actual" >> "$delivery/published-images.txt"
  if [ "$prototype" = false ]; then
    for channel in "$version" "${version%.*}" latest; do
      skopeo copy --all --preserve-digests "docker://docker.io/$repository@$actual" "docker://docker.io/$repository:$channel"
    done
  fi
done

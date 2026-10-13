#!/usr/bin/env bash
# Build, inspect and scan exact public artifacts before registry publication.
set -euo pipefail
delivery="${1:?fresh public artifact directory required}"
version="${2:?version required}"
revision="${3:?revision required}"
test ! -e "$delivery"
test -z "$(git status --porcelain)"
mkdir -p "$delivery/bin" "$delivery/reports"
docker buildx build --platform linux/amd64 --target artifacts \
  --build-arg "VERSION=$version" --build-arg "REVISION=$revision" \
  --output "type=local,dest=$delivery/bin" .
cp "$delivery/bin/artifact-manifest.json" "$delivery/reports/build-artifact-manifest.json"
python3 scripts/release/artifacts.py --directory "$delivery/bin" --version "$version" --revision "$revision" --smoke
cmp "$delivery/reports/build-artifact-manifest.json" "$delivery/bin/artifact-manifest.json"
python3 scripts/release/go_binary_evidence.py "$delivery/bin" "$delivery/reports/go"

# The exact public binary set also includes arm64 and Darwin release assets.
while IFS= read -r binary; do
  grype "file:$delivery/bin/$binary" -o json > "$delivery/reports/$binary.binary.grype.json"
  python3 - "$delivery" "$binary" <<'PY'
import json,sys
from pathlib import Path
sys.path.insert(0,'scripts/release')
from check_scan import check
root,binary=Path(sys.argv[1]),sys.argv[2]
source=root/'bin'/binary
mapping={str(source):(binary,str(source)), '/'+binary:(binary,str(source))}
check(root/'reports'/(binary+'.binary.grype.json'),'grype',root/'reports/go',mapping,root/'reports'/(binary+'.binary.assessment.json'))
PY
done < <(python3 -c 'import sys;sys.path.insert(0,"scripts/release");from artifacts import BINARIES;print("\n".join(BINARIES))')

for target in veyport audit-ingest audit-export; do
  docker buildx build --platform linux/amd64 --target "$target" \
    --build-arg "VERSION=$version" --build-arg "REVISION=$revision" \
    --sbom=true --provenance=mode=max \
    --output "type=oci,dest=$delivery/$target.oci.tar" .
  skopeo inspect --raw "oci-archive:$delivery/$target.oci.tar" > "$delivery/reports/$target.manifest.json"
  skopeo inspect --config "oci-archive:$delivery/$target.oci.tar" > "$delivery/reports/$target.config.json"
  python3 - "$delivery/reports/$target.config.json" "$version" "$revision" <<'PY'
import json,sys
config=json.load(open(sys.argv[1]))
labels=config.get('config',{}).get('Labels',{})
if config.get('architecture')!='amd64' or config.get('os')!='linux' or labels.get('org.opencontainers.image.version')!=sys.argv[2] or labels.get('org.opencontainers.image.revision')!=sys.argv[3]:
 raise SystemExit('exact OCI platform/version/revision verification failed')
PY
  sha256sum "$delivery/reports/$target.manifest.json" | awk '{print "sha256:" $1}' > "$delivery/reports/$target.digest"

  # Buildx's attested index may itself be wrapped in an OCI layout index.
  # Catalog the unchanged native manifest selected from that original archive;
  # retain and publish the complete original index with its attestations.
  scan_temporary="$(mktemp -d)"
  trap 'rm -rf "$scan_temporary"' EXIT
  skopeo copy --override-os linux --override-arch amd64 --preserve-digests \
    "oci-archive:$delivery/$target.oci.tar" "oci-archive:$scan_temporary/native.oci.tar"
  skopeo inspect --raw "oci-archive:$scan_temporary/native.oci.tar" > "$delivery/reports/$target.native.manifest.json"
  python3 scripts/release/oci_binding.py "$delivery/$target.oci.tar" \
    "$delivery/reports/$target.manifest.json" "$delivery/reports/$target.native.manifest.json" \
    "$delivery/reports/$target.config.json" "$version" "$revision" \
    > "$delivery/reports/$target.scan-binding.json"
  grype "oci-archive:$scan_temporary/native.oci.tar" -o json > "$delivery/reports/$target.grype.json"
  syft scan "oci-archive:$scan_temporary/native.oci.tar" -o "spdx-json=$delivery/reports/$target.spdx.json"
  rm -rf "$scan_temporary"
  trap - EXIT

  # Match every embedded Go binary to the actual separately scanned bytes.
  # Copy through docker-daemon selects the native runtime manifest while the
  # original OCI archive, attestations and index remain untouched for publish.
  local_image="veyport-delivery-scan:$target"
  skopeo copy "oci-archive:$delivery/$target.oci.tar" "docker-daemon:$local_image"
  container="$(docker create "$local_image")"
  temporary="$(mktemp -d)"
  trap 'docker rm -f "$container" >/dev/null; rm -rf "$temporary"' EXIT
  python3 - "$target" > "$temporary/binaries.txt" <<'PY'
import sys
sys.path.insert(0,'scripts/release')
from artifacts import BINARIES
target=sys.argv[1]
names=([n for n in BINARIES if not n.startswith('veyport-audit-')] if target=='veyport' else ['veyport-'+target+'-linux-amd64'])
for name in names:
 path=name if target=='veyport' else 'veyport-'+target
 print(name,path)
PY
  while read -r binary image_name; do
    docker cp "$container:/app/$image_name" "$temporary/$binary"
    cmp "$delivery/bin/$binary" "$temporary/$binary"
  done < "$temporary/binaries.txt"
  if [ "$target" = veyport ]; then
    docker cp "$container:/app/artifact-manifest.json" "$temporary/artifact-manifest.json"
    cmp "$delivery/bin/artifact-manifest.json" "$temporary/artifact-manifest.json"
  fi
  python3 - "$delivery" "$target" "$temporary/binaries.txt" <<'PY'
import json,sys
from pathlib import Path
sys.path.insert(0,'scripts/release')
from check_scan import check
root,target=Path(sys.argv[1]),sys.argv[2]
mapping={}
for line in Path(sys.argv[3]).read_text().splitlines():
 binary,path=line.split()
 mapping['/app/'+path]=(binary,str(root/'bin'/binary))
check(root/'reports'/(target+'.grype.json'),'grype',root/'reports/go',mapping,root/'reports'/(target+'.assessment.json'))
PY
  docker rm "$container" >/dev/null
  rm -rf "$temporary"
  trap - EXIT
done

python3 - "$delivery" <<'PY'
import sys
from pathlib import Path
root=Path(sys.argv[1])
for target in ('veyport','audit-ingest','audit-export'):
 path=root/(target+'.oci.tar')
 if not 0 < path.stat().st_size <= 512 << 20:
  raise SystemExit('OCI archive exceeds the qualified malware file bound')
PY

# An up-to-date database is mandatory; scan errors and exceeded scan limits fail.
clamscan --infected --recursive --max-filesize=512M --max-scansize=2048M \
  --alert-exceeds-max=yes "$delivery" > "$delivery/reports/malware.txt"
python3 - "$delivery" <<'PY'
import hashlib,sys
from pathlib import Path
root=Path(sys.argv[1])
files=sorted(p for p in root.rglob('*') if p.is_file())
if len(files)>1024 or any(p.is_symlink() for p in files): raise SystemExit('public evidence bounds exceeded')
with (root/'DELIVERY_SHA256SUMS').open('w') as out:
 for path in files:
  h=hashlib.file_digest(path.open('rb'),'sha256').hexdigest()
  out.write(h+'  '+str(path.relative_to(root))+'\n')
PY

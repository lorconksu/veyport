"""Bind a scanner's native manifest to the complete attested release archive."""

import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MAX_METADATA = 16 << 20


def binding(archive, published, native, config, version, revision):
    if not 0 < archive.stat().st_size <= 512 << 20:
        raise ValueError("OCI archive exceeds qualified scan bound")
    for raw in (published, native, config):
        if not raw or len(raw) > MAX_METADATA:
            raise ValueError("OCI metadata exceeds scan bound")
    published_digest = "sha256:" + hashlib.sha256(published).hexdigest()
    native_digest = "sha256:" + hashlib.sha256(native).hexdigest()
    with tarfile.open(archive) as tar:
        names = set()
        for index, member in enumerate(tar):
            if index >= 4096 or member.name in names:
                raise ValueError("bounded unambiguous OCI layout required")
            names.add(member.name)
        def read(name):
            member = tar.getmember(name)
            if not member.isfile() or not 0 < member.size <= MAX_METADATA:
                raise ValueError("invalid OCI metadata member")
            return tar.extractfile(member).read(MAX_METADATA + 1)

        def blob(descriptor):
            digest = descriptor.get("digest", "")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                raise ValueError("invalid OCI digest")
            raw = read("blobs/sha256/" + digest[7:])
            if len(raw) != descriptor.get("size") or "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError("OCI descriptor does not match exact bytes")
            return raw

        layout = json.loads(read("index.json"))
        roots = layout.get("manifests", [])
        if len(roots) != 1 or blob(roots[0]) != published:
            raise ValueError("published digest does not match archive index")
        document = json.loads(published)
        candidates = document.get("manifests", [])
        if not 1 <= len(candidates) <= 16:
            raise ValueError("bounded native index required")
        selected = [d for d in candidates if d.get("mediaType") == MANIFEST and d.get("platform") == {"architecture": "amd64", "os": "linux"}]
        if document.get("mediaType") != INDEX or len(selected) != 1 or selected[0].get("digest") != native_digest or blob(selected[0]) != native:
            raise ValueError("scan manifest does not match unique native archive image")
        image = json.loads(native)
        config_descriptor = image.get("config", {})
        # skopeo inspect --config formats JSON; bind its decoded configuration
        # to the original hash-verified config blob rather than its whitespace.
        if image.get("mediaType") != MANIFEST or json.loads(blob(config_descriptor)) != json.loads(config):
            raise ValueError("scan config does not match native manifest")
    image_config = json.loads(config)
    labels = image_config.get("config", {}).get("Labels", {})
    if image_config.get("architecture") != "amd64" or image_config.get("os") != "linux" or labels.get("org.opencontainers.image.version") != version or labels.get("org.opencontainers.image.revision") != revision:
        raise ValueError("exact OCI platform/version/revision mismatch")
    return {"published_index_digest": published_digest, "native_manifest_digest": native_digest, "config_digest": config_descriptor["digest"], "platform": "linux/amd64", "version": version, "revision": revision}


if __name__ == "__main__":
    try:
        archive, published, native, config, version, revision = sys.argv[1:]
        print(json.dumps(binding(Path(archive), Path(published).read_bytes(), Path(native).read_bytes(), Path(config).read_bytes(), version, revision), indent=2))
    except (ValueError, OSError, KeyError, tarfile.TarError) as exc:
        raise SystemExit("OCI scan binding failed: " + str(exc)) from exc

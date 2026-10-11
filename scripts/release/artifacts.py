#!/usr/bin/env python3
"""Build the fixed public binary manifest and check native version output."""
import argparse
import hashlib
import json
import platform
import re
import subprocess
from pathlib import Path

BINARIES = ("veyport",) + tuple(
    f"{name}-linux-{arch}"
    for name in ("veyport-agent", "veyport-audit-ingest", "veyport-audit-export")
    for arch in ("amd64", "arm64")
) + tuple(f"vey-{system}-{arch}" for system in ("linux", "darwin") for arch in ("amd64", "arm64"))


def manifest(directory, version, revision, smoke=False):
    directory = Path(directory)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}", version) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
        raise ValueError("bounded version and exact revision required")
    records = []
    for name in sorted(BINARIES):
        path = directory / name
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 128 << 20:
            raise ValueError("missing or invalid public binary")
        if name.startswith("vey-") and path.stat().st_size > 15 << 20:
            raise ValueError("CLI artifact exceeds the 15 MiB delivery bound")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1 << 20):
                digest.update(chunk)
        records.append({"path": name, "sha256": digest.hexdigest(), "bytes": path.stat().st_size})
    if smoke:
        if platform.system() != "Linux" or platform.machine() not in ("x86_64", "aarch64", "arm64"):
            raise ValueError("binary version smoke requires a native Linux runner")
        arch = "amd64" if platform.machine() == "x86_64" else "arm64"
        native = ("veyport", f"vey-linux-{arch}") + tuple(f"{name}-linux-{arch}" for name in ("veyport-agent", "veyport-audit-ingest", "veyport-audit-export"))
        for name in native:
            process = subprocess.run([str((directory / name).resolve()), "--version"], capture_output=True, timeout=5, check=True)
            expected = f"vey {version}" if name.startswith("vey-linux-") else version
            # Optional service CLIs intentionally use their diagnostic writer
            # for --version; require the same exact single output on either
            # stream, without accepting extra startup diagnostics.
            if (process.stdout + process.stderr).decode("utf-8").strip() != expected or (process.stdout and process.stderr):
                raise ValueError("binary version smoke failed")
    payload = {"schema_version": 1, "version": version, "revision": revision, "binaries": records}
    (directory / "artifact-manifest.json").write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
    (directory / "SHA256SUMS").write_text("".join(f"{r['sha256']}  {r['path']}\n" for r in records))
    for record in records:
        (directory / (record["path"] + ".sha256")).write_text(record["sha256"] + "\n")
    return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    try:
        manifest(args.directory, args.version, args.revision, args.smoke)
    except (ValueError, OSError, subprocess.SubprocessError, UnicodeError):
        parser.exit(1, "artifact manifest/version verification failed\n")

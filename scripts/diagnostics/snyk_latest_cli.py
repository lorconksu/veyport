#!/usr/bin/env python3
"""Resolve and verify the official stable Snyk CLI before trial credentials exist."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def unique_fields(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate release metadata key")
        value[key] = item
    return value


def download(url, target):
    subprocess.run([
        "curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https",
        "--proto-redir", "=https", "--connect-timeout", "10", "--max-time", "180",
        url, "--output", str(target),
    ], check=True, timeout=190)


def bootstrap(root):
    raw, tools = root / "raw", root / "tools"
    scanner, pending = tools / "snyk", tools / "snyk.download"
    # No cached executable may survive a failed fresh resolution.
    scanner.unlink(missing_ok=True)
    pending.unlink(missing_ok=True)
    resolution_path = raw / "snyk-cli.json"
    resolution_path.unlink(missing_ok=True)
    download("https://downloads.snyk.io/cli/stable/release.json", raw / "snyk-release.json")
    metadata = json.loads((raw / "snyk-release.json").read_text(), object_pairs_hook=unique_fields)
    if (type(metadata) is not dict or type(metadata.get("schemaVersion")) is not int
            or metadata["schemaVersion"] != 1 or type(metadata.get("version")) is not str
            or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", metadata["version"])
            or type(metadata.get("assets")) is not dict):
        raise ValueError("Invalid stable release metadata")
    version = metadata["version"]
    url = f"https://downloads.snyk.io/cli/v{version}/snyk-linux"
    asset = metadata["assets"].get("snyk-linux")
    if (type(asset) is not dict or asset.get("url") != url
            or asset.get("sha256Url") != url + ".sha256"
            or type(asset.get("sha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}  snyk-linux", asset["sha256"])):
        raise ValueError("Invalid official Linux asset")
    evidence = {"version": version, "url": url, "expected_sha256": asset["sha256"][:64], "verified": False}
    resolution_path.write_text(json.dumps(evidence, indent=2) + "\n")
    try:
        # The version-specific URL binds the bytes to this metadata even if stable moves.
        download(url, pending)
        with pending.open("rb") as binary:
            evidence["actual_sha256"] = hashlib.file_digest(binary, "sha256").hexdigest()
        resolution_path.write_text(json.dumps(evidence, indent=2) + "\n")
        if evidence["actual_sha256"] != evidence["expected_sha256"]:
            raise ValueError("Snyk checksum mismatch")
        # Same-origin HTTPS metadata/checksum verification, not an independent signature.
        pending.chmod(0o700)
        private_tmp = raw / "snyk-bootstrap-tmp"
        private_tmp.mkdir(mode=0o700, exist_ok=True)
        environment = {**os.environ, "SNYK_TMP_PATH": str(private_tmp)}
        with (raw / "snyk-version.stdout").open("wb") as stdout, (raw / "snyk-version.stderr").open("wb") as stderr:
            subprocess.run([str(pending), "--version"], stdout=stdout, stderr=stderr,
                           check=True, timeout=30, env=environment, cwd=raw)
        if (raw / "snyk-version.stdout").read_bytes() not in (version.encode(), (version + "\n").encode()):
            raise ValueError("Snyk version mismatch")
        pending.replace(scanner)
        evidence["verified"] = True
        resolution_path.write_text(json.dumps(evidence, indent=2) + "\n")
    finally:
        pending.unlink(missing_ok=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        bootstrap(args.root)
    except Exception:
        print("Snyk bootstrap failed; inspect private bootstrap evidence.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

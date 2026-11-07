#!/usr/bin/env python3
"""Publish a complete draft by immutable ID and attest its authenticated response."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import urllib.parse
import urllib.request
from artifacts import BINARIES
import git_tag
import metadata
from risk_acceptance import REPOSITORY, canonical, sha, strict_json, timestamp

MAX_RESPONSE = 4 << 20


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ReleaseAPI:
    def __init__(self):
        self.token = os.environ.get("GH_TOKEN", os.environ.get("GITHUB_TOKEN", ""))
        if not self.token:
            raise ValueError("publication authentication unavailable")

    def request(self, method, path, value=None, asset=None):
        prefix = "/repos/" + REPOSITORY + "/releases"
        if not path.startswith(prefix) or method not in {"POST", "PATCH"}:
            raise ValueError("publication API operation outside allowlist")
        host = "uploads.github.com" if asset is not None else "api.github.com"
        data = asset.read_bytes() if asset is not None else canonical(value)
        request = urllib.request.Request("https://" + host + path, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/octet-stream" if asset is not None else "application/json"})
        # Do not follow redirects with the publication credential.
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=180) as response:
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("publication response exceeds bound")
        result = strict_json(raw)
        if not isinstance(result, dict):
            raise ValueError("publication response must be an object")
        return result


def read_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 1 << 20:
        raise ValueError("bounded publication binding required")
    return strict_json(path.read_bytes())


def context(candidate_path, archive_path, tag, version, prototype):
    revision = os.environ["GITHUB_SHA"]
    metadata.identity(version, tag, revision, os.environ["GITHUB_REF"], prototype)
    candidate, archive = read_json(candidate_path), read_json(archive_path)
    expected = {"repository": REPOSITORY, "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "revision": revision}
    if os.environ["GITHUB_REPOSITORY"] != REPOSITORY or any(candidate.get(k) != v or archive.get(k) != v for k, v in expected.items()):
        raise ValueError("publication candidate/archive identity mismatch")
    if candidate.get("version") != version or archive.get("complete") is not True or archive.get("candidate_id") != candidate.get("candidate_id") or archive.get("workflow") != candidate.get("workflow"):
        raise ValueError("publication archive is not the qualified candidate")
    candidate_hash = sha(canonical(candidate))
    entries = [item for item in archive.get("files", []) if item.get("name") == "candidate.json"]
    if len(entries) != 1 or entries[0].get("sha256") != sha(Path(candidate_path).read_bytes()):
        raise ValueError("archive does not bind complete candidate inventory")
    return {**expected, "workflow": candidate["workflow"], "candidate_id": candidate["candidate_id"], "tag": tag, "version": version,
            "archive_manifest_sha256": sha(canonical(archive)), "candidate_manifest_sha256": candidate_hash}


def assets(delivery):
    root = Path(delivery)
    paths = [root / "bin" / suffix for name in BINARIES for suffix in (name, name + ".sha256")]
    paths += [root / "bin/SHA256SUMS", root / "bin/artifact-manifest.json", root / "release-summary.json"]
    for path in paths:
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 128 << 20:
            raise ValueError("public release asset missing or exceeds bound")
    return paths


def publish(delivery, binding, prototype, api=None, authorize=None):
    api = api or ReleaseAPI()
    root = Path(delivery)
    upload = assets(root)
    notes = root / "release-notes.md"
    if notes.is_symlink() or not notes.is_file() or notes.stat().st_size > 65536:
        raise ValueError("bounded release notes required")
    tag, revision = binding["tag"], binding["revision"]
    prefix = "/repos/" + REPOSITORY + "/releases"
    git_tag.verify(tag, revision, REPOSITORY, False)
    draft = api.request("POST", prefix, {"tag_name": tag, "target_commitish": revision, "name": binding["version"], "body": notes.read_text(), "draft": True, "prerelease": prototype})
    release_id = draft.get("id")
    if type(release_id) is not int or release_id < 1 or draft.get("draft") is not True or draft.get("tag_name") != tag:
        raise ValueError("immutable draft creation was not confirmed")
    for path in upload:
        name = path.name
        digest = sha(path.read_bytes())
        result = api.request("POST", prefix + f"/{release_id}/assets?name=" + urllib.parse.quote(name, safe=""), asset=path)
        if result.get("name") != name or result.get("state") != "uploaded" or result.get("size") != path.stat().st_size or result.get("digest") != "sha256:" + digest:
            raise ValueError("draft asset bytes were not confirmed")
    # Uploads address the immutable draft ID, never a mutable tag lookup. Only
    # a complete draft is made public, after a fresh exact-tag verification.
    if authorize is not None:
        authorize()
    git_tag.verify(tag, revision, REPOSITORY, False)
    response = api.request("PATCH", prefix + f"/{release_id}", {"draft": False, "prerelease": prototype, "make_latest": "false" if prototype else "true"})
    if type(response.get("id")) is not int or response.get("id") != release_id or response.get("draft") is not False or response.get("tag_name") != tag or response.get("prerelease") is not prototype:
        raise ValueError("exact-ID publication response invalid; retention hold required")
    timestamp(response.get("published_at"))
    return {**binding, "schema": 1, "release_id": release_id, "published_at": response["published_at"]}


def manifest(result):
    required = {"schema", "repository", "workflow", "run_id", "run_attempt", "revision", "candidate_id", "tag", "version", "archive_manifest_sha256", "candidate_manifest_sha256", "release_id", "published_at"}
    if set(result) != required or result["schema"] != 1 or result["repository"] != REPOSITORY or type(result["release_id"]) is not int or result["release_id"] < 1:
        raise ValueError("publication response binding invalid")
    timestamp(result["published_at"])
    if any(not re.fullmatch(r"[0-9a-f]{64}", result[k]) for k in ("archive_manifest_sha256", "candidate_manifest_sha256")):
        raise ValueError("publication archive/candidate digest invalid")
    return {"schema": 1, **{k: result[k] for k in ("repository", "workflow", "run_id", "run_attempt", "revision", "candidate_id")}, "complete": False, "files": [],
            "details": {"kind": "publication", **{k: result[k] for k in ("release_id", "published_at", "tag", "archive_manifest_sha256", "candidate_manifest_sha256")}}}


def private_json(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(canonical(value))
        output.flush()
        os.fsync(output.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("publish", "manifest"))
    parser.add_argument("--result", required=True)
    parser.add_argument("--delivery")
    parser.add_argument("--candidate")
    parser.add_argument("--archive")
    parser.add_argument("--tag")
    parser.add_argument("--version")
    parser.add_argument("--prototype", choices=("true", "false"))
    parser.add_argument("--manifest")
    args = parser.parse_args()
    try:
        if args.command == "publish":
            binding = context(args.candidate, args.archive, args.tag, args.version, args.prototype == "true")
            def authorize():
                script = Path(__file__).with_name("authorize_publication.sh")
                subprocess.run(["bash", str(script), str(Path(args.candidate).resolve().parent)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600, check=True)
            private_json(args.result, publish(args.delivery, binding, args.prototype == "true", authorize=authorize))
        else:
            private_json(args.manifest, manifest(read_json(args.result)))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        parser.exit(1, "publication/provenance incomplete; preserve archive retention hold\n")


if __name__ == "__main__":
    main()

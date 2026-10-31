#!/usr/bin/env python3
"""Encrypt exact candidate bytes and verify short-lived native qualification."""
import argparse
import base64
import datetime as dt
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time
import urllib.parse
from risk_acceptance import GitHub, REPOSITORY, canonical, now, sha, strict_json, timestamp

MAX_TOTAL = 4 << 30
MAX_FILE = 512 << 20


def file_digest(path):
    import hashlib
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def inventory(root):
    root = Path(root)
    result, total = [], 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("candidate links are forbidden")
        if path.is_dir():
            continue
        name = path.relative_to(root).as_posix()
        if not re.fullmatch(r"[A-Za-z0-9._/-]{1,240}", name) or any(p in ("", ".", "..") for p in name.split("/")):
            raise ValueError("unsafe candidate path")
        size = path.stat().st_size
        if not path.is_file() or size > MAX_FILE:
            raise ValueError("candidate file bound exceeded")
        total += size
        result.append({"name": name, "size": size, "sha256": file_digest(path)})
    if not 1 <= len(result) <= 1024 or total > MAX_TOTAL:
        raise ValueError("candidate inventory bound exceeded")
    return result


def manifest(root, version, candidate_id, workflow, audit_profile="standard"):
    if audit_profile not in ("standard", "enhanced"):
        raise ValueError("unsupported required audit profile")
    if workflow not in (".github/workflows/release.yml", ".github/workflows/staging.yml", ".github/workflows/ssdf-rehearsal.yml"):
        raise ValueError("untrusted candidate workflow")
    if os.environ["GITHUB_REPOSITORY"] != REPOSITORY or not re.fullmatch(r"[0-9a-f]{40}", os.environ["GITHUB_SHA"]) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", candidate_id) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}", version):
        raise ValueError("invalid candidate identity")
    return {"schema_version": 1, "repository": REPOSITORY, "workflow": workflow, "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "revision": os.environ["GITHUB_SHA"], "version": version, "candidate_id": candidate_id, "audit_profile": audit_profile, "files": inventory(root)}


def verify_files(root, candidate):
    actual = inventory(root)
    expected_names = {item["name"] for item in candidate["files"]}
    actual = [item for item in actual if item["name"] in expected_names or item["name"] not in {"published-images.txt", "release-notes.md", "release-summary.json"}]
    if actual != candidate["files"]:
        raise ValueError("candidate bytes changed after qualification")


def seal(root, candidate_path, recipient, output):
    candidate = strict_json(Path(candidate_path).read_bytes())
    verify_files(root, candidate)
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    # No plaintext tar or private decryption identity is uploaded or retained.
    with subprocess.Popen(["age", "-R", str(recipient), "-o", str(output)], stdin=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        try:
            with tarfile.open(fileobj=process.stdin, mode="w|") as archive:
                import io
                data = canonical(candidate)
                entry = tarfile.TarInfo("candidate.json")
                entry.size, entry.mode = len(data), 0o600
                archive.addfile(entry, io.BytesIO(data))
                for item in candidate["files"]:
                    path = Path(root) / item["name"]
                    info = archive.gettarinfo(str(path), arcname="delivery/" + item["name"])
                    if not info.isfile() or info.size != item["size"]:
                        raise ValueError("candidate changed while encrypting")
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    with path.open("rb") as source:
                        archive.addfile(info, source)
            process.stdin.close()
            if process.wait(timeout=180) != 0:
                raise ValueError("candidate encryption failed")
            verify_files(root, candidate)
        except BaseException:
            process.kill()
            process.wait()
            Path(output).unlink(missing_ok=True)
            raise


def verify_qualification(envelope, candidate, public_key, at=None):
    at = at or now()
    module_path = Path(__file__).resolve().parents[2] / "infra/evidence-collector/evidence.py"
    spec = importlib.util.spec_from_file_location("ssdf_evidence", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    payload = envelope["payload"]
    try:
        module.verify_signature(canonical(payload), envelope["signature"], public_key)
    except module.EvidenceError as error:
        raise ValueError("invalid native qualification signature") from error
    expected = {key: candidate[key] for key in ("repository", "run_id", "run_attempt", "revision", "candidate_id", "audit_profile")}
    expected["artifact_manifest_sha256"] = sha(canonical(candidate))
    if any(payload.get(k) != v for k, v in expected.items()) or payload.get("status") != "qualified":
        raise ValueError("candidate qualification binding failed")
    start, end = timestamp(payload["qualified_at"]), timestamp(payload["expires_at"])
    if not start <= at < end or end - start > dt.timedelta(minutes=30):
        raise ValueError("candidate lease/qualification expired")
    report = payload["report"]
    if any(report.get(k) != v for k, v in {"candidate_id": candidate["candidate_id"], "revision": candidate["revision"], "audit_profile": candidate["audit_profile"], "artifact_manifest_sha256": expected["artifact_manifest_sha256"]}.items()):
        raise ValueError("native report identity mismatch")
    return report


def wait(candidate, public_key, output, timeout=1800, api=None):
    api = api or GitHub()
    deadline = time.monotonic() + timeout
    context = f"ssdf-candidate/{candidate['run_id']}/{candidate['run_attempt']}"
    while time.monotonic() < deadline:
        statuses = api.get(f"commits/{candidate['revision']}/statuses?per_page=100")
        for status in statuses:
            if status.get("context") != context:
                continue
            if status.get("state") in ("error", "failure"):
                raise ValueError("candidate coordinator rejected qualification")
            if status.get("state") != "success":
                continue
            parsed = urllib.parse.urlsplit(status.get("target_url", ""))
            if (parsed.scheme, parsed.netloc, parsed.path) != ("https", "github.com", f"/{REPOSITORY}/actions/runs/{candidate['run_id']}") or parsed.query or not parsed.fragment.startswith("ssdf-candidate="):
                raise ValueError("untrusted candidate receipt location")
            encoded = parsed.fragment[len("ssdf-candidate="):]
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,16000}", encoded):
                raise ValueError("candidate receipt exceeds bound")
            envelope = strict_json(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            report = verify_qualification(envelope, candidate, public_key)
            Path(output).write_bytes(canonical(report) + b"\n")
            Path(str(output) + ".receipt.json").write_bytes(canonical(envelope) + b"\n")
            return
        time.sleep(min(15, max(0, deadline - time.monotonic())))
    raise ValueError("candidate qualification timed out")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("manifest", "seal", "verify-files", "wait", "verify-qualification"))
    parser.add_argument("--directory")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--version")
    parser.add_argument("--candidate-id")
    parser.add_argument("--workflow")
    parser.add_argument("--audit-profile", choices=("standard", "enhanced"), default="standard")
    parser.add_argument("--recipient")
    parser.add_argument("--output")
    parser.add_argument("--public-key")
    parser.add_argument("--receipt")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    try:
        if args.command == "manifest":
            candidate = manifest(args.directory, args.version, args.candidate_id, args.workflow, args.audit_profile)
            Path(args.manifest).write_bytes(canonical(candidate))
        elif args.command == "seal":
            seal(args.directory, args.manifest, args.recipient, args.output)
        else:
            candidate = strict_json(Path(args.manifest).read_bytes())
            if args.command == "verify-files":
                verify_files(args.directory, candidate)
            elif args.command == "verify-qualification":
                verify_qualification(strict_json(Path(args.receipt).read_bytes()), candidate, args.public_key)
            else:
                if not 1 <= args.timeout <= 1800:
                    raise ValueError("bounded qualification timeout required")
                wait(candidate, args.public_key, args.output, args.timeout)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, BrokenPipeError):
        parser.exit(1, "candidate qualification/transport failed; publication prohibited\n")


if __name__ == "__main__":
    main()

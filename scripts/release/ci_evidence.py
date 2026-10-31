#!/usr/bin/env python3
"""Encrypt bounded per-job evidence chunks; never upload plaintext reports."""
import argparse
import glob
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile
from risk_acceptance import canonical, sha

PART = 8 << 20
MAX_TOTAL = 512 << 20
JOBS = {"unit", "test", "integration", "smoke", "e2e", "sonar", "sast", "secrets", "vulnerability"} | {"server-" + str(i) for i in range(6)}
TEXT_SUFFIXES = {".json", ".jsonl", ".sarif", ".xml", ".txt", ".log", ".out", ".info", ".trace", ".network", ".properties", ".stdout", ".stderr"}


def redact(data):
    text = data.decode("utf-8")
    # Credentials are never an evidence requirement. Apply redaction before
    # calculating retained-payload digests. Do not provision extra secrets to
    # untrusted jobs merely to build this evidence bundle.
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "SONAR_TOKEN", "SNYK_TOKEN", "DOCKERHUB_TOKEN", "GITLEAKS_LICENSE"):
        secret = os.environ.get(name)
        if secret and len(secret) >= 8:
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]{8,}", r"\1[REDACTED]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "[REDACTED-JWT]", text)
    text = re.sub(r'(?i)([?&](?:access_token|token|api_key|key|sig|signature|password)=)[^&\s"<>]+', r'\1[REDACTED]', text)
    # Browser trace request/response bodies, cookies and auth state must not
    # survive merely to preserve every original log byte.
    text = re.sub(r'(?i)("(?:password|secret|token|access_token|refresh_token|totp_secret|authorization|cookie|set-cookie)"\s*:\s*)"(?:[^"\\]|\\.)*"', r'\1"[REDACTED]"', text)
    return text.encode()


def browser_archive(data):
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as target:
        members = source.infolist()
        if len(members) > 10000 or sum(m.file_size for m in members) > MAX_TOTAL:
            raise ValueError("browser diagnostics exceed safe bound")
        for entry in members:
            if entry.filename.startswith("/") or ".." in Path(entry.filename).parts or "\\" in entry.filename or len(entry.filename) > 240 or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("unsafe browser diagnostic archive")
            if entry.is_dir():
                continue
            if entry.file_size > 16 << 20:
                target.writestr(entry.filename, b"[REDACTED oversized browser resource]\n")
                continue
            payload = source.read(entry)
            if entry.filename.endswith((".trace", ".network")):
                lines = []
                import json
                def safe(value):
                    if isinstance(value, dict):
                        return {key: "[REDACTED]" if key.lower() in {"headers", "cookies", "postdata", "body", "storagestate", "password", "token", "secret", "value"} else safe(item) for key, item in value.items()}
                    if isinstance(value, list):
                        return [safe(item) for item in value]
                    return value
                for line in payload.splitlines():
                    lines.append(canonical(safe(json.loads(line))))
                payload = redact(b"\n".join(lines) + b"\n")
            elif entry.filename.startswith("resources/"):
                # Resources can contain authentication responses, DOM snapshots
                # and QR images. Retain their identity, not unknown credentials.
                payload = b"[REDACTED browser resource sha256:" + sha(payload).encode() + b"]\n"
            else:
                try:
                    payload = redact(payload)
                except UnicodeError:
                    pass
            target.writestr(entry.filename, payload)
    return output.getvalue()


def available(root, patterns):
    root = Path(root).resolve()
    paths, missing = set(), []
    for pattern in patterns:
        if not isinstance(pattern, str) or pattern.startswith("/") or ".." in Path(pattern).parts:
            raise ValueError("unsafe evidence pattern")
        matched = glob.glob(str(root / pattern), recursive=True)
        found = []
        for value in matched:
            path = Path(value)
            if path.is_dir() and not path.is_symlink():
                found.extend(p for p in path.rglob("*") if not p.is_dir() or p.is_symlink())
            else:
                found.append(path)
        if not found:
            missing.append(pattern)
        for path in found:
            relative = path.relative_to(root)
            current = root
            for part in relative.parts:
                current = current / part
                if current.is_symlink():
                    raise ValueError("evidence symlinks are forbidden")
            if not path.is_file() or path.stat().st_size > MAX_TOTAL:
                raise ValueError("invalid evidence source")
            paths.add(path)
    return sorted(paths), missing


def encrypt_job(root, output, recipient, job, status, patterns, revision, workflow, runner_results=None):
    if job not in JOBS or status not in {"success", "failure", "cancelled", "skipped"} or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("invalid job source binding")
    repository = os.environ["GITHUB_REPOSITORY"]
    workflow = workflow.removeprefix(repository + "/").split("@", 1)[0]
    if repository != "lorconksu/veyport" or workflow not in {".github/workflows/ci.yml", ".github/workflows/release.yml", ".github/workflows/staging.yml"}:
        raise ValueError("unexpected job workflow")
    root, output = Path(root).resolve(), Path(output)
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip() != revision:
        raise ValueError("job checkout differs from declared source")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    spec = importlib.util.spec_from_file_location("ssdf_evidence", Path(__file__).resolve().parents[2] / "infra/evidence-collector/evidence.py")
    crypto = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(crypto)
    paths, missing = available(root, patterns)
    names = {path: path.relative_to(root).as_posix() for path in paths}
    if runner_results is not None:
        trusted = Path(os.environ["RUNNER_TEMP"]) / "ssdf-results"
        if Path(runner_results) != trusted:
            raise ValueError("unexpected runner evidence root")
        if trusted.exists():
            extra, absent = available(trusted, ["**/*"])
            missing.extend("runner-results/" + value for value in absent)
            for path in extra:
                names[path] = "runner-results/" + path.relative_to(trusted).as_posix()
            paths.extend(extra)
        else:
            missing.append("runner-results")
    chunks, current, current_bytes, part_index = [], [], 0, {}
    originals, total = [], 0
    with tempfile.TemporaryDirectory() as directory:
        staging = Path(directory)
        (staging / "parts").mkdir()
        for path in paths:
            raw = path.read_bytes()
            if path.suffix == ".zip":
                retained = browser_archive(raw)
            elif path.suffix in TEXT_SUFFIXES:
                retained = redact(raw)
            else:
                retained = raw
            total += len(retained)
            if total > MAX_TOTAL:
                raise ValueError("per-job evidence exceeds archive resource budget")
            refs = []
            for offset in range(0, max(1, len(retained)), PART):
                data = retained[offset:offset + PART]
                digest = sha(data)
                name = "parts/" + digest
                (staging / name).write_bytes(data)
                item = {"name": name, "sha256": digest, "size": len(data)}
                if digest in part_index:
                    index = part_index[digest]
                else:
                    if current and (current_bytes + len(data) > PART or len(current) >= 256):
                        chunks.append(current)
                        current, current_bytes = [], 0
                    if len(chunks) >= 64:
                        raise ValueError("per-job evidence exceeds chunk bound")
                    index = len(chunks)
                    current.append(item)
                    current_bytes += len(data)
                    part_index[digest] = index
                refs.append({"name": name, "offset": offset, "size": len(data), "sha256": digest, "chunk_index": index})
            originals.append({"name": names[path], "sha256": sha(retained), "size": len(retained), "original_sha256": sha(raw), "redacted": retained != raw, "parts": refs})
        # Even a job that failed before generating any report has an explicit
        # encrypted partial-outcome chunk. Cancellation reconciliation records
        # jobs that could not reach this finalizer separately.
        if current:
            chunks.append(current)
        if not chunks:
            chunks = [[]]
        recipient_path = staging / "recipient.txt"
        if not re.fullmatch(r"age1[0-9a-z]{58}", recipient):
            raise ValueError("pinned age recipient unavailable")
        recipient_path.write_text(recipient + "\n")
        for index, items in enumerate(chunks):
            manifest = {"schema": 1, "repository": repository, "workflow": workflow, "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "revision": revision, "candidate_id": f"run-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}", "complete": False, "files": items, "details": {"kind": "job-chunk", "job": job, "chunk_index": index, "chunk_count": len(chunks), "github_sha": os.environ.get("GITHUB_SHA"), "checkout_revision": revision, "status": status, "missing": missing, "original_files": originals, "dast": "deferred-owner-decision"}}
            payload = crypto.pack(manifest, staging)
            (output / f"chunk-{index:04d}.age").write_bytes(crypto.age_encrypt(payload, recipient_path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    for flag in ("output", "recipient", "job", "status", "revision", "workflow"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--runner-results")
    parser.add_argument("--path", action="append", default=[])
    args = parser.parse_args()
    os.umask(0o077)
    try:
        encrypt_job(args.root, args.output, args.recipient, args.job, args.status, args.path, args.revision, args.workflow, args.runner_results)
    except Exception:
        # Provider errors, report text and signed URLs must never enter logs.
        parser.exit(1, "private job evidence encryption failed; reconciliation required\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exact-content risk approvals backed by a trusted, owner-dispatched GitHub run."""
import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = "lorconksu/veyport"
OWNER_LOGIN = "lorconksu"
OWNER_ID = 13374789
WORKFLOW = ".github/workflows/risk-approval.yml"
ENVIRONMENT = "ssdf-risk-approval"
TRUSTED_FILES = (WORKFLOW, "scripts/release/risk_acceptance.py")
MAX_BYTES = 1 << 20
SOURCE_SCOPES = {"source:go:" + n for n in ("hub", "agent", "cli", "proto", "infra/application-access/fixture")} | {"source:npm:web", "source:npm:tests/e2e", "source:pip:infra/audit-lab/storage"}
SOURCE_SCOPES |= {"source:sast:" + n for n in ("sonar", "semgrep", "codeql")}
IMAGE_SCOPES = {"image:" + n for n in ("veyport", "audit-ingest", "audit-export")}
NATIVE_SCOPES = {"native:grpc", "native:ssh"}
FINDING_SCOPES = SOURCE_SCOPES | IMAGE_SCOPES | NATIVE_SCOPES


def strict_json(data):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    except RecursionError as error:
        raise ValueError("JSON nesting exceeds bound") from error


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        raise ValueError("UTC timestamp required")
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def now():
    return dt.datetime.now(dt.timezone.utc)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_record(path):
    raw = Path(path).read_bytes()
    if len(raw) > 65536 or not raw.startswith(b"---\n"):
        raise ValueError("bounded JSON front matter required")
    parts = raw.split(b"\n---\n", 1)
    if len(parts) != 2 or not parts[1].strip():
        raise ValueError("human reasoning required")
    record = strict_json(parts[0][4:])
    if isinstance(record, dict) and re.fullmatch(r"CR-\d{4,8}", str(record.get("id", ""))):
        required = {"schema_version", "id", "inventory_sha256", "reason", "owner", "authorized_approver", "approval_time", "expires_at", "private_evidence_reference"}
        if set(record) != required or record["schema_version"] != 1 or Path(path).stem != record["id"] or not re.fullmatch(r"[0-9a-f]{64}", record["inventory_sha256"]):
            raise ValueError("invalid coverage review schema")
        if record["authorized_approver"] != OWNER_LOGIN or any(not isinstance(record[k], str) or not 1 <= len(record[k]) <= 4096 for k in ("reason", "owner")):
            raise ValueError("owner coverage review required")
        start, end = timestamp(record["approval_time"]), timestamp(record["expires_at"])
        if not start < end or end - start > dt.timedelta(days=90):
            raise ValueError("coverage review must expire within 90 days")
        if record["private_evidence_reference"] is not None and not re.fullmatch(r"evidence:[A-Za-z0-9._/-]{1,128}", record["private_evidence_reference"]):
            raise ValueError("private evidence must use opaque identifier")
        return record, sha(raw)
    required = {"schema_version", "id", "findings", "classification", "severity", "reason", "compensating_controls", "owner", "authorized_approver", "approval_time", "expires_at", "remediation_reference", "private_evidence_reference"}
    if set(record) != required or record["schema_version"] != 1 or not re.fullmatch(r"RA-\d{4,8}", record["id"]):
        raise ValueError("invalid risk record schema")
    if Path(path).stem != record["id"]:
        raise ValueError("risk record identifier mismatch")
    if record["classification"] not in ("accepted-risk", "false-positive", "not-affected") or record["severity"] not in ("critical", "high", "medium", "low", "info"):
        raise ValueError("invalid risk classification")
    for field in ("reason", "compensating_controls", "owner", "remediation_reference"):
        if not isinstance(record[field], str) or not 1 <= len(record[field]) <= 4096:
            raise ValueError("missing risk reasoning")
    if record["private_evidence_reference"] is not None and not re.fullmatch(r"evidence:[A-Za-z0-9._/-]{1,128}", record["private_evidence_reference"]):
        raise ValueError("private evidence must use an opaque identifier")
    if record["authorized_approver"] != OWNER_LOGIN:
        raise ValueError("owner approval required")
    start, end = timestamp(record["approval_time"]), timestamp(record["expires_at"])
    if not start < end or end - start > dt.timedelta(days=90):
        raise ValueError("bounded temporary exception required")
    findings = record["findings"]
    if not isinstance(findings, list) or not 1 <= len(findings) <= 100:
        raise ValueError("explicit finding scopes required")
    keys = set()
    for item in findings:
        if set(item) != {"scope", "scanner", "id", "component", "version"} or any(not isinstance(v, str) or not 1 <= len(v) <= 256 or "*" in v for v in item.values()):
            raise ValueError("exact report-scope/scanner/finding/component/version required")
        if item["scope"] not in FINDING_SCOPES:
            raise ValueError("unknown risk-acceptance report scope")
        key = canonical(item)
        if key in keys:
            raise ValueError("duplicate risk scope")
        keys.add(key)
    return record, sha(raw)


class GitHub:
    def __init__(self, token=None):
        self.token = token if token is not None else os.environ.get("GH_TOKEN", os.environ.get("GITHUB_TOKEN", ""))
        if not self.token:
            raise ValueError("GitHub authentication required")

    def get(self, path, raw=False):
        # Never forward authentication to artifact redirect hosts.
        url = "https://api.github.com/repos/" + REPOSITORY + "/" + path
        request = urllib.request.Request(url, headers={"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github.raw+json" if raw else "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        try:
            response = urllib.request.build_opener(NoRedirect).open(request, timeout=30)
        except urllib.error.HTTPError as error:
            if error.code != 302 or not path.endswith("/zip"):
                raise
            target = error.headers.get("Location", "")
            parsed = urllib.parse.urlsplit(target)
            if parsed.scheme != "https" or parsed.username or parsed.password or not parsed.hostname or not parsed.hostname.endswith(".blob.core.windows.net"):
                raise ValueError("unexpected artifact download host") from None
            response = urllib.request.urlopen(target, timeout=30)
        with response:
            data = response.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("GitHub response exceeds bound")
        return data if raw else strict_json(data)

    def content(self, path, revision):
        if not re.fullmatch(r"[0-9a-f]{40}|main", revision):
            raise ValueError("immutable revision required")
        return self.get("contents/" + path + "?ref=" + revision, raw=True)


def trusted_run(api, run_id, completed=True):
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id < 1:
        raise ValueError("invalid approval run")
    run = api.get(f"actions/runs/{run_id}")
    repo = api.get("")
    owner = repo["owner"]
    # Repository ownership is checked against the explicitly pinned login; both
    # numeric identities must agree, preventing a same-name descriptor forgery.
    if repo.get("full_name") != REPOSITORY or repo.get("default_branch") != "main" or owner.get("login") != OWNER_LOGIN or owner.get("type") != "User" or owner.get("id") != OWNER_ID:
        raise ValueError("unexpected repository owner")
    if run.get("repository", {}).get("full_name") != REPOSITORY or run.get("event") != "workflow_dispatch" or run.get("path") != WORKFLOW or run.get("head_branch") != "main" or run.get("run_attempt") != 1:
        raise ValueError("untrusted approval workflow source")
    for field in ("actor", "triggering_actor"):
        actor = run.get(field, {})
        if actor.get("id") != owner.get("id") or actor.get("login") != OWNER_LOGIN or actor.get("type") != "User":
            raise ValueError("approval must originate with the owner")
    if completed and (run.get("status") != "completed" or run.get("conclusion") != "success"):
        raise ValueError("approval workflow has not succeeded")
    ancestor = api.get("compare/" + run["head_sha"] + "...main")
    if ancestor.get("status") not in ("ahead", "identical"):
        raise ValueError("approval code is outside trusted main history")
    for path in TRUSTED_FILES:
        if api.content(path, run["head_sha"]) != api.content(path, "main"):
            raise ValueError("approval workflow implementation changed; renew explicit approval")
    env = api.get("environments/" + ENVIRONMENT)
    rules = [r for r in env.get("protection_rules", []) if r.get("type") == "required_reviewers"]
    if len(rules) != 1 or rules[0].get("prevent_self_review") is not False:
        raise ValueError("sole-owner protected approval environment is not configured")
    reviewers = rules[0].get("reviewers", [])
    if len(reviewers) != 1 or reviewers[0].get("type") != "User" or reviewers[0].get("reviewer", {}).get("id") != owner["id"]:
        raise ValueError("owner environment reviewer required")
    branch = api.get("environments/" + ENVIRONMENT + "/deployment-branch-policies")
    if env.get("deployment_branch_policy") != {"protected_branches": False, "custom_branch_policies": True} or [(r.get("name"), r.get("type")) for r in branch.get("branch_policies", [])] != [("main", "branch")]:
        raise ValueError("approval environment must allow only main")
    return run


def record_directory(record):
    return "coverage-reviews" if record["id"].startswith("CR-") else "risk-acceptances"


def record_scope(record):
    return {"inventory_sha256": record["inventory_sha256"]} if record["id"].startswith("CR-") else record["findings"]


def prepare(api, record_path, record_revision, expected_hash, run_id):
    record, digest = load_record(record_path)
    if digest != expected_hash or not re.fullmatch(r"[0-9a-f]{40}", record_revision):
        raise ValueError("record hash or revision mismatch")
    run = trusted_run(api, run_id, completed=False)
    if sha(api.content("docs/security/" + record_directory(record) + "/" + record["id"] + ".md", record_revision)) != digest:
        raise ValueError("record revision content mismatch")
    created = timestamp(run["created_at"])
    if not timestamp(record["approval_time"]) <= created < timestamp(record["expires_at"]) or created - timestamp(record["approval_time"]) > dt.timedelta(days=1):
        raise ValueError("approval proposal is stale or expired")
    return {"schema_version": 1, "repository": REPOSITORY, "record_id": record["id"], "record_revision": record_revision, "record_sha256": digest, "scope_sha256": sha(canonical(record_scope(record))), "run_id": run_id, "run_attempt": 1, "approved_by": OWNER_LOGIN, "approved_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"), "expires_at": record["expires_at"]}


def verify(api, record_path, approval, at=None):
    at = at or now()
    record, digest = load_record(record_path)
    expected = prepare(api, record_path, approval["record_revision"], digest, approval["run_id"])
    trusted_run(api, approval["run_id"])
    if approval != expected:
        raise ValueError("approval content was modified")
    if not timestamp(approval["approved_at"]) <= at < timestamp(record["expires_at"]):
        raise ValueError("approval is future-dated or expired")
    artifacts = api.get(f"actions/runs/{approval['run_id']}/artifacts?per_page=100")
    if artifacts.get("total_count", 0) > 100:
        raise ValueError("approval artifact pagination exceeds bound")
    found = [a for a in artifacts.get("artifacts", []) if a.get("name") == "ssdf-approval-" + record["id"] and not a.get("expired")]
    if len(found) != 1 or found[0].get("size_in_bytes", MAX_BYTES + 1) > MAX_BYTES:
        raise ValueError("approval evidence missing or ambiguous")
    payload = api.get(f"actions/artifacts/{found[0]['id']}/zip", raw=True)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        entries = archive.infolist()
        if len(entries) != 1 or entries[0].filename != "approval.json" or entries[0].file_size > 65536:
            raise ValueError("invalid approval artifact")
        archived = strict_json(archive.read(entries[0]))
    if archived != expected:
        raise ValueError("approval does not match authenticated artifact")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify"))
    parser.add_argument("--record", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--revision")
    parser.add_argument("--sha256")
    parser.add_argument("--run-id", type=int)
    args = parser.parse_args()
    try:
        api = GitHub()
        if args.command == "prepare":
            payload = prepare(api, args.record, args.revision, args.sha256, args.run_id)
            Path(args.approval).write_bytes(canonical(payload) + b"\n")
        else:
            verify(api, args.record, strict_json(Path(args.approval).read_bytes()))
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile):
        parser.exit(1, "risk approval verification failed (no exception authorized)\n")


if __name__ == "__main__":
    main()

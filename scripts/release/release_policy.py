#!/usr/bin/env python3
"""Fail-closed release finding evaluation; original reports remain private."""
import argparse
import datetime as dt
import os
from pathlib import Path
import re
from risk_acceptance import GitHub, canonical, now, sha, strict_json, timestamp, verify, load_record, SOURCE_SCOPES, IMAGE_SCOPES, NATIVE_SCOPES

BLOCKING_CLASSES = {"authentication", "authorization", "required-audit"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
POLICY_VERSION = "ssdf-2026-10-31-v1"


def read_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 << 20:
        raise ValueError("missing or oversized security evidence")
    return strict_json(path.read_bytes())


def validate_coverage(report, api, at):
    review = report.get("coverage_policy", {})
    descriptor = review.get("approval", {})
    identity = descriptor.get("id", "")
    if review.get("status") != "reviewed" or not re.fullmatch(r"CR-\d{4,8}", identity) or not re.fullmatch(r"[0-9a-f]{64}", str(review.get("inventory_sha256", ""))):
        raise ValueError("source coverage policy has not been approved")
    record_path = Path("docs/security/coverage-reviews") / (identity + ".md")
    record = verify(api or GitHub(), record_path, read_json(record_path.with_suffix(".approval.json")), at)
    if record["inventory_sha256"] != review["inventory_sha256"] or sha(record_path.read_bytes()) != descriptor.get("record_sha256"):
        raise ValueError("source coverage policy approval changed")
    return descriptor


def evaluate(reports, candidate_id, revision, artifact_hash, exceptions=(), api=None, at=None):
    at = at or now()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", candidate_id) or not re.fullmatch(r"[0-9a-f]{40}", revision) or not re.fullmatch(r"[0-9a-f]{64}", artifact_hash):
        raise ValueError("invalid candidate binding")
    scopes, findings, coverage_reviews = {}, [], []
    for report in reports:
        if report.get("schema_version") != 1 or report.get("candidate_id") != candidate_id or report.get("revision") != revision or report.get("artifact_manifest_sha256") != artifact_hash or report.get("status") != "completed":
            raise ValueError("incomplete or mismatched scan evidence")
        if not isinstance(report.get("scopes"), list) or len(report["scopes"]) > 100:
            raise ValueError("invalid scan scopes")
        declared = report.get("required_scopes")
        if not isinstance(declared, list) or len(set(declared)) != len(declared) or set(declared) != {s.get("id") for s in report["scopes"]}:
            raise ValueError("scan coverage declarations do not match results")
        if any(s.get("id", "").startswith("source:sast:") for s in report["scopes"]):
            coverage_reviews.append(validate_coverage(report, api, at))
        for scope in report["scopes"]:
            identity = scope.get("id")
            if identity in scopes or identity not in SOURCE_SCOPES | IMAGE_SCOPES | NATIVE_SCOPES:
                raise ValueError("duplicate or unknown scan scope")
            if scope.get("status") != "completed" or scope.get("authenticated") is not True or scope.get("coverage_complete") is not True:
                raise ValueError("operational or coverage failure cannot be excepted")
            if not isinstance(scope.get("findings"), list) or len(scope["findings"]) > 100000:
                raise ValueError("invalid finding inventory")
            scopes[identity] = scope
            findings.extend((identity, finding) for finding in scope["findings"])
    if set(scopes) != SOURCE_SCOPES | IMAGE_SCOPES | NATIVE_SCOPES:
        raise ValueError("required source, image or native coverage is absent")
    # Records are loaded/authorized independently; report-supplied waiver fields
    # and dashboard suppressions never create an approval.
    accepted, used = {}, []
    for record_path, approval_path in exceptions:
        record, _ = load_record(record_path)
        for scope in record["findings"]:
            key = tuple(scope[k] for k in ("scope", "scanner", "id", "component", "version"))
            if key in accepted:
                raise ValueError("ambiguous overlapping exceptions")
            accepted[key] = (record, record_path, approval_path)
    seen = {}
    verified = {}
    counts = {severity: 0 for severity in sorted(SEVERITIES)}
    licenses = 0
    for scope_identity, finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("invalid finding")
        values = [finding.get(k) for k in ("scanner", "id", "component", "version")]
        if any(not isinstance(v, str) or not 1 <= len(v) <= 256 for v in values):
            raise ValueError("unscoped finding")
        key = tuple(values)
        expected_scanner = scope_identity.removeprefix("source:sast:") if scope_identity.startswith("source:sast:") else "snyk" if scope_identity.startswith(("source:", "image:")) else scope_identity.removeprefix("native:")
        if finding["scanner"] != expected_scanner:
            raise ValueError("finding scanner does not match required scope")
        # Multiple dependency paths and independently scoped image/source
        # findings remain in raw evidence. Evaluate each without dropping risks.
        previous = seen.get(key)
        current = (finding.get("severity"), finding.get("classification"), finding.get("finding_type", "vulnerability"))
        if previous is not None and previous != current:
            raise ValueError("contradictory finding dispositions across scopes")
        is_new = previous is None
        seen[key] = current
        severity = finding.get("severity")
        classification = finding.get("classification")
        if severity not in SEVERITIES or classification not in {"unresolved", "vulnerability", "false-positive", "not-affected"} | BLOCKING_CLASSES:
            raise ValueError("unknown finding severity or disposition")
        if finding.get("finding_type", "vulnerability") == "license":
            if finding["scanner"] != "snyk" or not finding["id"].startswith("snyk:lic:") or classification in BLOCKING_CLASSES:
                raise ValueError("security failures cannot be disguised as license findings")
            licenses += int(is_new)
            continue
        if finding.get("finding_type", "vulnerability") != "vulnerability":
            raise ValueError("unknown finding type")
        counts[severity] += int(is_new)
        block = severity in {"critical", "high"} or classification in BLOCKING_CLASSES or classification in {"false-positive", "not-affected"}
        if severity in {"medium", "low"}:
            first_seen = timestamp(finding.get("first_seen"))
            if first_seen > at:
                raise ValueError("finding first-seen time is in the future")
            deadline = first_seen + dt.timedelta(days=30 if severity == "medium" else 90)
            block = block or at >= deadline
        match = accepted.get((scope_identity, *key))
        if block:
            if match is None:
                raise ValueError("blocking finding lacks a valid scoped owner approval")
            record, record_path, approval_path = match
            if record["id"] not in verified:
                verified[record["id"]] = verify(api or GitHub(), record_path, read_json(approval_path), at)
            record = verified[record["id"]]
            if record["severity"] != severity:
                raise ValueError("blocking finding lacks a valid scoped owner approval")
            # Findings labelled false-positive/not-affected need that precise
            # assessment; accepting risk cannot silently rewrite scanner output.
            if classification in {"false-positive", "not-affected"} and record["classification"] != classification:
                raise ValueError("finding disposition and approval disagree")
            used.append({"id": record["id"], "record_sha256": sha(Path(record_path).read_bytes()), "expires_at": record["expires_at"]})
    return {"schema_version": 1, "policy_version": POLICY_VERSION, "candidate_id": candidate_id, "revision": revision, "artifact_manifest_sha256": artifact_hash, "decision": "pass", "evaluated_at": at.strftime("%Y-%m-%dT%H:%M:%SZ"), "dast": "deferred-owner-decision", "counts": counts, "license_findings": licenses, "coverage_reviews": coverage_reviews, "exceptions": sorted({canonical(item): item for item in used}.values(), key=lambda v: v["id"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="append", required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--artifact-manifest-sha256", required=True)
    parser.add_argument("--exceptions", default="docs/security/risk-acceptances")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        root = Path(args.exceptions)
        exceptions = [(p, p.with_suffix(".approval.json")) for p in sorted(root.glob("RA-*.md"))]
        decision = evaluate([read_json(p) for p in args.report], args.candidate_id, args.revision, args.artifact_manifest_sha256, exceptions)
        Path(args.output).write_bytes(canonical(decision) + b"\n")
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, "release policy rejected candidate; inspect private evidence\n")


if __name__ == "__main__":
    main()

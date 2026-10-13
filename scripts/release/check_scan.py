#!/usr/bin/env python3
"""Fail closed on malformed, incomplete, or nonempty scanner evidence."""
import argparse
import hashlib
import json
from pathlib import Path

from go_binary_evidence import decode_stream, package_absent

# Individually reviewed source annotations, with bounded occurrence counts.
# The SARIF findings remain in public evidence; any other suppression blocks.
REVIEWED_ANNOTATIONS = {
    ("go.lang.security.audit.crypto.use_of_weak_crypto.use-of-md5", "hub/internal/auditingest/s3.go"): 1,
    ("go.lang.security.audit.net.cookie-missing-httponly.cookie-missing-httponly", "hub/internal/server/cookies.go"): 2,
    ("typescript.react.security.audit.react-dangerouslysetinnerhtml.react-dangerouslysetinnerhtml", "web/src/components/markdown-viewer.tsx"): 1,
    ("typescript.react.security.audit.react-dangerouslysetinnerhtml.react-dangerouslysetinnerhtml", "web/src/pages/server-detail.tsx"): 1,
}


def check(path, scanner, evidence=None, mappings=None, assessment=None):
    raw = Path(path).read_bytes()
    if not 0 < len(raw) <= 64 << 20:
        raise ValueError("bounded scanner evidence required")
    report = json.loads(raw)
    if not isinstance(report, dict):
        raise ValueError("scanner object required")
    if scanner == "grype":
        findings = report.get("matches")
        if not isinstance(findings, list) or not isinstance(report.get("descriptor"), dict) or report["descriptor"].get("name") != "grype" or not isinstance(report.get("source"), dict):
            raise ValueError("complete Grype evidence required")
        if report.get("ignoredMatches"):
            raise ValueError("ignored findings require review, not an automatic pass")
    elif scanner == "semgrep":
        runs = report.get("runs")
        if not isinstance(runs, list) or not runs:
            raise ValueError("complete SARIF evidence required")
        findings = []
        for run in runs:
            if not isinstance(run, dict) or not isinstance(run.get("results"), list) or run.get("tool", {}).get("driver", {}).get("name", "").lower() not in ("semgrep", "semgrep oss"):
                raise ValueError("complete Semgrep evidence required")
            if not run.get("invocations"):
                raise ValueError("scanner execution evidence required")
            for invocation in run["invocations"]:
                if not isinstance(invocation, dict) or invocation.get("executionSuccessful") is not True or any(n.get("level") in ("error", "warning") for n in invocation.get("toolExecutionNotifications", [])):
                    raise ValueError("scanner execution failed")
            findings.extend(run["results"])
    else:
        raise ValueError("unknown scanner")
    classifications = []
    annotations = {}
    for finding in findings:
        classified = False
        classification = "blocking"
        if scanner == "semgrep":
            locations = finding.get("locations", [])
            suppressions = finding.get("suppressions", [])
            if len(locations) == 1 and suppressions and all(s.get("kind") == "inSource" and s.get("status") in (None, "accepted") for s in suppressions):
                key = (finding.get("ruleId"), locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri"))
                annotations[key] = annotations.get(key, 0) + 1
                if annotations[key] <= REVIEWED_ANNOTATIONS.get(key, 0):
                    classification = "reviewed_nonsecurity_use"
        if scanner == "grype" and evidence is not None and mappings is not None:
            artifact, vulnerability = finding.get("artifact", {}), finding.get("vulnerability", {})
            locations = artifact.get("locations", [])
            if artifact.get("type") == "go-module" and locations:
                classified = True
                for location in locations:
                    mapping = mappings.get(location.get("path"))
                    if mapping is None:
                        classified = False
                        break
                    binary, source = mapping
                    raw_evidence = json.loads((Path(evidence) / (binary + ".go.json")).read_text())
                    # Reparse scanner shape and bind the evidence to the actual
                    # binary bytes extracted from this exact OCI image/artifact.
                    messages = decode_stream("\n".join(json.dumps(m) for m in raw_evidence["messages"]).encode())
                    if raw_evidence.get("binary") != binary or raw_evidence.get("sha256") != hashlib.sha256(Path(source).read_bytes()).hexdigest() or not package_absent(messages, vulnerability.get("id"), artifact.get("name")):
                        classified = False
                        break
        if classified:
            classification = "not_affected_known_package_absent"
        classifications.append({"id": finding.get("vulnerability", {}).get("id") if scanner == "grype" else finding.get("ruleId"), "classification": classification})
    if assessment:
        Path(assessment).write_text(json.dumps({"scanner": scanner, "finding_count": len(findings), "assessments": classifications}, indent=2) + "\n")
    if any(c["classification"] == "blocking" for c in classifications):
        raise ValueError(f"scanner gate failed: {len(findings)} findings")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scanner", choices=("grype", "semgrep"))
    parser.add_argument("report")
    parser.add_argument("--go-evidence")
    parser.add_argument("--binary-mapping", help="JSON mapping exact scanned paths to [public binary name, actual local file]")
    parser.add_argument("--assessment")
    args = parser.parse_args()
    try:
        mapping = json.loads(Path(args.binary_mapping).read_text()) if args.binary_mapping else None
        check(args.report, args.scanner, args.go_evidence, mapping, args.assessment)
    except (ValueError, OSError, TypeError, AttributeError):
        parser.exit(1, "scanner evidence invalid or findings present\n")

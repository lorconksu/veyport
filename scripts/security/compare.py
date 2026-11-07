#!/usr/bin/env python3
"""Export a private all-state scanner comparison without starting new scans.

Input is the dated collection directory with its content-hashed manifest. Review
proposals are descriptive evidence, never scanner dismissals or release waivers.
"""
import argparse
import hashlib
import json
from pathlib import Path

from snyk import sha256, write_private


def sarif(path, scanner):
    document = json.loads(path.read_text())
    if document.get("version") != "2.1.0" or not isinstance(document.get("runs"), list):
        raise ValueError("complete SARIF required")
    records = []
    for run in document["runs"]:
        for result in run.get("results", []):
            location = result.get("locations", [{}])[0].get("physicalLocation", {})
            uri = location.get("artifactLocation", {}).get("uri", "")
            rule = result.get("ruleId")
            review = "unresolved"
            rationale = "Requires flow review; test locations do not imply safe production behavior."
            if scanner == "snyk-code" and rule == "go/Sqli" and uri == "hub/internal/migrate/migrate.go":
                review = "false-positive-proposed"
                rationale = "Build-embedded SQL migration bytes; migration marker insertion is parameterized. No attacker-controlled SQL source identified."
            elif uri == "hub/internal/auditingest/s3.go" and (rule == "go/InsecureHash" or "use-of-md5" in rule):
                review = "reviewed-nonsecurity-use-proposed"
                rationale = "S3 Content-MD5 transport checksum; integrity authority remains SHA256 and authenticated receipts."
            elif uri == "hub/internal/server/cookies.go" and (rule == "go/WebCookieMissesCallToSetHttpOnly" or "cookie-missing-httponly" in rule):
                review = "reviewed-nonsecurity-use-proposed"
                rationale = "Double-submit CSRF cookie intentionally readable by browser; other location deletes cookies. Session cookies remain HttpOnly."
            records.append({"scanner": scanner, "id": hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest(),
                            "rule": rule, "scanner_level": result.get("level"), "location": location,
                            "test_location_heuristic": "_test.go" in uri or "/__tests__/" in uri or "/tests/" in uri or "/test/" in uri,
                            "native_suppressions": result.get("suppressions", []), "proposed_disposition": review,
                            "rationale": rationale, "approved_exception": False, "raw_result": result})
    return records


def export(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "collection-manifest.json").read_text())
    required = {"snyk-code.json", "semgrep/semgrep.sarif", "codeql-alerts-pages.json",
                "sonar-issues-pages.json", "sonar-hotspots.json"}
    codeql = {"codeql-" + language + ".sarif" for language in ("actions", "go", "javascript-typescript", "python", "ruby")}
    if not required | codeql <= set(manifest["files"]):
        raise ValueError("complete comparison inventory required")
    for relative, expected in manifest["files"].items():
        path = directory / relative
        if Path(relative).is_absolute() or ".." in Path(relative).parts or path.is_symlink() or path.stat().st_size != expected["bytes"] or sha256(path) != expected["sha256"]:
            raise ValueError("comparison source hash mismatch")
    records = []
    for file, scanner in [("snyk-code.json", "snyk-code"), ("semgrep/semgrep.sarif", "semgrep")]:
        records.extend(sarif(directory / file, scanner))
    for relative in sorted(codeql):
        records.extend(sarif(directory / relative, "codeql"))
    alerts = json.loads((directory / "codeql-alerts-pages.json").read_text())
    records.extend({"scanner": "codeql", "kind": "historical-alert", "id": alert["number"],
                    "native_state": alert["state"], "native_disposition": alert.get("dismissed_reason"),
                    "proposed_disposition": "unresolved", "approved_exception": False, "raw_result": alert}
                   for page in alerts for alert in (page if isinstance(page, list) else [page]))
    for page in json.loads((directory / "sonar-issues-pages.json").read_text()):
        records.extend({"scanner": "sonar", "kind": issue.get("type"), "id": issue["key"],
                        "native_state": issue["status"], "native_disposition": issue.get("resolution"),
                        "proposed_disposition": "unresolved", "approved_exception": False, "raw_result": issue}
                       for issue in page["issues"])
    records.extend({"scanner": "sonar", "kind": "security-hotspot", "id": issue["key"],
                    "native_state": issue["status"], "native_disposition": issue.get("resolution"),
                    "proposed_disposition": "unresolved", "approved_exception": False, "raw_result": issue}
                   for issue in json.loads((directory / "sonar-hotspots.json").read_text())["hotspots"])
    return {"schema_version": 1, "revision": manifest["source_revision"], "purpose": "comparison-only",
            "release_qualified": False, "scanner_retirement_justified": False,
            "collection_manifest_sha256": sha256(directory / "collection-manifest.json"),
            "records": records}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        write_private(args.output, export(args.directory))
    except (OSError, ValueError, TypeError, KeyError):
        parser.exit(1, "comparison evidence invalid\n")

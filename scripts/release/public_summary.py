#!/usr/bin/env python3
"""Write a fixed allowlist of public release metadata; never attach raw reports."""
import argparse
from pathlib import Path
from risk_acceptance import canonical, strict_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("delivery", "decision", "receipt", "version"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args()
    decision = strict_json(Path(args.decision).read_bytes())
    receipt = strict_json(Path(args.receipt).read_bytes())
    if decision["decision"] != "pass" or receipt["status"] != "archived":
        parser.exit(1, "publication summary requires passing archived qualification\n")
    summary = {key: decision[key] for key in ("policy_version", "candidate_id", "revision", "artifact_manifest_sha256", "decision", "dast", "counts")}
    summary["version"] = args.version
    summary["private_evidence_reference"] = "sha256:" + receipt["manifest_sha256"]
    root = Path(args.delivery)
    (root / "release-summary.json").write_bytes(canonical(summary) + b"\n")
    (root / "release-notes.md").write_text("Commit: `" + decision["revision"] + "`\n\nExact qualified image digests:\n\n" + (root / "published-images.txt").read_text() + "\nSecurity qualification passed; web/API DAST is deferred by owner decision. Detailed reports are retained privately under the manifest reference in release-summary.json. Publication does not imply staging deployment completion.\n")


if __name__ == "__main__":
    main()

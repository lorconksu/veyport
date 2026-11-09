#!/usr/bin/env python3
"""Prepare an encrypted-transport manifest, including explicitly incomplete runs."""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
from risk_acceptance import canonical, sha, strict_json


def prepare(root, delivery, security, candidate, workflow, version, complete):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    missing = []
    for name, source in (("delivery-reports", Path(delivery) / "reports"), ("security", Path(security))):
        if not source.is_dir() or source.is_symlink():
            missing.append(name)
            continue
        for path in source.rglob("*"):
            if path.is_symlink():
                raise ValueError("evidence links are forbidden")
            if path.is_file():
                target = root / name / path.relative_to(source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
    candidate_path = Path(candidate)
    if candidate_path.is_file() and not candidate_path.is_symlink():
        shutil.copyfile(candidate_path, root / "candidate.json")
    else:
        missing.append("candidate-manifest")
    exceptions = Path("docs/security/risk-acceptances")
    for path in sorted(exceptions.glob("RA-*")):
        if path.is_file() and not path.is_symlink():
            target = root / "exceptions" / path.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    for path in sorted(Path("docs/security/coverage-reviews").glob("CR-*")):
        if path.is_file() and not path.is_symlink():
            target = root / "coverage-reviews" / path.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            files.append({"name": path.relative_to(root).as_posix(), "sha256": sha(data), "size": len(data)})
    candidate_id = "run-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    result = {"schema": 1, "repository": os.environ["GITHUB_REPOSITORY"], "workflow": workflow, "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "revision": os.environ["GITHUB_SHA"], "candidate_id": candidate_id, "complete": complete and not missing, "files": files, "details": {"version": version, "dast": "deferred-owner-decision", "missing": missing, "decision": "qualified" if complete and not missing else "incomplete", "final_status": "pending-independent-reconciliation", "expected_ci_jobs": ["unit"] + ["server-" + str(i) for i in range(6)] + ["test", "integration", "smoke", "e2e", "sonar", "secrets", "vulnerability"]}}
    module_path = Path(__file__).resolve().parents[2] / "infra/evidence-collector/evidence.py"
    spec = importlib.util.spec_from_file_location("ssdf_evidence", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.manifest_valid(result)
    return result


def verify_sources(manifest_path, expected_hash, delivery, security, candidate):
    manifest = strict_json(Path(manifest_path).read_bytes())
    if sha(canonical(manifest)) != expected_hash or manifest.get("complete") is not True:
        raise ValueError("archive manifest is incomplete or changed")
    mappings = {"delivery-reports": Path(delivery) / "reports", "security": Path(security), "exceptions": Path("docs/security/risk-acceptances"), "coverage-reviews": Path("docs/security/coverage-reviews")}
    expected = {}
    for prefix, source in mappings.items():
        if not source.is_dir() or source.is_symlink():
            raise ValueError("archived evidence source missing")
        for path in source.rglob("*"):
            if path.is_symlink():
                raise ValueError("archived evidence source is a link")
            if path.is_file() and (prefix not in ("exceptions", "coverage-reviews") or path.name.startswith("RA-" if prefix == "exceptions" else "CR-")):
                expected[prefix + "/" + path.relative_to(source).as_posix()] = path
    expected["candidate.json"] = Path(candidate)
    if set(expected) != {item["name"] for item in manifest["files"]}:
        raise ValueError("evaluated evidence differs from archived inventory")
    for item in manifest["files"]:
        path = expected[item["name"]]
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item["size"] or sha(path.read_bytes()) != item["sha256"]:
            raise ValueError("evaluated evidence changed after archival")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("directory", "delivery", "security", "candidate", "workflow", "version", "manifest"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--complete", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()
    try:
        if args.verify:
            verify_sources(args.manifest, args.expected_sha256, args.delivery, args.security, args.candidate)
        else:
            result = prepare(args.directory, args.delivery, args.security, args.candidate, args.workflow, args.version, args.complete)
            Path(args.manifest).write_bytes(canonical(result))
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, "evidence manifest preparation failed; publication prohibited\n")


if __name__ == "__main__":
    main()

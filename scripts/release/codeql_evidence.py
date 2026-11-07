#!/usr/bin/env python3
"""Reuse exact full default CodeQL evidence or seal a same-job full local scan.

Local scans use the pinned CodeQL init/analyze Actions with uploads disabled.
The receipt is an integrity binding inside the trusted delivery job, not an
approval or a portable signature. Publication still requires policy review.
"""
import argparse
import datetime as dt
import os
from pathlib import Path
import shutil
import subprocess
import urllib.error
from risk_acceptance import REPOSITORY, canonical, now, sha, strict_json
from source_sast import CODEQL_CATEGORIES, ExportAPI, MAX_BYTES, export_codeql, fresh, save, sarif_findings

LANGUAGES = {c.removeprefix("/language:") for c in CODEQL_CATEGORIES}
CONFIG = {"queries": [{"uses": "security-extended"}]}
ACTION_SHA = "9b3254085494b55a0f7c4c2b3d2d52cc712ce370"


def read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_BYTES:
        raise ValueError("bounded immutable evidence file required")
    return strict_json(path.read_bytes())


def identity(manifest_path, root):
    candidate = read(manifest_path)
    if not isinstance(candidate, dict):
        raise ValueError("CodeQL candidate manifest malformed")
    expected = {"repository": REPOSITORY, "revision": os.environ.get("GITHUB_SHA"),
                "run_id": int(os.environ.get("GITHUB_RUN_ID", "0")),
                "run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "0"))}
    if any(candidate.get(k) != v for k, v in expected.items()) or candidate.get("workflow") not in (".github/workflows/staging.yml", ".github/workflows/release.yml"):
        raise ValueError("CodeQL trusted candidate binding mismatch")
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or os.environ.get("GITHUB_EVENT_NAME") not in ("workflow_dispatch", "push") or not os.environ.get("GITHUB_JOB") or os.environ.get("GITHUB_REF", "").startswith("refs/pull/"):
        raise ValueError("CodeQL requires trusted delivery context")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if revision != candidate["revision"] or subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=root, check=False).returncode:
        raise ValueError("CodeQL source checkout changed")
    return {**expected, "candidate_id": candidate["candidate_id"], "version": candidate["version"],
            "workflow": candidate["workflow"], "job": os.environ["GITHUB_JOB"], "ref": os.environ["GITHUB_REF"],
            "artifact_manifest_sha256": sha(Path(manifest_path).read_bytes())}


def inventory(directory):
    rows = []
    for path in sorted(Path(directory).rglob("*")):
        if path.is_symlink():
            raise ValueError("CodeQL evidence links forbidden")
        if path.is_dir():
            continue
        if path.name == "receipt.json" and path.parent == Path(directory):
            continue
        if not path.is_file() or not 0 < path.stat().st_size <= MAX_BYTES or len(rows) >= 32:
            raise ValueError("CodeQL evidence inventory exceeded")
        rows.append({"path": path.relative_to(directory).as_posix(), "sha256": sha(path.read_bytes())})
    return rows


def private_action_environment():
    # The pinned action uploads raw debug artifacts independently of upload:
    # never. Reject before init registers its post-job uploader.
    for key in ("RUNNER_DEBUG", "ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG",
                "CODEQL_ACTION_DEBUG_COMBINED_SARIF", "CODEQL_ACTION_EXPECT_UPLOAD_FAILED_SARIF",
                "CODEQL_ACTION_SKIP_SARIF_UPLOAD", "INPUT_DEBUG"):
        if os.environ.get(key, "").lower() not in ("", "0", "false"):
            raise ValueError("CodeQL debug artifact modes are forbidden in private delivery")


def prepare(output, manifest, root, api=None, sarif_directory=None):
    private_action_environment()
    binding = identity(manifest, root)
    directory = Path(output)
    sarif_directory = Path(sarif_directory or directory.parent / "codeql-local").absolute()
    if sarif_directory.exists() or sarif_directory.is_symlink():
        raise ValueError("CodeQL local output must be absent before preparation")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    default = directory / "default"
    default.mkdir(mode=0o700)
    receipt = {"schema_version": 1, "binding": binding, "started_at": now().isoformat(), "status": "pending-local", "mode": "same-job-local", "sarif_directory": str(sarif_directory)}
    try:
        findings = export_codeql(api or ExportAPI(), default, binding["revision"], binding["version"])
    except (ValueError, OSError, KeyError, TypeError, urllib.error.URLError) as error:
        # Missing, stale, failed, reduced, or inaccessible default evidence is
        # never treated as clean. It requires the independently complete scan.
        # Keep any partial provider export for encrypted diagnostics. Its name
        # and receipt status prevent it qualifying as completed evidence.
        default.rename(directory / "default-incomplete")
        receipt["reuse_unavailable"] = "configuration-or-analysis-unavailable"
        if isinstance(error, urllib.error.HTTPError):
            receipt["reuse_http_status"] = error.code
            error.close()
    else:
        save(default, "findings.json", findings)
        receipt.update(status="completed", mode="default-main", completed_at=now().strftime("%Y-%m-%dT%H:%M:%SZ"))
    receipt["files"] = inventory(directory)
    save(directory, "receipt.json", receipt)
    required = receipt["status"] != "completed"
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as handle:
            handle.write("local_required=" + str(required).lower() + "\n")
    return required


def action_configuration(path, root):
    value = read(path)
    if not isinstance(value, dict):
        raise ValueError("CodeQL action configuration malformed")
    if value.get("debugMode") is not False:
        raise ValueError("CodeQL private delivery requires debug mode disabled")
    languages = {"javascript-typescript" if n == "javascript" else n for n in value.get("languages", [])}
    if languages != LANGUAGES or value.get("originalUserInput") != CONFIG or value.get("computedConfig") != CONFIG:
        raise ValueError("known full CodeQL query/language configuration required")
    if value.get("overlayDatabaseMode") != "none" or value.get("extraQueryExclusions") != [] or value.get("trapCaches") != {} or value.get("dependencyCachingEnabled") != "none" or value.get("analysisKinds") != ["code-scanning"] or value.get("buildMode") is not None or value.get("useOverlayDatabaseCaching", False) or Path(value.get("repositoryRoot", "")).resolve() != Path(root).resolve():
        raise ValueError("CodeQL reduced or foreign configuration")
    return {k: value[k] for k in ("debugMode", "languages", "originalUserInput", "computedConfig", "overlayDatabaseMode", "extraQueryExclusions", "trapCaches", "dependencyCachingEnabled", "analysisKinds", "repositoryRoot", "version")}


def local_reports(directory, binding, started_at=None):
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("CodeQL report directory links forbidden")
    reports, findings = {}, []
    for path in sorted(directory.iterdir()):
        if path.is_dir() or path.suffix != ".sarif":
            raise ValueError("unexpected CodeQL report inventory")
        language = "javascript-typescript" if path.stem == "javascript" else path.stem
        if language not in LANGUAGES or language in reports:
            raise ValueError("unexpected CodeQL report language")
        raw = read(path)
        if not isinstance(raw, dict):
            raise ValueError("CodeQL local report malformed")
        if started_at is not None:
            started = dt.datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            if path.stat().st_mtime < started.timestamp():
                raise ValueError("CodeQL local report predates preparation")
        runs = raw.get("runs", [])
        if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
            raise ValueError("one full CodeQL run per language required")
        run = runs[0]
        if not isinstance(run.get("invocations"), list) or any(not isinstance(i, dict) for i in run["invocations"]):
            raise ValueError("CodeQL local execution receipt malformed")
        for invocation in run.get("invocations", []):
            if invocation.get("endTimeUtc"):
                fresh(invocation["endTimeUtc"])
                if started_at is not None and dt.datetime.fromisoformat(invocation["endTimeUtc"].replace("Z", "+00:00")) < started:
                    raise ValueError("CodeQL invocation predates preparation")
        pack = "javascript" if language == "javascript-typescript" else language
        if not any(p.get("name") == f"codeql/{pack}-queries" and p.get("rules") for p in run.get("tool", {}).get("extensions", [])):
            raise ValueError("CodeQL language rule inventory missing")
        category = run.get("automationDetails", {}).get("id")
        if category is not None and "/language:" in category and not category.rstrip("/").endswith("/language:" + language) and not category.rstrip("/").endswith("/language:" + pack):
            raise ValueError("CodeQL local category mismatch")
        if any(p.get("branch") not in (None, binding["ref"]) for p in run.get("versionControlProvenance", [])):
            raise ValueError("CodeQL local source ref mismatch")
        findings.extend(sarif_findings(raw, "codeql", binding["revision"], binding["version"], local_codeql=True))
        reports[language] = path
    if set(reports) != LANGUAGES:
        raise ValueError("all five full CodeQL languages required")
    return reports, findings


def finish(output, manifest, root, sarif_directory, action_config):
    directory = Path(output)
    receipt = read(directory / "receipt.json")
    binding = identity(manifest, root)
    if receipt.get("binding") != binding or receipt.get("status") != "pending-local" or receipt.get("mode") != "same-job-local" or inventory(directory) != receipt.get("files"):
        raise ValueError("CodeQL preparation receipt mismatch")
    fresh(receipt["started_at"])
    if receipt.get("sarif_directory") != str(Path(sarif_directory).absolute()):
        raise ValueError("CodeQL local report path changed")
    configuration = action_configuration(action_config, root)
    reports, _ = local_reports(sarif_directory, binding, receipt["started_at"])
    local = directory / "local"
    local.mkdir(mode=0o700)
    for language, source in reports.items():
        destination = local / (language + ".sarif")
        destination.write_bytes(source.read_bytes())
        destination.chmod(0o600)
    save(local, "configuration.json", configuration)
    receipt.update(status="completed", completed_at=now().strftime("%Y-%m-%dT%H:%M:%SZ"), action_sha=ACTION_SHA, files=inventory(directory))
    save(directory, "receipt.json", receipt)


def consume(output, manifest, root, destination, revision, version, candidate_id):
    directory = Path(output)
    if directory.is_symlink():
        raise ValueError("CodeQL receipt directory links forbidden")
    receipt = read(directory / "receipt.json")
    binding = identity(manifest, root)
    if receipt.get("schema_version") != 1 or receipt.get("binding") != binding or binding["revision"] != revision or binding["version"] != version or binding["candidate_id"] != candidate_id or receipt.get("status") != "completed" or receipt.get("files") != inventory(directory):
        raise ValueError("CodeQL full candidate evidence mismatch")
    fresh(receipt["started_at"])
    fresh(receipt["completed_at"])
    if receipt["mode"] == "same-job-local":
        if receipt.get("action_sha") != ACTION_SHA:
            raise ValueError("CodeQL action identity mismatch")
        local = directory / "local"
        configuration = local / "configuration.json"
        action_configuration(configuration, root)
        # Keep configuration separate from the strictly five-report directory.
        paths = list(local.glob("*.sarif"))
        reports = Path(destination) / "codeql-local"
        reports.mkdir(mode=0o700)
        for path in paths:
            shutil.copyfile(path, reports / path.name)
            (reports / path.name).chmod(0o600)
        _, findings = local_reports(reports, binding)
        save(destination, "codeql-local-configuration.json", read(configuration))
    elif receipt["mode"] == "default-main":
        default = directory / "default"
        analyses = read(default / "codeql-analyses.json")
        if {a.get("category") for a in analyses} != CODEQL_CATEGORIES:
            raise ValueError("CodeQL default language inventory changed")
        for item in analyses:
            fresh(item["created_at"])
            if item.get("commit_sha") != revision or item.get("ref") != "refs/heads/main":
                raise ValueError("CodeQL default source mismatch")
        findings = read(default / "findings.json")
        for path in default.iterdir():
            shutil.copyfile(path, Path(destination) / path.name)
            (Path(destination) / path.name).chmod(0o600)
    else:
        raise ValueError("unsupported CodeQL evidence mode")
    save(destination, "codeql-receipt.json", receipt)
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "finish"))
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", required=True)
    parser.add_argument("--artifact-manifest", required=True)
    parser.add_argument("--sarif-directory", required=True)
    parser.add_argument("--action-config")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.output, args.artifact_manifest, args.root, sarif_directory=args.sarif_directory)
        else:
            if not args.sarif_directory or not args.action_config:
                raise ValueError("CodeQL local completion inputs missing")
            finish(args.output, args.artifact_manifest, args.root, args.sarif_directory, args.action_config)
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, "complete exact-source CodeQL evidence unavailable; publication prohibited\n")


if __name__ == "__main__":
    main()

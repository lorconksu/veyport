#!/usr/bin/env python3
"""Collect complete Snyk baseline evidence without creating monitored projects.

Output is private: never upload this directory as a public Actions artifact.
Operational completeness and vulnerability policy are separate decisions.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

VERSION = "1.1308.3"
SOURCES = {
    **{f"source:go:{p}": (p, "go.mod", "gomodules") for p in
       ("hub", "agent", "cli", "proto", "infra/application-access/fixture")},
    **{f"source:npm:{p}": (p, "package.json", "npm") for p in ("web", "tests/e2e")},
    "source:pip:infra/audit-lab/storage": ("infra/audit-lab/storage", "requirements.txt", "pip"),
}
IMAGES = ("veyport", "audit-ingest", "audit-export")


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_private(path, value):
    # Exclusive creation prevents accidental reuse of an older successful scan.
    with Path(path).open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        stream.write(json.dumps(value, indent=2) + "\n")


def verify_image(archive, expected):
    """Bind the selected native OCI image to its real manifest/config/layers."""
    if not 0 < Path(archive).stat().st_size <= 512 << 20:
        raise ValueError("bounded OCI archive required")
    with tarfile.open(archive, "r:*") as image:
        members = image.getmembers()
        if len(members) > 4096 or len({m.name for m in members}) != len(members):
            raise ValueError("bounded unambiguous OCI archive required")
        files = {m.name: m for m in members if m.isfile()}
        if any(m.issym() or m.islnk() or m.name.startswith("/") or ".." in Path(m.name).parts for m in members):
            raise ValueError("unsafe OCI archive")

        def read(name, limit=8 << 20):
            member = files.get(name)
            if member is None or not 0 < member.size <= limit:
                raise ValueError("missing or oversized OCI content")
            return image.extractfile(member).read()

        def blob(descriptor, limit=512 << 20):
            digest = descriptor.get("digest", "")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                raise ValueError("sha256 OCI descriptor required")
            data = read("blobs/sha256/" + digest[7:], limit)
            if hashlib.sha256(data).hexdigest() != digest[7:] or len(data) != descriptor.get("size"):
                raise ValueError("corrupt OCI blob")
            return data

        index = json.loads(read("index.json"))
        manifests = index.get("manifests", [])
        if len(manifests) != 1 or manifests[0].get("digest") != expected:
            raise ValueError("scan a single selected native OCI manifest")
        manifest = json.loads(blob(manifests[0], 8 << 20))
        config = json.loads(blob(manifest["config"], 8 << 20))
        if config.get("os") != "linux" or config.get("architecture") != "amd64":
            raise ValueError("qualified native platform required")
        layers = manifest.get("layers")
        if not isinstance(layers, list) or not layers:
            raise ValueError("complete image layers required")
        for layer in layers:
            blob(layer)
        return config


def inventory(root):
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    manifests = {p for p in tracked if Path(p).name in ("go.mod", "package.json", "requirements.txt")}
    expected = {f"{p}/{f}" for p, f, _ in SOURCES.values()}
    if manifests != expected:
        raise ValueError("manifest inventory changed; review explicit source scope policy")
    for scope, (directory, filename, manager) in SOURCES.items():
        path = root / directory / filename
        if not path.is_file() or path.is_symlink():
            raise ValueError("regular manifest required")
        if manager == "npm":
            lock = json.loads((path.parent / "package-lock.json").read_text())
            manifest = json.loads(path.read_text())
            for kind in ("dependencies", "devDependencies", "optionalDependencies"):
                if lock.get("packages", {}).get("", {}).get(kind, {}) != manifest.get(kind, {}):
                    raise ValueError("npm manifest/lock mismatch")
        if manager == "pip":
            pins = [s.strip() for s in path.read_text().splitlines() if s.strip() and not s.startswith("#")]
            if not pins or any(not re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+", s) for s in pins):
                raise ValueError("all Python requirements must be pinned and resolved")
    return sorted(manifests)


def normalize(raw, exit_code, manager):
    """Reject empty, partial or filtered reports; preserve every vulnerability path."""
    reports = raw if isinstance(raw, list) else [raw]
    if not reports or exit_code not in (0, 1):
        raise ValueError("Snyk operational failure")
    findings, dependencies = [], 0
    for report in reports:
        if not isinstance(report, dict) or report.get("error") or report.get("errorCode"):
            raise ValueError("incomplete Snyk result")
        if report.get("packageManager") not in (manager if isinstance(manager, tuple) else (manager,)):
            raise ValueError("unexpected package manager")
        count = report.get("dependencyCount")
        vulnerabilities = report.get("vulnerabilities")
        if type(count) is not int or count <= 0 or not isinstance(vulnerabilities, list) or type(report.get("ok")) is not bool:
            raise ValueError("resolved nonempty dependency inventory required")
        if report["ok"] != (not vulnerabilities):
            raise ValueError("contradictory Snyk result")
        if report.get("filtered", {}).get("ignore") or report.get("filtered", {}).get("patch"):
            raise ValueError("ignored baseline must remain in full evidence")
        dependencies += count
        for v in vulnerabilities:
            if not isinstance(v, dict) or not all(isinstance(v.get(k), str) and v[k] for k in ("id", "name", "version", "severity")) or v["severity"] not in ("critical", "high", "medium", "low"):
                raise ValueError("invalid vulnerability")
            findings.append({"scanner": "snyk", "id": v["id"], "component": v["name"],
                             "version": v["version"], "severity": v["severity"],
                             "finding_type": "license" if v.get("type") == "license" or v["id"].startswith("snyk:lic:") else "vulnerability",
                             "classification": "unresolved", "first_seen": None,
                             "dependency_path": v.get("from", []),
                             "identifiers": v.get("identifiers", {})})
    if (exit_code == 1) != bool(findings):
        raise ValueError("exit status does not match complete baseline")
    unique = {}
    for finding in findings:
        key = tuple(finding[k] for k in ("scanner", "id", "component", "version"))
        if key in unique:
            prior = unique[key]
            if any(prior[k] != finding[k] for k in ("severity", "finding_type", "classification")):
                raise ValueError("contradictory vulnerability paths")
            if finding["dependency_path"] not in prior["dependency_paths"]:
                prior["dependency_paths"].append(finding["dependency_path"])
        else:
            unique[key] = {**finding, "dependency_paths": [finding["dependency_path"]]}
    return list(unique.values()), dependencies


def execute(command, cwd, output, timeout):
    # Do not echo commands/environment or raw provider diagnostics to public logs.
    with (output.with_suffix(".stdout")).open("xb") as stdout, (output.with_suffix(".stderr")).open("xb") as stderr:
        os.chmod(output.with_suffix(".stdout"), 0o600)
        os.chmod(output.with_suffix(".stderr"), 0o600)
        try:
            result = subprocess.run(command, cwd=cwd, stdout=stdout, stderr=stderr, timeout=timeout, check=False)
            return result.returncode
        except subprocess.TimeoutExpired:
            return 124


def collect(args):
    root = Path(args.root).resolve()
    output = Path(args.output).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", args.candidate_id):
        raise ValueError("immutable revision and bounded candidate identity required")
    manifest_path = Path(args.artifact_manifest)
    if manifest_path.is_symlink() or not 0 < manifest_path.stat().st_size <= 8 << 20:
        raise ValueError("bounded regular candidate manifest required")
    manifest_hash = sha256(args.artifact_manifest)
    scopes = list(SOURCES) if args.kind == "source" else ["image:" + args.image]
    envelope = {"schema_version": 1, "candidate_id": args.candidate_id, "revision": args.revision,
                "artifact_manifest_sha256": manifest_hash, "status": "failed", "required_scopes": scopes,
                "scanner": {"name": "snyk", "version": VERSION}, "scopes": [],
                "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "ignore_policy": False, "monitored_project_created": False}
    try:
        version = subprocess.check_output([args.scanner, "--version"], timeout=60).decode().strip()
        if version != VERSION:
            raise ValueError("unqualified Snyk CLI version")
        if not os.environ.get("SNYK_TOKEN"):
            raise ValueError("Snyk authentication required")
        if args.kind == "source":
            if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip() != args.revision:
                raise ValueError("source revision mismatch")
            # Track modified/untracked files too; otherwise evidence could bind a
            # worktree different from the immutable revision in the envelope.
            if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root):
                raise ValueError("source worktree must be clean")
            envelope["manifest_inventory"] = inventory(root)
        for index, scope in enumerate(scopes):
            result_path = output / f"scope-{index}.json"
            record = {"id": scope, "status": "failed", "authenticated": False,
                      "coverage_complete": False, "findings": []}
            envelope["scopes"].append(record)
            command = [args.scanner]
            if args.kind == "source":
                directory, filename, manager = SOURCES[scope]
                cwd = root / directory
                scan_file = "package-lock.json" if manager == "npm" else filename
                command += ["test", f"--file={scan_file}", f"--package-manager={manager}", "--dev"]
                if manager == "npm":
                    command += ["--strict-out-of-sync=true"]
                elif manager == "pip":
                    command += [f"--command={args.python}", "--skip-unresolved=false"]
                record["manifest_sha256"] = sha256(cwd / filename)
            else:
                cwd, manager = root, "deb"
                archive = Path(args.archive).resolve()
                if archive.is_symlink() or sha256(archive) != args.archive_sha256:
                    raise ValueError("exact scanned image archive mismatch")
                image_config = verify_image(archive, args.native_manifest_digest)
                if image_config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != args.revision:
                    raise ValueError("scanned native image source revision mismatch")
                command += ["container", "test", "oci-archive:" + str(archive), "--platform=linux/amd64"]
                record["archive_sha256"] = args.archive_sha256
                record["native_manifest_digest"] = args.native_manifest_digest
                # Container reports can include application package subreports.
                # Preserve those alongside the mandatory OS package inventory.
                manager = (args.package_manager, "gomodules", "npm", "pip")
            command += ["--ignore-policy", "--show-vulnerable-paths=all", "--json-file-output=" + str(result_path)]
            if args.org:
                command.append("--org=" + args.org)
            code = execute(command, cwd, result_path, args.timeout)
            record["exit_code"] = code
            try:
                if result_path.is_symlink() or not 0 < result_path.stat().st_size <= 64 << 20:
                    raise ValueError("missing or oversized Snyk report")
                os.chmod(result_path, 0o600)
                record["report_sha256"] = sha256(result_path)
                findings, count = normalize(json.loads(result_path.read_text()), code, manager)
                if args.kind == "image":
                    reports = json.loads(result_path.read_text())
                    reports = reports if isinstance(reports, list) else [reports]
                    if not any(r.get("packageManager") == args.package_manager for r in reports):
                        raise ValueError("missing OS package inventory")
                record.update(status="completed", authenticated=True, coverage_complete=True,
                              findings=findings, dependency_count=count)
            except (OSError, ValueError, TypeError, KeyError):
                record["error"] = "Incomplete scanner result; review private diagnostics."
        if args.kind == "image" and sha256(args.archive) != args.archive_sha256:
            raise ValueError("image archive mutated during scan")
        if sha256(args.artifact_manifest) != manifest_hash:
            raise ValueError("artifact manifest mutated during scan")
        if args.kind == "source" and subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root):
            raise ValueError("source dependency resolution mutated the immutable checkout")
        if all(s["status"] == "completed" for s in envelope["scopes"]):
            envelope["status"] = "completed"
    except (OSError, ValueError, TypeError, KeyError, AttributeError, tarfile.TarError, subprocess.SubprocessError):
        envelope["error"] = "Scanner execution or complete coverage verification failed; review private diagnostics."
    envelope["completed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    write_private(output / "assessment.json", envelope)
    return envelope["status"] == "completed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("source", "image"))
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--artifact-manifest", required=True)
    parser.add_argument("--scanner", default="snyk")
    parser.add_argument("--org")
    parser.add_argument("--python", default="python3")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--image", choices=IMAGES)
    parser.add_argument("--archive")
    parser.add_argument("--archive-sha256")
    parser.add_argument("--native-manifest-digest")
    parser.add_argument("--package-manager", default="apk")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 1800:
        parser.error("scanner deadline must be between 1 and 1800 seconds")
    if args.kind == "image" and (not args.image or not args.archive or not re.fullmatch(r"[0-9a-f]{64}", args.archive_sha256 or "") or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.native_manifest_digest or "")):
        parser.error("image requires exact archive hash and native manifest digest")
    try:
        return 0 if collect(args) else 1
    except (OSError, ValueError, subprocess.SubprocessError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

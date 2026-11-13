#!/usr/bin/env python3
"""Throwaway Snyk Actions trial. Raw evidence must stay in RUNNER_TEMP and be sealed."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import tarfile
import time

PROJECTS = (
    "hub/go.mod", "agent/go.mod", "cli/go.mod", "proto/go.mod",
    "infra/application-access/fixture/go.mod", "web/package.json",
    "infra/audit-lab/storage/requirements.txt",
)
SOURCES = {
    "75ab7490e73aee6d4094da7ece988417e92c519d": "1.26.10",
    "9add3445d449083319a0d1cb334d13729bccbb85": "1.26.11",
}
CLI_VERSION = "1.1308.3"
ORG = "28d5c9da-7ca3-45df-954e-9d83d811ae0d"
RECIPIENT = "age1xr200qhckma63jw9rwsemeca4ypc02r9cpkr6kk8t4k6f30lka6q824feg"
COMPLETE = {"scan_complete_clean", "scan_complete_with_findings"}
VERSION_PATTERNS = {
    "snyk": r"1\.1308\.3", "go": r"go1\.26\.(10|11)",
    "node": r"v25\.\d+\.\d+", "npm": r"\d+\.\d+\.\d+",
    "python": r"Python 3\.12\.\d+", "age": r"v?\d+\.\d+\.\d+",
}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON key")
        value[key] = item
    return value


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Nonfinite JSON")
    return number


def load_report(path):
    try:
        return json.loads(path.read_text(), object_pairs_hook=unique_pairs, parse_float=finite_float,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
    except (OSError, UnicodeError, ValueError, RecursionError):
        return None


def incomplete():
    return {"status": "scan_incomplete", "dependency_count": 0,
            "vulnerability_path_records": 0, "license_path_records": 0, "license_enabled": False}


def assess(value, exit_code, project):
    """Accept one legacy Open Source report only, including license-policy metadata."""
    result = incomplete()
    if type(value) is not dict or exit_code not in (0, 1) or "error" in value:
        return result
    if any(field in value and type(value[field]) is not str
           for field in ("targetFile", "displayTargetFile")):
        return result
    expected_manager = "gomodules" if project.endswith("go.mod") else "npm" if project.endswith("package.json") else "pip"
    # v1.1308.3 format-test-meta.ts calls a truthy licensesPolicy "Licenses: enabled".
    # Default policy legitimately contains null orgLicenseRules and severities.
    licenses = value.get("licensesPolicy")
    target = value.get("targetFile") or value.get("displayTargetFile")
    targets = {"package.json", "package-lock.json"} if expected_manager == "npm" else {Path(project).name}
    issues = value.get("vulnerabilities")
    count = value.get("dependencyCount")
    if (type(count) is not int or count <= 0 or type(value.get("ok")) is not bool
            or type(issues) is not list or type(licenses) is not dict
            or not {"orgLicenseRules", "severities"} <= licenses.keys()
            or any(licenses[k] is not None and type(licenses[k]) not in (dict, list)
                   for k in ("orgLicenseRules", "severities"))
            or value.get("packageManager") != expected_manager
            or target not in targets
            or value.get("org") not in (ORG, "lorconksu")):
        return result
    if any(type(issue) is not dict or issue.get("type") not in (None, "vuln", "license")
           or not isinstance(issue.get("id"), str) or not issue["id"] for issue in issues):
        return result
    if (exit_code == 0 and (not value["ok"] or issues)) or (exit_code == 1 and (value["ok"] or not issues)):
        return result
    license_path_records = sum(issue.get("type") == "license" for issue in issues)
    return {"status": "scan_complete_with_findings" if issues else "scan_complete_clean",
            "dependency_count": count, "vulnerability_path_records": len(issues) - license_path_records,
            "license_path_records": license_path_records, "license_enabled": True}


def capture(command, cwd, prefix, timeout=300):
    """Bound runner-owned processes; the privileged resolver shares this deadline."""
    environment = os.environ.copy()
    # Leave teardown time before the outer deadline, even for a resolver started late.
    environment["SNYK_TRIAL_RESOLVER_DEADLINE"] = str(time.monotonic() + timeout - min(5, timeout / 4))
    with prefix.with_suffix(".stdout").open("wb") as stdout, prefix.with_suffix(".stderr").open("wb") as stderr:
        try:
            process = subprocess.Popen([str(arg) for arg in command], cwd=cwd, stdout=stdout,
                                       stderr=stderr, start_new_session=True, env=environment)
        except OSError:
            stderr.write(b"Process could not be started.\n")
            return 125
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            stderr.write(b"Diagnostic subprocess deadline reached.\n")
            return 124


def python_resolver_command(raw, python):
    # Only public plugin code is exposed; reports/tools remain in separate private directories.
    assets = raw.parent / "resolver-assets"
    assets.mkdir(mode=0o711, exist_ok=True)
    assets.chmod(0o711)
    os.environ["SNYK_TMP_PATH"] = str(assets)
    python_command = raw / "snyk-python"
    supervisor_program = (
        "import os, signal, subprocess, sys, time\n"
        "deadline = float(sys.argv[1])\n"
        "if deadline <= time.monotonic():\n    sys.exit(124)\n"
        "child = subprocess.Popen(sys.argv[2:], start_new_session=True)\n"
        "try:\n    code = child.wait(timeout=max(0, deadline - time.monotonic()))\n"
        "except subprocess.TimeoutExpired:\n    code = 124\n"
        "finally:\n"
        "    try:\n        os.killpg(child.pid, signal.SIGKILL)\n"
        "    except ProcessLookupError:\n        pass\n"
        "child.wait()\n"
        "sys.exit(code)\n")
    python_command.write_text(
        '#!/bin/sh\nset -eu\nunset SNYK_TOKEN\nasset_root=' + shlex.quote(str(assets)) + '\n'
        'case "${1-}" in\n'
        '  --version) ;;\n'
        '  "$asset_root/"*/pip_resolve.py)\n'
        '    directory=${1%/pip_resolve.py}\n'
        '    relative=${directory#"$asset_root/"}\n'
        '    case "$relative" in ""|.|..|*/*) exit 2 ;; esac\n'
        '    /usr/bin/chmod -R a+rX -- "$directory"\n'
        '    ;;\n'
        '  *) exit 2 ;;\n'
        'esac\n'
        'exec /usr/bin/sudo -n ' + shlex.quote(sys.executable) + ' -I -S -c '
        + shlex.quote(supervisor_program) + ' "$SNYK_TRIAL_RESOLVER_DEADLINE" '
        '/usr/bin/setpriv --reuid=65534 --regid=65534 '
        '--clear-groups --no-new-privs ' + shlex.quote(str(python)) + ' "$@"\n')
    python_command.chmod(0o700)
    return python_command


def scan_projects(source, scanner, raw, python, timeout=300):
    python_command = python_resolver_command(raw, python)
    rows = []
    for index, project in enumerate(PROJECTS):
        attempts = []
        result = incomplete()
        for attempt in (1, 2):
            prefix = raw / f"project-{index}-attempt-{attempt}"
            output = prefix.with_suffix(".json")
            command = [scanner, "test", f"--org={ORG}", f"--file={Path(project).name}",
                       "--json", f"--json-file-output={output}"]
            if project == "web/package.json":
                command.append("--dev")
            if project.endswith("requirements.txt"):
                command.extend(["--package-manager=pip", f"--command={python_command}"])
            code = capture(command, (source / project).parent, prefix, timeout)
            result = assess(load_report(output), code, project)
            attempts.append({"exit_code": code, "status": result["status"]})
            # A completed scan with findings is final; only processing failures retry.
            if result["status"] in COMPLETE:
                break
        rows.append({"path": project, **result, "attempts": attempts})
    return rows


def public_summary(state):
    """Rebuild an allowlist; raw scanner strings never become public values."""
    sha = state.get("source_sha")
    if sha not in SOURCES:
        raise ValueError("Unrecognized source")
    versions = {key: value if isinstance(value := state.get("versions", {}).get(key), str)
                and re.fullmatch(pattern, value) else "unavailable"
                for key, pattern in VERSION_PATTERNS.items()}
    rows, exits = [], {}
    candidates = state.get("projects", [])
    for project in PROJECTS:
        found = [row for row in candidates if row.get("path") == project]
        row = found[0] if len(found) == 1 else {}
        status = row.get("status") if row.get("status") in COMPLETE else "scan_incomplete"
        counts = {key: value if type(value := row.get(key)) is int and value >= 0 else 0
                  for key in ("dependency_count", "vulnerability_path_records", "license_path_records")}
        codes = []
        for attempt in row.get("attempts", [])[:2]:
            code = attempt.get("exit_code")
            if type(code) is int and -128 <= code <= 255:
                codes.append(code)
                exits[str(code)] = exits.get(str(code), 0) + 1
        rows.append({"path": project, "status": status, **counts, "exit_codes": codes,
                     "license_enabled": row.get("license_enabled") is True})
    complete = (state.get("preparation_complete") is True and state.get("manifests_unchanged") is True
                and all(row["status"] in COMPLETE for row in rows)
                and all(value != "unavailable" for value in versions.values()))
    return {"source_sha": sha, "versions": versions, "projects": rows, "exit_counts": exits,
            "processing_status": "trial_complete" if complete else "trial_incomplete"}


def manifest_hashes(source):
    paths = (*PROJECTS, *(p.replace("go.mod", "go.sum") for p in PROJECTS if p.endswith("go.mod")),
             "web/package-lock.json")
    return {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in paths}


def revision(directory):
    return subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"],
                                   text=True, stderr=subprocess.DEVNULL).strip()


def resolver_workspace_scope(root, source, control):
    """Accept only this job's canonical checkout and temporary-directory layout."""
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ""))
    temporary = Path(os.environ.get("RUNNER_TEMP", ""))
    common = temporary.parent
    directories = (root, source, control, workspace, workspace.parent, temporary, common)
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or any(not path.is_absolute() or not path.is_dir() or path.resolve() != path for path in directories)
            or temporary.name != "_temp" or workspace.parent.parent != common
            or workspace.name != workspace.parent.name or workspace.parent == temporary
            or source != workspace / "source" or control != workspace / "diagnostic"
            or root != temporary / "snyk-runner-trial"
            or any(path.stat().st_uid != os.geteuid() for path in (root, source, workspace, workspace.parent))):
        raise ValueError("Unapproved resolver workspace scope or layout")
    manifest = source / PROJECTS[-1]
    if manifest.resolve() != manifest or not manifest.is_file():
        raise ValueError("Unapproved resolver manifest scope")
    return workspace, temporary, common


def resolver_permissions(root, source, control):
    workspace, temporary, common = resolver_workspace_scope(root, source, control)
    manifest = source / PROJECTS[-1]
    # Metadata and UID65534 access results stay only in encrypted raw evidence.
    paths = dict.fromkeys((*manifest.parents, manifest, root, *root.parents, root / "raw", root / "tools"))
    paths = [path for path in paths if path.exists()]

    def access_snapshot():
        modes = {str(path): {"mode": f"{stat.S_IMODE(path.stat().st_mode):04o}", "uid": path.stat().st_uid}
                 for path in paths}
        program = ('import json, os, sys; print(json.dumps({p: {"readable": os.access(p, os.R_OK), '
                   '"searchable": os.path.isdir(p) and os.access(p, os.X_OK)} for p in sys.argv[1:]}))')
        result = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/setpriv", "--reuid=65534", "--regid=65534",
                                 "--clear-groups", "--no-new-privs", sys.executable, "-I", "-S", "-c", program,
                                 *map(str, paths)], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return {"probe_exit_code": result.returncode, **modes}
        for name, access in json.loads(result.stdout).items():
            modes[name].update(access)
        return {"probe_exit_code": 0, **modes}

    evidence = {"before": access_snapshot()}
    evidence_path = root / "raw/resolver-path-access.json"
    write_json(evidence_path, evidence)
    if (evidence["before"]["probe_exit_code"] != 0
            or not all(evidence["before"][str(path)]["searchable"] for path in (common, temporary))):
        raise ValueError("Resolver workspace common ancestry is not traversable")
    # Grant traversal only below the common runner-work parent; never chmod that parent or home.
    for directory in (workspace.parent, workspace):
        directory.chmod(stat.S_IMODE(directory.stat().st_mode) | stat.S_IXOTH)
    # Public dependencies and the pinned Python manifest may be read, never private evidence.
    root.chmod(0o711)
    venv = root / "venv"
    if venv.exists():
        for path in (venv, *venv.rglob("*")):
            if not path.is_symlink():
                mode = stat.S_IMODE(path.stat().st_mode)
                path.chmod(mode | (0o555 if path.is_dir() or mode & 0o111 else 0o444))
    manifest.chmod(stat.S_IMODE(manifest.stat().st_mode) | 0o444)
    directory = manifest.parent
    while directory != source.parent:
        directory.chmod(stat.S_IMODE(directory.stat().st_mode) | 0o555)
        directory = directory.parent
    evidence["after"] = access_snapshot()
    write_json(evidence_path, evidence)


def prepare(args, raw):
    # Reject path/environment mismatches before any preparation permission changes.
    resolver_workspace_scope(args.root, args.source, args.control)
    if (args.sha not in SOURCES or not re.fullmatch(r"[0-9a-f]{40}", args.control_sha)
            or revision(args.source) != args.sha or revision(args.control) != args.control_sha):
        raise ValueError("Revision verification failed")
    lock_name = "scripts/diagnostics/snyk_runner_trial_requirements.lock"
    lock = args.control / lock_name
    state = {"source_sha": args.sha, "control_sha": args.control_sha, "versions": {}, "projects": [],
             "preparation_complete": False, "manifests_unchanged": False,
             "manifest_hashes": manifest_hashes(args.source),
             "python_lock": {"path": lock_name, "sha256": hashlib.sha256(lock.read_bytes()).hexdigest()}}
    write_json(raw / "state.json", state)
    stub = args.source / "hub/web/dist/index.html"
    stub.parent.mkdir(parents=True, exist_ok=True)
    stub.touch()
    commands = [
        (["npm", "ci", "--ignore-scripts", "--include=dev", "--no-audit", "--no-fund"], args.source / "web"),
        (["/usr/bin/python3.12", "-I", "-m", "venv", str(args.root / "venv")], args.source),
        ([args.root / "venv/bin/python", "-I", "-m", "pip", "--isolated", "install", "--require-hashes",
          "--only-binary=:all:", "--disable-pip-version-check", "-r", lock,
          "-r", args.source / PROJECTS[-1]], args.source),
    ]
    # Pre-resolve Go package graphs without executing repository code or editing manifests.
    for project in PROJECTS[:5]:
        for name in ("go.mod", "go.sum"):
            (args.source / project).with_name(name).chmod(0o444)
        commands.append((["go", "list", "-deps", "./..."], (args.source / project).parent))
    codes = [capture(cmd, cwd, raw / f"prepare-{index}", timeout=600)
             for index, (cmd, cwd) in enumerate(commands)]
    resolver_permissions(args.root, args.source, args.control)
    # Check ancestor traversal without opening the runner home or private evidence.
    codes.append(capture(["/usr/bin/sudo", "-n", "/usr/bin/setpriv", "--reuid=65534", "--regid=65534",
                          "--clear-groups", "--no-new-privs", "/usr/bin/test", "-r", args.source / PROJECTS[-1]],
                         args.source, raw / "resolver-access", timeout=30))
    python_command = python_resolver_command(raw, args.root / "venv/bin/python")
    version_commands = {
        "snyk": [args.scanner, "--version"], "go": ["go", "version"],
        "node": ["node", "--version"], "npm": ["npm", "--version"],
        "python": [python_command, "--version"], "age": ["age", "--version"],
    }
    for name, command in version_commands.items():
        prefix = raw / f"version-{name}"
        code = capture(command, args.source, prefix, timeout=30)
        text = prefix.with_suffix(".stdout").read_text(errors="replace").strip()
        if name == "go":
            match = re.fullmatch(r"go version (go[\d.]+) linux/amd64", text)
            text = match[1] if match else "unavailable"
        state["versions"][name] = text if code == 0 and re.fullmatch(VERSION_PATTERNS[name], text) else "unavailable"
    unchanged = manifest_hashes(args.source) == state["manifest_hashes"]
    state.update(preparation_exit_codes=codes, manifests_unchanged=unchanged,
                 preparation_complete=all(code == 0 for code in codes) and unchanged
                 and all(value != "unavailable" for value in state["versions"].values())
                 and state["versions"]["go"] == "go" + SOURCES[args.sha])
    write_json(raw / "state.json", state)
    # Preserve failed preparation evidence while preventing the credential-bearing step.
    return state["preparation_complete"]


def scan(args, raw):
    state = load_report(raw / "state.json")
    if (not state or revision(args.source) != args.sha or revision(args.control) != args.control_sha
            or state["source_sha"] != args.sha or state["control_sha"] != args.control_sha):
        raise ValueError("Scan provenance verification failed")
    if state.get("preparation_complete") is not True:
        raise ValueError("Scan preparation incomplete")
    state["projects"] = scan_projects(args.source, args.scanner, raw, args.root / "venv/bin/python")
    state["manifests_unchanged"] = manifest_hashes(args.source) == state["manifest_hashes"]
    write_json(raw / "state.json", state)
    return public_summary(state)["processing_status"] == "trial_complete"


def seal(args, raw):
    state = load_report(raw / "state.json")
    if not state:
        state = {"source_sha": args.sha}
    summary = public_summary(state)
    public = args.root / "public"
    public.mkdir(mode=0o700, exist_ok=True)
    archive = args.root / "evidence.tar.gz"
    ciphertext = public / "evidence.tar.gz.age"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(raw, arcname="raw")
    code = capture(["age", "-r", RECIPIENT, "-o", ciphertext, archive], args.root,
                   args.root / "encryption", timeout=120)
    if code != 0 or not ciphertext.is_file() or ciphertext.stat().st_size == 0:
        ciphertext.unlink(missing_ok=True)
        raise ValueError("Encryption failed")
    write_json(public / "summary.json", summary)
    # Delete plaintext only after encryption succeeded. The workflow also cleans on failure.
    archive.unlink()
    import shutil
    shutil.rmtree(raw)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "scan", "seal"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--sha", required=True, choices=SOURCES)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--scanner", type=Path, required=True)
    args = parser.parse_args()
    raw = args.root / "raw"
    raw.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        if args.mode == "prepare":
            return 0 if prepare(args, raw) else 1
        elif args.mode == "scan":
            return 0 if scan(args, raw) else 1
        else:
            seal(args, raw)
    except Exception:
        # Exception messages may include private subprocess data; never echo them.
        import traceback
        (raw / "helper-error.txt").write_text(traceback.format_exc())
        print("Snyk trial processing incomplete; inspect encrypted evidence if available.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

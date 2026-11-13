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
import shutil
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
ORG = "28d5c9da-7ca3-45df-954e-9d83d811ae0d"
RECIPIENT = "age1xr200qhckma63jw9rwsemeca4ypc02r9cpkr6kk8t4k6f30lka6q824feg"
PYTHON_REQUIREMENTS_SHA256 = "62b9aed312adedeba09dcc1e858e70831c0f955c976edc1ccc90457cc51adc52"
COMPLETE = {"scan_complete_clean", "scan_complete_with_findings"}
VERSION_PATTERNS = {
    "snyk": r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", "go": r"go1\.26\.(10|11)",
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


def capture(command, cwd, prefix, timeout=300, env=None):
    """Bound runner-owned processes; the privileged resolver shares this deadline."""
    environment = os.environ.copy()
    environment.update(env or {})
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


def python_resolver_command(raw, python, public_root):
    # Only public plugin code is exposed; reports/tools remain in the private root.
    public_workspace_scope(public_root)
    assets = public_root / "resolver-assets"
    assets.mkdir(mode=0o711, exist_ok=True)
    assets.chmod(0o711)
    python_command = raw / "snyk-python"
    supervisor_program = (
        "import os, subprocess, sys, tempfile, time\n"
        "from pathlib import Path\n"
        "deadline = float(sys.argv[1])\n"
        "if deadline <= time.monotonic():\n    sys.exit(124)\n"
        "if os.geteuid() != 0:\n    sys.exit(125)\n"
        "group = Path(tempfile.mkdtemp(prefix='veyport-snyk-resolver.', dir='/sys/fs/cgroup'))\n"
        "child = kill_fd = None\n"
        "try:\n"
        "    group.chmod(0o700)\n"
        "    if 'populated 0' not in (group / 'cgroup.events').read_text().splitlines():\n"
        "        raise RuntimeError('Resolver cgroup is not empty')\n"
        "    kill_fd = os.open(group / 'cgroup.kill', os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)\n"
        "    def enter_group():\n"
        "        fd = os.open(group / 'cgroup.procs', os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)\n"
        "        try:\n            os.write(fd, str(os.getpid()).encode())\n"
        "        finally:\n            os.close(fd)\n"
        "        if deadline <= time.monotonic():\n            os._exit(124)\n"
        "    # This isolated supervisor is single-threaded; membership precedes exec and UID drop.\n"
        "    child = subprocess.Popen(sys.argv[2:], start_new_session=True, preexec_fn=enter_group)\n"
        "    try:\n        code = child.wait(timeout=max(0, deadline - time.monotonic()))\n"
        "    except subprocess.TimeoutExpired:\n        code = 124\n"
        "finally:\n"
        "    try:\n"
        "        if kill_fd is not None:\n"
        "            os.write(kill_fd, b'1')\n"
        "            cleanup_deadline = time.monotonic() + 1\n"
        "            if child is not None:\n"
        "                child.wait(timeout=max(0, cleanup_deadline - time.monotonic()))\n"
        "            while 'populated 0' not in (group / 'cgroup.events').read_text().splitlines():\n"
        "                if time.monotonic() >= cleanup_deadline:\n"
        "                    raise TimeoutError('Resolver cgroup did not empty')\n"
        "                time.sleep(0.01)\n"
        "        group.rmdir()\n"
        "    finally:\n"
        "        if kill_fd is not None:\n            os.close(kill_fd)\n"
        "sys.exit(code)\n")
    python_command.write_text(
        '#!/bin/sh\nset -eu\nunset SNYK_TOKEN\nasset_root=' + shlex.quote(str(assets)) + '\n'
        'case "${1-}" in\n'
        '  --version) ;;\n'
        '  "$asset_root/"*/pip_resolve.py)\n'
        '    directory=${1%/pip_resolve.py}\n'
        '    relative=${directory#"$asset_root/"}\n'
        '    case "$relative" in ""|.|..|*/*) exit 2 ;; esac\n'
        '    test ! -L "$directory"\n'
        '    test ! -L "$1"\n'
        '    test "$(/usr/bin/realpath -e -- "$directory")" = "$directory"\n'
        '    test -z "$(/usr/bin/find "$directory" -type l -print -quit)"\n'
        '    test -z "$(/usr/bin/find "$directory" ! -uid ' + str(os.geteuid()) + ' -print -quit)"\n'
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


def scan_projects(source, scanner, raw, python, public_root, timeout=300):
    python_command = python_resolver_command(raw, python, public_root)
    private_tmp = raw / "snyk-tmp"
    private_tmp.mkdir(mode=0o700, exist_ok=True)
    rows = []
    for index, project in enumerate(PROJECTS):
        attempts = []
        result = incomplete()
        for attempt in (1, 2):
            prefix = raw / f"project-{index}-attempt-{attempt}"
            output = prefix.with_suffix(".json")
            command = [scanner, "test", f"--org={ORG}", f"--file={Path(project).name}",
                       "--json", f"--json-file-output={output}"]
            environment = {"SNYK_TMP_PATH": str(private_tmp)}
            if project == "web/package.json":
                command.append("--dev")
            if project.endswith("requirements.txt"):
                # Recheck immediately before each Python invocation, after the other six projects.
                verify_python_mirror_files(public_root, source)
                command.extend(["--package-manager=pip", f"--command={python_command}"])
                environment["SNYK_TMP_PATH"] = str(public_root / "resolver-assets")
            cwd = (public_root / "mirror" / project).parent if project.endswith("requirements.txt") else (source / project).parent
            code = capture(command, cwd, prefix, timeout, env=environment)
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


def public_workspace_scope(public_root, *, empty=False, inspect_tree=False):
    """Accept only the owner's dedicated mktemp directory directly under canonical /tmp."""
    if (not public_root.is_absolute() or public_root.parent != Path("/tmp")
            or not re.fullmatch(r"veyport-snyk-public\.[A-Za-z0-9_]{8}", public_root.name)
            or Path("/tmp").resolve() != Path("/tmp") or public_root.resolve() != public_root
            or not public_root.is_dir() or public_root.stat().st_uid != os.geteuid()
            or stat.S_IMODE(public_root.stat().st_mode) & 0o022):
        raise ValueError("Unapproved public Python workspace scope or ownership")
    children = list(public_root.iterdir())
    if ((empty and children) or any(path.name not in ("venv", "mirror", "resolver-assets") for path in children)):
        raise ValueError("Unapproved public Python workspace contents")
    paths = list(public_root.rglob("*")) if inspect_tree else children
    mirror = public_root / "mirror" / PROJECTS[-1]
    mirror_paths = {mirror, *mirror.parents}
    for path in paths:
        if public_root / "mirror" in path.parents and path not in mirror_paths:
            raise ValueError("Unapproved public Python workspace mirror path")
        info = path.lstat()
        # --copies avoids interpreter links; venv's standard lib64 alias stays inside its tree.
        if path.is_symlink():
            if path != public_root / "venv/lib64" or os.readlink(path) != "lib":
                raise ValueError("Unapproved public Python workspace symlink")
        elif (not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
              or path.resolve() != path or info.st_mode & 0o022
              or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
            raise ValueError("Unapproved public Python workspace path or permissions")
        if info.st_uid != os.geteuid():
            raise ValueError("Unapproved public Python workspace owner")
    return public_root


def create_python_mirror(public_root, source, sha):
    public_workspace_scope(public_root, inspect_tree=True)
    original = source / PROJECTS[-1]
    if original.resolve() != original or not original.is_file():
        raise ValueError("Unapproved Python mirror source")
    content = original.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if sha not in SOURCES or digest != PYTHON_REQUIREMENTS_SHA256:
        raise ValueError("Python mirror source hash mismatch")
    mirror = public_root / "mirror" / PROJECTS[-1]
    directory = public_root / "mirror"
    directory.mkdir(mode=0o700)
    for name in Path(PROJECTS[-1]).parent.parts:
        directory = directory / name
        directory.mkdir(mode=0o700)
    mirror.write_bytes(content)
    mirror.chmod(0o444)
    return {"source_sha": sha, "source_path": PROJECTS[-1], "source_sha256": digest,
            "mirror_sha256": hashlib.sha256(mirror.read_bytes()).hexdigest(), "public_root": str(public_root)}


def verify_python_mirror_files(public_root, source):
    public_workspace_scope(public_root, inspect_tree=True)
    original, mirror = source / PROJECTS[-1], public_root / "mirror" / PROJECTS[-1]
    if (original.resolve() != original or mirror.resolve() != mirror
            or not original.is_file() or not mirror.is_file()):
        raise ValueError("Python mirror scope mismatch")
    if (hashlib.sha256(original.read_bytes()).hexdigest() != PYTHON_REQUIREMENTS_SHA256
            or hashlib.sha256(mirror.read_bytes()).hexdigest() != PYTHON_REQUIREMENTS_SHA256):
        raise ValueError("Python mirror source or content hash mismatch")


def verify_python_mirror(public_root, source, sha, binding):
    verify_python_mirror_files(public_root, source)
    expected = {"source_sha": sha, "source_path": PROJECTS[-1], "source_sha256": PYTHON_REQUIREMENTS_SHA256,
                "mirror_sha256": PYTHON_REQUIREMENTS_SHA256, "public_root": str(public_root)}
    if sha not in SOURCES or binding != expected:
        raise ValueError("Python mirror provenance or hash mismatch")
    return expected


def resolver_permissions(root, source, public_root):
    public_workspace_scope(public_root, inspect_tree=True)
    manifest, mirror = source / PROJECTS[-1], public_root / "mirror" / PROJECTS[-1]
    # Metadata and UID65534 access results stay only in encrypted raw evidence.
    paths = dict.fromkeys((*manifest.parents, manifest, root, *root.parents, root / "raw", root / "tools",
                          public_root, mirror, public_root / "venv/bin/python"))
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
    write_json(root / "raw/resolver-path-access.json", evidence)
    # Never mutate the original checkout, runner home, or private evidence permissions.
    for name in ("venv", "mirror"):
        subtree = public_root / name
        if subtree.exists():
            for path in (subtree, *subtree.rglob("*")):
                if not path.is_symlink():
                    mode = stat.S_IMODE(path.stat().st_mode)
                    path.chmod(mode | (0o555 if path.is_dir() or mode & 0o111 else 0o444))
    public_root.chmod(0o711)
    evidence["after"] = access_snapshot()
    write_json(root / "raw/resolver-path-access.json", evidence)


def cleanup_public_workspace(public_root):
    # rmtree never follows the single approved internal venv alias; no privileged cleanup.
    public_workspace_scope(public_root, inspect_tree=True)
    shutil.rmtree(public_root)


def verify_snyk_resolution(raw, scanner):
    """Detect intermediate client changes relative to the private bootstrap record."""
    resolution = load_report(raw / "snyk-cli.json")
    if (type(resolution) is not dict or resolution.get("verified") is not True
            or type(resolution.get("version")) is not str
            or not re.fullmatch(VERSION_PATTERNS["snyk"], resolution["version"])
            or resolution.get("url") != f'https://downloads.snyk.io/cli/v{resolution["version"]}/snyk-linux'
            or any(type(resolution.get(key)) is not str or not re.fullmatch(r"[0-9a-f]{64}", resolution[key])
                   for key in ("expected_sha256", "actual_sha256"))
            or resolution["expected_sha256"] != resolution["actual_sha256"]):
        raise ValueError("Snyk bootstrap resolution invalid")
    with scanner.open("rb") as binary:
        digest = hashlib.file_digest(binary, "sha256").hexdigest()
    if digest != resolution["actual_sha256"]:
        raise ValueError("Snyk bootstrap scanner hash mismatch")
    return resolution["version"]


def prepare(args, raw):
    # Validate the dedicated public scope before any dependency or permission mutation.
    public_workspace_scope(args.public_root, empty=True)
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
    state["python_mirror"] = create_python_mirror(args.public_root, args.source, args.sha)
    write_json(raw / "state.json", state)
    stub = args.source / "hub/web/dist/index.html"
    stub.parent.mkdir(parents=True, exist_ok=True)
    stub.touch()
    commands = [
        (["npm", "ci", "--ignore-scripts", "--include=dev", "--no-audit", "--no-fund"], args.source / "web"),
        (["/usr/bin/python3.12", "-I", "-m", "venv", "--copies", str(args.public_root / "venv")], args.source),
        ([args.public_root / "venv/bin/python", "-I", "-m", "pip", "--isolated", "install", "--require-hashes",
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
    resolver_permissions(args.root, args.source, args.public_root)
    # Prove mirror readability without opening the runner home or private evidence.
    codes.append(capture(["/usr/bin/sudo", "-n", "/usr/bin/setpriv", "--reuid=65534", "--regid=65534",
                          "--clear-groups", "--no-new-privs", "/usr/bin/test", "-r", args.public_root / "mirror" / PROJECTS[-1]],
                         args.source, raw / "resolver-access", timeout=30))
    python_command = python_resolver_command(raw, args.public_root / "venv/bin/python", args.public_root)
    private_tmp = raw / "snyk-tmp"
    private_tmp.mkdir(mode=0o700, exist_ok=True)
    resolved_version = verify_snyk_resolution(raw, args.scanner)
    version_commands = {
        "snyk": [args.scanner, "--version"], "go": ["go", "version"],
        "node": ["node", "--version"], "npm": ["npm", "--version"],
        "python": [python_command, "--version"], "age": ["age", "--version"],
    }
    for name, command in version_commands.items():
        prefix = raw / f"version-{name}"
        code = capture(command, args.source, prefix, timeout=30, env={"SNYK_TMP_PATH": str(private_tmp)})
        text = prefix.with_suffix(".stdout").read_text(errors="replace").strip()
        if name == "go":
            match = re.fullmatch(r"go version (go[\d.]+) linux/amd64", text)
            text = match[1] if match else "unavailable"
        state["versions"][name] = text if code == 0 and re.fullmatch(VERSION_PATTERNS[name], text) else "unavailable"
    unchanged = manifest_hashes(args.source) == state["manifest_hashes"]
    state.update(preparation_exit_codes=codes, manifests_unchanged=unchanged,
                 preparation_complete=all(code == 0 for code in codes) and unchanged
                 and all(value != "unavailable" for value in state["versions"].values())
                 and state["versions"]["snyk"] == resolved_version
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
    verify_python_mirror(args.public_root, args.source, args.sha, state.get("python_mirror"))
    if manifest_hashes(args.source) != state["manifest_hashes"]:
        raise ValueError("Scan manifests changed after preparation")
    resolved_version = verify_snyk_resolution(raw, args.scanner)
    if state.get("versions", {}).get("snyk") != resolved_version:
        raise ValueError("Snyk bootstrap prepared version mismatch")
    state["projects"] = scan_projects(args.source, args.scanner, raw, args.public_root / "venv/bin/python", args.public_root)
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
    parser.add_argument("mode", choices=("prepare", "scan", "seal", "cleanup"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--sha", required=True, choices=SOURCES)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--public-root", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "cleanup":
        try:
            cleanup_public_workspace(args.public_root)
        except Exception:
            print("Public Python workspace cleanup incomplete.", file=sys.stderr)
            return 1
        return 0
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

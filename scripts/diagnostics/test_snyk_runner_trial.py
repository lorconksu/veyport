"""Acceptance and privacy checks for the throwaway runner diagnostic."""
import copy
import hashlib
import importlib.util
import json
import os
import shlex
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "trial", Path(__file__).with_name("snyk_runner_trial.py"))
trial = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trial)


def report():
    return {"ok": True, "dependencyCount": 12, "vulnerabilities": [],
            "licensesPolicy": {"orgLicenseRules": None, "severities": None},
            "targetFile": "go.mod", "packageManager": "gomodules", "org": "lorconksu"}


SOURCE_SHA = "9add3445d449083319a0d1cb334d13729bccbb85"
PYTHON_REQUIREMENTS = b"boto3==1.40.72\ncryptography==46.0.5\n"


def scanner_resolution(raw, scanner, version="1.1308.3"):
    raw.mkdir(parents=True, exist_ok=True)
    if not scanner.exists():
        scanner.write_text("#!/bin/sh\nprintf executed >> " + shlex.quote(str(raw / "scanner-executed"))
                           + "\nprintf '%s\\n' " + shlex.quote(version) + "\n")
        scanner.chmod(0o700)
    digest = hashlib.sha256(scanner.read_bytes()).hexdigest()
    resolution = {"verified": True, "version": version,
                  "url": f"https://downloads.snyk.io/cli/v{version}/snyk-linux",
                  "expected_sha256": digest, "actual_sha256": digest}
    trial.write_json(raw / "snyk-cli.json", resolution)
    return resolution


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o022))

    def test_public_python_workspace_bypasses_private_home_without_permission_changes(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
            home, public_root = Path(directory), Path(public_directory)
            home.chmod(0o750)
            source, root = home / "work/repo/source", home / "work/_temp/snyk-runner-trial"
            manifest = source / trial.PROJECTS[-1]
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes(PYTHON_REQUIREMENTS)
            for name in ("raw", "tools"):
                (root / name).mkdir(parents=True, mode=0o700)
                (root / name / "private").write_text("private fixture")
            root.chmod(0o700)
            original_modes = {p: p.lstat().st_mode for p in (home, *home.rglob("*"))}
            binding = trial.create_python_mirror(public_root, source, SOURCE_SHA)
            subprocess.run([sys.executable, "-m", "venv", "--copies", "--without-pip", str(public_root / "venv")], check=True)
            trial.resolver_permissions(root, source, public_root)
            wrapper = trial.python_resolver_command(root / "raw", public_root / "venv/bin/python", public_root)
            assets = public_root / "resolver-assets/fixture"
            assets.mkdir(mode=0o700)
            script = assets / "pip_resolve.py"
            script.write_text("import pathlib; print(pathlib.Path('requirements.txt').read_text(), end='')")
            code = trial.capture([wrapper, script], (public_root / "mirror" / trial.PROJECTS[-1]).parent,
                                 root / "raw/actual-resolution", timeout=10)
            self.assertEqual(code, 0)
            self.assertEqual((root / "raw/actual-resolution.stdout").read_bytes(), PYTHON_REQUIREMENTS)
            self.assertEqual({p: p.lstat().st_mode for p in original_modes}, original_modes)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(binding, trial.verify_python_mirror(public_root, source, SOURCE_SHA, binding))
            evidence = json.loads((root / "raw/resolver-path-access.json").read_text())
            self.assertFalse(evidence["after"][str(manifest)]["readable"])
            self.assertTrue(evidence["after"][str(public_root / "mirror" / trial.PROJECTS[-1])]["readable"])
            for name in ("raw", "tools"):
                self.assertFalse(evidence["after"][str(root / name)]["searchable"])

    def test_public_workspace_scope_rejects_unsafe_paths_before_mutation(self):
        for invalid in ("relative", "name", "nested", "symlink", "writable", "owner", "unexpected", "nested-link", "hardlink", "mirror-path"):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory(
                    prefix="veyport-snyk-public.", dir="/tmp") as directory:
                public_root = Path(directory)
                candidate = public_root
                alias = None
                try:
                    if invalid == "relative":
                        candidate = Path("relative")
                    elif invalid == "name":
                        candidate = Path("/tmp")
                    elif invalid == "nested":
                        candidate = public_root / "veyport-snyk-public.12345678"
                        candidate.mkdir()
                    elif invalid == "symlink":
                        # Atomic exclusive creation: exercise the canonical-root guard, not its parent check.
                        while True:
                            candidate = Path("/tmp") / f"veyport-snyk-public.{os.urandom(4).hex()}"
                            try:
                                candidate.symlink_to(public_root, target_is_directory=True)
                            except FileExistsError:
                                continue
                            alias = candidate
                            break
                    elif invalid == "writable":
                        public_root.chmod(0o777)
                    elif invalid == "unexpected":
                        (public_root / "raw").mkdir()
                    elif invalid == "nested-link":
                        (public_root / "venv").mkdir()
                        (public_root / "venv/outside").symlink_to("/tmp", target_is_directory=True)
                    elif invalid == "hardlink":
                        (public_root / "venv").mkdir()
                        original = public_root / "venv/original"
                        original.write_text("public fixture")
                        (public_root / "venv/alias").hardlink_to(original)
                    elif invalid == "mirror-path":
                        (public_root / "mirror").mkdir()
                        (public_root / "mirror/extra").write_text("unapproved fixture")
                    before = {p: p.lstat().st_mode for p in (public_root, *public_root.rglob("*"))}
                    if alias:
                        before[alias] = alias.lstat().st_mode
                    message = ("^Unapproved public Python workspace scope or ownership$" if alias
                               else "public Python workspace")
                    with mock.patch.object(trial.os, "geteuid", return_value=os.geteuid() + (1 if invalid == "owner" else 0)):
                        with self.assertRaisesRegex(ValueError, message):
                            trial.public_workspace_scope(candidate, inspect_tree=True)
                    self.assertEqual({p: p.lstat().st_mode for p in before}, before)
                finally:
                    if alias:
                        alias.unlink()

    def test_python_mirror_binding_rejects_tampering_before_scanner(self):
        for invalid in ("mirror", "source", "sha", "binding", "symlink"):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                    prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
                root, public_root = Path(directory), Path(public_directory)
                source, raw = root / "source", root / "raw"
                raw.mkdir()
                original = source / trial.PROJECTS[-1]
                original.parent.mkdir(parents=True)
                original.write_bytes(PYTHON_REQUIREMENTS)
                binding = trial.create_python_mirror(public_root, source, SOURCE_SHA)
                mirror = public_root / "mirror" / trial.PROJECTS[-1]
                if invalid == "mirror":
                    mirror.chmod(0o600)
                    mirror.write_text("boto3==0\n")
                elif invalid == "source":
                    original.write_text("changed\n")
                elif invalid == "sha":
                    binding["source_sha"] = "b" * 40
                elif invalid == "binding":
                    binding["source_sha256"] = "0" * 64
                elif invalid == "symlink":
                    mirror.unlink()
                    mirror.symlink_to(original)
                state = {"source_sha": SOURCE_SHA, "control_sha": "a" * 40, "preparation_complete": True,
                         "python_mirror": binding, "manifest_hashes": {}}
                trial.write_json(raw / "state.json", state)
                args = SimpleNamespace(root=root, source=source, control=root / "control", scanner=root / "scanner",
                                       public_root=public_root, sha=SOURCE_SHA, control_sha="a" * 40)
                with mock.patch.object(trial, "revision", side_effect=[SOURCE_SHA, "a" * 40]), \
                        mock.patch.object(trial, "scan_projects", side_effect=AssertionError("Scanner started")):
                    with self.assertRaisesRegex(ValueError, "mirror|public Python workspace"):
                        trial.scan(args, raw)

    def test_public_cleanup_is_owner_scoped_and_does_not_follow_links(self):
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory(
                prefix="veyport-snyk-public.", dir="/tmp") as directory:
            public_root, sentinel = Path(directory), Path(outside) / "keep"
            sentinel.write_text("private fixture")
            link = public_root / "mirror" / trial.PROJECTS[-1]
            link.parent.mkdir(parents=True)
            link.symlink_to(sentinel)
            with self.assertRaisesRegex(ValueError, "public Python workspace symlink"):
                trial.cleanup_public_workspace(public_root)
            self.assertEqual(sentinel.read_text(), "private fixture")
            link.unlink()
            trial.cleanup_public_workspace(public_root)
            self.assertFalse(public_root.exists())
            self.assertEqual(sentinel.read_text(), "private fixture")

    def test_prepare_cli_gates_on_prerequisites_and_retains_state(self):
        for failure in (None, "dependency", "access", "version", "version-exit", "manifest"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                    prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
                common, public_root = Path(directory), Path(public_directory)
                common.chmod(0o755)
                workspace, temporary = common / "repo/repo", common / "_temp"
                workspace.mkdir(parents=True)
                temporary.mkdir()
                root = temporary / "snyk-runner-trial"
                source, control, raw = workspace / "source", workspace / "diagnostic", root / "raw"
                names = (*trial.PROJECTS, *(p.replace("go.mod", "go.sum") for p in trial.PROJECTS if p.endswith("go.mod")),
                         "web/package-lock.json")
                for name in names:
                    path = source / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(PYTHON_REQUIREMENTS if name == trial.PROJECTS[-1] else b"fixture\n")
                lock = control / "scripts/diagnostics/snyk_runner_trial_requirements.lock"
                lock.parent.mkdir(parents=True)
                lock.write_text("synthetic lock provenance\n")
                scanner_resolution(raw, root / "scanner")
                sha, control_sha = "9add3445d449083319a0d1cb334d13729bccbb85", "a" * 40
                versions = {"snyk": "1.1308.3", "go": "go version go1.26.11 linux/amd64", "node": "v25.2.0",
                            "npm": "11.6.2", "python": "Python 3.12.13", "age": "v1.2.1"}

                def external(command, cwd, prefix, timeout, env=None):
                    if prefix.name.startswith("version-"):
                        name = prefix.name.removeprefix("version-")
                        prefix.with_suffix(".stdout").write_text("unsupported" if failure == "version" and name == "python"
                                                                 else versions[name])
                        if failure == "version-exit" and name == "age":
                            return 125
                    if failure == "manifest" and prefix.name == "prepare-0":
                        (source / trial.PROJECTS[-1]).write_text("changed\n")
                    if ((failure == "dependency" and prefix.name == "prepare-2")
                            or (failure == "access" and prefix.name == "resolver-access")):
                        return 1
                    return 0

                argv = ["snyk_runner_trial.py", "prepare", "--source", str(source), "--control", str(control),
                        "--root", str(root), "--public-root", str(public_root), "--scanner", str(root / "scanner"),
                        "--sha", sha, "--control-sha", control_sha]
                saved_umask = os.umask(0o077)
                try:
                    with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(workspace),
                                                      "RUNNER_TEMP": str(temporary)}), \
                            mock.patch.object(sys, "argv", argv), \
                            mock.patch.object(trial, "revision", side_effect=[sha, control_sha]), \
                            mock.patch.object(trial, "capture", side_effect=external), \
                            mock.patch.object(trial, "scan_projects", side_effect=AssertionError("Scanner started")):
                        code = trial.main()
                finally:
                    os.umask(saved_umask)
                state = json.loads((raw / "state.json").read_text())
                self.assertEqual(code, 0 if failure is None else 1)
                self.assertIs(state["preparation_complete"], failure is None)
                self.assertEqual(state["projects"], [])
                self.assertEqual(state["source_sha"], sha)
                self.assertEqual(state["control_sha"], control_sha)
                self.assertEqual(len(state["preparation_exit_codes"]), 9)
                self.assertTrue((source / trial.PROJECTS[-1]).exists())
                self.assertFalse((root / "public").exists())

    def test_prepare_requires_hash_locked_wheels_and_original_requirements(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
            common, public_root = Path(directory), Path(public_directory)
            common.chmod(0o755)
            workspace, temporary = common / "repo/repo", common / "_temp"
            workspace.mkdir(parents=True)
            temporary.mkdir()
            root = temporary / "snyk-runner-trial"
            source, control, raw = workspace / "source", workspace / "diagnostic", root / "raw"
            raw.mkdir(parents=True, mode=0o700)
            names = (*trial.PROJECTS, *(p.replace("go.mod", "go.sum") for p in trial.PROJECTS if p.endswith("go.mod")),
                     "web/package-lock.json")
            for name in names:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(PYTHON_REQUIREMENTS if name == trial.PROJECTS[-1] else b"fixture\n")
            lock = control / "scripts/diagnostics/snyk_runner_trial_requirements.lock"
            lock.parent.mkdir(parents=True)
            lock.write_text("synthetic lock provenance\n")
            scanner_resolution(raw, root / "scanner")
            original = (source / trial.PROJECTS[-1]).read_bytes()
            args = SimpleNamespace(source=source, control=control, root=root, public_root=public_root, scanner=root / "scanner",
                                   sha="9add3445d449083319a0d1cb334d13729bccbb85", control_sha="a" * 40)
            versions = {"snyk": "1.1308.3", "go": "go version go1.26.11 linux/amd64", "node": "v25.2.0",
                        "npm": "11.6.2", "python": "Python 3.12.13", "age": "v1.2.1"}

            def external(command, cwd, prefix, timeout, env=None):
                if "pip" in command:
                    self.assertIn("--require-hashes", command)
                    self.assertIn("--only-binary=:all:", command)
                    requirements = [Path(command[index + 1]) for index, item in enumerate(command) if item == "-r"]
                    self.assertEqual(requirements, [lock, source / trial.PROJECTS[-1]])
                if prefix.name.startswith("version-"):
                    prefix.with_suffix(".stdout").write_text(versions[prefix.name.removeprefix("version-")])
                return 0

            with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(workspace),
                                              "RUNNER_TEMP": str(temporary)}), \
                    mock.patch.object(trial, "revision", side_effect=[args.sha, args.control_sha]), \
                    mock.patch.object(trial, "capture", side_effect=external):
                trial.prepare(args, raw)
            state = json.loads((raw / "state.json").read_text())
            self.assertTrue(state["preparation_complete"])
            self.assertEqual(state["python_lock"], {"path": "scripts/diagnostics/snyk_runner_trial_requirements.lock",
                                                   "sha256": hashlib.sha256(lock.read_bytes()).hexdigest()})
            self.assertEqual((source / trial.PROJECTS[-1]).read_bytes(), original)
            self.assertEqual(state["python_mirror"], trial.verify_python_mirror(public_root, source, args.sha, state["python_mirror"]))

    def test_distinguishes_clean_from_vulnerability_and_license_findings(self):
        clean = trial.assess(report(), 0, "hub/go.mod")
        self.assertEqual(clean["status"], "scan_complete_clean")
        finding = report()
        finding["ok"] = False
        finding["vulnerabilities"] = [{"id": "PRIVATE", "type": "license"}, {"id": "PRIVATE"}]
        result = trial.assess(finding, 1, "hub/go.mod")
        self.assertEqual(result, {"status": "scan_complete_with_findings", "dependency_count": 12,
                                  "vulnerability_path_records": 1, "license_path_records": 1, "license_enabled": True})

    def test_rejects_false_success_and_inconsistent_results(self):
        cases = [None, [], {}, {"error": "PRIVATE"}]
        for patch in ({"dependencyCount": 0}, {"dependencyCount": True},
                      {"licensesPolicy": None}, {"licensesPolicy": {}},
                      {"licensesPolicy": {"orgLicenseRules": False, "severities": None}},
                      {"ok": False}, {"org": "other"}, {"targetFile": "package.json"},
                      {"targetFile": [], "displayTargetFile": "go.mod"},
                      {"targetFile": {}, "displayTargetFile": "go.mod"},
                      {"targetFile": ["go.mod"]}, {"targetFile": {"name": "go.mod"}},
                      {"displayTargetFile": []}, {"displayTargetFile": {}},
                      {"org": []}, {"packageManager": {}},
                      {"packageManager": "npm"}, {"vulnerabilities": [{"type": "unknown"}]},
                      {"error": "PRIVATE"}):
            candidate = report()
            candidate.update(patch)
            cases.append(candidate)
        for candidate in cases:
            with self.subTest(candidate=candidate):
                self.assertEqual(trial.assess(candidate, 0, "hub/go.mod")["status"], "scan_incomplete")
        for exit_code in (1, 2, 3, 124, 125):
            self.assertEqual(trial.assess(report(), exit_code, "hub/go.mod")["status"], "scan_incomplete")

    def test_npm_lockfile_metadata_accepts_explicit_manifest_scan(self):
        candidate = report()
        candidate.update(packageManager="npm", targetFile="", displayTargetFile="package-lock.json")
        self.assertEqual(trial.assess(candidate, 0, "web/package.json")["status"], "scan_complete_clean")
        candidate["displayTargetFile"] = "unrelated.json"
        self.assertEqual(trial.assess(candidate, 0, "web/package.json")["status"], "scan_incomplete")

    def test_json_loader_rejects_duplicates_nonfinite_and_malformed(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"
            self.assertIsNone(trial.load_report(target))
            for contents in ('{"ok":true,"ok":false}', '{"dependencyCount":NaN}',
                             '{"nested":[{"value":1e999}]}', '{"nested":{"value":-1e999}}',
                             'broken', ''):
                target.write_text(contents)
                self.assertIsNone(trial.load_report(target))
            target.write_text(json.dumps(report()))
            self.assertEqual(trial.load_report(target), report())

    def test_json_recursion_failure_is_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "deep.json"
            target.write_text("[" * 2000 + "0" + "]" * 2000)
            self.assertEqual(trial.assess(trial.load_report(target), 0, "hub/go.mod")["status"], "scan_incomplete")
            # Python versions differ in decoder nesting limits; exercise its failure boundary too.
            with mock.patch.object(trial.json, "loads", side_effect=RecursionError):
                self.assertIsNone(trial.load_report(target))

    def test_public_summary_never_copies_scanner_text_or_unknown_fields(self):
        state = {"source_sha": "9add3445d449083319a0d1cb334d13729bccbb85",
                 "preparation_complete": True, "manifests_unchanged": True,
                 "versions": {"snyk": "1.1308.3", "go": "PRIVATE\n::error::SECRET", "unexpected": "PRIVATE"},
                 "projects": [{"path": "hub/go.mod", "status": "scan_complete_clean",
                               "dependency_count": 12, "vulnerability_path_records": 0, "license_path_records": 0,
                               "license_enabled": True, "raw": "PRIVATE", "attempts": [{"exit_code": 0, "raw": "PRIVATE"}]}],
                 "raw": "PRIVATE"}
        value = trial.public_summary(state)
        self.assertNotIn("PRIVATE", json.dumps(value))
        self.assertNotIn("SECRET", json.dumps(value))
        self.assertEqual(value["versions"]["go"], "unavailable")
        self.assertEqual(value["exit_counts"], {"0": 1})
        self.assertEqual(value["processing_status"], "trial_incomplete")
        self.assertEqual(len(value["projects"]), 7)
        poisoned = copy.deepcopy(state)
        poisoned["projects"][0]["path"] = "PRIVATE"
        self.assertNotIn("PRIVATE", json.dumps(trial.public_summary(poisoned)))


class ScannerBindingTests(unittest.TestCase):
    def fixture(self, root, public_root):
        source, control, raw = root / "source", root / "control", root / "raw"
        names = (*trial.PROJECTS, *(p.replace("go.mod", "go.sum") for p in trial.PROJECTS if p.endswith("go.mod")),
                 "web/package-lock.json")
        for name in names:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(PYTHON_REQUIREMENTS if name == trial.PROJECTS[-1] else b"fixture\n")
        lock = control / "scripts/diagnostics/snyk_runner_trial_requirements.lock"
        lock.parent.mkdir(parents=True)
        lock.write_text("synthetic lock provenance\n")
        args = SimpleNamespace(source=source, control=control, root=root, public_root=public_root,
                               scanner=root / "scanner", sha=SOURCE_SHA, control_sha="a" * 40)
        resolution = scanner_resolution(raw, args.scanner)
        return args, raw, resolution

    def prepare(self, args, raw, *, tamper_during_dependencies=False):
        capture = trial.capture
        versions = {"go": "go version go1.26.11 linux/amd64", "node": "v25.2.0", "npm": "11.6.2",
                    "python": "Python 3.12.13", "age": "v1.2.1"}

        def external(command, cwd, prefix, timeout, **options):
            if tamper_during_dependencies and prefix.name == "prepare-7":
                args.scanner.write_text(args.scanner.read_text() + "# changed during preparation\n")
            if prefix.name == "version-snyk":
                return capture(command, cwd, prefix, timeout, **options)
            if prefix.name.startswith("version-"):
                prefix.with_suffix(".stdout").write_text(versions[prefix.name.removeprefix("version-")])
            return 0

        with mock.patch.object(trial, "revision", side_effect=[args.sha, args.control_sha]), \
                mock.patch.object(trial, "resolver_permissions"), \
                mock.patch.object(trial, "capture", side_effect=external):
            return trial.prepare(args, raw)

    def invalidate(self, failure, raw, scanner, resolution):
        path = raw / "snyk-cli.json"
        if failure == "missing":
            path.unlink()
        elif failure == "malformed":
            path.write_text("not JSON")
        elif failure == "duplicate":
            path.write_text('{"verified":false,' + json.dumps(resolution)[1:])
        elif failure == "tampered":
            scanner.write_text(scanner.read_text() + "# changed after bootstrap\n")
        else:
            field, value = {
                "unverified": ("verified", False), "truthy": ("verified", 1),
                "version": ("version", "1.2.3-beta"), "version-type": ("version", 123),
                "hash": ("actual_sha256", "not a hash"), "hash-type": ("actual_sha256", 123),
                "mismatch": ("expected_sha256", "0" * 64), "url": ("url", "https://evil.example/snyk"),
            }[failure]
            resolution[field] = value
            trial.write_json(path, resolution)

    def test_prepare_rejects_invalid_bootstrap_resolution_before_version_execution(self):
        for failure in ("missing", "malformed", "duplicate", "unverified", "truthy", "version", "version-type",
                        "hash", "hash-type", "mismatch", "url", "tampered", "dependency-tamper"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                    prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
                args, raw, resolution = self.fixture(Path(directory), Path(public_directory))
                if failure != "dependency-tamper":
                    self.invalidate(failure, raw, args.scanner, resolution)
                with self.assertRaisesRegex(ValueError, "Snyk bootstrap"):
                    self.prepare(args, raw, tamper_during_dependencies=failure == "dependency-tamper")
                self.assertFalse((raw / "scanner-executed").exists())
                self.assertFalse(json.loads((raw / "state.json").read_text())["preparation_complete"])

    def test_prepare_binds_observed_version_to_bootstrap_resolution(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
            args, raw, resolution = self.fixture(Path(directory), Path(public_directory))
            resolution.update(version="1.1308.4", url="https://downloads.snyk.io/cli/v1.1308.4/snyk-linux")
            trial.write_json(raw / "snyk-cli.json", resolution)
            self.assertFalse(self.prepare(args, raw))
            self.assertEqual((raw / "scanner-executed").read_text(), "executed")
            state = json.loads((raw / "state.json").read_text())
            self.assertEqual(state["versions"]["snyk"], "1.1308.3")
            self.assertFalse(state["preparation_complete"])

    def test_scan_rechecks_bootstrap_binding_immediately_before_scanner(self):
        for failure in (None, "missing", "malformed", "duplicate", "unverified", "truthy", "version", "version-type",
                        "hash", "hash-type", "mismatch", "url", "tampered", "prepared-version"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                    prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
                args, raw, resolution = self.fixture(Path(directory), Path(public_directory))
                self.assertTrue(self.prepare(args, raw))
                (raw / "scanner-executed").unlink()
                if failure == "prepared-version":
                    state = json.loads((raw / "state.json").read_text())
                    state["versions"]["snyk"] = "1.1308.4"
                    trial.write_json(raw / "state.json", state)
                elif failure:
                    self.invalidate(failure, raw, args.scanner, resolution)

                def scans(*unused):
                    if failure:
                        self.fail("Scanner started with invalid bootstrap binding")
                    (raw / "scanner-executed").write_text("scanned")
                    return [{"path": path, "status": "scan_complete_clean"} for path in trial.PROJECTS]

                with mock.patch.object(trial, "revision", side_effect=[args.sha, args.control_sha]), \
                        mock.patch.object(trial, "scan_projects", side_effect=scans):
                    if failure:
                        with self.assertRaisesRegex(ValueError, "Snyk bootstrap"):
                            trial.scan(args, raw)
                        self.assertFalse((raw / "scanner-executed").exists())
                    else:
                        self.assertTrue(trial.scan(args, raw))
                        self.assertEqual((raw / "scanner-executed").read_text(), "scanned")


class LatestClientTests(unittest.TestCase):
    def fixture(self, directory, *, version="2.3.4", printed_version=None):
        root = Path(directory)
        (root / "raw").mkdir()
        (root / "tools").mkdir()
        fixtures = root / "fixtures"
        fixtures.mkdir()
        # Execution leaves a marker; a bad digest must never create it.
        binary = ("#!/bin/sh\nprintf executed >> " + shlex.quote(str(root / "executed"))
                  + "\nprintf '%s' \"${SNYK_TMP_PATH-}\" > " + shlex.quote(str(root / "bootstrap-tmp-path"))
                  + "\npwd > " + shlex.quote(str(root / "bootstrap-cwd"))
                  + "\nprintf '%s\\n' " + shlex.quote(printed_version or version) + "\n").encode()
        (fixtures / "binary").write_bytes(binary)
        metadata = {"version": version, "schemaVersion": 1, "assets": {"snyk-linux": {
            "url": f"https://downloads.snyk.io/cli/v{version}/snyk-linux",
            "sha256": hashlib.sha256(binary).hexdigest() + "  snyk-linux",
            "sha256Url": f"https://downloads.snyk.io/cli/v{version}/snyk-linux.sha256"}}}
        fake_bin = root / "bin"
        fake_bin.mkdir()
        curl = fake_bin / "curl"
        curl.write_text("#!" + sys.executable + r'''
import json, os, pathlib, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ["DOWNLOAD_FIXTURE"])
with (root / "requests.jsonl").open("a") as log:
    print(json.dumps(args), file=log)
assert args[:6] == ["--fail", "--silent", "--show-error", "--location", "--proto", "=https"]
assert args[6:12] == ["--proto-redir", "=https", "--connect-timeout", "10", "--max-time", "180"]
url, option, target = args[12:]
assert option == "--output"
if url == "https://downloads.snyk.io/cli/stable/release.json":
    name = "release.json"
elif url == json.loads((root / "fixtures/release.json").read_text())["assets"]["snyk-linux"]["url"]:
    name = "binary"
else:
    sys.exit(5)
if os.environ.get("FAIL_DOWNLOAD") == name:
    sys.exit(22)
pathlib.Path(target).write_bytes((root / "fixtures" / name).read_bytes())
''')
        curl.chmod(0o700)
        return root, metadata

    def bootstrap(self, root, metadata, *, fail_download=""):
        (root / "fixtures/release.json").write_text(metadata if isinstance(metadata, str) else json.dumps(metadata))
        helper = Path(__file__).with_name("snyk_latest_cli.py")
        # No inherited credentials or configuration: model precredential bootstrap.
        environment = {"PATH": str(root / "bin") + ":/usr/bin:/bin", "DOWNLOAD_FIXTURE": str(root),
                       "FAIL_DOWNLOAD": fail_download}
        return subprocess.run([sys.executable, "-I", str(helper), "--root", str(root)],
                              env=environment, capture_output=True, text=True, timeout=10)

    def test_latest_metadata_download_is_verified_before_execution_and_keeps_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root, metadata = self.fixture(directory)
            result = self.bootstrap(root, metadata)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout + result.stderr, "")
            self.assertEqual((root / "executed").read_text(), "executed")
            self.assertEqual(stat.S_IMODE((root / "tools/snyk").stat().st_mode), 0o700)
            self.assertEqual(json.loads((root / "raw/snyk-release.json").read_text()), metadata)
            resolution = json.loads((root / "raw/snyk-cli.json").read_text())
            self.assertEqual(resolution, {"version": "2.3.4", "url": "https://downloads.snyk.io/cli/v2.3.4/snyk-linux",
                                         "expected_sha256": hashlib.sha256((root / "fixtures/binary").read_bytes()).hexdigest(),
                                         "actual_sha256": hashlib.sha256((root / "tools/snyk").read_bytes()).hexdigest(),
                                         "verified": True})
            self.assertEqual((root / "raw/snyk-version.stdout").read_text(), "2.3.4\n")
            self.assertEqual((root / "bootstrap-tmp-path").read_text(), str(root / "raw/snyk-bootstrap-tmp"))
            self.assertEqual((root / "bootstrap-cwd").read_text(), str(root / "raw") + "\n")
            self.assertEqual(stat.S_IMODE((root / "raw/snyk-bootstrap-tmp").stat().st_mode), 0o700)
            requests = [json.loads(line)[12] for line in (root / "requests.jsonl").read_text().splitlines()]
            self.assertEqual(requests, ["https://downloads.snyk.io/cli/stable/release.json",
                                       "https://downloads.snyk.io/cli/v2.3.4/snyk-linux"])

    def test_malformed_metadata_aborts_before_binary_download_or_execution(self):
        mutations = [
            ("version", value) for value in ("1.2.3-beta", "1.2.3\n", "v1.2.3", "01.2.3", "1.2", "١.2.3", None, 123)
        ] + [("url", value) for value in (
            "http://downloads.snyk.io/cli/v2.3.4/snyk-linux", "https://evil.example/cli/v2.3.4/snyk-linux",
            "https://downloads.snyk.io.evil.example/cli/v2.3.4/snyk-linux", "https://downloads.snyk.io/cli/stable/snyk-linux",
            "https://downloads.snyk.io/cli/v2.3.5/snyk-linux", "https://downloads.snyk.io/cli/v2.3.4/snyk-linux?x=1",
            "https://downloads.snyk.io/cli/v2.3.4/snyk-macos", None,
        )] + [("sha256", value) for value in ("a" * 64, "g" * 64 + "  snyk-linux", "a" * 64 + "  snyk-macos",
                                              "a" * 64 + "  snyk-linux\n", None)] + [
            ("sha256Url", "https://evil.example/snyk-linux.sha256"), ("schemaVersion", 2),
            ("assets", {}), ("assets", []), ("asset", []), ("schemaVersion", True),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as directory:
                root, metadata = self.fixture(directory)
                if field in ("version", "schemaVersion", "assets"):
                    metadata[field] = value
                elif field == "asset":
                    metadata["assets"]["snyk-linux"] = value
                else:
                    metadata["assets"]["snyk-linux"][field] = value
                result = self.bootstrap(root, metadata)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "executed").exists())
                self.assertFalse((root / "tools/snyk").exists())
                self.assertTrue((root / "requests.jsonl").exists(), result.stderr)
                self.assertEqual(len((root / "requests.jsonl").read_text().splitlines()), 1)

    def test_checksum_mismatch_never_executes_binary_or_keeps_cached_client(self):
        with tempfile.TemporaryDirectory() as directory:
            root, metadata = self.fixture(directory)
            metadata["assets"]["snyk-linux"]["sha256"] = "0" * 64 + "  snyk-linux"
            (root / "tools/snyk").write_text("old cached binary")
            result = self.bootstrap(root, metadata)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "executed").exists())
            self.assertFalse((root / "tools/snyk").exists())
            self.assertFalse((root / "tools/snyk.download").exists())

    def test_malformed_or_ambiguous_json_aborts_before_binary_download(self):
        for failure in ("broken", "null", "[]", "duplicate"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root, metadata = self.fixture(directory)
                contents = ('{"version":"9.9.9",' + json.dumps(metadata)[1:]) if failure == "duplicate" else failure
                result = self.bootstrap(root, contents)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "executed").exists())
                self.assertEqual(len((root / "requests.jsonl").read_text().splitlines()), 1)

    def test_wrong_binary_version_and_failed_downloads_abort_without_fallback(self):
        for failure in ("version", "release.json", "binary"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root, metadata = self.fixture(directory, printed_version="9.9.9" if failure == "version" else None)
                (root / "tools/snyk").write_text("old cached binary")
                result = self.bootstrap(root, metadata, fail_download=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((root / "executed").exists(), failure == "version")
                self.assertFalse((root / "tools/snyk").exists())
                self.assertFalse((root / "tools/snyk.download").exists())

    def test_public_version_accepts_stable_updates_and_rejects_untrusted_text(self):
        for version in ("1.1308.4", "2.0.0", "0.1.0", "1.2.3-beta", "01.2.3", "1.2.3\n", "١.2.3", "PRIVATE", 123):
            with self.subTest(version=version):
                state = {"source_sha": SOURCE_SHA, "versions": {"snyk": version}}
                expected = version if version in ("1.1308.4", "2.0.0", "0.1.0") else "unavailable"
                self.assertEqual(trial.public_summary(state)["versions"]["snyk"], expected)


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o022))

    def test_snyk_temp_scope_and_caller_environment_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
            root, public_root = Path(directory), Path(public_directory)
            root.chmod(0o700)
            source, control, raw = root / "source", root / "control", root / "raw"
            raw.mkdir(mode=0o700)
            names = (*trial.PROJECTS, *(p.replace("go.mod", "go.sum") for p in trial.PROJECTS if p.endswith("go.mod")),
                     "web/package-lock.json")
            for name in names:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(PYTHON_REQUIREMENTS if name == trial.PROJECTS[-1] else b"fixture\n")
            lock = control / "scripts/diagnostics/snyk_runner_trial_requirements.lock"
            lock.parent.mkdir(parents=True)
            lock.write_text("synthetic lock provenance\n")
            scanner = root / "scanner"
            scanner.write_text('''#!/usr/bin/env python3
import json, os, pathlib, stat, sys, tempfile, time
target = "--version" if "--version" in sys.argv else next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--file="))
tmp = pathlib.Path(os.environ["SNYK_TMP_PATH"])
record = {"target":target,"tmp":str(tmp),"mode":stat.S_IMODE(tmp.stat().st_mode),
          "token_present":"SNYK_TOKEN" in os.environ,"extra":os.environ.get("CALLER_VALUE"),
          "deadline_remaining":float(os.environ["SNYK_TRIAL_RESOLVER_DEADLINE"]) - time.monotonic()}
with pathlib.Path(os.environ["ENV_LOG"]).open("a") as log:
    print(json.dumps(record), file=log)
if target != "requirements.txt":
    # Other CLI temp data must never contaminate the strictly inspected public assets tree.
    (pathlib.Path(tempfile.mkdtemp(dir=tmp)) / "private-cli-link").symlink_to("/tmp", target_is_directory=True)
if target == "--version":
    print("1.1308.3")
else:
    output = pathlib.Path(next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--json-file-output=")))
    manager = "pip" if target == "requirements.txt" else "npm" if target == "package.json" else "gomodules"
    output.write_text(json.dumps({"ok":True,"dependencyCount":12,"vulnerabilities":[],"licensesPolicy":{"orgLicenseRules":None,"severities":None},"org":"lorconksu","targetFile":target,"packageManager":manager}))
''')
            scanner.chmod(0o700)
            scanner_resolution(raw, scanner)
            args = SimpleNamespace(source=source, control=control, root=root, public_root=public_root,
                                   scanner=scanner, sha=SOURCE_SHA, control_sha="a" * 40)
            versions = {"go": "go version go1.26.11 linux/amd64", "node": "v25.2.0",
                        "npm": "11.6.2", "python": "Python 3.12.13", "age": "v1.2.1"}
            capture = trial.capture

            def preparation(command, cwd, prefix, timeout, **options):
                if prefix.name == "version-snyk":
                    return capture(command, cwd, prefix, timeout, **options)
                if prefix.name.startswith("version-"):
                    prefix.with_suffix(".stdout").write_text(versions[prefix.name.removeprefix("version-")])
                return 0

            environment = {"PATH": os.environ["PATH"], "SNYK_TMP_PATH": str(root / "ambient-temp"),
                           "SNYK_TRIAL_RESOLVER_DEADLINE": "caller-deadline", "CALLER_VALUE": "retained",
                           "ENV_LOG": str(raw / "environments.jsonl")}
            with mock.patch.dict(os.environ, environment, clear=True):
                before = dict(os.environ)
                with mock.patch.object(trial, "revision", side_effect=[args.sha, args.control_sha]), \
                        mock.patch.object(trial, "resolver_permissions"), \
                        mock.patch.object(trial, "capture", side_effect=preparation):
                    self.assertTrue(trial.prepare(args, raw))
                version = json.loads((raw / "environments.jsonl").read_text())
                self.assertTrue(Path(version["tmp"]).is_relative_to(raw), "Snyk version temp must stay private")
                self.assertEqual(version["mode"], 0o700)
                self.assertFalse(version["token_present"])
                self.assertEqual(dict(os.environ), before)
                os.environ["SNYK_TOKEN"] = "synthetic-test-only"
                before = dict(os.environ)
                rows = trial.scan_projects(source, scanner, raw, public_root / "venv/bin/python", public_root, timeout=5)
                self.assertEqual(dict(os.environ), before)
            records = [json.loads(line) for line in (raw / "environments.jsonl").read_text().splitlines()]
            self.assertEqual(len(records), 8)
            self.assertEqual([record["target"] for record in records[1:]], [Path(p).name for p in trial.PROJECTS])
            self.assertTrue(all(row["status"] == "scan_complete_clean" and len(row["attempts"]) == 1 for row in rows))
            for record in records[:-1]:
                self.assertTrue(Path(record["tmp"]).is_relative_to(raw))
                self.assertEqual(record["mode"], 0o700)
            self.assertEqual(records[-1]["tmp"], str(public_root / "resolver-assets"))
            self.assertTrue(all(record["token_present"] for record in records[1:]))
            self.assertTrue(all(record["extra"] == "retained" and record["deadline_remaining"] > 0 for record in records))
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)

    def test_scan_rejects_incomplete_preparation_before_starting_scanner(self):
        for preparation in (False, None, 1, "true", "missing"):
            with self.subTest(preparation=preparation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                raw = root / "raw"
                raw.mkdir()
                sha, control_sha = "9add3445d449083319a0d1cb334d13729bccbb85", "a" * 40
                state = {"source_sha": sha, "control_sha": control_sha}
                if preparation != "missing":
                    state["preparation_complete"] = preparation
                state_path = raw / "state.json"
                trial.write_json(state_path, state)
                before = state_path.read_bytes()
                args = SimpleNamespace(root=root, source=root / "source", control=root / "control",
                                       scanner=root / "scanner", sha=sha, control_sha=control_sha)
                with mock.patch.object(trial, "revision", side_effect=[sha, control_sha]), \
                        mock.patch.object(trial, "scan_projects", side_effect=AssertionError("Scanner started")):
                    with self.assertRaisesRegex(ValueError, "preparation"):
                        trial.scan(args, raw)
                self.assertEqual(state_path.read_bytes(), before)

    def test_scan_rejects_provenance_before_starting_scanner(self):
        sha, control_sha = "9add3445d449083319a0d1cb334d13729bccbb85", "a" * 40
        cases = (
            (None, sha, control_sha),
            ("malformed", sha, control_sha),
            ({"source_sha": sha, "control_sha": control_sha}, "b" * 40, control_sha),
            ({"source_sha": sha, "control_sha": control_sha}, sha, "b" * 40),
            ({"source_sha": "b" * 40, "control_sha": control_sha}, sha, control_sha),
            ({"source_sha": sha, "control_sha": "b" * 40}, sha, control_sha),
        )
        for state, source_revision, control_revision in cases:
            with self.subTest(state=state, revisions=(source_revision, control_revision)), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                raw = root / "raw"
                raw.mkdir()
                state_path = raw / "state.json"
                if state is not None:
                    state_path.write_text("invalid JSON" if state == "malformed" else json.dumps(state))
                before = state_path.read_bytes() if state_path.exists() else None
                args = SimpleNamespace(root=root, source=root / "source", control=root / "control",
                                       scanner=root / "scanner", sha=sha, control_sha=control_sha)
                with mock.patch.object(trial, "revision", side_effect=[source_revision, control_revision]), \
                        mock.patch.object(trial, "scan_projects", side_effect=AssertionError("Scanner started")):
                    with self.assertRaisesRegex(ValueError, "provenance"):
                        trial.scan(args, raw)
                self.assertEqual(state_path.read_bytes() if state_path.exists() else None, before)

    def test_all_seven_attempted_findings_not_retried_errors_bounded_and_logs_private(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
            root, public_root = Path(directory), Path(public_directory)
            source = root / "source"
            raw = root / "raw"
            source.mkdir()
            raw.mkdir()
            for name in trial.PROJECTS:
                manifest = source / name
                manifest.parent.mkdir(parents=True, exist_ok=True)
                manifest.write_bytes(PYTHON_REQUIREMENTS if name == trial.PROJECTS[-1] else b"fixture")
            scanner = root / "scanner"
            scanner.write_text('''#!/usr/bin/env python3
import json, pathlib, sys
output = pathlib.Path(next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--json-file-output=")))
print("PRIVATE_TOKEN_RAW_STDOUT")
print("PRIVATE_TOKEN_RAW_STDERR", file=sys.stderr)
print(str(pathlib.Path.cwd()), file=sys.stderr)
if pathlib.Path.cwd().name == "hub":
    output.write_text(json.dumps({"ok":False,"dependencyCount":12,"vulnerabilities":[{"id":"PRIVATE"}],"licensesPolicy":{"orgLicenseRules":None,"severities":None},"org":"lorconksu","targetFile":"go.mod","packageManager":"gomodules"}))
    sys.exit(1)
if pathlib.Path.cwd().name == "agent":
    output.write_text(json.dumps({"ok":True,"dependencyCount":12,"vulnerabilities":[],"licensesPolicy":{"orgLicenseRules":None,"severities":None},"org":"lorconksu","targetFile":{"name":"go.mod"},"packageManager":"gomodules"}))
    sys.exit(0)
if pathlib.Path.cwd().name == "cli":
    output.write_text("[" * 2000 + "0" + "]" * 2000)
    sys.exit(0)
output.write_text('{"error":"PRIVATE"}')
sys.exit(2)
''')
            scanner.chmod(0o700)
            sha, control_sha = "9add3445d449083319a0d1cb334d13729bccbb85", "a" * 40
            scanner_resolution(raw, scanner)
            trial.write_json(raw / "state.json", {"source_sha": sha, "control_sha": control_sha,
                                                   "versions": {"snyk": "1.1308.3"},
                                                   "preparation_complete": True, "manifest_hashes": {},
                                                   "python_mirror": trial.create_python_mirror(public_root, source, sha)})
            args = SimpleNamespace(root=root, source=source, control=root / "control", scanner=scanner,
                                   public_root=public_root, sha=sha, control_sha=control_sha)
            with mock.patch.object(trial, "revision", side_effect=[sha, control_sha]), \
                    mock.patch.object(trial, "manifest_hashes", return_value={}):
                self.assertFalse(trial.scan(args, raw))
            rows = json.loads((raw / "state.json").read_text())["projects"]
            self.assertEqual(len(rows), 7)
            self.assertEqual(rows[0]["status"], "scan_complete_with_findings")
            self.assertEqual(len(rows[0]["attempts"]), 1)
            self.assertTrue(all(len(row["attempts"]) == 2 for row in rows[1:]))
            self.assertTrue(all(row["status"] == "scan_incomplete" for row in rows[1:]))
            self.assertIn("PRIVATE_TOKEN_RAW_STDOUT", (raw / "project-0-attempt-1.stdout").read_text())
            self.assertIn("PRIVATE_TOKEN_RAW_STDERR", (raw / "project-0-attempt-1.stderr").read_text())
            self.assertNotIn("PRIVATE", json.dumps(rows))
            for index, project in enumerate(trial.PROJECTS):
                cwd = (public_root / "mirror" / project).parent if index == 6 else (source / project).parent
                self.assertIn(str(cwd), (raw / f"project-{index}-attempt-1.stderr").read_text())

    def test_python_mirror_is_rechecked_immediately_before_resolution(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
            root, public_root = Path(directory), Path(public_directory)
            source, raw = root / "source", root / "raw"
            raw.mkdir()
            manifest = source / trial.PROJECTS[-1]
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes(PYTHON_REQUIREMENTS)
            trial.create_python_mirror(public_root, source, SOURCE_SHA)
            seen = []

            def external(command, cwd, prefix, timeout, env=None):
                seen.append(cwd)
                if len(seen) == 12:
                    mirror = public_root / "mirror" / trial.PROJECTS[-1]
                    mirror.chmod(0o600)
                    mirror.write_text("tampered after six scans\n")
                return 2

            with mock.patch.object(trial, "capture", side_effect=external):
                with self.assertRaisesRegex(ValueError, "mirror.*hash mismatch"):
                    trial.scan_projects(source, root / "scanner", raw, Path(sys.executable), public_root)
            self.assertEqual(len(seen), 12)
            self.assertNotIn((public_root / "mirror" / trial.PROJECTS[-1]).parent, seen)

    def test_python_resolver_has_separate_identity_and_arguments_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
            root, public_root = Path(directory), Path(public_directory)
            root.chmod(0o711)
            probe = root / "probe"
            probe.mkdir(mode=0o777)
            probe.chmod(0o1777)
            subprocess.run([sys.executable, "-m", "venv", "--copies", "--without-pip", str(public_root / "venv")], check=True)
            site = next((public_root / "venv/lib").glob("python*/site-packages"))
            hook = """import json, os, pathlib, subprocess
root = pathlib.Path(ROOT_PATH)
scanner = (root / "probe/scanner-pid").read_text()
try:
    pathlib.Path("/proc/" + scanner + "/environ").read_bytes()
    proc_access = "readable"
except PermissionError:
    proc_access = "denied"
try:
    (root / "raw/private-probe").read_text()
    private_access = "readable"
except PermissionError:
    private_access = "denied"
status = pathlib.Path("/proc/self/status").read_text()
result = {"token_present": "SNYK_TOKEN" in os.environ, "uid": os.geteuid(), "gid": os.getegid(),
          "groups": os.getgroups(), "no_new_privs": "NoNewPrivs:\t1" in status,
          "scanner_proc": proc_access, "private_file": private_access,
          "sudo_exit": subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/true"], capture_output=True).returncode}
(root / "probe/startup.json").write_text(json.dumps(result))
""".replace("ROOT_PATH", repr(str(root)))
            (site / "startup_probe.py").write_text(hook)
            (site / "startup_probe.pth").write_text("import startup_probe\n")
            source, raw = root / "source", root / "raw"
            project = "infra/audit-lab/storage/requirements.txt"
            (source / project).parent.mkdir(parents=True)
            (source / project).write_bytes(PYTHON_REQUIREMENTS)
            trial.create_python_mirror(public_root, source, SOURCE_SHA)
            raw.mkdir(mode=0o700)
            (raw / "private-probe").write_text("synthetic private evidence")
            scanner = root / "scanner"
            scanner.write_text('''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys, tempfile
output = pathlib.Path(next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--json-file-output=")))
command = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--command="))
probe = pathlib.Path(os.environ["PROBE"])
(probe / "scanner-env").write_text("present" if "SNYK_TOKEN" in os.environ else "absent")
(probe / "scanner-pid").write_text(str(os.getpid()))
assets = pathlib.Path(tempfile.mkdtemp(dir=os.environ.get("SNYK_TMP_PATH", str(probe))))
script = assets / "pip_resolve.py"
script.write_text("import json,sys; print(json.dumps(sys.argv[1:]))")
script.chmod(0o600)
child = subprocess.run([command, str(script), "argument with spaces", "quote'argument", "$HOME", ""], capture_output=True, text=True, check=True)
(probe / "args").write_text(child.stdout)
output.write_text(json.dumps({"ok":True,"dependencyCount":12,"vulnerabilities":[],"licensesPolicy":{"orgLicenseRules":None,"severities":None},"org":"lorconksu","targetFile":"requirements.txt","packageManager":"pip"}))
''')
            scanner.chmod(0o700)
            environment = {"SNYK_TOKEN": "synthetic-test-only", "PROBE": str(probe), "PATH": os.environ["PATH"]}
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(trial, "PROJECTS", (project,)):
                trial.resolver_permissions(root, source, public_root)
                rows = trial.scan_projects(source, scanner, raw, public_root / "venv/bin/python", public_root, timeout=5)
            self.assertEqual(rows[0]["status"], "scan_complete_clean")
            self.assertEqual((probe / "scanner-env").read_text(), "present")
            startup = json.loads((probe / "startup.json").read_text())
            self.assertFalse(startup["token_present"])
            self.assertEqual(startup["scanner_proc"], "denied")
            self.assertEqual(startup["private_file"], "denied")
            self.assertEqual((startup["uid"], startup["gid"], startup["groups"]), (65534, 65534, []))
            self.assertTrue(startup["no_new_privs"])
            self.assertNotEqual(startup["sudo_exit"], 0)
            self.assertEqual(json.loads((probe / "args").read_text()),
                             ["argument with spaces", "quote'argument", "$HOME", ""])

    def test_subprocess_deadline_captures_output_and_terminates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = trial.capture(["/bin/sh", "-c", "echo PRIVATE; sleep 20"], root, root / "deadline", timeout=0.05)
            self.assertEqual(result, 124)
            self.assertIn("PRIVATE", (root / "deadline.stdout").read_text())

    def test_resolver_rejects_symlinked_asset_directory_before_canonicalization(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
            root, public_root = Path(directory), Path(public_directory)
            wrapper = trial.python_resolver_command(root, Path(sys.executable), public_root)
            contents = wrapper.read_text()
            canonical_check = '    test "$(/usr/bin/realpath -e -- "$directory")" = "$directory"\n'
            self.assertEqual(contents.count(canonical_check), 1)
            # A success checkpoint isolates the explicit guards from canonicalization,
            # traversal, chmod and privileged execution in this test-only launcher copy.
            wrapper.write_text(contents.replace(canonical_check, '    exit 0\n'))
            assets = public_root / "resolver-assets"
            target = assets / "fixture"
            target.mkdir()
            (target / "pip_resolve.py").write_text("raise AssertionError('Must not execute')\n")
            linked = assets / "linked"
            linked.symlink_to(target, target_is_directory=True)
            accepted = subprocess.run([wrapper, target / "pip_resolve.py"], capture_output=True, timeout=5)
            self.assertEqual(accepted.returncode, 0)
            rejected = subprocess.run([wrapper, linked / "pip_resolve.py"], capture_output=True, timeout=5)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(accepted.stdout + accepted.stderr + rejected.stdout + rejected.stderr, b"")

    def test_resolver_refuses_unavailable_cgroups_before_python_starts(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
            root, public_root = Path(directory), Path(public_directory)
            raw, unavailable = root / "raw", root / "unavailable-cgroupfs"
            raw.mkdir()
            unavailable.mkdir()
            wrapper = trial.python_resolver_command(raw, Path(sys.executable), public_root)
            command = shlex.split(wrapper.read_text().split("\nexec ", 1)[1])
            program = command[command.index("-c") + 1]
            # A regular filesystem lacks kernel cgroup interfaces; alter only this test copy's root.
            self.assertEqual(program.count("dir='/sys/fs/cgroup'"), 1)
            program = program.replace("dir='/sys/fs/cgroup'", "dir=" + repr(str(unavailable)))
            result = subprocess.run(["/usr/bin/sudo", "-n", sys.executable, "-I", "-S", "-c", program,
                                     str(time.monotonic() + 5), "/usr/bin/setpriv", "--reuid=65534", "--regid=65534",
                                     "--clear-groups", "--no-new-privs", sys.executable, "-I", "-S", "-c",
                                     "print('Downloaded Python started')"], env={"PATH": os.environ["PATH"]},
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(list(unavailable.iterdir()), [])

    def test_scan_deadline_terminates_late_cross_uid_resolver_and_detached_descendant(self):
        self.assertNotEqual(os.geteuid(), 0, "Exercise the runner user's signal permissions")
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
            root, public_root = Path(directory), Path(public_directory)
            root.chmod(0o711)
            raw, probe = root / "raw", root / "probe"
            raw.mkdir(mode=0o700)
            # Only the runner-owned fake scanner writes markers, via the resolver's stdout.
            probe.mkdir(mode=0o700)
            source = root / "source"
            project = "infra/audit-lab/storage/requirements.txt"
            (source / project).parent.mkdir(parents=True)
            (source / project).write_bytes(PYTHON_REQUIREMENTS)
            trial.create_python_mirror(public_root, source, SOURCE_SHA)
            scanner = root / "scanner"
            scanner.write_text('''#!/usr/bin/env python3
import os, pathlib, subprocess, sys, tempfile, time
command = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--command="))
assets = pathlib.Path(tempfile.mkdtemp(dir=os.environ["SNYK_TMP_PATH"]))
script = assets / "pip_resolve.py"
script.write_text("""import json, os, pathlib, subprocess, sys, time
denied = 0
for name, contents in (("planted.json", json.dumps({"pids": [1]})), ("malformed.json", "invalid JSON")):
    try:
        (pathlib.Path(sys.argv[1]) / name).write_text(contents)
    except PermissionError:
        denied += 1
child = subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time; time.sleep(20)"], stdout=subprocess.DEVNULL, start_new_session=True)
group = pathlib.Path("/sys/fs/cgroup") / pathlib.Path("/proc/self/cgroup").read_text().strip().removeprefix("0::/")
controls_denied = 0
for control in (group / "cgroup.procs", group / "cgroup.kill", pathlib.Path("/sys/fs/cgroup/cgroup.procs")):
    try:
        fd = os.open(control, os.O_WRONLY)
        os.close(fd)
    except PermissionError:
        controls_denied += 1
print(json.dumps({"uid": os.geteuid(), "mode": sys.argv[2], "pids": [os.getpid(), child.pid], "sessions": [os.getsid(0), os.getsid(child.pid)], "marker_writes_denied": denied, "cgroup":str(group), "cgroup_owner":group.stat().st_uid, "cgroup_mode":group.stat().st_mode & 0o777, "controls_denied":controls_denied}), flush=True)
if sys.argv[2] == "sleep":
    time.sleep(20)
""")
# Model work before Snyk starts Python: a new per-resolver duration would finish too late.
# Leave about two seconds before the shared cutoff for hosted sudo/Python startup.
time.sleep(2.5)
probe = pathlib.Path(os.environ["PROBE"])
mode = "sleep" if not list(probe.iterdir()) else "exit"
child = subprocess.Popen([command, str(script), str(probe), mode], stdout=subprocess.PIPE, text=True)
marker = child.stdout.readline()
(probe / assets.name).write_text(marker)
child.stdout.close()
child.wait()
sys.exit(2)
''')
            scanner.chmod(0o700)

            def alive(pid):
                try:
                    state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                    return state != "Z"
                except FileNotFoundError:
                    return False

            failed = True
            try:
                environment = {"PROBE": str(probe), "PATH": os.environ["PATH"]}
                with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(trial, "PROJECTS", (project,)):
                    trial.resolver_permissions(root, source, public_root)
                    rows = trial.scan_projects(source, scanner, raw, Path(sys.executable), public_root, timeout=6)
                markers = [json.loads(path.read_text()) for path in probe.iterdir()]
                self.assertEqual(len(markers), 2, "Both attempts must really start the resolver")
                self.assertEqual(sorted(marker["mode"] for marker in markers), ["exit", "sleep"])
                self.assertTrue(all(marker["uid"] == 65534 for marker in markers))
                self.assertTrue(all(marker["sessions"][1] == marker["pids"][1]
                                    and marker["sessions"][0] != marker["sessions"][1] for marker in markers))
                self.assertTrue(all(marker["marker_writes_denied"] == 2 for marker in markers))
                self.assertFalse((probe / "planted.json").exists())
                self.assertFalse((probe / "malformed.json").exists())
                self.assertEqual(rows[0]["status"], "scan_incomplete")
                pids = [pid for marker in markers for pid in marker["pids"]]
                limit = time.monotonic() + 0.5
                while any(alive(pid) for pid in pids) and time.monotonic() < limit:
                    time.sleep(0.01)
                self.assertFalse([pid for pid in pids if alive(pid)], "Resolver or descendant survived the scan deadline")
                for marker in markers:
                    self.assertRegex(marker["cgroup"], r"^/sys/fs/cgroup/veyport-snyk-resolver\.[A-Za-z0-9_]{8}$")
                    self.assertEqual((marker["cgroup_owner"], marker["cgroup_mode"], marker["controls_denied"]), (0, 0o700, 3))
                    self.assertFalse(Path(marker["cgroup"]).exists(), "Dedicated cgroup survived resolver cleanup")
                failed = False
            finally:
                if failed:
                    # No signals based on marker content: even broken cleanup leaves only finite fixtures.
                    time.sleep(20.5)


class SealingTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o022))

    def test_workflow_cleanup_attempts_all_actions_and_preserves_failures(self):
        repo = Path(__file__).resolve().parents[2]
        workflow = (repo / ".github/workflows/snyk-runner-trial.yml").read_text()
        step = next(block for block in workflow.split("      - name: ") if 'snyk_runner_trial.py" cleanup' in block)
        script = "\n".join(line[10:] for line in step.split("        run: |\n", 1)[1].splitlines()) + "\n"
        self.assertEqual(script.count("/usr/bin/python3.12"), 1)
        script = script.replace("/usr/bin/python3.12", shlex.quote(sys.executable))
        for failure in ("public", "raw", "archive", None):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory(
                    prefix="veyport-snyk-public.", dir="/tmp") as public_directory:
                fixture, public_root = Path(directory), Path(public_directory)
                root, control, tools = fixture / "trial", fixture / "control", fixture / "tools"
                raw = root / "raw"
                raw.mkdir(parents=True, mode=0o700)
                sentinels = [raw / "private.txt", root / "evidence.tar.gz", root / "encryption.stdout", root / "encryption.stderr"]
                for path in sentinels:
                    path.write_text("synthetic private plaintext")
                (root / "public").mkdir()
                ciphertext = root / "public/evidence.tar.gz.age"
                ciphertext.write_bytes(b"synthetic ciphertext")
                (public_root / "resolver-assets").mkdir()
                public_sentinel = public_root / "resolver-assets/public.txt"
                public_sentinel.write_text("public fixture")
                helper = control / "scripts/diagnostics/snyk_runner_trial.py"
                helper.parent.mkdir(parents=True)
                helper.write_text('''import os, pathlib, shutil, sys
assert sys.argv[1] == "cleanup"
with pathlib.Path(os.environ["CLEANUP_EVENTS"]).open("a") as log:
    print("public", file=log)
# Even a helper that recreates plaintext must run before the private cleanup.
raw = pathlib.Path(os.environ["TRIAL_ROOT"]) / "raw"
raw.mkdir(exist_ok=True)
(raw / "helper-error.txt").write_text("synthetic helper error")
code = int(os.environ["PUBLIC_CLEANUP_EXIT"])
if code == 0:
    shutil.rmtree(os.environ["PUBLIC_PYTHON_ROOT"])
sys.exit(code)
''')
                tools.mkdir()
                rm = tools / "rm"
                rm.write_text('''#!/usr/bin/env python3
import os, pathlib, subprocess, sys
with pathlib.Path(os.environ["CLEANUP_EVENTS"]).open("a") as log:
    print(sys.argv[1], file=log)
if os.environ.get("RM_FAILURE") == sys.argv[1]:
    sys.exit(1)
sys.exit(subprocess.run(["/bin/rm", *sys.argv[1:]]).returncode)
''')
                rm.chmod(0o700)
                events = fixture / "events"
                environment = {"PATH": str(tools) + os.pathsep + os.environ["PATH"], "TRIAL_ROOT": str(root),
                               "CONTROL": str(repo if failure is None else control), "SOURCE": str(fixture / "source"),
                               "SOURCE_SHA": SOURCE_SHA, "CONTROL_SHA": "a" * 40, "PUBLIC_PYTHON_ROOT": str(public_root),
                               "CLEANUP_EVENTS": str(events), "PUBLIC_CLEANUP_EXIT": "1" if failure == "public" else "0",
                               "RM_FAILURE": "-rf" if failure == "raw" else "-f" if failure == "archive" else ""}
                result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
                                        env=environment, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0 if failure is None else 1)
                self.assertEqual(result.stdout + result.stderr, "")
                self.assertEqual([p.exists() for p in sentinels],
                                 [failure == "raw", *([failure == "archive"] * 3)])
                self.assertEqual((raw / "helper-error.txt").exists(), failure == "raw")
                self.assertEqual(events.read_text().splitlines(),
                                 ["-rf", "-f"] if failure is None else ["public", "-rf", "-f"])
                self.assertEqual(public_sentinel.exists(), failure == "public")
                self.assertEqual(ciphertext.read_bytes(), b"synthetic ciphertext")

    def test_seal_publishes_summary_then_removes_plaintext_only_after_encryption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            raw.mkdir()
            (raw / "private.txt").write_text("PRIVATE evidence")
            trial.write_json(raw / "state.json", {"source_sha": "9add3445d449083319a0d1cb334d13729bccbb85"})
            archive, public = root / "evidence.tar.gz", root / "public"
            ciphertext, summary = public / "evidence.tar.gz.age", public / "summary.json"
            events = []
            summarize, write_json = trial.public_summary, trial.write_json

            def build_summary(state):
                self.assertFalse(archive.exists())
                events.append("summary built")
                return summarize(state)

            def encrypt(command, cwd, prefix, timeout):
                self.assertEqual(events, ["summary built"])
                self.assertEqual(command, ["age", "-r", trial.RECIPIENT, "-o", ciphertext, archive])
                self.assertEqual((cwd, prefix, timeout), (root, root / "encryption", 120))
                self.assertFalse(summary.exists())
                with tarfile.open(archive, "r:gz") as bundle:
                    self.assertEqual(bundle.extractfile("raw/private.txt").read(), b"PRIVATE evidence")
                self.assertTrue((raw / "private.txt").exists())
                ciphertext.write_bytes(b"synthetic ciphertext")
                events.append("encrypted")
                return 0

            def publish(path, value):
                self.assertEqual(path, summary)
                self.assertEqual(events, ["summary built", "encrypted"])
                self.assertEqual(ciphertext.read_bytes(), b"synthetic ciphertext")
                self.assertTrue(archive.exists())
                self.assertTrue(raw.exists())
                events.append("summary published")
                write_json(path, value)

            with mock.patch.object(trial, "public_summary", side_effect=build_summary), \
                    mock.patch.object(trial, "capture", side_effect=encrypt), \
                    mock.patch.object(trial, "write_json", side_effect=publish):
                trial.seal(SimpleNamespace(root=root), raw)
            self.assertEqual(events, ["summary built", "encrypted", "summary published"])
            self.assertEqual(ciphertext.read_bytes(), b"synthetic ciphertext")
            value = json.loads(summary.read_text())
            self.assertEqual(value["source_sha"], "9add3445d449083319a0d1cb334d13729bccbb85")
            self.assertEqual(value["processing_status"], "trial_incomplete")
            self.assertNotIn("PRIVATE", summary.read_text())
            self.assertFalse(archive.exists())
            self.assertFalse(raw.exists())
            self.assertEqual(set(public.iterdir()), {summary, ciphertext})

    def test_seal_failure_never_publishes_or_deletes_plaintext(self):
        # capture() reports its timeout as 124; partial output must also be discarded.
        for label, code, output in (("nonzero", 1, b"partial"), ("empty", 0, b""),
                                    ("timeout", 124, b"partial"), ("missing", 0, None)):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                raw = root / "raw"
                raw.mkdir()
                (raw / "private.txt").write_text("PRIVATE evidence")
                archive, public = root / "evidence.tar.gz", root / "public"
                ciphertext = public / "evidence.tar.gz.age"

                def encrypt(command, cwd, prefix, timeout):
                    self.assertTrue(archive.exists())
                    self.assertTrue((raw / "private.txt").exists())
                    self.assertFalse((public / "summary.json").exists())
                    if output is not None:
                        ciphertext.write_bytes(output)
                    return code

                with mock.patch.object(trial, "capture", side_effect=encrypt):
                    with self.assertRaisesRegex(ValueError, "Encryption failed"):
                        trial.seal(SimpleNamespace(root=root, sha="9add3445d449083319a0d1cb334d13729bccbb85"), raw)
                self.assertEqual(list(public.iterdir()), [])
                self.assertTrue(archive.exists())
                self.assertEqual((raw / "private.txt").read_text(), "PRIVATE evidence")
                with tarfile.open(archive, "r:gz") as bundle:
                    self.assertEqual(bundle.extractfile("raw/private.txt").read(), b"PRIVATE evidence")


if __name__ == "__main__":
    unittest.main()

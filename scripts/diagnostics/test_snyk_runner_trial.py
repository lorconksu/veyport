"""Acceptance and privacy checks for the throwaway runner diagnostic."""
import copy
import hashlib
import importlib.util
import json
import os
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


class AcceptanceTests(unittest.TestCase):
    def test_prepare_cli_gates_on_prerequisites_and_retains_state(self):
        for failure in (None, "dependency", "access", "version", "version-exit", "manifest"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, control, raw = root / "source", root / "control", root / "raw"
                names = (*trial.PROJECTS, *(p.replace("go.mod", "go.sum") for p in trial.PROJECTS if p.endswith("go.mod")),
                         "web/package-lock.json")
                for name in names:
                    path = source / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("fixture\n")
                lock = control / "scripts/diagnostics/snyk_runner_trial_requirements.lock"
                lock.parent.mkdir(parents=True)
                lock.write_text("synthetic lock provenance\n")
                sha, control_sha = "9add3445d449083319a0d1cb334d13729bccbb85", "a" * 40
                versions = {"snyk": "1.1308.3", "go": "go version go1.26.11 linux/amd64", "node": "v25.2.0",
                            "npm": "11.6.2", "python": "Python 3.12.13", "age": "v1.2.1"}

                def external(command, cwd, prefix, timeout):
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
                        "--root", str(root), "--scanner", str(root / "scanner"), "--sha", sha, "--control-sha", control_sha]
                saved_umask = os.umask(0o077)
                try:
                    with mock.patch.object(sys, "argv", argv), \
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
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, control, raw = root / "source", root / "control", root / "raw"
            raw.mkdir()
            names = (*trial.PROJECTS, *(p.replace("go.mod", "go.sum") for p in trial.PROJECTS if p.endswith("go.mod")),
                     "web/package-lock.json")
            for name in names:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
            lock = control / "scripts/diagnostics/snyk_runner_trial_requirements.lock"
            lock.parent.mkdir(parents=True)
            lock.write_text("synthetic lock provenance\n")
            original = (source / trial.PROJECTS[-1]).read_bytes()
            args = SimpleNamespace(source=source, control=control, root=root, scanner=root / "scanner",
                                   sha="9add3445d449083319a0d1cb334d13729bccbb85", control_sha="a" * 40)
            versions = {"snyk": "1.1308.3", "go": "go version go1.26.11 linux/amd64", "node": "v25.2.0",
                        "npm": "11.6.2", "python": "Python 3.12.13", "age": "v1.2.1"}

            def external(command, cwd, prefix, timeout):
                if "pip" in command:
                    self.assertIn("--require-hashes", command)
                    self.assertIn("--only-binary=:all:", command)
                    requirements = [Path(command[index + 1]) for index, item in enumerate(command) if item == "-r"]
                    self.assertEqual(requirements, [lock, source / trial.PROJECTS[-1]])
                if prefix.name.startswith("version-"):
                    prefix.with_suffix(".stdout").write_text(versions[prefix.name.removeprefix("version-")])
                return 0

            with mock.patch.object(trial, "revision", side_effect=[args.sha, args.control_sha]), \
                    mock.patch.object(trial, "capture", side_effect=external):
                trial.prepare(args, raw)
            state = json.loads((raw / "state.json").read_text())
            self.assertTrue(state["preparation_complete"])
            self.assertEqual(state["python_lock"], {"path": "scripts/diagnostics/snyk_runner_trial_requirements.lock",
                                                   "sha256": hashlib.sha256(lock.read_bytes()).hexdigest()})
            self.assertEqual((source / trial.PROJECTS[-1]).read_bytes(), original)

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


class ExecutionTests(unittest.TestCase):
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
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            raw = root / "raw"
            source.mkdir()
            raw.mkdir()
            for name in trial.PROJECTS:
                manifest = source / name
                manifest.parent.mkdir(parents=True, exist_ok=True)
                manifest.write_text("fixture")
            scanner = root / "scanner"
            scanner.write_text('''#!/usr/bin/env python3
import json, pathlib, sys
output = pathlib.Path(next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--json-file-output=")))
print("PRIVATE_TOKEN_RAW_STDOUT")
print("PRIVATE_TOKEN_RAW_STDERR", file=sys.stderr)
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
            trial.write_json(raw / "state.json", {"source_sha": sha, "control_sha": control_sha,
                                                   "preparation_complete": True, "manifest_hashes": {}})
            args = SimpleNamespace(root=root, source=source, control=root / "control", scanner=scanner,
                                   sha=sha, control_sha=control_sha)
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

    def test_python_resolver_has_separate_identity_and_arguments_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o711)
            probe = root / "probe"
            probe.mkdir(mode=0o777)
            probe.chmod(0o1777)
            subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(root / "venv")], check=True)
            site = next((root / "venv/lib").glob("python*/site-packages"))
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
            (source / project).write_text("fixture")
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
                rows = trial.scan_projects(source, scanner, raw, root / "venv/bin/python", timeout=5)
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

    def test_scan_deadline_terminates_late_cross_uid_resolver_and_descendant(self):
        self.assertNotEqual(os.geteuid(), 0, "Exercise the runner user's signal permissions")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o711)
            raw, probe = root / "raw", root / "probe"
            raw.mkdir(mode=0o700)
            # Only the runner-owned fake scanner writes markers, via the resolver's stdout.
            probe.mkdir(mode=0o700)
            source = root / "source"
            project = "infra/audit-lab/storage/requirements.txt"
            (source / project).parent.mkdir(parents=True)
            (source / project).write_text("fixture")
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
child = subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time; time.sleep(20)"], stdout=subprocess.DEVNULL)
print(json.dumps({"uid": os.geteuid(), "mode": sys.argv[2], "pids": [os.getpid(), child.pid], "marker_writes_denied": denied}), flush=True)
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
                    rows = trial.scan_projects(source, scanner, raw, Path(sys.executable), timeout=6)
                markers = [json.loads(path.read_text()) for path in probe.iterdir()]
                self.assertEqual(len(markers), 2, "Both attempts must really start the resolver")
                self.assertEqual(sorted(marker["mode"] for marker in markers), ["exit", "sleep"])
                self.assertTrue(all(marker["uid"] == 65534 for marker in markers))
                self.assertTrue(all(marker["marker_writes_denied"] == 2 for marker in markers))
                self.assertFalse((probe / "planted.json").exists())
                self.assertFalse((probe / "malformed.json").exists())
                self.assertEqual(rows[0]["status"], "scan_incomplete")
                pids = [pid for marker in markers for pid in marker["pids"]]
                limit = time.monotonic() + 0.5
                while any(alive(pid) for pid in pids) and time.monotonic() < limit:
                    time.sleep(0.01)
                self.assertFalse([pid for pid in pids if alive(pid)], "Resolver or descendant survived the scan deadline")
                failed = False
            finally:
                if failed:
                    # No signals based on marker content: even broken cleanup leaves only finite fixtures.
                    time.sleep(20.5)


class SealingTests(unittest.TestCase):
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

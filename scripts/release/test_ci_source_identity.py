"""Verify that coverage, tests and scanners use the same reviewed source tree."""
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"
REVISION = "${{ github.event.pull_request.head.sha || github.sha }}"
SOURCE_JOBS = {
    "unit", "server-tests", "test", "integration", "smoke", "e2e",
    "sonarcloud", "sast", "secret-scan", "vulnerability-scan",
}


def source_jobs():
    text = WORKFLOW.read_text().split("\njobs:\n", 1)[1]
    starts = list(re.finditer(r"(?m)^  ([\w-]+):\n", text))
    return {match[1]: text[match.start():starts[index + 1].start() if index + 1 < len(starts) else len(text)]
            for index, match in enumerate(starts)}


def guard(block):
    matches = re.findall(
        r"      - name: Verify checked-out source revision\n"
        r"        shell: bash\n        env:\n          EXPECTED_SOURCE_SHA: ([^\n]+)\n"
        r"        run: \|\n((?:          [^\n]*\n)+)", block)
    if len(matches) != 1 or matches[0][0] != REVISION:
        raise AssertionError("Each source job must guard the same reviewed revision")
    return "".join(line[10:] + "\n" for line in matches[0][1].splitlines())


def named_step(block, name):
    return next(step for step in re.split(r"(?m)(?=^      - )", block)
                if step.startswith("      - name: " + name + "\n"))


def step_command(step):
    command = re.search(r"(?m)^        run: (.+)$", step)[1]
    if command == "|":
        return "\n".join(line[10:] for line in step.split("        run: |\n", 1)[1].splitlines())
    return command


class CISourceIdentity(unittest.TestCase):
    def test_aggregate_prepares_evidence_before_requiring_successful_dependencies(self):
        block = source_jobs()["test"]
        self.assertIn("    needs: [unit, server-tests]\n    if: always()\n", block)
        gate = named_step(block, "Require all complete test jobs")
        self.assertNotIn("        if:", gate)
        self.assertNotIn("continue-on-error", block)
        self.assertLess(block.index("uses: actions/checkout@"), block.index("name: Verify checked-out source revision"))
        self.assertLess(block.index("name: Verify checked-out source revision"), block.index(gate))
        self.assertLess(block.index(gate), block.index("uses: actions/setup-go@"))
        for name in ("Encrypt available private job evidence", "Transfer only encrypted job evidence"):
            self.assertIn("        if: always()\n", named_step(block, name))

    def test_aggregate_failed_dependencies_are_captured_and_encrypted(self):
        block = source_jobs()["test"]
        gate = step_command(named_step(block, "Require all complete test jobs"))
        finalize = step_command(named_step(block, "Encrypt available private job evidence"))
        self.assertIn("python3 scripts/release/capture_step.py --name test-requirements -- ", gate)
        self.assertIn('UNIT_RESULT: ${{ needs.unit.result }}', block)
        self.assertIn('SERVER_RESULT: ${{ needs.server-tests.result }}', block)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            for name in ("scripts/release/capture_step.py", "scripts/release/ci_evidence.py",
                         "scripts/release/risk_acceptance.py", "infra/evidence-collector/evidence.py"):
                target = source / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(WORKFLOW.parents[2] / name, target)
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GITHUB_REPOSITORY="lorconksu/veyport", GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1",
                       GITHUB_WORKFLOW_REF="lorconksu/veyport/.github/workflows/ci.yml@refs/pull/115/merge",
                       EVIDENCE_JOB="test")
            for args in (("init", "-b", "main"), ("add", "."),
                         ("-c", "user.name=CI evidence test", "-c", "user.email=ci@example.invalid", "commit", "-m", "fixture")):
                subprocess.run(["git", *args], cwd=source, env=env, check=True, capture_output=True)
            env["EXPECTED_SOURCE_SHA"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, env=env, text=True).strip()
            subprocess.run(["bash", "-e", "-c", guard(block)], cwd=source, env=env, check=True, capture_output=True)
            for unit in ("success", "failure", "cancelled", "skipped"):
                for server in ("success", "failure", "cancelled", "skipped"):
                    with self.subTest(unit=unit, server=server):
                        runner = root / (unit + "-" + server)
                        env.update(RUNNER_TEMP=str(runner), UNIT_RESULT=unit, SERVER_RESULT=server)
                        result = subprocess.run(["bash", "-e", "-c", gate], cwd=source, env=env, capture_output=True)
                        self.assertEqual(result.returncode, 0 if unit == server == "success" else 1)
                        captured = json.loads((runner / "ssdf-results/test-requirements.result.json").read_text())
                        self.assertEqual(captured["exit_code"], result.returncode)
            # Replay the always() finalizer after a real dependency-gate failure;
            # ordinary coverage/download steps remain skipped by default success().
            identity = root / "identity"
            subprocess.run(["age-keygen", "-o", str(identity)], check=True, capture_output=True)
            env.update(AGE_RECIPIENT=subprocess.check_output(["age-keygen", "-y", str(identity)], text=True).strip(),
                       RUNNER_TEMP=str(root / "failure-success"), JOB_STATUS="failure")
            subprocess.run(["bash", "-e", "-c", finalize], cwd=source, env=env, check=True, capture_output=True)
            chunks = sorted((Path(env["RUNNER_TEMP"]) / "ssdf-job-test").glob("chunk-*.age"))
            self.assertEqual(len(chunks), 1)
            payload = subprocess.check_output(["age", "-d", "-i", str(identity), str(chunks[0])])
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(manifest["revision"], env["EXPECTED_SOURCE_SHA"])
                self.assertEqual(manifest["details"]["status"], "failure")
                self.assertFalse(manifest["complete"])
                files = {item["name"]: item for item in manifest["details"]["original_files"]}
                captured = files["runner-results/test-requirements.result.json"]
                record = json.loads(b"".join(archive.read("blobs/" + part["sha256"]) for part in captured["parts"]))
                self.assertEqual(record["exit_code"], 1)
                self.assertIn("coverage-*.out", manifest["details"]["missing"])

    def test_every_source_job_pins_and_guards_before_consuming_source(self):
        jobs = source_jobs()
        self.assertEqual(set(jobs), SOURCE_JOBS | {"auto-release"})
        for name in SOURCE_JOBS:
            with self.subTest(job=name):
                block = jobs[name]
                self.assertEqual(block.count("uses: actions/checkout@"), 1)
                checkout = re.search(r"      - uses: actions/checkout@[^\n]+\n"
                                     r"        with:\n          ref: ([^\n]+)\n"
                                     r"(?:          [^\n]+\n)*", block)
                self.assertIsNotNone(checkout)
                self.assertEqual(checkout[1], REVISION)
                self.assertTrue(block[checkout.end():].startswith("      - name: Verify checked-out source revision\n"))
                guard(block)
        self.assertIn("-Dsonar.scm.revision=" + REVISION, jobs["sonarcloud"])

    def test_release_and_approval_helpers_share_captured_full_discovery(self):
        unit = source_jobs()["unit"]
        self.assertEqual(re.findall(r"(?m)^      - name: .*helper tests$", unit),
                         ["      - name: Release and approval helper tests"])
        self.assertEqual(unit.count('python3 -m unittest discover -s scripts/release -p "test_*.py"'), 1)
        self.assertIn(
            '      - name: Release and approval helper tests\n'
            '        run: python3 scripts/release/capture_step.py --name release-helpers -- '
            'python3 -m unittest discover -s scripts/release -p "test_*.py"\n', unit)

    def test_automatic_publication_is_held_for_every_trigger(self):
        # Pin the leading literal false: the conjunction is false for every
        # event/ref, including push, PR, workflow_call and workflow_dispatch.
        # Preserve the prerequisites and original tag/dispatch flow for the
        # separately reviewed restoration; all source jobs still run above.
        jobs = source_jobs()
        self.assertIn("    needs: [integration, smoke, e2e, sonarcloud, sast, secret-scan, vulnerability-scan]\n",
                      jobs["auto-release"])
        self.assertNotIn("EXPECTED_SOURCE_SHA", jobs["auto-release"])
        self.assertNotIn("          ref:", jobs["auto-release"])
        self.assertEqual(re.findall(r"(?m)^    if: (.+)$", jobs["auto-release"]),
                         ["false && github.event_name == 'push' && github.ref == 'refs/heads/main'"])
        self.assertIn("docs/security/approval-bootstrap.md", jobs["auto-release"])

    def test_actual_merge_tree_is_refused_and_exact_pr_or_push_head_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

            def git(*args):
                return subprocess.check_output(["git", *args], cwd=repo, env=env, text=True, stderr=subprocess.DEVNULL).strip()

            git("init", "-b", "main")
            git("config", "user.name", "CI source guard test")
            git("config", "user.email", "ci-guard@example.invalid")
            (repo / "base").write_text("initial base")
            git("add", ".")
            git("commit", "-m", "base")
            git("checkout", "-b", "feature")
            (repo / "feature").write_text("reviewed head")
            git("add", ".")
            git("commit", "-m", "feature")
            head = git("rev-parse", "HEAD")
            git("checkout", "main")
            (repo / "base").write_text("changed base")
            git("add", ".")
            git("commit", "-m", "base moved")
            git("merge", "--no-ff", "feature", "-m", "synthetic PR merge")
            merge = git("rev-parse", "HEAD")
            self.assertNotEqual(merge, head)
            for name in SOURCE_JOBS:
                with self.subTest(job=name, event="PR merge checkout"):
                    result = subprocess.run(["bash", "-c", guard(source_jobs()[name])], cwd=repo,
                                            env=dict(env, EXPECTED_SOURCE_SHA=head), capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
                with self.subTest(job=name, event="non-PR push SHA fallback"):
                    result = subprocess.run(["bash", "-c", guard(source_jobs()[name])], cwd=repo,
                                            env=dict(env, EXPECTED_SOURCE_SHA=merge), capture_output=True)
                    self.assertEqual(result.returncode, 0)
            git("checkout", "--detach", head)
            for name in SOURCE_JOBS:
                with self.subTest(job=name, event="exact PR head"):
                    result = subprocess.run(["bash", "-c", guard(source_jobs()[name])], cwd=repo,
                                            env=dict(env, EXPECTED_SOURCE_SHA=head), capture_output=True)
                    self.assertEqual(result.returncode, 0)

    def test_missing_or_malformed_expected_revision_fails_without_evaluation(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            sentinel = folder / "unexpected-evaluation"
            for value in (None, "", "a" * 39, "A" * 40, "$(touch unexpected-evaluation)"):
                env = dict(os.environ)
                env.pop("EXPECTED_SOURCE_SHA", None)
                if value is not None:
                    env["EXPECTED_SOURCE_SHA"] = value
                with self.subTest(value=value):
                    result = subprocess.run(["bash", "-c", guard(source_jobs()["sonarcloud"])],
                                            cwd=folder, env=env, capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(sentinel.exists())


if __name__ == "__main__":
    unittest.main()

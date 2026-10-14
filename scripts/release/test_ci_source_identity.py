"""Verify that coverage, tests and scanners use the same reviewed source tree."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


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


class CISourceIdentity(unittest.TestCase):
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
        # The push-only automatic release retains its existing checkout and tag flow.
        self.assertNotIn("EXPECTED_SOURCE_SHA", jobs["auto-release"])
        self.assertNotIn("          ref:", jobs["auto-release"])
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", jobs["auto-release"])

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

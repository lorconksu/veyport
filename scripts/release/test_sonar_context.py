import json
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse

import sonar_context as sonar


class SonarContext(unittest.TestCase):
    def setUp(self):
        self.repository = "lorconksu/veyport"
        self.revision = "a" * 40
        self.branch = "feat/application-access"
        self.event = {"repository": {"full_name": self.repository, "private": False}}
        self.pr = {"number": 101, "state": "open", "merged": False, "merged_at": None,
                   "head": {"sha": self.revision, "ref": self.branch, "repo": {"full_name": self.repository}},
                   "base": {"ref": "main", "repo": {"full_name": self.repository}}}
        self.sonar = {
            "components/show": {"component": {"key": sonar.PROJECT, "visibility": "public"}},
            "settings/values": {"settings": [{"key": "sonar.branch.longLivedBranches.regex", "value": "(branch|release)-.*"}]},
            "project_branches/list": {"branches": []},
            "project_analyses/search": {"analyses": [{"revision": self.revision}]},
        }

    def sonar_fetch(self, endpoint, params):
        return copy.deepcopy(self.sonar[endpoint])

    def resolve(self, required=True, fetch=None, ref=None, event_name="workflow_dispatch", main=None, **kwargs):
        return sonar.resolve(event_name, self.event, self.repository, ref or "refs/heads/" + self.branch,
                             self.revision, required, fetch=fetch, belongs_to_main=main, sonar_fetch=self.sonar_fetch, **kwargs)

    def test_manual_prototype_and_nonprototype_bind_actual_open_exact_head_pr(self):
        for required in (True, False):
            calls = []
            def fetch(path):
                calls.append(path)
                return [self.pr] if "?" in path else self.pr
            args = self.resolve(required=required, fetch=fetch)
            self.assertEqual(args, "-Dsonar.pullrequest.key=101 -Dsonar.pullrequest.branch=feat/application-access -Dsonar.pullrequest.base=main")
            self.assertNotIn("sonar.branch.name", args)
            self.assertIn("head=lorconksu%3Afeat%2Fapplication-access", calls[0])
            self.assertEqual(calls[1], "repos/lorconksu/veyport/pulls/101")
        self.assertIn("pullrequest.key=101", self.resolve(fetch=lambda path: [self.pr] if "?" in path else self.pr,
                      ref="refs/tags/prototype-application-access.1", event_name="workflow_call"))

    def test_absent_ambiguous_stale_closed_merged_wrong_repo_or_base_refuse_without_main_fallback(self):
        for rows in ([], [self.pr, {**self.pr, "number": 102}],
                     [{**self.pr, "head": {**self.pr["head"], "sha": "b" * 40}}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.resolve(required=False, fetch=lambda path: rows)
        cases = [
            {**self.pr, "state": "closed"}, {**self.pr, "merged": True},
            {**self.pr, "head": {**self.pr["head"], "sha": "b" * 40}},
            {**self.pr, "head": {**self.pr["head"], "repo": {"full_name": "unrelated/fork"}}},
            {**self.pr, "base": {**self.pr["base"], "ref": "other-base"}},
            {**self.pr, "number": 102},
        ]
        for current in cases:
            with self.subTest(current=current), self.assertRaises(ValueError):
                self.resolve(fetch=lambda path: [self.pr] if "?" in path else current)
        with self.assertRaises(OSError):
            self.resolve(fetch=lambda path: (_ for _ in ()).throw(OSError("API unavailable")))

    def test_real_pr_preserves_context_and_main_or_stable_requires_main_history(self):
        event = {**self.event, "pull_request": self.pr}
        args = sonar.resolve("pull_request", event, self.repository, "refs/pull/101/merge", self.revision, False)
        self.assertIn("pullrequest.key=101", args)
        for ref in ("refs/heads/main", "refs/tags/v2.0.52"):
            expected = "main" if ref == "refs/heads/main" else sonar.candidate_branch(self.revision)
            self.assertEqual(self.resolve(required=False, ref=ref, main=lambda ref, revision: True), "-Dsonar.branch.name=" + expected)
            with self.assertRaises(ValueError): self.resolve(required=False, ref=ref, main=lambda ref, revision: False)
            with self.assertRaises(ValueError): self.resolve(required=True, ref=ref, main=lambda ref, revision: True)
        with self.assertRaises(ValueError): self.resolve(required=False, ref="refs/tags/arbitrary")

    def test_complete_pagination_and_unsafe_branch_metadata(self):
        unrelated = [{**self.pr, "number": number, "head": {**self.pr["head"], "sha": "b" * 40}} for number in range(200, 300)]
        calls = []
        def fetch(path):
            calls.append(path)
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            if query.get("page") == ["1"]: return unrelated
            if query.get("page") == ["2"]: return [self.pr]
            return self.pr
        self.assertIn("pullrequest.key=101", self.resolve(fetch=fetch))
        self.assertEqual(len(calls), 3)
        for unsafe in ("feature\nargs=-Dsonar.branch.name=main", "feature -Dsonar.sources=other", "$(touch marker)"):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                self.resolve(ref="refs/heads/" + unsafe, fetch=lambda path: [self.pr])

    def test_real_git_main_history_and_source_output_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, env=env, text=True, stderr=subprocess.DEVNULL).strip()
            git("init", "-b", "main")
            git("config", "user.name", "Sonar context test")
            git("config", "user.email", "sonar-test@example.invalid")
            (root / "base").write_text("main source")
            git("add", ".")
            git("commit", "-m", "main")
            main_revision = git("rev-parse", "HEAD")
            git("tag", "v2.0.52")
            (root / "base").write_text("advanced main source")
            git("add", ".")
            git("commit", "-m", "main advanced after release")
            advanced_main_revision = git("rev-parse", "HEAD")
            self.assertNotEqual(main_revision, advanced_main_revision)
            git("update-ref", "refs/remotes/origin/main", advanced_main_revision)
            git("checkout", "-b", "feature")
            (root / "feature").write_text("feature source")
            git("add", ".")
            git("commit", "-m", "feature")
            feature_revision = git("rev-parse", "HEAD")
            # Use subprocess cwd selection without changing the process working directory.
            original_run = subprocess.run
            def run(args, **kwargs): return original_run(args, cwd=root, env=env, **kwargs)
            def output(args, **kwargs): return original_run(args, cwd=root, env=env, check=True, capture_output=True, text=True).stdout
            with patch.object(sonar.subprocess, "run", side_effect=run), patch.object(sonar.subprocess, "check_output", side_effect=output):
                self.assertTrue(sonar.main_source("refs/heads/main", main_revision))
                self.assertTrue(sonar.main_source("refs/tags/v2.0.52", main_revision))
                release_args = sonar.resolve("workflow_dispatch", self.event, self.repository,
                                             "refs/tags/v2.0.52", main_revision, False, sonar_fetch=self.sonar_fetch)
                self.assertEqual(release_args, "-Dsonar.branch.name=" + sonar.candidate_branch(main_revision))
                self.assertNotEqual(release_args, "-Dsonar.branch.name=main")
                self.assertFalse(sonar.main_source("refs/heads/main", feature_revision))
                self.assertFalse(sonar.main_source("refs/tags/v2.0.52", feature_revision))
                event = root / "event.json"; event.write_text(json.dumps(self.event))
                output_file = root / "outputs"
                context = {"EXPECTED_SOURCE_SHA": feature_revision, "SONAR_PULL_REQUEST_REQUIRED": "false",
                    "GITHUB_EVENT_PATH": str(event), "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_REPOSITORY": self.repository, "GITHUB_REF": "refs/heads/main", "GITHUB_OUTPUT": str(output_file)}
                with patch.dict(os.environ, context), self.assertRaises(ValueError): sonar.main()
                self.assertFalse(output_file.exists())

    def test_workflow_requires_context_before_scanner_and_prototype_caller_requires_pr(self):
        repo = Path(__file__).resolve().parents[2]
        workflow = (repo / ".github/workflows/ci.yml").read_text()
        sonar_job = workflow.split("  sonarcloud:\n", 1)[1].split("  secret-scan:\n", 1)[0]
        self.assertLess(sonar_job.index("run: python3 scripts/release/sonar_context.py"), sonar_job.index("uses: SonarSource/sonarqube-scan-action@"))
        self.assertIn("${{ steps.sonar-context.outputs.args }}", sonar_job)
        self.assertIn("SONAR_PULL_REQUEST_REQUIRED: ${{ inputs.sonar_pull_request_required }}", sonar_job)
        self.assertIn("SONAR_FULL_BRANCH_REQUIRED: ${{ inputs.sonar_full_branch_required }}", sonar_job)
        self.assertEqual(sonar_job.count("uses: SonarSource/sonarqube-scan-action@"), 1)
        self.assertIn("-Dsonar.qualitygate.wait=${{ steps.sonar-context.outputs.quality_gate_wait }}", sonar_job)
        self.assertIn("-Dsonar.qualitygate.timeout=300", sonar_job)
        caller = (repo / ".github/workflows/staging.yml").read_text().split("  required-ci:\n", 1)[1].split("  prototype-delivery:\n", 1)[0]
        self.assertIn("sonar_pull_request_required: true", caller)
        self.assertIn("sonar_full_branch_required: true", caller)

    def test_trusted_staging_replaces_pr_context_with_revision_bound_full_branch(self):
        self.event["inputs"] = {"prototype": "true"}
        ref = "refs/heads/" + self.branch
        calls = []
        def fetch(path):
            calls.append(path)
            return [self.pr] if "?" in path else self.pr
        args = self.resolve(fetch=fetch, full_branch=True,
                            workflow_ref=self.repository + "/.github/workflows/staging.yml@" + ref)
        self.assertEqual(args, "-Dsonar.branch.name=release-ssdf-candidate-" + self.revision)
        self.assertNotIn("pullrequest", args)
        self.assertEqual(len(calls), 2)
        plan = self.resolve(fetch=fetch, full_branch=True, details=True,
                            workflow_ref=self.repository + "/.github/workflows/staging.yml@" + ref)
        self.assertEqual(plan["args"], args)
        self.assertIn("sonar.pullrequest.key=101", plan["gate_args"])
        self.assertEqual(plan["quality_gate_wait"], "false")
        for invalid in ({"required": False}, {"event_name": "pull_request"},
                        {"workflow_ref": self.repository + "/.github/workflows/other.yml@" + ref}):
            options = {"fetch": fetch, "full_branch": True,
                       "workflow_ref": self.repository + "/.github/workflows/staging.yml@" + ref, **invalid}
            with self.subTest(invalid=invalid), self.assertRaises(ValueError): self.resolve(**options)
        moved = {**self.pr, "head": {**self.pr["head"], "sha": "b" * 40}}
        with self.assertRaises(ValueError):
            self.resolve(fetch=lambda path: [self.pr] if "?" in path else moved, full_branch=True,
                         workflow_ref=self.repository + "/.github/workflows/staging.yml@" + ref)

    def test_full_context_refuses_private_pattern_mismatch_short_or_foreign_revision_branch(self):
        branch = {"name": sonar.candidate_branch(self.revision), "type": "LONG", "isMain": False}
        self.sonar["project_branches/list"]["branches"] = [branch]
        self.assertIn(branch["name"], sonar.full_branch_context(self.revision, self.sonar_fetch))
        for change in ({"type": "SHORT"}, {"isMain": True}):
            self.sonar["project_branches/list"]["branches"] = [{**branch, **change}]
            with self.subTest(change=change), self.assertRaises(ValueError):
                sonar.full_branch_context(self.revision, self.sonar_fetch)
        self.sonar["project_branches/list"]["branches"] = [branch]
        self.sonar["project_analyses/search"]["analyses"] = [{"revision": "b" * 40}]
        with self.assertRaises(ValueError): sonar.full_branch_context(self.revision, self.sonar_fetch)
        self.sonar["project_branches/list"]["branches"] = []
        self.sonar["settings/values"]["settings"][0]["value"] = "main|stable-.*"
        with self.assertRaises(ValueError): sonar.full_branch_context(self.revision, self.sonar_fetch)
        self.sonar["settings/values"]["settings"][0]["value"] = "(branch|release)-.*"
        self.sonar["components/show"]["component"]["visibility"] = "private"
        with self.assertRaises(ValueError): sonar.full_branch_context(self.revision, self.sonar_fetch)

    def test_runtime_gate_context_requires_exact_trusted_open_pr_and_caller(self):
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps({**self.event, "inputs": {"prototype": "true"}}))
            ref = "refs/heads/" + self.branch
            environment = {"GITHUB_EVENT_PATH": str(event_path), "GITHUB_REPOSITORY": self.repository,
                           "GITHUB_SHA": self.revision, "GITHUB_REF": ref, "GITHUB_EVENT_NAME": "workflow_dispatch",
                           "GITHUB_WORKFLOW_REF": self.repository + "/.github/workflows/staging.yml@" + ref}
            fetch = lambda path: [self.pr] if "?" in path else self.pr
            with patch.dict(os.environ, environment):
                self.assertIn("sonar.pullrequest.key=101", sonar.runtime_gate_context(self.revision, fetch))
                for changed in ({"GITHUB_SHA": "b" * 40}, {"GITHUB_EVENT_NAME": "pull_request"},
                                {"GITHUB_WORKFLOW_REF": self.repository + "/.github/workflows/other.yml@" + ref}):
                    with self.subTest(changed=changed), patch.dict(os.environ, changed), self.assertRaises(ValueError):
                        sonar.runtime_gate_context(self.revision, fetch)
                moved = {**self.pr, "head": {**self.pr["head"], "sha": "b" * 40}}
                with self.assertRaises(ValueError):
                    sonar.runtime_gate_context(self.revision, lambda path: [self.pr] if "?" in path else moved)

    def test_stable_inventory_plan_and_runtime_require_exact_main_ancestry(self):
        plan = self.resolve(required=False, ref="refs/tags/v2.0.52", main=lambda *_: True, details=True)
        self.assertEqual(plan["gate_args"], "-Dsonar.branch.name=main")
        self.assertEqual(plan["quality_gate_wait"], "false")
        event = {**self.event, "pull_request": self.pr}
        normal = sonar.resolve("pull_request", event, self.repository, "refs/pull/101/merge", self.revision, False, details=True)
        self.assertEqual(normal["gate_args"], normal["args"])
        self.assertEqual(normal["quality_gate_wait"], "true")
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(self.event))
            ref = "refs/tags/v2.0.52"
            environment = {"GITHUB_EVENT_PATH": str(event_path), "GITHUB_REPOSITORY": self.repository,
                           "GITHUB_SHA": self.revision, "GITHUB_REF": ref, "GITHUB_EVENT_NAME": "push",
                           "GITHUB_WORKFLOW_REF": self.repository + "/.github/workflows/release.yml@" + ref}
            with patch.dict(os.environ, environment):
                expected = {"status": "ahead", "merge_base_commit": {"sha": self.revision}}
                self.assertEqual(sonar.runtime_gate_context(self.revision, lambda _: expected), "-Dsonar.branch.name=main")
                for comparison in ({**expected, "status": "diverged"}, {**expected, "merge_base_commit": {"sha": "b" * 40}}):
                    with self.subTest(comparison=comparison), self.assertRaises(ValueError):
                        sonar.runtime_gate_context(self.revision, lambda _: comparison)


if __name__ == "__main__":
    unittest.main()

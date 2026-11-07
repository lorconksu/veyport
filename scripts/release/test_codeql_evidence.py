import copy
import datetime as dt
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import codeql_evidence as evidence
import source_sast as sast
from risk_acceptance import canonical, strict_json


def report(language, revision, local=False):
    pack = "javascript" if language == "javascript-typescript" else language
    run = {"tool": {"driver": {"name": "CodeQL"}, "extensions": [{"name": f"codeql/{pack}-queries", "rules": [{"id": f"{pack}/auth", "properties": {"tags": ["external/cwe/cwe-287"], "security-severity": "3"}}]}]},
           "results": [], "properties": {"codeqlConfigSummary": {}},
           "automationDetails": {"id": "/language:" + language + "/"}}
    if local:
        run["invocations"] = [{"executionSuccessful": True}]
        run["properties"]["codeqlConfigSummary"] = {"disableDefaultQueries": False, "queries": [{"type": "builtinSuite", "uses": "security-extended"}]}
    else:
        run["versionControlProvenance"] = [{"repositoryUri": "https://github.com/" + sast.REPOSITORY, "revisionId": revision, "branch": "refs/heads/main"}]
    return {"version": "2.1.0", "runs": [run]}


class DefaultAPI:
    def __init__(self, revision):
        self.configuration = {"state": "configured", "languages": sorted(evidence.LANGUAGES), "query_suite": "default", "updated_at": "2026-01-01T00:00:00Z"}
        self.analyses = [{"id": i, "category": "/language:" + language, "ref": "refs/heads/main", "analysis_key": sast.CODEQL_DEFAULT_KEY, "commit_sha": revision, "created_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "tool": {"name": "CodeQL"}, "results_count": 0} for i, language in enumerate(sorted(evidence.LANGUAGES))]
        self.reports = {a["id"]: report(a["category"].split(":", 1)[1], revision) for a in self.analyses}

    def get(self, path):
        self.assert_path(path)
        return copy.deepcopy(self.configuration)

    def assert_path(self, path):
        if path != "code-scanning/default-setup":
            raise AssertionError(path)

    def pages(self, path):
        return copy.deepcopy(self.analyses) if path.startswith("code-scanning/analyses?") else []

    def sarif(self, identifier):
        return copy.deepcopy(self.reports[identifier])


class CodeQLDefaultTests(unittest.TestCase):
    def test_five_full_default_main_languages_without_local_invocations_are_reusable(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(sast.export_codeql(DefaultAPI("a" * 40), directory, "a" * 40, "1.0"), [])

    def test_foreign_pr_or_sha_unknown_producer_warning_count_stale_and_reduced_fail(self):
        mutations = [lambda a: a.analyses[0].update(ref="refs/pull/115/merge"),
                     lambda a: a.analyses[0].update(commit_sha="b" * 40),
                     lambda a: a.analyses[0].update(analysis_key="custom/workflow:upload"),
                     lambda a: a.analyses[0].update(warning="partial extraction"),
                     lambda a: a.analyses[0].update(error="timeout"),
                     lambda a: a.analyses[0].update(results_count=1),
                     lambda a: a.analyses[0].update(created_at="2026-01-01T00:00:00Z"),
                     lambda a: a.reports[0]["runs"][0]["properties"].update(incrementalMode="diff-informed"),
                     lambda a: a.reports[0]["runs"][0]["properties"].update(resultsTruncated=True),
                     lambda a: a.reports[0]["runs"][0]["tool"]["extensions"].append({"name": "codeql-action/pr-diff-range"}),
                     lambda a: a.reports[0]["runs"][0]["automationDetails"].update(id="/language:foreign/"),
                     lambda a: a.reports[0]["runs"][0]["versionControlProvenance"][0].update(branch="refs/pull/115/head"),
                     lambda a: a.configuration.update(state="not-configured"),
                     lambda a: a.configuration.update(languages=["go"])]
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as directory:
                api = DefaultAPI("a" * 40)
                mutate(api)
                with self.assertRaises(ValueError):
                    sast.export_codeql(api, directory, "a" * 40, "1.0")

    def test_default_configuration_changes_during_export_are_rejected(self):
        api = DefaultAPI("a" * 40)
        with tempfile.TemporaryDirectory() as directory, patch.object(api, "get", side_effect=[api.configuration, {**api.configuration, "query_suite": "extended"}]):
            with self.assertRaises(ValueError):
                sast.export_codeql(api, directory, "a" * 40, "1.0")


class CodeQLLocalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-q", "--allow-empty", "-m", "fixture"], cwd=self.root, check=True)
        self.revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.root, text=True).strip()
        self.environment = {"GITHUB_REPOSITORY": sast.REPOSITORY, "GITHUB_SHA": self.revision, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_REF": "refs/heads/feat/ssdf-pipeline", "GITHUB_JOB": "delivery", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_OUTPUT": str(self.base / "outputs")}
        self.patch = patch.dict(os.environ, self.environment)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.manifest = self.base / "candidate.json"
        self.manifest.write_bytes(canonical({"repository": sast.REPOSITORY, "revision": self.revision, "run_id": 123, "run_attempt": 2, "workflow": ".github/workflows/staging.yml", "candidate_id": "run-123-2", "version": "1.0"}))
        self.output = self.base / "evidence"
        self.reports = self.base / "reports"
        self.config = self.base / "config"
        self.config.write_bytes(canonical({"debugMode": False, "languages": ["javascript" if n == "javascript-typescript" else n for n in evidence.LANGUAGES], "originalUserInput": evidence.CONFIG, "computedConfig": evidence.CONFIG, "overlayDatabaseMode": "none", "extraQueryExclusions": [], "trapCaches": {}, "dependencyCachingEnabled": "none", "analysisKinds": ["code-scanning"], "repositoryRoot": str(self.root), "version": "4.39.1"}))

    def prepare_local(self):
        api = DefaultAPI(self.revision)
        with patch.object(api, "get", side_effect=urllib.error.HTTPError("https://api.github.com/fixed", 403, "forbidden", {}, io.BytesIO(b"private body"))):
            self.assertTrue(evidence.prepare(self.output, self.manifest, self.root, api, self.reports))
        self.reports.mkdir()
        for language in evidence.LANGUAGES:
            (self.reports / (language + ".sarif")).write_bytes(canonical(report(language, self.revision, local=True)))

    def finish(self):
        evidence.finish(self.output, self.manifest, self.root, self.reports, self.config)

    def consume(self):
        destination = self.base / "export"
        destination.mkdir(exist_ok=True)
        return evidence.consume(self.output, self.manifest, self.root, destination, self.revision, "1.0", "run-123-2")

    def test_forbidden_default_config_requires_full_local_then_exact_candidate_can_consume(self):
        self.prepare_local()
        receipt = evidence.read(self.output / "receipt.json")
        self.assertEqual(receipt["reuse_http_status"], 403)
        self.assertEqual(receipt["status"], "pending-local")
        self.assertNotIn("private body", (self.output / "receipt.json").read_text())
        self.assertIn("local_required=true", (self.base / "outputs").read_text())
        self.finish()
        self.assertEqual(self.consume(), [])

    def test_complete_default_evidence_skips_local_and_is_candidate_bound(self):
        self.assertFalse(evidence.prepare(self.output, self.manifest, self.root, DefaultAPI(self.revision)))
        self.assertIn("local_required=false", (self.base / "outputs").read_text())
        self.assertEqual(self.consume(), [])

    def test_partial_reuse_export_preserved_but_still_requires_full_local_scan(self):
        api = DefaultAPI(self.revision)
        api.reports[0]["runs"][0]["properties"]["incrementalMode"] = "diff-informed"
        self.assertTrue(evidence.prepare(self.output, self.manifest, self.root, api, self.reports))
        self.assertTrue((self.output / "default-incomplete/codeql-0.sarif").is_file())
        receipt = evidence.read(self.output / "receipt.json")
        self.assertEqual(receipt["status"], "pending-local")
        self.assertTrue(any(f["path"] == "default-incomplete/codeql-0.sarif" for f in receipt["files"]))
        with self.assertRaises(ValueError):
            self.consume()

    def test_missing_language_pending_receipt_cannot_pass(self):
        self.prepare_local()
        (self.reports / "go.sarif").unlink()
        with self.assertRaises(ValueError):
            self.finish()
        with self.assertRaises(ValueError):
            self.consume()

    def test_failed_warning_incremental_truncated_or_foreign_local_scans_rejected(self):
        self.prepare_local()
        path = self.reports / "go.sarif"
        original = evidence.read(path)
        mutations = [lambda r: r.update(invocations=[]),
                     lambda r: r.update(invocations=None),
                     lambda r: r["invocations"][0].update(executionSuccessful=False),
                     lambda r: r["invocations"][0].update(toolExecutionNotifications=[{"level": "warning", "message": {"text": "partial"}}]),
                     lambda r: r["properties"].update(incrementalMode="overlay"),
                     lambda r: r["properties"].update(resultsTruncated=True),
                     lambda r: r["tool"]["extensions"].append({"name": "codeql-action/pr-diff-range"}),
                     lambda r: r["properties"]["codeqlConfigSummary"].update(disableDefaultQueries=True),
                     lambda r: r.update(versionControlProvenance=[{"repositoryUri": "https://github.com/other/repo", "revisionId": self.revision}]),
                     lambda r: r["tool"]["extensions"][0].update(name="codeql/ruby-queries")]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(original)
                mutate(value["runs"][0])
                path.write_bytes(canonical(value))
                with self.assertRaises(ValueError):
                    self.finish()

    def test_debug_upload_modes_rejected_before_preparation(self):
        for key in ("RUNNER_DEBUG", "ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG",
                    "CODEQL_ACTION_DEBUG_COMBINED_SARIF", "CODEQL_ACTION_EXPECT_UPLOAD_FAILED_SARIF",
                    "CODEQL_ACTION_SKIP_SARIF_UPLOAD", "INPUT_DEBUG"):
            for value in ("1", "true"):
                with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                    with self.assertRaisesRegex(ValueError, "debug artifact"):
                        evidence.prepare(self.output, self.manifest, self.root, DefaultAPI(self.revision))
                    self.assertFalse(self.output.exists())

    def test_reduced_action_configuration_rejected(self):
        self.prepare_local()
        original = evidence.read(self.config)
        mutations = [lambda c: c.update(debugMode=True), lambda c: c.pop("debugMode"), lambda c: c["languages"].remove("go"), lambda c: c["computedConfig"].update({"paths-ignore": ["hub"]}), lambda c: c.update(overlayDatabaseMode="overlay"), lambda c: c.update(extraQueryExclusions=[{"exclude": {"tags": "security"}}]), lambda c: c.update(repositoryRoot="/other"), lambda c: c.update(trapCaches={"go": "/tmp/cache"})]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                config = copy.deepcopy(original)
                mutate(config)
                self.config.write_bytes(canonical(config))
                with self.assertRaises(ValueError):
                    self.finish()

    def test_report_altered_after_completion_rejected(self):
        self.prepare_local()
        self.finish()
        (self.output / "local/go.sarif").write_bytes(canonical(report("go", self.revision)))
        with self.assertRaises(ValueError):
            self.consume()

    def test_preexisting_or_stale_report_cannot_be_rebound_to_current_run(self):
        self.reports.mkdir()
        with self.assertRaises(ValueError):
            evidence.prepare(self.output, self.manifest, self.root, DefaultAPI(self.revision), self.reports)
        self.reports.rmdir()
        self.prepare_local()
        os.utime(self.reports / "go.sarif", (1, 1))
        with self.assertRaises(ValueError):
            self.finish()

    def test_replay_other_run_attempt_job_ref_or_manifest_rejected(self):
        self.prepare_local()
        self.finish()
        for key, value in [("GITHUB_RUN_ID", "124"), ("GITHUB_RUN_ATTEMPT", "3"), ("GITHUB_JOB", "other"), ("GITHUB_REF", "refs/heads/other")]:
            with self.subTest(key=key), patch.dict(os.environ, {key: value}):
                with self.assertRaises(ValueError):
                    self.consume()
        self.manifest.write_bytes(self.manifest.read_bytes() + b"\n")
        with self.assertRaises(ValueError):
            self.consume()

    def test_pull_request_untrusted_context_and_symlink_rejected(self):
        for environment in ({"GITHUB_EVENT_NAME": "pull_request"}, {"GITHUB_REF": "refs/pull/115/head"}, {"GITHUB_REPOSITORY": "other/repo"}):
            with self.subTest(environment=environment), patch.dict(os.environ, environment):
                with self.assertRaises(ValueError):
                    evidence.prepare(self.output, self.manifest, self.root, DefaultAPI(self.revision))
        self.prepare_local()
        path = self.reports / "go.sarif"
        path.unlink()
        path.symlink_to(self.reports / "ruby.sarif")
        with self.assertRaises(ValueError):
            self.finish()

    def test_absent_first_seen_and_suppressed_findings_remain_for_policy_triage(self):
        self.prepare_local()
        path = self.reports / "go.sarif"
        value = evidence.read(path)
        value["runs"][0]["results"] = [{"ruleId": "go/auth", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "hub/auth.go"}}}], "suppressions": [{"kind": "inSource"}]}]
        path.write_bytes(canonical(value))
        self.finish()
        findings = self.consume()
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0]["first_seen"])
        self.assertTrue(findings[0]["suppressed"])
        self.assertEqual(findings[0]["classification"], "authentication")


if __name__ == "__main__":
    unittest.main()

import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error

import sonar_job_evidence as capture

REVISION = "a" * 40
CONTEXT = "-Dsonar.pullrequest.key=115 -Dsonar.pullrequest.branch=feature -Dsonar.pullrequest.base=main"


class Clock:
    def __init__(self):
        self.instant = 0
        self.pauses = []

    def now(self):
        return self.instant

    def pause(self, duration):
        self.pauses.append(duration)
        self.instant += duration


class Provider:
    def __init__(self):
        self.calls = []
        self.hook = None
        self.task = {"task": {"id": "task-1", "componentKey": capture.PROJECT,
                              "status": "SUCCESS", "analysisId": "analysis-1", "pullRequest": "115"}}
        self.pr = {"key": "115", "commit": {"sha": REVISION}, "analysisDate": "2026-10-31T00:00:00Z"}
        self.gate = "OK"
        self.component = {"key": capture.PROJECT, "visibility": "public"}

    def get(self, endpoint, params):
        self.calls.append((endpoint, params))
        if self.hook:
            replacement = self.hook(endpoint, params)
            if replacement is not None:
                return replacement
        if endpoint == "ce/task":
            return copy.deepcopy(self.task)
        if endpoint == "components/show":
            return {"component": copy.deepcopy(self.component)}
        if endpoint == "qualitygates/project_status":
            return {"projectStatus": {"status": self.gate}}
        if endpoint == "project_pull_requests/list":
            return {"pullRequests": [copy.deepcopy(self.pr)]}
        if endpoint == "project_analyses/search":
            return {"analyses": [{"key": "analysis-1", "revision": REVISION}]}
        key = {"issues/search": "issues", "hotspots/search": "hotspots"}[endpoint]
        return {"paging": {"total": 0}, key: []}


class SonarJobEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.task_file = self.root / "report-task.txt"
        self.task_file.write_text("serverUrl=https://sonarcloud.io\nprojectKey=" + capture.PROJECT + "\nceTaskId=task-1\n")
        self.provider = Provider()
        self.clock = Clock()

    def collect(self, context=CONTEXT, **kwargs):
        return capture.collect(self.task_file, context, REVISION, self.root / "output", self.provider,
                               timeout=4, clock=self.clock.now, pause=self.clock.pause, **kwargs)

    def test_explicit_public_mode_verifies_project_around_exact_source_transaction(self):
        result = self.collect(public_project=True)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["provider_access"], "public-project-anonymous")
        self.assertFalse(result["client_authenticated"])
        self.assertEqual(result["task_access"], "analysis-token")
        endpoints = [endpoint for endpoint, _ in self.provider.calls]
        self.assertEqual(endpoints.count("components/show"), 2)
        self.assertLess(endpoints.index("components/show"), endpoints.index("issues/search"))
        issues = next(params for endpoint, params in self.provider.calls if endpoint == "issues/search")
        self.assertEqual(issues["issueStatuses"], "OPEN,CONFIRMED,FALSE_POSITIVE,ACCEPTED,FIXED")

    def test_public_mode_rejects_wrong_project_private_or_missing_visibility(self):
        for component in ({"key": "other", "visibility": "public"}, {"key": capture.PROJECT, "visibility": "private"}, {"key": capture.PROJECT}):
            self.provider.component = component
            result = capture.collect(self.task_file, CONTEXT, REVISION, self.root / str(len(self.provider.calls)), self.provider,
                                     timeout=4, clock=self.clock.now, pause=self.clock.pause, public_project=True)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["attempts"][0]["stage"], "project-visibility-before")
            self.assertFalse(any(endpoint == "issues/search" for endpoint, _ in self.provider.calls))

    def test_public_mode_preserves_supersession_refusal(self):
        self.provider.pr["commit"]["sha"] = "b" * 40
        result = self.collect(public_project=True)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(any(endpoint == "issues/search" for endpoint, _ in self.provider.calls))

    def test_public_mode_rejects_visibility_change_after_retrieval(self):
        def hook(endpoint, _params):
            if endpoint == "hotspots/search":
                self.provider.component["visibility"] = "private"
        self.provider.hook = hook
        result = self.collect(public_project=True)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["attempts"][0]["stage"], "project-visibility-after")
        self.assertFalse((self.root / "output/context.json").exists())

    def test_permanent_request_errors_stop_without_masking_reason_and_retain_private_body(self):
        def hook(endpoint, _params):
            if endpoint == "issues/search":
                raise urllib.error.HTTPError("https://private.example/?token=sensitive", 400, "secret reason", {}, io.BytesIO(b'{"errors":[{"msg":"private provider reason"}]}'))

        self.provider.hook = hook
        result = self.collect()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["failure_reason"], "provider-http-400")
        self.assertEqual(result["failure_stage"], "issues")
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(self.clock.pauses, [])
        retained = json.loads((self.root / "output/attempt-0001/provider-error.json").read_bytes())
        self.assertIn("private provider reason", retained["body"])
        self.assertNotIn("private provider reason", json.dumps(result))
        self.assertNotIn("sensitive", json.dumps(result))

    def test_exact_successful_pr_export_does_not_retry_or_start_a_scan(self):
        result = self.collect()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["analysis_id"], "analysis-1")
        self.assertEqual(self.clock.pauses, [])
        self.assertTrue(all(endpoint in {"ce/task", "qualitygates/project_status", "project_pull_requests/list", "issues/search", "hotspots/search"} for endpoint, _ in self.provider.calls))
        self.assertTrue((self.root / "output/context.json").exists())

    def test_stale_provider_view_converges_only_to_exact_revision(self):
        snapshots = 0

        def hook(endpoint, _params):
            nonlocal snapshots
            if endpoint == "project_pull_requests/list":
                snapshots += 1
                if snapshots == 1:
                    return {"pullRequests": [{**self.provider.pr, "commit": {"sha": "b" * 40}}]}

        self.provider.hook = hook
        result = self.collect()
        self.assertEqual(result["status"], "completed")
        self.assertEqual([x["status"] for x in result["attempts"]], ["partial", "completed"])
        self.assertEqual(result["attempts"][0]["stage"], "snapshot-before")
        self.assertNotIn("failure_reason", result)
        self.assertTrue((self.root / "output/attempt-0001/pull-requests.json").exists())

    def test_persistent_supersession_exhausts_deadline_as_partial(self):
        self.provider.pr["commit"]["sha"] = "b" * 40
        result = self.collect()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["attempts"][0]["reason"], "pr-source-unavailable-or-superseded")
        self.assertLessEqual(sum(self.clock.pauses), 4)
        self.assertFalse((self.root / "output/context.json").exists())

    def test_snapshot_move_after_fetch_restarts_the_transaction(self):
        snapshots = 0

        def hook(endpoint, _params):
            nonlocal snapshots
            if endpoint == "project_pull_requests/list":
                snapshots += 1
                result = copy.deepcopy(self.provider.pr)
                if snapshots == 2:
                    result["commit"]["sha"] = "b" * 40
                return {"pullRequests": [result]}

        self.provider.hook = hook
        result = self.collect()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["attempts"][0]["stage"], "snapshot-after")
        self.assertEqual(sum(endpoint == "issues/search" for endpoint, _ in self.provider.calls), 2)

    def test_changed_task_analysis_never_rebinds_export_on_retry(self):
        def hook(endpoint, _params):
            if endpoint == "hotspots/search":
                self.provider.task["task"]["analysisId"] = "other-analysis"
                raise OSError("private exception text must not escape")

        self.provider.hook = hook
        result = self.collect()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["failure_stage"], "task-recheck")
        self.assertEqual(result["failure_reason"], "scanner-task-identity-changed")
        self.assertTrue(all(params["analysisId"] == "analysis-1" for endpoint, params in self.provider.calls if endpoint == "qualitygates/project_status"))

    def test_successful_earlier_pages_and_payloads_survive_provider_failure(self):
        def hook(endpoint, params):
            if endpoint == "issues/search":
                if params["p"] == 1:
                    return {"paging": {"total": 2}, "issues": [{"key": "first"}]}
                raise urllib.error.HTTPError("https://private.example/?token=sensitive", 503, "raw secret body", {}, io.BytesIO())

        self.provider.hook = hook
        result = self.collect()
        first = self.root / "output/attempt-0001/issues-page-1.json"
        self.assertTrue(first.exists())
        self.assertTrue((self.root / "output/quality-gate.json").exists())
        self.assertEqual(result["attempts"][0]["stage"], "issues")
        self.assertEqual(result["attempts"][0]["reason"], "provider-http-503")
        serialized = json.dumps(result)
        self.assertNotIn("private.example", serialized)
        self.assertNotIn("sensitive", serialized)
        self.assertNotIn("raw secret body", serialized)

    def test_failed_gate_is_preserved_not_relabelled_as_a_pass(self):
        self.provider.gate = "ERROR"
        result = self.collect()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["quality_gate"], "ERROR")
        self.assertEqual(json.loads((self.root / "output/quality-gate.json").read_text())["projectStatus"]["status"], "ERROR")

    def test_failed_task_or_wrong_pr_context_is_not_retried(self):
        for field, value in [("status", "FAILED"), ("pullRequest", "116")]:
            with self.subTest(field=field):
                self.provider.task["task"][field] = value
                output = self.root / ("failed-" + field)
                result = capture.collect(self.task_file, CONTEXT, REVISION, output, self.provider,
                                         timeout=4, clock=self.clock.now, pause=self.clock.pause)
                self.assertEqual(result["status"], "partial")
                self.assertEqual(result["failure_stage"], "task")
                self.assertEqual(self.clock.pauses, [])
                self.provider.task["task"].update(status="SUCCESS", pullRequest="115")

    def test_ambiguous_context_is_refused_before_provider_requests(self):
        result = self.collect(CONTEXT + " -Dsonar.branch.name=main")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["failure_reason"], "analysis-context-ambiguous-or-missing")
        self.assertEqual(self.provider.calls, [])

    def test_full_branch_export_keeps_exact_analysis_and_revision(self):
        self.provider.task["task"].pop("pullRequest")
        result = self.collect("-Dsonar.branch.name=main")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["scope"], "full-branch")

    def test_response_arriving_after_deadline_is_retained_but_not_completed(self):
        def hook(endpoint, _params):
            if endpoint == "hotspots/search":
                self.clock.instant = 5

        self.provider.hook = hook
        result = self.collect()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["failure_reason"], "export-deadline-exceeded")
        self.assertTrue((self.root / "output/attempt-0001/hotspots-page-1.json").exists())


if __name__ == "__main__":
    unittest.main()

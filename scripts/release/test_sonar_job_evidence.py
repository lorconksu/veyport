import copy
import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

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
        self.pr = {"key": "115", "commit": {"sha": REVISION}, "analysisDate": dt.datetime.now(dt.timezone.utc).isoformat(),
                   "branch": "feature", "base": "main", "status": {"qualityGateStatus": "OK"}}
        self.gate = "OK"
        self.component = {"key": capture.PROJECT, "visibility": "public"}
        self.branch = {"name": "main", "type": "LONG", "isMain": True, "commit": {"sha": REVISION}}
        self.analysis = {"key": "analysis-1", "revision": REVISION, "date": dt.datetime.now(dt.timezone.utc).isoformat()}

    def get(self, endpoint, params):
        self.calls.append((endpoint, params))
        if self.hook:
            replacement = self.hook(endpoint, params)
            if replacement is not None:
                return replacement
        if endpoint == "ce/task":
            return copy.deepcopy(self.task)
        if endpoint == "ce/component":
            return {"queue": [], "current": copy.deepcopy(self.task["task"])}
        if endpoint == "components/show":
            return {"component": copy.deepcopy(self.component)}
        if endpoint == "qualitygates/project_status":
            return {"projectStatus": {"status": self.gate}}
        if endpoint == "project_pull_requests/list":
            return {"pullRequests": [copy.deepcopy(self.pr)]}
        if endpoint == "project_analyses/search":
            return {"analyses": [copy.deepcopy(self.analysis)]}
        if endpoint == "project_branches/list":
            return {"branches": [copy.deepcopy(self.branch)]}
        key = {"issues/search": "issues", "hotspots/search": "hotspots"}[endpoint]
        return {"paging": {"pageIndex": params["p"], "pageSize": params["ps"], "total": 0}, key: []}


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
        if "release-ssdf-candidate-" in context:
            kwargs.setdefault("gate_context", CONTEXT)
        with patch.object(capture, "runtime_gate_context", return_value=CONTEXT):
            return capture.collect(self.task_file, context, REVISION, self.root / "output", self.provider,
                                   timeout=4, clock=self.clock.now, pause=self.clock.pause, **kwargs)

    def test_explicit_public_mode_verifies_project_around_exact_source_transaction(self):
        result = self.collect(public_project=True)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["provider_access"], "public-project-anonymous")
        self.assertFalse(result["client_authenticated"])
        self.assertEqual(result["task_access"], "public-project-component")
        self.assertEqual(result["task_binding"], "exact-scanner-task-id")
        self.assertNotIn("ce/task", [endpoint for endpoint, _ in self.provider.calls])
        endpoints = [endpoint for endpoint, _ in self.provider.calls]
        self.assertEqual(endpoints.count("components/show"), 2)
        self.assertLess(endpoints.index("components/show"), endpoints.index("issues/search"))
        issues = next(params for endpoint, params in self.provider.calls if endpoint == "issues/search")
        self.assertEqual(issues["issueStatuses"], "OPEN,CONFIRMED,FALSE_POSITIVE,ACCEPTED,FIXED")

    def test_public_component_requires_exact_task_once_and_preserves_source_and_analysis_checks(self):
        original = copy.deepcopy(self.provider.task['task'])
        cases = [({'queue': [], 'current': {**original, 'id': 'foreign'}}, 'scanner-task-unavailable-or-superseded'),
                 ({'queue': [original], 'current': original}, 'scanner-task-unavailable-or-superseded'),
                 ({'queue': {}, 'current': original}, 'scanner-task-public-view-invalid'),
                 ({'queue': [None], 'current': original}, 'scanner-task-public-view-invalid'),
                 ({'queue': [], 'current': {**original, 'componentKey': 'other'}}, 'scanner-task-not-successful-or-mismatched'),
                 ({'queue': [], 'current': {**original, 'pullRequest': '116'}}, 'scanner-task-context-mismatch')]
        for index, (view, expected) in enumerate(cases):
            self.provider.hook = lambda endpoint, params, view=view: view if endpoint == 'ce/component' else None
            result = capture.collect(self.task_file, CONTEXT, REVISION, self.root / ('public-' + str(index)), self.provider,
                                     timeout=4, clock=self.clock.now, pause=self.clock.pause, public_project=True)
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['failure_reason'], expected)
        self.provider.hook = lambda endpoint, params: {'queue': [original], 'current': {**original, 'id': 'other'}} if endpoint == 'ce/component' else None
        result = capture.collect(self.task_file, CONTEXT, REVISION, self.root / 'queued-exact', self.provider,
                                 timeout=4, clock=self.clock.now, pause=self.clock.pause, public_project=True)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['failure_reason'], 'scanner-task-unavailable-or-superseded')

    def test_public_task_disappearing_before_retry_stays_partial(self):
        def hook(endpoint, params):
            if endpoint == 'issues/search':
                raise ValueError('synthetic transient issue view')
            if endpoint == 'ce/component' and self.clock.instant > 0:
                return {'queue': [], 'current': {**self.provider.task['task'], 'id': 'superseding-task'}}
        self.provider.hook = hook
        result = self.collect(public_project=True)
        self.assertEqual(result['status'], 'partial')
        self.assertTrue(any(item['stage'] == 'task-recheck' for item in result['attempts']))
        self.assertFalse(any(endpoint == 'ce/task' for endpoint, _ in self.provider.calls))

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

    def test_same_commit_new_analysis_cannot_launder_old_passing_gate(self):
        for public in (False, True):
            for timing in ('before-first-snapshot', 'during-issues', 'after-final-snapshot'):
                for new_gate in ('ERROR', 'OK'):
                    with self.subTest(public=public, timing=timing, new_gate=new_gate):
                        provider = Provider(); clock = Clock(); moved = [False]; reads = [0]
                        def hook(endpoint, params):
                            if endpoint == 'project_pull_requests/list':
                                reads[0] += 1
                            if (timing == 'before-first-snapshot' and endpoint == 'qualitygates/project_status'
                                    and params.get('analysisId') == 'analysis-1'
                                    or timing == 'during-issues' and endpoint == 'issues/search'
                                    or timing == 'after-final-snapshot' and endpoint == 'project_pull_requests/list' and reads[0] == 2):
                                moved[0] = True
                            if moved[0] and endpoint == 'ce/component':
                                return {'queue': [], 'current': {**provider.task['task'], 'id': 'task-2', 'analysisId': 'analysis-2'}}
                            if endpoint == 'qualitygates/project_status':
                                return {'projectStatus': {'status': new_gate if moved[0] and 'pullRequest' in params else 'OK'}}
                            if moved[0] and endpoint == 'project_pull_requests/list' and timing == 'before-first-snapshot':
                                return {'pullRequests': [{**provider.pr, 'status': {'qualityGateStatus': new_gate}}]}
                        provider.hook = hook
                        output = self.root / ('interleave-' + str(public) + timing + new_gate)
                        result = capture.collect(self.task_file, CONTEXT, REVISION, output, provider,
                            timeout=4, clock=clock.now, pause=clock.pause, public_project=public)
                        self.assertEqual(result['status'], 'partial')
                        self.assertFalse((output / 'context.json').exists())
                        self.assertEqual(result['analysis_id'], 'analysis-1')
                        self.assertTrue(all(params['analysisId'] == 'analysis-1' for endpoint, params in provider.calls
                                            if endpoint == 'qualitygates/project_status' and 'analysisId' in params))

    def test_final_current_task_requires_exact_successful_current_not_queue_or_history(self):
        for public in (False, True):
            for fault in ('missing', 'null', 'queued-only', 'id', 'analysis', 'project', 'context', 'status'):
                with self.subTest(public=public, fault=fault):
                    provider = Provider(); clock = Clock(); exported = [False]
                    def hook(endpoint, params):
                        if endpoint == 'hotspots/search': exported[0] = True
                        if endpoint == 'ce/component' and exported[0]:
                            current = copy.deepcopy(provider.task['task'])
                            view = {'queue': [], 'current': current}
                            if fault == 'missing': view.pop('current')
                            elif fault == 'null': view['current'] = None
                            elif fault == 'queued-only': view.update(queue=[current], current=None)
                            elif fault == 'id': current['id'] = 'task-2'
                            elif fault == 'analysis': current['analysisId'] = 'analysis-2'
                            elif fault == 'project': current['componentKey'] = 'other-project'
                            elif fault == 'context': current['pullRequest'] = '116'
                            else: current['status'] = 'FAILED'
                            return view
                    provider.hook = hook
                    output = self.root / ('final-current-' + str(public) + fault)
                    result = capture.collect(self.task_file, CONTEXT, REVISION, output, provider,
                        timeout=4, clock=clock.now, pause=clock.pause, public_project=public)
                    self.assertEqual(result['status'], 'partial')
                    self.assertFalse((output / 'context.json').exists())

    def test_current_gate_and_row_must_match_exact_analysis_gate_without_date_assumption(self):
        for public in (False, True):
            for fault in ('gate', 'row', 'valid-unrelated-date'):
                with self.subTest(public=public, fault=fault):
                    provider = Provider(); clock = Clock()
                    provider.task['task']['executedAt'] = '2026-01-01T00:00:00Z'
                    def hook(endpoint, params):
                        if fault == 'gate' and endpoint == 'qualitygates/project_status' and 'pullRequest' in params:
                            return {'projectStatus': {'status': 'ERROR'}}
                        if fault == 'row' and endpoint == 'project_pull_requests/list':
                            return {'pullRequests': [{**provider.pr, 'status': {'qualityGateStatus': 'ERROR'}}]}
                    provider.hook = hook
                    result = capture.collect(self.task_file, CONTEXT, REVISION,
                        self.root / ('gate-row-' + str(public) + fault), provider,
                        timeout=4, clock=clock.now, pause=clock.pause, public_project=public)
                    self.assertEqual(result['status'], 'completed' if fault == 'valid-unrelated-date' else 'partial')
                    self.assertLessEqual(clock.instant, 4)

    def test_original_failed_gate_remains_completed_failed_evidence_in_both_modes(self):
        for public in (False, True):
            with self.subTest(public=public):
                provider = Provider(); clock = Clock(); provider.gate = 'ERROR'
                provider.pr['status']['qualityGateStatus'] = 'ERROR'
                output = self.root / ('failed-current-' + str(public))
                result = capture.collect(self.task_file, CONTEXT, REVISION, output, provider,
                    timeout=4, clock=clock.now, pause=clock.pause, public_project=public)
                self.assertEqual(result['status'], 'completed')
                self.assertEqual(result['quality_gate'], 'ERROR')
                self.assertEqual(json.loads((output / 'quality-gate.json').read_bytes())['projectStatus']['status'], 'ERROR')
                self.assertTrue((output / 'issues.json').exists())
                self.assertTrue((output / 'hotspots.json').exists())

    def test_exact_current_success_can_coexist_pending_other_task_and_raw_reads_retained(self):
        for public in (False, True):
            with self.subTest(public=public):
                provider = Provider(); clock = Clock()
                provider.hook = lambda endpoint, params: {'queue': [{'id': 'pending-task', 'status': 'PENDING'}],
                    'current': copy.deepcopy(provider.task['task'])} if endpoint == 'ce/component' else None
                output = self.root / ('pending-other-' + str(public))
                result = capture.collect(self.task_file, CONTEXT, REVISION, output, provider,
                    timeout=4, clock=clock.now, pause=clock.pause, public_project=public)
                self.assertEqual(result['status'], 'completed')
                self.assertEqual(result['quality_gate'], 'OK')
                attempt = output / 'attempt-0001'
                self.assertEqual(json.loads((attempt / 'task-before.json').read_bytes())['task']['id'], 'task-1')
                self.assertEqual(json.loads((attempt / 'task-after.json').read_bytes())['task']['analysisId'], 'analysis-1')
                self.assertTrue((attempt / 'task-component-read-0002.json').exists())
                self.assertTrue((attempt / 'quality-gate-read-0003.json').exists())
                self.assertEqual(clock.pauses, [])

    def test_exact_successful_pr_export_does_not_retry_or_start_a_scan(self):
        result = self.collect()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["analysis_id"], "analysis-1")
        self.assertEqual(self.clock.pauses, [])
        self.assertTrue(all(endpoint in {"ce/task", "ce/component", "qualitygates/project_status", "project_pull_requests/list", "issues/search", "hotspots/search"} for endpoint, _ in self.provider.calls))
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
        self.assertEqual(sum(endpoint == "issues/search" for endpoint, _ in self.provider.calls), 4)

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
        self.assertTrue(all(params["analysisId"] == "analysis-1" for endpoint, params in self.provider.calls if endpoint == "qualitygates/project_status" and "analysisId" in params))

    def test_successful_earlier_pages_and_payloads_survive_provider_failure(self):
        def hook(endpoint, params):
            if endpoint == "issues/search":
                if params["p"] == 1:
                    return {"paging": {"pageIndex": params["p"], "pageSize": 1, "total": 2}, "issues": [{"key": "first"}]}
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
        self.provider.pr["status"]["qualityGateStatus"] = "ERROR"
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
        self.assertEqual(sum(endpoint == "project_branches/list" for endpoint, _ in self.provider.calls), 2)

    def test_candidate_full_branch_requires_long_nonmain_exact_source(self):
        self.provider.task["task"].pop("pullRequest")
        branch = capture.candidate_branch(REVISION)
        self.provider.branch.update(name=branch, isMain=False)
        self.provider.branch.pop("commit")
        result = self.collect("-Dsonar.branch.name=" + branch)
        self.assertEqual(result["status"], "completed")
        for index, change in enumerate(({"type": "SHORT"}, {"isMain": True})):
            self.provider.branch.update(name=branch, type="LONG", isMain=False, commit={"sha": REVISION})
            self.provider.branch.update(change)
            result = capture.collect(self.task_file, "-Dsonar.branch.name=" + branch, REVISION,
                                     self.root / ("invalid-" + str(index)), self.provider,
                                     timeout=4, clock=self.clock.now, pause=self.clock.pause)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["attempts"][0]["reason"], "branch-not-long-lived-or-source-mismatched")

    def test_long_candidate_branch_still_requires_exact_analysis_revision(self):
        self.provider.task["task"].pop("pullRequest")
        branch = capture.candidate_branch(REVISION)
        self.provider.branch.update(name=branch, isMain=False)
        self.provider.analysis["revision"] = "b" * 40
        result = self.collect("-Dsonar.branch.name=" + branch)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["attempts"][0]["reason"], "branch-analysis-unavailable-or-superseded")

    def test_candidate_branch_type_change_during_export_is_refused(self):
        self.provider.task["task"].pop("pullRequest")
        branch = capture.candidate_branch(REVISION)
        self.provider.branch.update(name=branch, isMain=False)
        def hook(endpoint, _params):
            if endpoint == "hotspots/search":
                self.provider.branch["type"] = "SHORT"
        self.provider.hook = hook
        result = self.collect("-Dsonar.branch.name=" + branch)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["attempts"][0]["stage"], "snapshot-after")
        self.assertFalse((self.root / "output/context.json").exists())

    def test_unbound_historical_tag_branch_refused_before_provider_requests(self):
        result = self.collect("-Dsonar.branch.name=refs/tags/v2.0.57")
        self.assertEqual(result["failure_reason"], "full-branch-context-not-source-bound")
        self.assertEqual(self.provider.calls, [])

    def test_response_arriving_after_deadline_is_retained_but_not_completed(self):
        def hook(endpoint, _params):
            if endpoint == "hotspots/search":
                self.clock.instant = 5

        self.provider.hook = hook
        result = self.collect()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["failure_reason"], "export-deadline-exceeded")
        self.assertTrue((self.root / "output/attempt-0001/hotspots-page-1.json").exists())

    def candidate(self):
        self.provider.task["task"].pop("pullRequest", None)
        self.provider.branch.update(name=capture.candidate_branch(REVISION), isMain=False)
        return "-Dsonar.branch.name=" + capture.candidate_branch(REVISION)

    def test_inventory_none_requires_independent_exact_pr_gate_not_relabelled(self):
        context = self.candidate()
        def hook(endpoint, params):
            if endpoint == "qualitygates/project_status":
                return {"projectStatus": {"status": "OK" if "pullRequest" in params else "NONE"}}
        self.provider.hook = hook
        result = self.collect(context)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["quality_gate"], "NONE")
        self.assertEqual(result["inventory_quality_gate"], "NONE")
        self.assertEqual(result["required_quality_gate"], "OK")
        self.assertEqual(result["required_quality_gate_scope"], "pull-request-new-code")
        self.assertTrue((self.root / "output/required-quality-gate.json").is_file())

    def test_inventory_error_even_with_good_pr_gate_blocks(self):
        context = self.candidate()
        self.provider.hook = lambda endpoint, params: {"projectStatus": {"status": "OK" if "pullRequest" in params else "ERROR"}} if endpoint == "qualitygates/project_status" else None
        result = self.collect(context)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["failure_reason"], "inventory-quality-gate-failed")
        self.assertEqual(json.loads((self.root / "output/quality-gate.json").read_text())["projectStatus"]["status"], "ERROR")

    def test_inventory_none_or_ok_cannot_replace_failed_missing_stale_or_changed_pr_gate(self):
        context = self.candidate()
        self.provider.pr["analysisDate"] = "2026-01-01T00:00:00Z"
        result = self.collect(context)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["attempts"][0]["stage"], "required-quality-gate-before")
        for index, status in enumerate(("NONE", "ERROR")):
            self.provider.pr["analysisDate"] = dt.datetime.now(dt.timezone.utc).isoformat()
            self.provider.hook = lambda endpoint, params: {"projectStatus": {"status": status if "pullRequest" in params else "OK"}} if endpoint == "qualitygates/project_status" else None
            with patch.object(capture, "runtime_gate_context", return_value=CONTEXT):
                value = capture.collect(self.task_file, context, REVISION, self.root / ("gate-" + str(index)), self.provider,
                                        timeout=4, clock=self.clock.now, pause=self.clock.pause, gate_context=CONTEXT)
            self.assertEqual(value["status"], "partial")

    def test_independent_gate_move_during_inventory_blocks(self):
        context = self.candidate()
        def hook(endpoint, _params):
            if endpoint == "hotspots/search":
                self.provider.pr["commit"]["sha"] = "b" * 40
        self.provider.hook = hook
        result = self.collect(context)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(any(a["stage"] == "required-quality-gate-after" for a in result["attempts"]))

    def test_gate_flags_cannot_override_trusted_resolver(self):
        result = self.collect(self.candidate(), gate_context="-Dsonar.branch.name=main")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["failure_reason"], "required-quality-gate-context-mismatch")

    def test_candidate_inventory_requires_gate_context_and_stable_candidate_uses_exact_main(self):
        context = self.candidate()
        with patch.object(capture, "runtime_gate_context", return_value=CONTEXT):
            result = capture.collect(self.task_file, context, REVISION, self.root / "missing-gate", self.provider,
                                     timeout=4, clock=self.clock.now, pause=self.clock.pause)
        self.assertEqual(result["failure_reason"], "required-quality-gate-context-mismatch")
        main_context = '-Dsonar.branch.name=main'
        def hook(endpoint, params):
            if endpoint == 'project_branches/list':
                return {'branches': [copy.deepcopy(self.provider.branch), {'name': 'main', 'isMain': True, 'type': 'LONG', 'commit': {'sha': REVISION}}]}
            if endpoint == 'project_analyses/search' and params['branch'] == 'main':
                return {'analyses': [{**self.provider.analysis, 'key': 'main-analysis'}]}
            if endpoint == 'qualitygates/project_status':
                return {'projectStatus': {'status': 'OK' if params.get('analysisId') == 'main-analysis' else 'NONE'}}
        self.provider.hook = hook
        with patch.object(capture, 'runtime_gate_context', return_value=main_context):
            result = capture.collect(self.task_file, context, REVISION, self.root / 'stable-gate', self.provider,
                                     timeout=4, clock=self.clock.now, pause=self.clock.pause, gate_context=main_context)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['inventory_quality_gate'], 'NONE')
        self.assertEqual(result['required_quality_gate_scope'], 'main-quality-gate')

    def test_pending_ce_is_polled_bounded_and_failed_or_never_finishing_ce_blocks(self):
        polls = 0
        def hook(endpoint, _params):
            nonlocal polls
            if endpoint == "ce/task":
                polls += 1
                if polls == 1:
                    value = copy.deepcopy(self.provider.task)
                    value["task"]["status"] = "PENDING"
                    return value
        self.provider.hook = hook
        result = self.collect()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.clock.pauses, [2])
        self.provider.hook = None
        self.provider.task["task"]["status"] = "IN_PROGRESS"
        value = capture.collect(self.task_file, CONTEXT, REVISION, self.root / "pending", self.provider,
                                timeout=4, clock=self.clock.now, pause=self.clock.pause)
        self.assertEqual(value["status"], "partial")
        self.assertEqual(value["failure_reason"], "scanner-task-deadline-exceeded")
        self.assertEqual(self.clock.instant, 6)

    def test_gate_can_converge_after_a_minute_without_repeating_github_lookups(self):
        context = self.candidate()
        def hook(endpoint, params):
            if endpoint == 'qualitygates/project_status':
                status = 'OK' if 'pullRequest' in params and self.clock.instant >= 80 else 'NONE'
                return {'projectStatus': {'status': status}}
        self.provider.hook = hook
        with patch.object(capture, 'runtime_gate_context', return_value=CONTEXT) as trusted:
            result = capture.collect(self.task_file, context, REVISION, self.root / 'late-gate', self.provider,
                                     timeout=120, clock=self.clock.now, pause=self.clock.pause, gate_context=CONTEXT)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(self.clock.instant, 80)
        self.assertEqual(trusted.call_count, 2)
        self.assertGreater(len(result['attempts']), 15)


if __name__ == "__main__":
    unittest.main()

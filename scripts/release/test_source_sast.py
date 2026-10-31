import copy
import datetime as dt
import unittest
import tempfile
import io
import urllib.error
from pathlib import Path
from unittest.mock import patch
import source_sast as sast

REV = 'a' * 40


def sarif():
    return {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'CodeQL'}, 'extensions': [{'rules': [{'id': 'go/auth', 'properties': {'security-severity': '3.0', 'tags': ['external/cwe/cwe-287']}}]}]}, 'versionControlProvenance': [{'revisionId': REV, 'repositoryUri': 'https://github.com/lorconksu/veyport'}], 'results': [{'ruleId': 'go/auth', 'properties': {'github/alertNumber': 7}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'hub/auth.go'}}}]}]}]}


class SourceEvidenceTests(unittest.TestCase):
    def test_public_reader_omits_credentials_and_uses_fixed_https_without_redirects(self):
        api = sast.Sonar(public_project=True)
        response = lambda: io.BytesIO(b'{"component":{"key":"lorconksu_veyport","visibility":"public"}}')
        with patch.dict(sast.os.environ, {"SONAR_TOKEN": "private-analysis-credential"}), patch.object(sast.urllib.request, 'build_opener') as opener:
            requests = [('components/show', {'component': sast.PROJECT}), ('issues/search', {'componentKeys': sast.PROJECT}),
                        ('qualitygates/project_status', {'analysisId': 'analysis-1'}), ('project_pull_requests/list', {'project': sast.PROJECT}),
                        ('hotspots/search', {'projectKey': sast.PROJECT}), ('project_analyses/search', {'project': sast.PROJECT})]
            opener.return_value.open.side_effect = [response() for _ in range(len(requests) + 1)]
            for endpoint, params in requests:
                api.get(endpoint, params)
            api.get('ce/task', {'id': 'task-1'})
            calls = opener.return_value.open.call_args_list
            public_request = calls[0].args[0]
            self.assertEqual(public_request.full_url, 'https://sonarcloud.io/api/components/show?component=lorconksu_veyport')
            for call in calls[:-1]:
                request = call.args[0]
                self.assertIsNone(request.get_header('Authorization'))
                self.assertNotIn('private-analysis-credential', str(request.header_items()) + request.full_url)
                self.assertTrue(request.full_url.startswith('https://sonarcloud.io/api/'))
            self.assertEqual(calls[-1].args[0].get_header('Authorization'), 'Bearer private-analysis-credential')
            self.assertTrue(all(isinstance(call.args[0], sast.NoRedirect) for call in opener.call_args_list))
        self.assertIsNone(sast.NoRedirect().redirect_request(None, None, 302, None, None, 'https://elsewhere.example'))

    def test_public_reader_rejects_other_projects_and_unknown_endpoints_before_transport(self):
        api = sast.Sonar(public_project=True)
        with patch.object(sast.urllib.request, 'build_opener') as opener:
            for endpoint, params in [('issues/search', {'componentKeys': 'other'}), ('projects/search', {}), ('qualitygates/project_status', {'analysisId': '../other'}), ('components/show', {'component': sast.PROJECT + ',other'})]:
                with self.assertRaises(ValueError):
                    api.get(endpoint, params)
            opener.assert_not_called()

    def test_analysis_only_credential_rejection_requires_explicit_public_reader(self):
        def transport(request, **_kwargs):
            if request.get_header('Authorization'):
                raise urllib.error.HTTPError(request.full_url, 400, 'analysis credential cannot browse', {}, io.BytesIO())
            return io.BytesIO(b'{"paging":{"total":0},"issues":[]}')

        with patch.dict(sast.os.environ, {'SONAR_TOKEN': 'analysis-only'}), patch.object(sast.urllib.request, 'build_opener') as opener:
            opener.return_value.open.side_effect = transport
            # An authenticated request never silently falls back after HTTP400.
            with self.assertRaises(urllib.error.HTTPError) as raised:
                sast.Sonar().get('issues/search', {'componentKeys': sast.PROJECT})
            raised.exception.close()
            self.assertEqual(opener.return_value.open.call_count, 1)
            value = sast.Sonar(public_project=True).get('issues/search', {'componentKeys': sast.PROJECT})
            self.assertEqual(value['issues'], [])
            self.assertIsNone(opener.return_value.open.call_args.args[0].get_header('Authorization'))

    def test_full_public_export_checks_visibility_and_preserves_exact_branch_gate_and_states(self):
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        class API(sast.Sonar):
            def __init__(self):
                self.visibility = 'public'
                self.revision = REV
                self.gate = 'OK'
                self.statuses = None
            def get(self, endpoint, params):
                if endpoint == 'components/show':
                    return {'component': {'key': sast.PROJECT, 'visibility': self.visibility}}
                if endpoint == 'project_analyses/search':
                    return {'analyses': [{'revision': self.revision, 'key': 'analysis-1', 'date': now}]}
                if endpoint == 'qualitygates/project_status':
                    return {'projectStatus': {'status': self.gate}}
                key = {'issues/search': 'issues', 'hotspots/search': 'hotspots'}[endpoint]
                if key == 'issues':
                    self.statuses = params['issueStatuses']
                return {'paging': {'total': 0}, key: []}
        with tempfile.TemporaryDirectory() as directory:
            api = API()
            self.assertEqual(sast.export_sonar(api, directory, REV, '2.0.58', 'main', public_project=True), [])
            self.assertEqual(api.statuses, 'OPEN,CONFIRMED,FALSE_POSITIVE,ACCEPTED,FIXED')
            for field, value in [('visibility', 'private'), ('revision', 'b' * 40), ('gate', 'ERROR')]:
                api = API();setattr(api, field, value)
                with self.assertRaises(ValueError):
                    sast.export_sonar(api, directory, REV, '2.0.58', 'main', public_project=True)

    def test_baseline_including_dismissed_and_auth_failure_preserved(self):
        alerts = [{'number': 7, 'created_at': '2026-01-01T00:00:00Z', 'state': 'dismissed', 'dismissed_reason': "won't fix"}]
        result = sast.sarif_findings(sarif(), 'codeql', REV, '2.0.58', alerts)
        self.assertEqual(result[0]['severity'], 'low')
        self.assertEqual(result[0]['classification'], 'authentication')
        self.assertTrue(result[0]['suppressed'])
        self.assertEqual(result[0]['first_seen'], '2026-01-01T00:00:00Z')

    def test_wrong_revision_incomplete_execution_and_missing_rule_fail(self):
        for mutate in (lambda r: r['runs'][0]['versionControlProvenance'][0].update(revisionId='b' * 40), lambda r: r['runs'][0].update(invocations=[{'executionSuccessful': False}]), lambda r: r['runs'][0]['tool'].update(extensions=[])):
            raw = sarif()
            mutate(raw)
            with self.assertRaises(ValueError):
                sast.sarif_findings(raw, 'codeql', REV, '2.0.58')

    def test_sarif_false_positive_does_not_disappear(self):
        raw = sarif()
        raw['runs'][0]['results'][0]['suppressions'] = [{'kind': 'external'}]
        result = sast.sarif_findings(raw, 'codeql', REV, '2.0.58', [{'number': 7, 'state': 'dismissed', 'dismissed_reason': 'false positive'}])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['classification'], 'false-positive')

    def test_missing_provider_first_seen_is_not_replaced_by_scan_time(self):
        result = sast.sarif_findings(sarif(), 'codeql', REV, '2.0.58')
        self.assertIsNone(result[0]['first_seen'])

    def test_freshness_bound_and_future_rejected(self):
        at = dt.datetime(2026, 10, 31, 12, tzinfo=dt.timezone.utc)
        sast.fresh('2026-10-30T12:00:00Z', at)
        for value in ('2026-10-30T11:59:59Z', '2026-10-31T12:00:01Z', 'invalid'):
            with self.assertRaises(ValueError):
                sast.fresh(value, at)

    def test_sonar_pagination_never_accepts_missing_pages(self):
        api = sast.Sonar()
        with patch.object(api, 'get', side_effect=[{'paging': {'total': 2}, 'issues': [{'key': 'one'}]}, {'paging': {'total': 2}, 'issues': []}]):
            with self.assertRaises(ValueError):
                api.pages('issues/search', {}, 'issues')

    def test_sonar_current_revision_can_not_replace_historic_evidence(self):
        api = sast.Sonar()
        with patch.object(api, 'get', return_value={'analyses': [{'revision': 'b' * 40}]}):
            with self.assertRaises(ValueError):
                sast.export_sonar(api, '.', REV, '2.0.58', 'main')

    def test_policy_inventory_binds_source_around_annotations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hub").mkdir()
            path = root / "hub/example.go"
            path.write_text('package example\n// NOSONAR: example annotation\nfunc run() {}\n')
            (root / "sonar-project.properties").write_text('sonar.sources=hub\n')
            tracked = b'hub/example.go\0sonar-project.properties\0'
            with patch.object(sast.subprocess, 'check_output', return_value=tracked):
                before = sast.suppression_inventory(root)
                path.write_text(path.read_text().replace('func run()', 'func changed()'))
                after = sast.suppression_inventory(root)
            self.assertEqual(before['annotations'][0]['annotation_sha256'], after['annotations'][0]['annotation_sha256'])
            self.assertNotEqual(before['annotations'][0]['source_sha256'], after['annotations'][0]['source_sha256'])
            self.assertNotEqual(sast.sha(sast.canonical(before)), sast.sha(sast.canonical(after)))

    def test_missing_inventory_review_never_invents_false_positive_assessment(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                sast.reviewed_inventory('a' * 64, directory, None)

    def test_codeql_missing_language_is_incomplete_not_clean(self):
        api = sast.ExportAPI('test-token')
        with patch.object(api, 'pages', return_value=[]):
            with self.assertRaises(ValueError):
                sast.export_codeql(api, '.', REV, '2.0.58')


if __name__ == '__main__':
    unittest.main()

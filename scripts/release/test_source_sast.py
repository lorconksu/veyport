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
                if endpoint == 'project_branches/list':
                    return {'branches': [{'name': 'main', 'isMain': True, 'type': 'LONG'}]}
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

    def test_candidate_sonar_requires_exact_deterministic_long_branch_and_stable_analysis(self):
        branch = 'release-ssdf-candidate-' + REV
        completed = dt.datetime.now(dt.timezone.utc).isoformat()
        def fake(branch_type='LONG', commit=None, change=False):
            api = sast.Sonar()
            calls = {'analysis': 0}
            def get(endpoint, _params):
                if endpoint == 'project_branches/list':
                    row = {'name': branch, 'type': branch_type, 'isMain': False}
                    if commit is not None:
                        row['commit'] = {'sha': commit}
                    return {'branches': [row, {'name': 'main', 'type': 'LONG', 'isMain': True}]}
                if endpoint == 'project_analyses/search':
                    calls['analysis'] += 1
                    return {'analyses': [{'revision': REV, 'key': 'different' if change and calls['analysis'] > 1 else 'analysis-1', 'date': completed}]}
                if endpoint == 'qualitygates/project_status':
                    return {'projectStatus': {'status': 'OK'}}
                raise AssertionError(endpoint)
            api.get = get
            api.pages = lambda *_: ([], [])
            return api
        with tempfile.TemporaryDirectory() as directory, patch('sonar_context.runtime_gate_context', return_value='-Dsonar.branch.name=main'):
            # commit is optional in Sonar's branch inventory; exact revision
            # comes from the stable full branch analysis, independently.
            self.assertEqual(sast.export_sonar(fake(), directory, REV, '2.0.58', branch), [])
            for api in (fake(branch_type='SHORT'), fake(commit='b' * 40), fake(change=True)):
                with self.assertRaises(ValueError):
                    sast.export_sonar(api, directory, REV, '2.0.58', branch)
            for untrusted in ('refs/tags/v2.0.58', 'PR-115', 'release-ssdf-candidate-' + 'b' * 40, 'arbitrary-long-branch'):
                with self.assertRaises(ValueError):
                    sast.export_sonar(fake(), directory, REV, '2.0.58', untrusted)

    def test_independent_pr_gate_requires_exact_fresh_source_and_actual_ok_status(self):
        context = '-Dsonar.pullrequest.key=115 -Dsonar.pullrequest.branch=feature -Dsonar.pullrequest.base=main'
        row = {'key': '115', 'branch': 'feature', 'base': 'main', 'commit': {'sha': REV},
               'analysisDate': dt.datetime.now(dt.timezone.utc).isoformat(), 'status': {'qualityGateStatus': 'OK'}}
        api = sast.Sonar()
        gate = {'projectStatus': {'status': 'OK'}}
        api.get = lambda endpoint, _: {'pullRequests': [copy.deepcopy(row)]} if endpoint == 'project_pull_requests/list' else gate
        self.assertEqual(sast.sonar_gate_snapshot(api, context, REV)['scope'], 'pull-request-new-code')
        mutations = [lambda r: r['commit'].update(sha='b' * 40), lambda r: r.update(base='other'),
                     lambda r: r.update(branch='other'), lambda r: r.update(analysisDate='2026-01-01T00:00:00Z'),
                     lambda r: r['status'].update(qualityGateStatus='NONE')]
        for mutate in mutations:
            changed = copy.deepcopy(row);mutate(changed)
            api.get = lambda endpoint, _: {'pullRequests': [changed]} if endpoint == 'project_pull_requests/list' else gate
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                sast.sonar_gate_snapshot(api, context, REV)
        for status in ('NONE', 'ERROR', 'WARN', None):
            api.get = lambda endpoint, _: {'pullRequests': [row]} if endpoint == 'project_pull_requests/list' else {'projectStatus': {'status': status}}
            with self.subTest(status=status), self.assertRaises(ValueError):
                sast.sonar_gate_snapshot(api, context, REV)
        for invalid in (context + ' -Dsonar.pullrequest.key=116', '-Dsonar.branch.name=foreign', '-Dsonar.pullrequest.key=115'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                sast.sonar_gate_snapshot(api, invalid, REV)

    def test_independent_main_gate_requires_fresh_exact_main_analysis(self):
        api = sast.Sonar()
        branch = {'name': 'main', 'type': 'LONG', 'isMain': True, 'commit': {'sha': REV}}
        analysis = {'key': 'main-analysis', 'revision': REV, 'date': dt.datetime.now(dt.timezone.utc).isoformat()}
        gate = {'projectStatus': {'status': 'OK'}}
        def get(endpoint, _):
            if endpoint == 'project_branches/list':return {'branches': [branch]}
            if endpoint == 'project_analyses/search':return {'analyses': [analysis]}
            return gate
        api.get = get
        self.assertEqual(sast.sonar_gate_snapshot(api, '-Dsonar.branch.name=main', REV)['scope'], 'main-quality-gate')
        for field, value in (('revision', 'b' * 40), ('date', '2026-01-01T00:00:00Z')):
            old = analysis[field];analysis[field] = value
            with self.assertRaises(ValueError):sast.sonar_gate_snapshot(api, '-Dsonar.branch.name=main', REV)
            analysis[field] = old
        gate['projectStatus']['status'] = 'NONE'
        with self.assertRaises(ValueError):sast.sonar_gate_snapshot(api, '-Dsonar.branch.name=main', REV)

    def test_inventory_none_is_diagnostic_and_independent_gate_is_bound_before_after(self):
        branch = 'release-ssdf-candidate-' + REV
        context = '-Dsonar.pullrequest.key=115 -Dsonar.pullrequest.branch=feature -Dsonar.pullrequest.base=main'
        completed = dt.datetime.now(dt.timezone.utc).isoformat()
        class API(sast.Sonar):
            def __init__(self):
                self.raw_gate, self.required_gate, self.move = 'NONE', 'OK', False
                self.pr = {'key': '115', 'branch': 'feature', 'base': 'main', 'commit': {'sha': REV},
                           'analysisDate': completed, 'status': {'qualityGateStatus': 'OK'}}
            def get(self, endpoint, params):
                if endpoint == 'project_branches/list':return {'branches': [{'name': branch, 'type': 'LONG', 'isMain': False}]}
                if endpoint == 'project_analyses/search':return {'analyses': [{'key': 'candidate-analysis', 'revision': REV, 'date': completed}]}
                if endpoint == 'project_pull_requests/list':return {'pullRequests': [copy.deepcopy(self.pr)]}
                if endpoint == 'qualitygates/project_status':return {'projectStatus': {'status': self.required_gate if 'pullRequest' in params else self.raw_gate}}
                raise AssertionError(endpoint)
            def pages(self, endpoint, *_):
                if self.move and endpoint == 'hotspots/search':self.pr['commit']['sha'] = 'b' * 40
                return [], []
        with tempfile.TemporaryDirectory() as directory, patch('sonar_context.runtime_gate_context', return_value=context):
            api = API()
            self.assertEqual(sast.export_sonar(api, directory, REV, '2.0.58', branch), [])
            self.assertEqual(sast.strict_json((Path(directory) / 'sonar-quality-gate.json').read_bytes())['projectStatus']['status'], 'NONE')
            self.assertEqual(sast.strict_json((Path(directory) / 'sonar-required-gate-after.json').read_bytes())['quality_gate']['projectStatus']['status'], 'OK')
            for field, value in (('raw_gate', 'ERROR'), ('required_gate', 'NONE'), ('required_gate', 'ERROR'), ('move', True)):
                api = API();setattr(api, field, value)
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    sast.export_sonar(api, directory, REV, '2.0.58', branch)

    def test_public_reader_allows_only_fixed_project_exact_pr_gate(self):
        api = sast.Sonar(public_project=True)
        with patch.object(sast.urllib.request, 'build_opener') as opener:
            opener.return_value.open.return_value = io.BytesIO(b'{"projectStatus":{"status":"OK"}}')
            api.get('qualitygates/project_status', {'projectKey': sast.PROJECT, 'pullRequest': '115'})
            self.assertIsNone(opener.return_value.open.call_args.args[0].get_header('Authorization'))
            for params in ({'projectKey': 'other', 'pullRequest': '115'}, {'projectKey': sast.PROJECT, 'pullRequest': '../other'},
                           {'projectKey': sast.PROJECT, 'branch': 'main'}):
                with self.subTest(params=params), self.assertRaises(ValueError):api.get('qualitygates/project_status', params)

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

    def test_policy_inventory_binds_full_scan_workflow_and_helper_configuration(self):
        names = ['.github/workflows/delivery.yml', '.github/workflows/staging.yml', '.github/workflows/release.yml', 'scripts/release/codeql_evidence.py', 'scripts/release/sonar_context.py', 'scripts/release/source_sast.py']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('full scanner configuration\n')
            with patch.object(sast.subprocess, 'check_output', return_value=('\0'.join(names) + '\0').encode()):
                before = sast.suppression_inventory(root)
                self.assertEqual({c['path'] for c in before['configurations']}, set(names))
                (root / names[0]).write_text('changed queries or language configuration\n')
                after = sast.suppression_inventory(root)
            self.assertNotEqual(sast.sha(sast.canonical(before)), sast.sha(sast.canonical(after)))

    def test_codeql_missing_language_is_incomplete_not_clean(self):
        api = sast.ExportAPI('test-token')
        with patch.object(api, 'pages', return_value=[]), patch.object(sast, 'default_codeql_configuration', return_value={}):
            with self.assertRaises(ValueError):
                sast.export_codeql(api, '.', REV, '2.0.58')


class CodeQLHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'codeql-local').mkdir()
        self.raw = sarif()
        run = self.raw['runs'][0]
        run['automationDetails'] = {'id': '/language:go/'}
        run['versionControlProvenance'][0]['branch'] = 'refs/heads/main'
        run['invocations'] = [{'executionSuccessful': True}]
        run['properties'] = {'codeqlConfigSummary': {'disableDefaultQueries': False, 'queries': [{'type': 'builtinSuite', 'uses': 'security-extended'}]}}
        result = run['results'][0]
        result['partialFingerprints'] = {'primaryLocationLineHash': 'abc:1'}
        result['locations'][0]['physicalLocation']['region'] = {'startLine': 10, 'endLine': 10, 'startColumn': 3, 'endColumn': 9}
        result['codeFlows'] = [{'threadFlows': [{'locations': [{'location': copy.deepcopy(result['locations'][0])}]}]}]
        self.write_local()
        historic = copy.deepcopy(self.raw)
        historic['runs'][0]['versionControlProvenance'][0]['revisionId'] = 'b' * 40
        class API:
            def __init__(self):
                self.raw = historic
                self.analyses = [{'id': 123, 'category': '/language:go', 'ref': 'refs/heads/main',
                                  'analysis_key': sast.CODEQL_DEFAULT_KEY, 'commit_sha': 'b' * 40,
                                  'created_at': '2026-10-30T00:00:00Z', 'tool': {'name': 'CodeQL'}, 'results_count': 1}]
                self.alerts = [{'number': 7, 'created_at': '2026-01-01T00:00:00Z', 'state': 'dismissed',
                                'dismissed_reason': 'false positive', 'tool': {'name': 'CodeQL'}, 'rule': {'id': 'go/auth'}}]
            def pages(self, path):
                return copy.deepcopy(self.analyses if 'analyses?' in path else self.alerts)
            def sarif(self, analysis_id):
                if analysis_id != 123:raise AssertionError(analysis_id)
                return copy.deepcopy(self.raw)
        self.api = API()

    def write_local(self):
        (self.root / 'codeql-local/go.sarif').write_bytes(sast.canonical(self.raw))

    def link(self):
        findings = sast.sarif_findings(self.raw, 'codeql', REV, '2.0.58', local_codeql=True)
        return sast.link_codeql_history(self.api, self.root, REV, '2.0.58', findings)

    def test_exact_history_sets_date_and_archives_sources_without_importing_dismissal(self):
        finding = self.link()[0]
        self.assertEqual(finding['first_seen'], '2026-01-01T00:00:00Z')
        self.assertEqual(finding['classification'], 'authentication')
        self.assertFalse(finding['suppressed'])
        self.assertIsNone(finding['provider_state'])
        ledger = sast.strict_json((self.root / 'codeql-first-seen-history.json').read_bytes())
        self.assertEqual(len(ledger['matches']), 1)
        self.assertEqual(ledger['unmatched'], [])
        self.assertEqual(finding['first_seen_evidence']['provider_sarif_sha256'], sast.sha((self.root / 'codeql-history-0.sarif').read_bytes()))
        self.assertEqual(finding['first_seen_evidence']['provider_alerts_sha256'], sast.sha((self.root / 'codeql-history-alerts.json').read_bytes()))
        self.assertTrue((self.root / ledger['sources'][0]['sarif']).is_file())
        self.assertTrue((self.root / 'codeql-history-alerts.json').is_file())

    def test_coordinate_defaults_and_artifact_indexes_do_not_prevent_exact_match(self):
        historic = self.api.raw['runs'][0]['results'][0]
        historic['locations'][0]['physicalLocation']['region'].pop('endLine')
        historic['locations'][0]['physicalLocation']['artifactLocation']['index'] = 99
        self.assertIsNotNone(self.link()[0]['first_seen'])

    def test_missing_fingerprint_coordinates_and_changed_flow_remain_unknown(self):
        original = copy.deepcopy(self.api.raw)
        mutations = [lambda r: r.pop('partialFingerprints'),
                     lambda r: r['partialFingerprints'].update(primaryLocationLineHash='changed'),
                     lambda r: r['locations'][0]['physicalLocation']['region'].update(startLine=11),
                     lambda r: r['locations'][0]['physicalLocation']['region'].pop('startColumn'),
                     lambda r: r['codeFlows'][0]['threadFlows'][0]['locations'][0]['location']['physicalLocation']['region'].update(startColumn=4)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.api.raw = copy.deepcopy(original)
                mutate(self.api.raw['runs'][0]['results'][0])
                self.assertIsNone(self.link()[0]['first_seen'])

    def test_wrong_rule_tool_invalid_missing_or_future_provider_dates_remain_unknown(self):
        original = copy.deepcopy(self.api.alerts)
        for change in [{'rule': {'id': 'other'}}, {'tool': {'name': 'other'}}, {'created_at': None},
                       {'created_at': '2027-01-01T00:00:00Z'}, {'created_at': '2026-01-01T00:00:00'}]:
            with self.subTest(change=change):
                self.api.alerts = copy.deepcopy(original)
                self.api.alerts[0].update(change)
                self.assertIsNone(self.link()[0]['first_seen'])

    def test_ambiguous_provider_identities_remain_unknown(self):
        other = copy.deepcopy(self.api.raw['runs'][0]['results'][0])
        other['properties']['github/alertNumber'] = 8
        self.api.raw['runs'][0]['results'].append(other)
        self.api.analyses[0]['results_count'] = 2
        self.api.alerts.append({**self.api.alerts[0], 'number': 8})
        self.assertIsNone(self.link()[0]['first_seen'])
        ledger = sast.strict_json((self.root / 'codeql-first-seen-history.json').read_bytes())
        self.assertEqual(ledger['unmatched'][0]['reason'], 'ambiguous-history')

    def test_partial_foreign_or_failed_analysis_cannot_supply_history(self):
        original = copy.deepcopy(self.api.raw)
        for mutate in [lambda r: r['versionControlProvenance'][0].update(revisionId='c' * 40),
                       lambda r: r['versionControlProvenance'][0].update(branch='refs/pull/115/merge'),
                       lambda r: r['invocations'][0].update(executionSuccessful=False),
                       lambda r: r['properties'].update(resultsTruncated=True)]:
            with self.subTest(mutate=mutate):
                self.api.raw = copy.deepcopy(original)
                mutate(self.api.raw['runs'][0])
                with self.assertRaises(ValueError):self.link()

    def test_duplicate_alert_inventory_and_provider_outage_fail_closed(self):
        self.api.alerts.append(copy.deepcopy(self.api.alerts[0]))
        with self.assertRaises(ValueError):self.link()
        with patch.object(self.api, 'pages', side_effect=OSError('provider unavailable')):
            with self.assertRaises(OSError):self.link()

    def test_current_report_mismatch_and_conflicting_date_rejected(self):
        with self.assertRaises(ValueError):
            sast.link_codeql_history(self.api, self.root, REV, '2.0.58', [])
        findings = sast.sarif_findings(self.raw, 'codeql', REV, '2.0.58', local_codeql=True)
        changed = [{**findings[0], 'component': 'other.go'}]
        with self.assertRaises(ValueError):
            sast.link_codeql_history(self.api, self.root, REV, '2.0.58', changed)
        findings[0]['first_seen'] = '2026-02-01T00:00:00Z'
        with self.assertRaises(ValueError):
            sast.link_codeql_history(self.api, self.root, REV, '2.0.58', findings)


if __name__ == '__main__':
    unittest.main()

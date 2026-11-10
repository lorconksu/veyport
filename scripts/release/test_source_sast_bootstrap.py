"""Independent source export/history/pagination/inventory tests for main tooling."""
import copy
import datetime as dt
import unittest
import tempfile
import io
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import source_sast as sast

REV = 'a' * 40


def sarif():
    return {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'CodeQL'}, 'extensions': [{'rules': [{'id': 'go/auth', 'properties': {'security-severity': '3.0', 'tags': ['external/cwe/cwe-287']}}]}]}, 'automationDetails': {'id': '/language:go/'}, 'versionControlProvenance': [{'branch': 'refs/heads/main', 'revisionId': REV, 'repositoryUri': 'https://github.com/lorconksu/veyport'}], 'results': [{'ruleId': 'go/auth', 'properties': {'github/alertNumber': 7}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'hub/auth.go'}, 'region': {'startLine': 10, 'endLine': 10, 'startColumn': 3, 'endColumn': 9}}}]}]}]}


def provider_alert(number=7, state='dismissed', dismissed_reason="won't fix", **changes):
    value = {'number': number, 'created_at': '2026-01-01T00:00:00Z', 'state': state,
        'dismissed_reason': dismissed_reason, 'tool': {'name': 'CodeQL'}, 'rule': {'id': 'go/auth'},
        'most_recent_instance': {'ref': 'refs/heads/main', 'analysis_key': sast.CODEQL_DEFAULT_KEY,
            'category': '/language:go', 'commit_sha': REV, 'state': 'open',
            'location': {'path': 'hub/auth.go', 'start_line': 10, 'end_line': 10,
                         'start_column': 3, 'end_column': 9}}}
    value.update(changes)
    return value


class SourceEvidenceTests(unittest.TestCase):
    def test_historical_semgrep_sarif_decoder_is_retained(self):
        raw = sarif()
        raw['runs'][0]['tool']['driver']['name'] = 'Semgrep OSS'
        findings = sast.sarif_findings(raw, 'semgrep', REV, '2.0.58')
        self.assertEqual(findings[0]['scanner'], 'semgrep')
        self.assertEqual(findings[0]['classification'], 'authentication')
        self.assertIsNone(findings[0]['first_seen'])

    def test_collection_requires_only_retained_scanners_and_preserves_each_export_failure(self):
        for failed in (None, "codeql", "sonar", "review"):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = root / 'candidate.json'
                manifest.write_text('{}')
                args = SimpleNamespace(output=root / 'raw', assessment=root / 'assessment.json',
                    candidate_id='candidate-1', revision=REV, version='2.0.58',
                    artifact_manifest=manifest, sonar_branch='main', root=root)
                with patch.object(sast, 'export_codeql', side_effect=ValueError('missing exact CodeQL') if failed == 'codeql' else None, return_value=[]), \
                     patch.object(sast, 'export_sonar', side_effect=ValueError('failed Sonar gate') if failed == 'sonar' else None, return_value=[]), \
                     patch.object(sast, 'suppression_inventory', return_value={'configurations': [], 'annotations': []}), \
                     patch.object(sast, 'reviewed_inventory', side_effect=ValueError('review absent') if failed == 'review' else None, return_value={'id': 'CR-test'}) as historical_review:
                    result = sast.collect(args, api=object(), sonar=object())
                historical_review.assert_not_called()
                evidence = sast.strict_json(args.assessment.read_bytes())
                self.assertEqual(evidence['coverage_policy']['technical_status'], 'completed')
                for exported in evidence['scopes']:
                    self.assertEqual(exported['technical_coverage_complete'], exported['status'] == 'completed')
                self.assertEqual(evidence['required_scopes'], ['source:sast:codeql', 'source:sast:sonar'])
                self.assertEqual({s['id'] for s in evidence['scopes']}, set(evidence['required_scopes']))
                if failed in ('codeql', 'sonar'):
                    self.assertFalse(result)
                    scope = next(s for s in evidence['scopes'] if s['id'] == 'source:sast:' + failed)
                    self.assertEqual(scope['status'], 'failed')
                    self.assertFalse(scope['authenticated'])
                    self.assertFalse(scope['coverage_complete'])
                elif failed in (None, "review"):
                    self.assertEqual(evidence['coverage_policy']['status'], 'pending-owner-policy-review')
                    self.assertTrue(all(not s['coverage_complete'] for s in evidence['scopes']))
                if failed in (None, 'review'):
                    self.assertTrue(result)
                    self.assertTrue(all(s['authenticated'] for s in evidence['scopes']))
                    self.assertTrue(all(s['technical_coverage_complete'] for s in evidence['scopes']))
                    # Honest technical completion plus pending policy is not a
                    # release pass or a repository-provided approval.

    def test_missing_optional_codeql_adapter_retains_failed_assessment_without_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); manifest = root / 'candidate.json'; manifest.write_text('{}')
            args = SimpleNamespace(output=root / 'raw', assessment=root / 'assessment.json', candidate_id='candidate-1',
                revision=REV, version='2.0.58', artifact_manifest=manifest, sonar_branch='main', root=root,
                codeql_evidence=root / 'provided-codeql')
            with patch.dict('sys.modules', {'codeql_evidence': None}), \
                    patch.object(sast, 'export_codeql', side_effect=AssertionError('no fallback')) as cloud, \
                    patch.object(sast, 'export_sonar', return_value=[]), \
                    patch.object(sast, 'suppression_inventory', return_value={'configurations': [], 'annotations': []}):
                self.assertFalse(sast.collect(args, api=object(), sonar=object()))
            cloud.assert_not_called()
            assessment = sast.strict_json(args.assessment.read_bytes())
            self.assertEqual(assessment, sast.strict_json((args.output / 'assessment.json').read_bytes()))
            codeql = next(scope for scope in assessment['scopes'] if scope['id'] == 'source:sast:codeql')
            self.assertEqual(assessment['status'], 'failed')
            self.assertEqual(codeql['status'], 'failed')
            self.assertFalse(codeql['authenticated'])
            self.assertFalse(codeql['coverage_complete'])
            self.assertFalse(codeql['technical_coverage_complete'])
            self.assertEqual(assessment['coverage_policy']['status'], 'pending-owner-policy-review')
            self.assertTrue(all(not scope['coverage_complete'] for scope in assessment['scopes']))

    def test_available_optional_consumer_dispatch_and_import_failure_stay_controlled(self):
        for broken in (False, True):
            with self.subTest(broken=broken), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); manifest = root / 'candidate.json'; manifest.write_text('{}'); calls = []
                args = SimpleNamespace(output=root / 'raw', assessment=root / 'assessment.json', candidate_id='candidate-1',
                    revision=REV, version='2.0.58', artifact_manifest=manifest, sonar_branch='main', root=root,
                    codeql_evidence=root / 'provided-codeql')
                def consume(*values):
                    calls.append(values)
                    if broken: raise ImportError('private dependency detail')
                    return []
                with patch.dict('sys.modules', {'codeql_evidence': SimpleNamespace(consume=consume)}), \
                        patch.object(sast, 'export_codeql', side_effect=AssertionError('no fallback')), \
                        patch.object(sast, 'export_sonar', return_value=[]), \
                        patch.object(sast, 'suppression_inventory', return_value={'configurations': [], 'annotations': []}):
                    self.assertEqual(sast.collect(args, api=object(), sonar=object()), not broken)
                self.assertEqual(calls, [(args.codeql_evidence, manifest, root, args.output, REV, '2.0.58', 'candidate-1')])
                assessment = sast.strict_json(args.assessment.read_bytes())
                self.assertNotIn('private dependency detail', args.assessment.read_text())
                self.assertEqual(assessment['status'], 'failed' if broken else 'completed')
                self.assertEqual(assessment['coverage_policy']['status'], 'pending-owner-policy-review')
                self.assertTrue(all(not scope['coverage_complete'] for scope in assessment['scopes']))

    def test_inventory_failure_fails_assessment_without_changing_scanner_truth(self):
        inventory = {'configurations': [], 'annotations': []}
        errors = [ValueError('private inventory detail'), OSError('private inventory detail'),
                  KeyError('private inventory detail'), TypeError('private inventory detail'), 'archive']
        for error in errors:
            with self.subTest(error=type(error).__name__ if error != 'archive' else error), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); manifest = root / 'candidate.json'; manifest.write_text('{}')
                args = SimpleNamespace(output=root / 'raw', assessment=root / 'assessment.json',
                    candidate_id='candidate-1', revision=REV, version='2.0.58',
                    artifact_manifest=manifest, sonar_branch='main', root=root)
                original_save = sast.save
                def save(destination, name, value):
                    if error == 'archive' and name == 'source-policy-inventory.json':
                        raise OSError('private inventory detail')
                    return original_save(destination, name, value)
                with patch.object(sast, 'export_codeql', return_value=[]), \
                        patch.object(sast, 'export_sonar', return_value=[]), \
                        patch.object(sast, 'suppression_inventory', return_value=inventory,
                                     side_effect=None if error == 'archive' else error), \
                        patch.object(sast, 'save', side_effect=save):
                    result = sast.collect(args, api=object(), sonar=object())
                assessment = sast.strict_json(args.assessment.read_bytes())
                self.assertEqual(assessment, sast.strict_json((args.output / 'assessment.json').read_bytes()))
                self.assertEqual(assessment['status'], 'failed')
                self.assertIs(result, False)
                self.assertEqual(assessment['coverage_policy']['technical_status'], 'failed')
                self.assertEqual(assessment['coverage_policy']['status'], 'pending-owner-policy-review')
                self.assertEqual(assessment['coverage_policy']['inventory_sha256'],
                                 sast.sha(sast.canonical(inventory)) if error == 'archive' else None)
                self.assertEqual(assessment['required_scopes'], ['source:sast:codeql', 'source:sast:sonar'])
                self.assertEqual(len(assessment['scopes']), 2)
                self.assertTrue(all(scope['status'] == 'completed' and scope['authenticated']
                                    and scope['technical_coverage_complete'] and not scope['coverage_complete']
                                    for scope in assessment['scopes']))
                self.assertFalse((args.output / 'source-policy-inventory.json').exists())
                self.assertNotIn('private inventory detail', args.assessment.read_text())

    def test_inventory_cli_failure_preserves_envelope_and_verified_inventory_still_completes(self):
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); manifest = root / 'candidate.json'; manifest.write_text('{}')
                argv = ['source_sast.py', '--output', str(root / 'raw'), '--assessment', str(root / 'assessment.json'),
                        '--revision', REV, '--version', '2.0.58', '--candidate-id', 'candidate-1',
                        '--artifact-manifest', str(manifest), '--sonar-branch', 'main', '--root', str(root)]
                with patch('sys.argv', argv), patch('sys.stderr', new_callable=io.StringIO) as stderr, \
                        patch.object(sast, 'ExportAPI', return_value=object()), \
                        patch.object(sast, 'Sonar', return_value=object()), \
                        patch.object(sast, 'export_codeql', return_value=[]), \
                        patch.object(sast, 'export_sonar', return_value=[]), \
                        patch.object(sast, 'suppression_inventory', return_value={'configurations': [], 'annotations': []},
                                     side_effect=ValueError('private inventory detail') if failed else None):
                    if failed:
                        with self.assertRaises(SystemExit) as stopped:
                            sast.main()
                        self.assertEqual(stopped.exception.code, 1)
                        self.assertIn('full-baseline SAST export incomplete; publication prohibited', stderr.getvalue())
                    else:
                        self.assertIsNone(sast.main())
                        self.assertEqual(stderr.getvalue(), '')
                assessment = sast.strict_json((root / 'assessment.json').read_bytes())
                self.assertEqual(assessment, sast.strict_json((root / 'raw/assessment.json').read_bytes()))
                self.assertEqual(assessment['status'], 'failed' if failed else 'completed')
                self.assertEqual(assessment['coverage_policy']['technical_status'], 'failed' if failed else 'completed')
                self.assertEqual(assessment['coverage_policy']['status'], 'pending-owner-policy-review')
                self.assertTrue(all(scope['technical_coverage_complete'] and not scope['coverage_complete']
                                    for scope in assessment['scopes']))
                self.assertNotIn('private inventory detail', stderr.getvalue())

    def test_missing_optional_adapter_cli_exits_controlled_and_keeps_envelope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); manifest = root / 'candidate.json'; manifest.write_text('{}')
            argv = ['source_sast.py', '--output', str(root / 'raw'), '--assessment', str(root / 'assessment.json'),
                '--revision', REV, '--version', '2.0.58', '--candidate-id', 'candidate-1',
                '--artifact-manifest', str(manifest), '--sonar-branch', 'main', '--root', str(root),
                '--codeql-evidence', str(root / 'provided-codeql')]
            with patch.dict('sys.modules', {'codeql_evidence': None}), patch('sys.argv', argv), \
                    patch('sys.stderr', new_callable=io.StringIO) as stderr, \
                    patch.object(sast, 'Sonar', return_value=object()), \
                    patch.object(sast, 'export_sonar', return_value=[]), \
                    patch.object(sast, 'suppression_inventory', return_value={'configurations': [], 'annotations': []}), \
                    self.assertRaises(SystemExit) as stopped:
                sast.main()
            self.assertEqual(stopped.exception.code, 1)
            self.assertIn('publication prohibited', stderr.getvalue())
            self.assertNotIn('Traceback', stderr.getvalue())
            self.assertEqual(sast.strict_json((root / 'assessment.json').read_bytes())['status'], 'failed')

    def test_public_reader_omits_credentials_and_uses_fixed_https_without_redirects(self):
        api = sast.Sonar(public_project=True)
        response = lambda: io.BytesIO(b'{"component":{"key":"lorconksu_veyport","visibility":"public"}}')
        with patch.dict(sast.os.environ, {"SONAR_TOKEN": "private-analysis-credential"}), patch.object(sast.urllib.request, 'build_opener') as opener:
            requests = [('components/show', {'component': sast.PROJECT}), ('issues/search', {'componentKeys': sast.PROJECT}),
                        ('qualitygates/project_status', {'analysisId': 'analysis-1'}), ('project_pull_requests/list', {'project': sast.PROJECT}),
                        ('hotspots/search', {'projectKey': sast.PROJECT}), ('project_analyses/search', {'project': sast.PROJECT}),
                        ('ce/component', {'component': sast.PROJECT})]
            opener.return_value.open.side_effect = [response() for _ in range(len(requests) + 1)]
            for endpoint, params in requests:
                api.get(endpoint, params)
            with self.assertRaises(ValueError):
                api.get('ce/task', {'id': 'task-1'})
            calls = opener.return_value.open.call_args_list
            public_request = calls[0].args[0]
            self.assertEqual(public_request.full_url, 'https://sonarcloud.io/api/components/show?component=lorconksu_veyport')
            for call in calls:
                request = call.args[0]
                self.assertIsNone(request.get_header('Authorization'))
                self.assertNotIn('private-analysis-credential', str(request.header_items()) + request.full_url)
                self.assertTrue(request.full_url.startswith('https://sonarcloud.io/api/'))
            self.assertIsNone(calls[-1].args[0].get_header('Authorization'))
            self.assertTrue(all(isinstance(call.args[0], sast.NoRedirect) for call in opener.call_args_list))
        self.assertIsNone(sast.NoRedirect().redirect_request(None, None, 302, None, None, 'https://elsewhere.example'))

    def test_public_reader_rejects_other_projects_and_unknown_endpoints_before_transport(self):
        api = sast.Sonar(public_project=True)
        with patch.object(sast.urllib.request, 'build_opener') as opener:
            for endpoint, params in [('issues/search', {'componentKeys': 'other'}), ('projects/search', {}), ('qualitygates/project_status', {'analysisId': '../other'}), ('components/show', {'component': sast.PROJECT + ',other'}), ('ce/component', {'component': 'other'}),
                                     ('ce/component', {'component': sast.PROJECT, 'additionalFields': 'scannerContext'}), ('ce/task', {'id': 'task-1'})]:
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
                return {'paging': {'total': 0, 'pageIndex': params['p'], 'pageSize': params['ps']}, key: []}
        with tempfile.TemporaryDirectory() as directory:
            api = API()
            self.assertEqual(sast.export_sonar(api, directory, REV, '2.0.58', 'main', public_project=True), [])
            self.assertEqual(api.statuses, 'OPEN,CONFIRMED,FALSE_POSITIVE,ACCEPTED,FIXED')
            readback = sast.strict_json((Path(directory) / 'sonar-inventory-readback.json').read_bytes())
            self.assertEqual(set(readback), {'issues/search', 'hotspots/search'})
            self.assertTrue(all(value['observations'] == 2 and value['immutable_snapshot'] is False for value in readback.values()))
            for field, value in [('visibility', 'private'), ('revision', 'b' * 40), ('gate', 'ERROR')]:
                api = API();setattr(api, field, value)
                with self.assertRaises(ValueError):
                    sast.export_sonar(api, directory, REV, '2.0.58', 'main', public_project=True)

    def test_baseline_including_dismissed_and_auth_failure_preserved(self):
        alerts = [provider_alert()]
        result = sast.sarif_findings(sarif(), 'codeql', REV, '2.0.58', alerts)
        self.assertEqual(result[0]['severity'], 'low')
        self.assertEqual(result[0]['classification'], 'authentication')
        self.assertTrue(result[0]['suppressed'])
        self.assertEqual(result[0]['first_seen'], '2026-01-01T00:00:00Z')

    def test_sarif_effective_suppression_requires_explicit_accepted_and_preserves_records(self):
        cases = [(None, False), ([], False), ([{'kind': 'inSource'}], False),
            ([{'kind': 'external', 'status': 'accepted'}], True),
            ([{'kind': 'inSource', 'status': 'underReview'}], False),
            ([{'kind': 'external', 'status': 'rejected'}], False),
            ([{'kind': 'inSource', 'status': 'rejected'}, {'kind': 'external', 'status': 'accepted'}], True)]
        for records, expected in cases:
            with self.subTest(records=records):
                raw = sarif(); raw['runs'][0]['results'][0]['suppressions'] = copy.deepcopy(records)
                before = copy.deepcopy(raw)
                finding = sast.sarif_findings(raw, 'codeql', REV, '2.0.58')[0]
                self.assertEqual(finding['suppressed'], expected)
                self.assertEqual(finding['sarif_suppressions'], records)
                self.assertEqual(raw, before)
                if records:
                    raw['runs'][0]['results'][0]['suppressions'][0]['status'] = 'rejected'
                    self.assertEqual(finding['sarif_suppressions'], records)
        raw = sarif()
        finding = sast.sarif_findings(raw, 'codeql', REV, '2.0.58')[0]
        self.assertFalse(finding['suppressed'])
        self.assertIsNone(finding['sarif_suppressions'])

    def test_malformed_suppression_metadata_cannot_be_accepted(self):
        cases = ['accepted', True, {}, [None], ['accepted'], [{}], [{'kind': 'other', 'status': 'accepted'}],
                 [{'kind': 'inSource', 'status': None}], [{'kind': 'external', 'status': True}],
                 [{'kind': 'inSource', 'status': 'unknown'}], [{'kind': 'external', 'status': []}]]
        for records in cases:
            with self.subTest(records=records):
                raw = sarif();raw['runs'][0]['results'][0]['suppressions'] = records
                with self.assertRaises(ValueError): sast.sarif_findings(raw, 'codeql', REV, '2.0.58')

    def test_duplicate_api_alerts_rejected_even_identical_or_across_pages(self):
        first = provider_alert(state='open')
        for second in (copy.deepcopy(first), {**first, 'state': 'dismissed', 'dismissed_reason': 'false positive'}):
            with self.subTest(second=second), self.assertRaises(ValueError):
                sast.sarif_findings(sarif(), 'codeql', REV, '2.0.58', [first, second])
            api = sast.ExportAPI.__new__(sast.ExportAPI)
            pages = [[provider_alert(number=n, state='open', most_recent_instance={**first['most_recent_instance'], 'location': {**first['most_recent_instance']['location'], 'path': 'hub/auth.go' if n == 7 else f'hub/other{n}.go'}}) for n in range(1, 101)], [second]]
            with patch.object(api, 'get', side_effect=pages) as get:
                rows = api.pages('code-scanning/alerts?ref=refs%2Fheads%2Fmain')
            self.assertEqual(get.call_count, 2)
            with self.assertRaises(ValueError): sast.sarif_findings(sarif(), 'codeql', REV, '2.0.58', rows)

    def test_api_and_explicit_sarif_alert_ids_require_positive_integers(self):
        for number in (True, False, None, 0, -1, '7', 7.0):
            with self.subTest(number=number):
                with self.assertRaises(ValueError):
                    sast.sarif_findings(sarif(), 'codeql', REV, '2.0.58', [provider_alert(number=number)])
                raw = sarif();raw['runs'][0]['results'][0]['properties']['github/alertNumber'] = number
                with self.assertRaises(ValueError): sast.sarif_findings(raw, 'codeql', REV, '2.0.58', [provider_alert(number=1)])
                with self.assertRaises(ValueError): sast._codeql_history_alert_map([{'number': number}])
        for invalid in (None, [], 'properties'):
            raw = sarif();raw['runs'][0]['results'][0]['properties'] = invalid
            with self.assertRaises(ValueError): sast.sarif_findings(raw, 'codeql', REV, '2.0.58')
        raw = sarif();raw['runs'][0]['results'][0]['properties'].pop('github/alertNumber')
        finding = sast.sarif_findings(raw, 'codeql', REV, '2.0.58')[0]
        self.assertTrue(finding['id'].startswith('go/auth:'))
        self.assertIsNone(finding['provider_state'])

    def test_stale_dismissal_reason_cannot_reclassify_open_or_fixed_alert(self):
        for state in ('open', 'fixed'):
            for status in ('accepted', 'underReview', 'rejected'):
                with self.subTest(state=state, status=status):
                    raw = sarif();raw['runs'][0]['results'][0]['suppressions'] = [{'kind': 'external', 'status': status}]
                    finding = sast.sarif_findings(raw, 'codeql', REV, '2.0.58',
                        [provider_alert(state=state, dismissed_reason='false positive')])[0]
                    self.assertEqual(finding['classification'], 'authentication')
                    self.assertEqual(finding['suppressed'], status == 'accepted')
                    self.assertEqual(finding['provider_state'], state)
        for reason, classification in [('false positive', 'false-positive'), ('used in tests', 'not-affected'), ("won't fix", 'authentication')]:
            finding = sast.sarif_findings(sarif(), 'codeql', REV, '2.0.58',
                [provider_alert(dismissed_reason=reason)])[0]
            self.assertTrue(finding['suppressed'])
            self.assertEqual(finding['classification'], classification)

    def test_history_binding_includes_preserved_suppression_status(self):
        raw = sarif();raw['runs'][0]['results'][0]['suppressions'] = [{'kind': 'external', 'status': 'underReview'}]
        normalized = sast.sarif_findings(raw, 'codeql', REV, '2.0.58')
        changed = copy.deepcopy(normalized)
        changed[0]['sarif_suppressions'][0]['status'] = 'rejected'
        self.assertTrue(sast._codeql_history_inventory_matches(normalized, normalized))
        self.assertFalse(sast._codeql_history_inventory_matches(changed, normalized))

    def test_wrong_revision_incomplete_execution_and_missing_rule_fail(self):
        for mutate in (lambda r: r['runs'][0]['versionControlProvenance'][0].update(revisionId='b' * 40), lambda r: r['runs'][0].update(invocations=[{'executionSuccessful': False}]), lambda r: r['runs'][0]['tool'].update(extensions=[])):
            raw = sarif()
            mutate(raw)
            with self.assertRaises(ValueError):
                sast.sarif_findings(raw, 'codeql', REV, '2.0.58')

    def test_sarif_false_positive_does_not_disappear(self):
        raw = sarif()
        raw['runs'][0]['results'][0]['suppressions'] = [{'kind': 'external'}]
        result = sast.sarif_findings(raw, 'codeql', REV, '2.0.58', [provider_alert(dismissed_reason='false positive')])
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
        with patch.object(api, 'get', side_effect=[{'paging': {'total': 2, 'pageIndex': 1, 'pageSize': 1}, 'issues': [{'key': 'one'}]}, {'paging': {'total': 2, 'pageIndex': 2, 'pageSize': 1}, 'issues': []}]):
            with self.assertRaises(ValueError):
                api.pages('issues/search', {}, 'issues')

    def test_sonar_current_revision_can_not_replace_historic_evidence(self):
        api = sast.Sonar()
        completed = dt.datetime.now(dt.timezone.utc).isoformat()
        def get(endpoint, _params):
            if endpoint == 'project_branches/list':
                return {'branches': [{'name': 'main', 'type': 'LONG', 'isMain': True, 'commit': {'sha': REV}}]}
            if endpoint == 'project_analyses/search':
                return {'analyses': [{'revision': 'b' * 40, 'key': 'historical-analysis', 'date': completed}]}
            if endpoint == 'qualitygates/project_status':
                return {'projectStatus': {'status': 'OK'}}
            raise AssertionError(endpoint)
        with tempfile.TemporaryDirectory() as directory, patch.object(api, 'get', side_effect=get) as reads, \
                patch.object(api, 'pages', return_value=([], [])) as pages:
            with self.assertRaisesRegex(ValueError, '^latest full Sonar branch analysis must match candidate$'):
                sast.export_sonar(api, directory, REV, '2.0.58', 'main')
            self.assertEqual([call.args[0] for call in reads.call_args_list],
                             ['project_branches/list', 'project_analyses/search'])
            pages.assert_not_called()
            self.assertEqual(list(Path(directory).iterdir()), [])

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

    def test_frontend_measurement_configuration_and_toolchain_are_bound(self):
        names = ['web/vitest.config.ts', 'web/vite.config.ts', 'web/tsconfig.json',
                 'web/tsconfig.app.json', 'web/tsconfig.node.json', 'web/package.json',
                 'web/package-lock.json', 'web/.gitignore', 'web/.npmrc',
                 'web/vitest.workspace.ts', 'web/vitest.config.mts']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'web').mkdir()
            for name in names:
                (root / name).write_text('original measurement policy\n')
            with patch.object(sast.subprocess, 'check_output', return_value=('\0'.join(names) + '\0').encode()):
                before = sast.suppression_inventory(root)
                self.assertEqual({c['path'] for c in before['configurations']}, set(names))
                for name in names:
                    with self.subTest(name=name):
                        path = root / name
                        path.write_text('changed measurement policy\n')
                        after = sast.suppression_inventory(root)
                        self.assertNotEqual(sast.sha(sast.canonical(before)), sast.sha(sast.canonical(after)))
                        path.write_text('original measurement policy\n')
            tracked = names[:-1]
            with patch.object(sast.subprocess, 'check_output', return_value=('\0'.join(tracked) + '\0').encode()):
                removed = sast.suppression_inventory(root)
            self.assertNotEqual(before, removed)
            with patch.object(sast.subprocess, 'check_output', return_value=('\0'.join(names) + '\0').encode()):
                self.assertEqual(before, sast.suppression_inventory(root))

    def test_coverage_hints_bind_previously_unannotated_frontend_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'web/src').mkdir(parents=True)
            path = root / 'web/src/example.tsx'
            plain = 'export const value = () => 1\n'
            path.write_text(plain)
            with patch.object(sast.subprocess, 'check_output', return_value=b'web/src/example.tsx\0'):
                original = sast.suppression_inventory(root)
                self.assertEqual(original['annotations'], [])
                for prefix in ('c8', 'v8', 'istanbul', 'node:coverage'):
                    for hint in ('if', 'else', 'next', 'file', 'start', 'stop'):
                        with self.subTest(prefix=prefix, hint=hint):
                            marker = f'/* {prefix} ignore {hint} */\n'
                            path.write_text(marker + plain)
                            added = sast.suppression_inventory(root)
                            self.assertEqual(len(added['annotations']), 1)
                            annotation = added['annotations'][0]
                            self.assertEqual(annotation['scanners'], ['coverage-v8'])
                            self.assertEqual(annotation['line'], 1)
                            self.assertEqual(annotation['annotation_sha256'], sast.sha(marker.rstrip('\n').encode()))
                            self.assertEqual(annotation['source_sha256'], sast.sha(path.read_bytes()))
                            self.assertNotEqual(original, added)
                            path.write_text(marker + plain.replace('1', '2'))
                            self.assertNotEqual(added, sast.suppression_inventory(root))
                            path.write_text(marker.replace(hint, hint + ' changed rationale') + plain)
                            self.assertNotEqual(added, sast.suppression_inventory(root))
                            path.write_text(plain)
                            self.assertEqual(original, sast.suppression_inventory(root))

    def test_coverage_hint_candidates_include_multiline_and_raw_text_provider_forms(self):
        source = ('/**\n\ufeffistanbul\n ignore\n next */\n'
                  'export const text = "prefixv8 ignore start"\n'
                  '/* node:coverage ignore stop: explanation */\n'
                  '/* c8 ignore nextish */\n'
                  '/* v8 ignore file_suffix */\n')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'web/src').mkdir(parents=True)
            path = root / 'web/src/example.tsx'
            path.write_text(source)
            with patch.object(sast.subprocess, 'check_output', return_value=b'web/src/example.tsx\0'):
                annotations = sast.suppression_inventory(root)['annotations']
            self.assertEqual([a['line'] for a in annotations], [2, 5, 6])
            self.assertTrue(all(a['scanners'] == ['coverage-v8'] for a in annotations))
            path.write_text(source.replace('\n', '\r'))
            with patch.object(sast.subprocess, 'check_output', return_value=b'web/src/example.tsx\0'):
                self.assertEqual([a['line'] for a in sast.suppression_inventory(root)['annotations']], [2, 5, 6])

    def test_measurement_inventory_selected_files_fail_closed(self):
        for name in ('web/vitest.config.ts', 'web/package-lock.json', 'web/src/example.tsx',
                     'infra/evidence-viewer/viewer.py', 'scripts/release/private_review.py',
                     '.github/workflows/private-risk-approval.yml'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / name
                path.parent.mkdir(parents=True)
                tracked = (name + '\0').encode()
                with patch.object(sast.subprocess, 'check_output', return_value=tracked):
                    with self.assertRaisesRegex(ValueError, 'source policy inventory is incomplete'):
                        sast.suppression_inventory(root)
                    target = root / 'target'
                    target.write_text('/* c8 ignore file */\n')
                    path.symlink_to(target)
                    with self.assertRaisesRegex(ValueError, 'source policy inventory is incomplete'):
                        sast.suppression_inventory(root)
                    path.unlink()
                    path.write_bytes(b' ' * ((4 << 20) + 1))
                    with self.assertRaisesRegex(ValueError, 'source policy inventory is incomplete'):
                        sast.suppression_inventory(root)

    def test_policy_inventory_binds_full_scan_workflow_and_helper_configuration(self):
        names = ['.github/workflows/delivery.yml', '.github/workflows/staging.yml', '.github/workflows/release.yml', 'scripts/release/codeql_evidence.py', 'scripts/release/sonar_context.py', 'scripts/release/source_sast.py', 'scripts/release/scan_contract.py', 'scripts/release/release_policy.py']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('full scanner configuration\n')
            with patch.object(sast.subprocess, 'check_output', return_value=('\0'.join(names) + '\0').encode()):
                before = sast.suppression_inventory(root)
                self.assertEqual({c['path'] for c in before['configurations']}, set(names))
                reviews = root / 'reviews'
                reviews.mkdir()
                (reviews / 'CR-0001.md').write_text('historical review fixture')
                old_hash = sast.sha(sast.canonical(before))
                for name in names:
                    with self.subTest(configuration=name):
                        path = root / name
                        path.write_text('changed queries or active scanner policy\n')
                        after = sast.suppression_inventory(root)
                        new_hash = sast.sha(sast.canonical(after))
                        self.assertNotEqual(old_hash, new_hash)
                        with patch.object(sast, 'load_record', return_value=({'inventory_sha256': old_hash}, None)), \
                             patch.object(sast, 'verify', side_effect=AssertionError('stale review must not be authenticated')):
                            with self.assertRaisesRegex(ValueError, 'needs owner policy review'):
                                sast.reviewed_inventory(new_hash, reviews, object())
                        path.write_text('full scanner configuration\n')

    def test_all_active_language_roots_bind_python_and_suppression_candidates(self):
        names = ['infra/evidence-viewer/viewer.py', 'infra/evidence-collector/evidence.py',
                 'scripts/native-candidate/run.py', 'scripts/unlisted-helper.py', 'future/component.py']
        markers = ('# codeql[py/path-injection] rationale', '# CoDeQL [py/path-injection] rationale',
                   '# lgtm[py/path-injection] rationale', '# LGTM [py/path-injection]',
                   '# CODEQL disable example', '# CodeQL suppress example',
                   '# noqa', '# noqa: F401', '# NOQA', '# nosec', '# NOSEC B602', '# NOSONAR')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('def run(): return 1\n')
            with patch.object(sast.subprocess, 'check_output', return_value=('\0'.join(names) + '\0').encode()):
                before = sast.suppression_inventory(root)
                self.assertEqual(before['schema_version'], 2)
                self.assertEqual(before['sources'], sorted(names))
                self.assertEqual(before['annotations'], [])
                for name in names:
                    path = root / name
                    for marker in markers:
                        with self.subTest(path=name, marker=marker):
                            path.write_text(marker + '\ndef run(): return 1\n')
                            annotated = sast.suppression_inventory(root)
                            self.assertNotEqual(before, annotated)
                            row = next(item for item in annotated['annotations'] if item['path'] == name)
                            self.assertEqual(row['source_sha256'], sast.sha(path.read_bytes()))
                            self.assertEqual(row['annotation_sha256'], sast.sha(marker.encode()))
                            expected = 'python-suppression' if 'noqa' in marker.lower() or 'nosec' in marker.lower() else 'sonar' if 'NOSONAR' in marker else 'codeql'
                            self.assertIn(expected, row['scanners'])
                            path.write_text(marker + '\ndef run(): return 2\n')
                            self.assertNotEqual(annotated, sast.suppression_inventory(root))
                            path.write_text('def run(): return 1\n')
                            self.assertEqual(before, sast.suppression_inventory(root))
                # An ordinary unannotated source edit remains candidate-bound,
                # not a new whole-code coverage approval requirement.
                (root / 'future/component.py').write_text('def run(): return 2\n')
                self.assertEqual(before, sast.suppression_inventory(root))

    def test_scanned_language_extensions_and_source_path_inventory_are_complete(self):
        names = ['new/package.go', 'new/handler.py', 'new/component.jsx', 'new/component.mts',
                 'new/component.cts', 'new/template.vue', 'new/page.html', 'new/schema.json',
                 'new/workflow.yml', 'new/config.xml', 'new/module.rb', 'new/template.erb',
                 'new/project.gemspec', 'ruby/Gemfile', 'tools/local-action/action.yaml', 'proto/generated.pb.go']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('source text\n')
            tracked = ('\0'.join(names) + '\0').encode()
            with patch.object(sast.subprocess, 'check_output', return_value=tracked):
                before = sast.suppression_inventory(root)
            self.assertEqual(before['sources'], sorted(names))
            with patch.object(sast.subprocess, 'check_output', return_value=('\0'.join(names[:-1]) + '\0').encode()):
                self.assertNotEqual(before, sast.suppression_inventory(root))

    def test_new_workflows_policy_helpers_and_nested_configs_invalidate_old_review(self):
        names = ['.github/workflows/private-risk-approval.yml', '.github/workflows/risk-approval.yml',
                 '.github/workflows/future-policy.yaml', 'custom/action.yml', '.github/codeql/new.qls',
                 'scripts/release/private_review.py', 'scripts/release/risk_acceptance.py',
                 'scripts/release/evidence_manifest.py', 'scripts/release/publication.py',
                 'scripts/security/future-scan.sh', 'scripts/native-candidate/run.py', 'scripts/review/dual_review.py',
                 'infra/evidence-viewer/.snyk', 'infra/evidence-viewer/pyproject.toml', '.gitleaks.toml', 'Makefile']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('original policy configuration\n')
            with patch.object(sast.subprocess, 'check_output', return_value=('\0'.join(names) + '\0').encode()):
                before = sast.suppression_inventory(root)
                self.assertEqual({item['path'] for item in before['configurations']}, set(names))
                old_hash = sast.sha(sast.canonical(before))
                reviews = root / 'reviews'
                reviews.mkdir()
                (reviews / 'CR-0001.md').write_text('historical exact-inventory fixture')
                for name in names:
                    with self.subTest(path=name):
                        path = root / name
                        path.write_text('changed policy configuration\n')
                        after = sast.suppression_inventory(root)
                        new_hash = sast.sha(sast.canonical(after))
                        self.assertNotEqual(old_hash, new_hash)
                        with patch.object(sast, 'load_record', return_value=({'inventory_sha256': old_hash}, None)), \
                             patch.object(sast, 'verify', side_effect=AssertionError('stale review cannot be used')):
                            with self.assertRaisesRegex(ValueError, 'needs owner policy review'):
                                sast.reviewed_inventory(new_hash, reviews, object())
                        path.write_text('original policy configuration\n')

    def test_frontend_script_variants_bind_coverage_ignore_hints(self):
        names = ['web/src/component' + suffix for suffix in ('.jsx', '.mjs', '.cjs', '.mts', '.cts')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('export const value = 1\n')
            with patch.object(sast.subprocess, 'check_output', return_value=('\0'.join(names) + '\0').encode()):
                before = sast.suppression_inventory(root)
                for name in names:
                    path = root / name
                    path.write_text('/* v8 ignore next */\nexport const value = 1\n')
                    after = sast.suppression_inventory(root)
                    self.assertNotEqual(before, after)
                    row = next(item for item in after['annotations'] if item['path'] == name)
                    self.assertIn('coverage-v8', row['scanners'])
                    self.assertEqual(row['source_sha256'], sast.sha(path.read_bytes()))
                    path.write_text('export const value = 1\n')

    def test_inventory_rejects_linked_parent_fifo_duplicate_and_aggregate_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'real'
            target.mkdir()
            (target / 'source.py').write_text('# noqa\n')
            (root / 'infra').symlink_to(target, target_is_directory=True)
            with patch.object(sast.subprocess, 'check_output', return_value=b'infra/source.py\0'):
                with self.assertRaisesRegex(ValueError, 'source policy inventory is incomplete'):
                    sast.suppression_inventory(root)
            import os
            os.mkfifo(root / 'fifo.py')
            with patch.object(sast.subprocess, 'check_output', return_value=b'fifo.py\0'):
                with self.assertRaisesRegex(ValueError, 'source policy inventory is incomplete'):
                    sast.suppression_inventory(root)
            with patch.object(sast.subprocess, 'check_output', return_value=b'real/source.py\0real/source.py\0'):
                with self.assertRaisesRegex(ValueError, 'source policy inventory is incomplete'):
                    sast.suppression_inventory(root)
            with patch.object(sast.subprocess, 'check_output', return_value=b'real/source.py\0'):
                with patch.object(sast, 'MAX_INVENTORY_TOTAL', 1), self.assertRaisesRegex(ValueError, 'source policy inventory is incomplete'):
                    sast.suppression_inventory(root)
                with patch.object(sast, 'MAX_INVENTORY_FILES', 0), self.assertRaisesRegex(ValueError, 'source policy inventory is incomplete'):
                    sast.suppression_inventory(root)

    def test_codeql_missing_language_is_incomplete_not_clean(self):
        api = sast.ExportAPI('test-token')
        with patch.object(api, 'pages', return_value=[]), patch.object(sast, 'default_codeql_configuration', return_value={}):
            with self.assertRaises(ValueError):
                sast.export_codeql(api, '.', REV, '2.0.58')


class CodeQLCorrelationTests(unittest.TestCase):
    def finding(self, raw=None, alerts=None):
        return sast.sarif_findings(raw or sarif(), 'codeql', REV, '2.0.58',
            [provider_alert(dismissed_reason='false positive')] if alerts is None else alerts)

    def test_referenced_alert_must_match_rule_and_tool_before_any_metadata(self):
        for key, value in [('rule', {'id': 'go/other'}), ('tool', {'name': 'Other'})]:
            with self.subTest(key=key):
                alert = provider_alert(**{key: value})
                with self.assertRaisesRegex(ValueError, 'correlat'):
                    self.finding(alerts=[alert])

    def test_primary_file_and_every_precise_coordinate_are_independent(self):
        for key, value in [('path', 'hub/other.go'), ('start_line', 9), ('end_line', 11),
                           ('start_column', 2), ('end_column', 10)]:
            with self.subTest(key=key):
                alert = provider_alert();alert['most_recent_instance']['location'][key] = value
                with self.assertRaisesRegex(ValueError, 'correlat'):
                    self.finding(alerts=[alert])

    def test_duplicate_sarif_alert_numbers_reject_across_results_runs_or_no_provider(self):
        for across_runs in (False, True):
            for alerts in ([], [provider_alert()]):
                with self.subTest(runs=across_runs, alerts=bool(alerts)):
                    raw = sarif()
                    if across_runs:raw['runs'].append(copy.deepcopy(raw['runs'][0]))
                    else:raw['runs'][0]['results'].append(copy.deepcopy(raw['runs'][0]['results'][0]))
                    with self.assertRaisesRegex(ValueError, 'duplicate SARIF alert'):
                        self.finding(raw, alerts)

    def test_current_scope_commit_and_missing_proof_cannot_borrow_state_or_date(self):
        for key, value in [('ref', 'refs/pull/115/merge'), ('analysis_key', 'other:upload'),
                           ('category', '/language:python'), ('commit_sha', 'b' * 40),
                           ('location', None)]:
            with self.subTest(key=key):
                alert = provider_alert();alert['most_recent_instance'][key] = value
                with self.assertRaisesRegex(ValueError, 'correlat'):
                    self.finding(alerts=[alert])
        for key in ('rule', 'tool', 'most_recent_instance'):
            with self.subTest(missing=key):
                alert = provider_alert();alert.pop(key)
                with self.assertRaisesRegex(ValueError, 'correlat'):
                    self.finding(alerts=[alert])

    def test_same_primary_distinct_alerts_or_flows_are_ambiguous(self):
        first = provider_alert();second = provider_alert(number=8, state='open')
        with self.assertRaisesRegex(ValueError, 'ambiguous.*correlat'):
            self.finding(alerts=[first, second])
        raw = sarif();other = copy.deepcopy(raw['runs'][0]['results'][0]);other['properties'].pop('github/alertNumber')
        other['codeFlows'] = [{'threadFlows': []}];raw['runs'][0]['results'].append(other)
        with self.assertRaisesRegex(ValueError, 'ambiguous.*correlat'):
            self.finding(raw, [first])
        # Without a provider association, independent results stay intact. Only
        # explicit accepted SARIF suppression is effective, as before.
        raw['runs'][0]['results'][0]['suppressions'] = [{'kind': 'external', 'status': 'accepted'}]
        findings = self.finding(raw, [])
        self.assertEqual(len(findings), 2)
        self.assertEqual([row['suppressed'] for row in findings], [True, False])
        self.assertTrue(all(row['first_seen'] is None and row['provider_state'] is None for row in findings))

    def test_legitimate_multiple_results_locations_flows_and_global_dismissal(self):
        raw = sarif();result = raw['runs'][0]['results'][0]
        result['locations'].append(copy.deepcopy(result['locations'][0]))
        result['locations'][1]['physicalLocation']['artifactLocation']['uri'] = 'hub/related.go'
        result['codeFlows'] = [{'threadFlows': [{'locations': [{'location': copy.deepcopy(location)} for location in result['locations']]}]}]
        other = copy.deepcopy(result);other['properties']['github/alertNumber'] = 8
        other['locations'][0]['physicalLocation']['artifactLocation']['uri'] = 'hub/other.go'
        raw['runs'][0]['results'].append(other)
        alert = provider_alert(dismissed_reason='false positive');second = provider_alert(number=8, state='open')
        second['most_recent_instance']['location']['path'] = 'hub/other.go'
        findings = self.finding(raw, [alert, second])
        self.assertEqual(len(findings), 2)
        self.assertEqual([row['suppressed'] for row in findings], [True, False])
        self.assertEqual([row['provider_state'] for row in findings], ['dismissed', 'open'])
        self.assertEqual(findings[0]['classification'], 'false-positive')
        self.assertTrue(all(row['first_seen'] == '2026-01-01T00:00:00Z' for row in findings))
        # The official REST example uses dismissed alert / open latest instance.
        self.assertEqual(alert['most_recent_instance']['state'], 'open')

    def test_documented_sarif_defaults_and_provider_line_only_columns(self):
        for columns in ({'start_column': 0, 'end_column': 0}, {}, {'start_column': 1, 'end_column': 0}):
            with self.subTest(columns=columns):
                raw = sarif();raw['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region'] = {'startLine': 10}
                alert = provider_alert();location = alert['most_recent_instance']['location']
                location.pop('start_column');location.pop('end_column');location.update(columns)
                self.assertTrue(self.finding(raw, [alert])[0]['suppressed'])
        raw = sarif();raw['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region'].pop('endLine')
        raw['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region'].pop('startColumn')
        alert = provider_alert();alert['most_recent_instance']['location']['start_column'] = 1
        self.assertTrue(self.finding(raw, [alert])[0]['suppressed'])

    def test_unknown_columns_cannot_match_a_precise_range_or_invent_a_default(self):
        for columns in ({'start_column': 0, 'end_column': 0}, {}, {'start_column': 0, 'end_column': 9}, {'start_column': 3}):
            with self.subTest(columns=columns):
                alert = provider_alert();location = alert['most_recent_instance']['location']
                location.pop('start_column');location.pop('end_column');location.update(columns)
                with self.assertRaisesRegex(ValueError, 'correlat'):
                    self.finding(alerts=[alert])

    def test_relative_uri_decoding_is_explicit_and_unresolved_aliases_reject(self):
        raw = sarif();raw['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'] = 'hub/auth%20test.go'
        alert = provider_alert();alert['most_recent_instance']['location']['path'] = 'hub/auth test.go'
        self.assertTrue(self.finding(raw, [alert])[0]['suppressed'])
        for change in ({'uriBaseId': '%SRCROOT%'}, {'uri': 'file:///tmp/hub/auth.go'},
                       {'uri': 'hub/../hub/auth.go'}, {'uri': 'hub/auth.go?query'}, {'uri': 'hub/auth%ZZ.go'},
                       {'index': 99}):
            with self.subTest(change=change):
                raw = sarif();raw['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation'].update(change)
                with self.assertRaisesRegex(ValueError, 'correlat'):
                    self.finding(raw)

    def test_malformed_coordinates_never_alias_integers(self):
        for key, value in [('start_line', True), ('end_line', '10'), ('start_column', False), ('end_column', -1)]:
            with self.subTest(key=key):
                alert = provider_alert();alert['most_recent_instance']['location'][key] = value
                with self.assertRaisesRegex(ValueError, 'correlat'):
                    self.finding(alerts=[alert])

    def test_real_default_export_and_collection_fail_closed_on_a_mutated_match(self):
        class API:
            def __init__(self, wrong=False):
                self.analyses, self.reports = [], {}
                self.alerts = [provider_alert()]
                if wrong:self.alerts[0]['most_recent_instance']['location']['path'] = 'hub/unrelated.go'
                for index, category in enumerate(sorted(sast.CODEQL_CATEGORIES), 1):
                    raw = sarif();raw['runs'][0]['automationDetails']['id'] = category + '/'
                    if category != '/language:go':raw['runs'][0]['results'] = []
                    self.reports[index] = raw
                    self.analyses.append({'id': index, 'category': category, 'ref': 'refs/heads/main',
                        'analysis_key': sast.CODEQL_DEFAULT_KEY, 'commit_sha': REV,
                        'created_at': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                        'tool': {'name': 'CodeQL'}, 'results_count': len(raw['runs'][0]['results'])})
            def get(self, path):
                if path != 'code-scanning/default-setup':raise AssertionError(path)
                return {'state': 'configured', 'languages': [key.split(':', 1)[1] for key in sorted(sast.CODEQL_CATEGORIES)],
                        'query_suite': 'default', 'updated_at': '2026-01-01T00:00:00Z'}
            def pages(self, path):
                if path == 'code-scanning/analyses?tool_name=CodeQL&ref=refs%2Fheads%2Fmain':return copy.deepcopy(self.analyses)
                if path == 'code-scanning/alerts?ref=refs%2Fheads%2Fmain':return copy.deepcopy(self.alerts)
                raise AssertionError(path)
            def sarif(self, identity):return copy.deepcopy(self.reports[identity])
        for wrong in (False, True):
            with self.subTest(wrong=wrong), tempfile.TemporaryDirectory() as directory:
                root = Path(directory);manifest = root / 'candidate.json';manifest.write_text('{}')
                args = SimpleNamespace(output=root / 'raw', assessment=root / 'assessment.json',
                    artifact_manifest=manifest, candidate_id='candidate-1', revision=REV, version='2.0.58',
                    sonar_branch='main', root=root)
                with patch.object(sast, 'export_sonar', return_value=[]), patch.object(sast, 'suppression_inventory', return_value={'configurations': [], 'annotations': []}):
                    completed = sast.collect(args, api=API(wrong), sonar=object())
                assessment = sast.strict_json(args.assessment.read_bytes())
                scope = next(item for item in assessment['scopes'] if item['id'] == 'source:sast:codeql')
                self.assertEqual(completed, not wrong)
                self.assertEqual(scope['status'], 'failed' if wrong else 'completed')
                self.assertEqual(scope['authenticated'], not wrong)
                self.assertEqual(len(scope['findings']), 0 if wrong else 1)
                self.assertTrue((root / 'raw/codeql-alerts.json').is_file())
                self.assertTrue(list((root / 'raw').glob('codeql-*.sarif')))
                self.assertEqual(assessment['coverage_policy']['status'], 'pending-owner-policy-review')

    def test_consistent_direct_uri_and_artifact_index_are_supported(self):
        raw = sarif();run = raw['runs'][0]
        artifact = run['results'][0]['locations'][0]['physicalLocation']['artifactLocation']
        artifact['index'] = 0
        run['artifacts'] = [{'location': copy.deepcopy(artifact)}]
        self.assertTrue(self.finding(raw)[0]['suppressed'])
        for change in ({'uri': 'hub/unrelated.go'}, {'index': 1}, {'index': False}, {'uriBaseId': '%SRCROOT%'}):
            with self.subTest(change=change):
                changed = copy.deepcopy(raw);changed['runs'][0]['artifacts'][0]['location'].update(change)
                with self.assertRaisesRegex(ValueError, 'correlat'):
                    self.finding(changed)
        for index in (True, -1, 1, '0'):
            with self.subTest(index=index):
                changed = copy.deepcopy(raw)
                changed['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['index'] = index
                with self.assertRaisesRegex(ValueError, 'correlat'):
                    self.finding(changed)

    def test_malformed_association_objects_fail_with_a_controlled_error(self):
        for key, value in [('commit_sha', None), ('category', None), ('location', []),
                           ('location', {'path': 'hub/auth.go', 'start_line': 10, 'end_line': 10, 'start_column': 1.0, 'end_column': 0}),
                           ('location', {'path': 'hub/auth.go', 'start_line': 10, 'end_line': 10, 'start_column': None, 'end_column': None})]:
            with self.subTest(key=key, value=value):
                alert = provider_alert();alert['most_recent_instance'][key] = value
                with self.assertRaisesRegex(ValueError, 'correlat'):
                    self.finding(alerts=[alert])
        for field, value in [('physicalLocation', None)]:
            raw = sarif();raw['runs'][0]['results'][0]['locations'][0][field] = value
            with self.assertRaisesRegex(ValueError, 'correlat'):
                self.finding(raw)

    def test_no_provider_or_unmatched_reference_does_not_gain_api_metadata(self):
        for alerts in ([], [provider_alert(number=8)]):
            finding = self.finding(alerts=alerts)[0]
            self.assertFalse(finding['suppressed'])
            self.assertIsNone(finding['first_seen'])
            self.assertIsNone(finding['provider_state'])


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
                self.alerts = [provider_alert(dismissed_reason='false positive')]
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

    def test_current_provider_coordinates_and_context_are_required_for_history_dates(self):
        original = copy.deepcopy(self.api.alerts)
        for key, value in [('ref', 'refs/pull/115/merge'), ('analysis_key', 'other:upload'),
                           ('category', '/language:python'), ('location', {'path': 'hub/other.go', 'start_line': 10, 'end_line': 10, 'start_column': 3, 'end_column': 9})]:
            with self.subTest(key=key):
                self.api.alerts = copy.deepcopy(original)
                self.api.alerts[0]['most_recent_instance'][key] = value
                self.assertIsNone(self.link()[0]['first_seen'])
                ledger = sast.strict_json((self.root / 'codeql-first-seen-history.json').read_bytes())
                self.assertIn('correlation', ledger['sources'][0]['alert_correlation_error'])
                self.assertEqual(ledger['matches'], [])
        self.api.alerts = copy.deepcopy(original)
        # Latest provider instance is for current REV, historical SARIF is for
        # the older b... source; exact primary identity still supports history.
        self.assertNotEqual(self.api.alerts[0]['most_recent_instance']['commit_sha'], self.api.analyses[0]['commit_sha'])
        self.assertIsNotNone(self.link()[0]['first_seen'])

    def test_different_provider_alert_at_same_primary_does_not_lend_history_date(self):
        self.api.alerts.append(provider_alert(number=8))
        self.assertIsNone(self.link()[0]['first_seen'])
        ledger = sast.strict_json((self.root / 'codeql-first-seen-history.json').read_bytes())
        self.assertIn('ambiguous', ledger['sources'][0]['alert_correlation_error'])
        self.assertEqual(ledger['matches'], [])

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

    def test_coordinate_defaults_match_but_unresolved_artifact_index_is_unknown(self):
        historic = self.api.raw['runs'][0]['results'][0]
        historic['locations'][0]['physicalLocation']['region'].pop('endLine')
        self.assertIsNotNone(self.link()[0]['first_seen'])
        historic['locations'][0]['physicalLocation']['artifactLocation']['index'] = 99
        self.assertIsNone(self.link()[0]['first_seen'])
        ledger = sast.strict_json((self.root / 'codeql-first-seen-history.json').read_bytes())
        self.assertIn('URI alias unresolved', ledger['sources'][0]['alert_correlation_error'])

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
        self.assertEqual(ledger['unmatched'][0]['reason'], 'no-exact-history')
        self.assertIn('ambiguous', ledger['sources'][0]['alert_correlation_error'])
        self.assertEqual(ledger['matches'], [])

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


class SonarPaginationTests(unittest.TestCase):
    @staticmethod
    def page(rows, total, index=1, size=2, key='issues'):
        return {'paging': {'pageIndex': index, 'pageSize': size, 'total': total},
                key: [({'key': value, 'component': 'same-file', 'rule': 'same-rule'} if isinstance(value, str) else value)
                      for value in rows]}

    def test_legitimate_clamped_pagination_and_reordered_readback_match_inventory(self):
        first = [self.page(['one', 'two'], 3), self.page(['three'], 3, index=2)]
        repeated = [self.page(['three', 'one'], 3), self.page(['two'], 3, index=2)]
        api = sast.Sonar()
        with patch.object(api, 'get', side_effect=first + repeated) as get:
            rows, pages = api.pages('issues/search', {}, 'issues')
        self.assertEqual([row['key'] for row in rows], ['one', 'two', 'three'])
        self.assertEqual(pages, first)
        self.assertEqual([call.args[1]['p'] for call in get.call_args_list], [1, 2, 1, 2])
        self.assertTrue(all(call.args[1]['ps'] == 500 for call in get.call_args_list))
        proof = api.inventory_readback['issues/search']
        self.assertEqual((proof['total'], proof['page_size'], proof['observations']), (3, 2, 2))
        self.assertFalse(proof['immutable_snapshot'])
        self.assertNotEqual(proof['page_sha256'], proof['readback_page_sha256'])

    def test_empty_inventory_still_requires_complete_readback(self):
        api = sast.Sonar()
        empty = self.page([], 0, size=500)
        with patch.object(api, 'get', side_effect=[empty, empty]) as get:
            rows, pages = api.pages('issues/search', {}, 'issues')
        self.assertEqual(rows, [])
        self.assertEqual(pages, [empty])
        self.assertEqual(get.call_count, 2)

    def test_duplicate_ids_in_page_or_across_pages_never_fill_reported_total(self):
        for key, endpoint in [('issues', 'issues/search'), ('hotspots', 'hotspots/search')]:
            variants = [[self.page(['one', 'one'], 2, key=key)],
                        [self.page(['one', 'two'], 3, key=key), self.page(['one'], 3, index=2, key=key)]]
            for pages in variants:
                api = sast.Sonar()
                with self.subTest(key=key, pages=len(pages)), patch.object(api, 'get', side_effect=pages) as get:
                    with self.assertRaises(ValueError): api.pages(endpoint, {}, key)
                    self.assertEqual(get.call_count, len(pages))  # no retry hides the duplicate
                    self.assertNotIn(endpoint, api.inventory_readback)

    def test_malformed_finding_id_is_rejected_for_both_endpoints(self):
        invalid = [None, '', True, 7, {}, [], 'two words', 'newline\nkey', 'x'*129, 'path/../identity', 'é']
        for key, endpoint in [('issues', 'issues/search'), ('hotspots', 'hotspots/search')]:
            for identity in invalid:
                api = sast.Sonar()
                with self.subTest(key=key, identity=identity), patch.object(api, 'get', return_value=self.page([{'key': identity}], 1, key=key)):
                    with self.assertRaises(ValueError): api.pages(endpoint, {}, key)
        for row in [None, [], 'not-an-object', {}]:
            malformed = self.page([], 1)
            malformed['issues'] = [row]
            with self.subTest(row=row), patch.object(sast.Sonar, 'get', return_value=malformed):
                with self.assertRaises(ValueError): sast.Sonar().pages('issues/search', {}, 'issues')

    def test_malformed_page_metadata_and_row_counts_fail_closed(self):
        initial = self.page(['one'], 1)
        mutations = [lambda value: value.pop('paging'), lambda value: value.update(paging=[]),
                     lambda value: value['paging'].update(total=True), lambda value: value['paging'].update(total=-1),
                     lambda value: value['paging'].update(total=50_001), lambda value: value['paging'].update(pageIndex=True),
                     lambda value: value['paging'].update(pageIndex=2), lambda value: value['paging'].update(pageSize=0),
                     lambda value: value['paging'].update(pageSize=501), lambda value: value['paging'].update(pageSize=True),
                     lambda value: value.update(issues={}), lambda value: value.update(issues=[]),
                     lambda value: value['issues'].append({'key': 'extra'})]
        for mutate in mutations:
            value = copy.deepcopy(initial)
            mutate(value)
            with self.subTest(value=value), patch.object(sast.Sonar, 'get', return_value=value):
                with self.assertRaises(ValueError): sast.Sonar().pages('issues/search', {}, 'issues')

    def test_page_total_size_and_progress_drift_are_rejected(self):
        first = self.page(['one'], 2, size=1)
        variants = [self.page(['two'], 3, index=2, size=1),
                    self.page([], 2, index=2, size=2),
                    self.page(['two'], 2, index=1, size=1),
                    self.page([], 2, index=2, size=1)]
        for second in variants:
            with self.subTest(second=second), patch.object(sast.Sonar, 'get', side_effect=[first, second]):
                with self.assertRaises(ValueError): sast.Sonar().pages('issues/search', {}, 'issues')

    def test_readback_rejects_member_content_or_total_changes_at_same_analysis(self):
        first = self.page(['one', 'two'], 2)
        changed_content = copy.deepcopy(first)
        changed_content['issues'][0]['issueStatus'] = 'FALSE_POSITIVE'
        variants = [self.page(['one', 'replacement'], 2), changed_content,
                    self.page(['one'], 1), self.page(['one', 'two'], 2, size=3)]
        for repeated in variants:
            with self.subTest(repeated=repeated), patch.object(sast.Sonar, 'get', side_effect=[first, repeated]) as get:
                with self.assertRaises(ValueError): sast.Sonar().pages('issues/search', {}, 'issues')
                self.assertEqual(get.call_count, 2)

    def test_bounds_cover_total_items_and_cumulative_page_bytes(self):
        with patch.object(sast, 'MAX_SONAR_PAGES', 2), patch.object(sast.Sonar, 'get', return_value=self.page(['one'], 3, size=1)):
            with self.assertRaises(ValueError): sast.Sonar().pages('issues/search', {}, 'issues')
        first, second = self.page(['one'], 2, size=1), self.page(['two'], 2, size=1, index=2)
        maximum = len(sast.canonical(first)) + len(sast.canonical(second)) - 1
        with patch.object(sast, 'MAX_SONAR_INVENTORY_BYTES', maximum), patch.object(sast.Sonar, 'get', side_effect=[first, second]) as get:
            with self.assertRaises(ValueError): sast.Sonar().pages('issues/search', {}, 'issues')
            self.assertEqual(get.call_count, 2)

    def test_failed_later_export_cannot_reuse_prior_stability_proof(self):
        api = sast.Sonar()
        value = self.page(['one'], 1)
        with patch.object(api, 'get', side_effect=[value, value]):
            api.pages('issues/search', {}, 'issues')
        self.assertIn('issues/search', api.inventory_readback)
        with patch.object(api, 'get', return_value=self.page(['one', 'one'], 2)):
            with self.assertRaises(ValueError): api.pages('issues/search', {}, 'issues')
        self.assertNotIn('issues/search', api.inventory_readback)


class SonarDirectArchiveTests(unittest.TestCase):
    @staticmethod
    def wire(severity='MAJOR'):
        value = {'paging': {'pageIndex': 1, 'pageSize': 500, 'total': 1},
                 'issues': [{'key': 'issue-one', 'severity': severity}]}
        return b' \n' + sast.canonical(value) + b'\n'

    @staticmethod
    def prefix():
        branches = {'branches': [{'name': 'main', 'type': 'LONG', 'isMain': True}]}
        analysis = {'analyses': [{'key': 'analysis-one', 'revision': REV,
                                  'date': dt.datetime.now(dt.timezone.utc).isoformat()}]}
        return [io.BytesIO(sast.canonical(branches)), io.BytesIO(sast.canonical(analysis))]

    def export(self, root, responses):
        with patch.dict(sast.os.environ, {'SONAR_TOKEN': 'synthetic-credential-never-archive'}), \
                patch.object(sast.urllib.request, 'build_opener') as opener:
            opener.return_value.open.side_effect = self.prefix() + responses
            api = sast.Sonar()
            with self.assertRaises((ValueError, urllib.error.HTTPError)):
                sast.export_sonar(api, root, REV, '2.0.58', 'main')
            self.assertNotIn('issues/search', api.inventory_readback)
            self.assertFalse((root/'sonar-inventory-readback.json').exists())
            self.assertIsNone(api._page_capture)
            self.assertIsNone(api._page_archive_budget)
            return opener.return_value.open.call_count

    def test_failed_direct_export_retains_both_exact_wire_versions_and_unique_attempts(self):
        first, second = self.wire(), self.wire('CRITICAL')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for _ in range(2):
                self.assertEqual(self.export(root, [io.BytesIO(first), io.BytesIO(second)]), 4)
            attempts = list((root/'sonar-page-attempts').iterdir())
            self.assertEqual(len(attempts), 2)
            for attempt in attempts:
                self.assertEqual(attempt.stat().st_mode & 0o077, 0)
                self.assertEqual((attempt/'initial-page-1.body').read_bytes(), first)
                self.assertEqual((attempt/'readback-page-1.body').read_bytes(), second)
                for name, raw in [('initial-page-1', first), ('readback-page-1', second)]:
                    receipt = sast.strict_json((attempt/(name+'.json')).read_bytes())
                    self.assertEqual(receipt['representation'], 'wire')
                    self.assertFalse(receipt['truncated'])
                    self.assertEqual(receipt['received_bytes'], len(raw))
                    self.assertEqual(receipt['sha256'], sast.sha(raw))
                for path in attempt.iterdir():
                    self.assertEqual(path.stat().st_mode & 0o077, 0)
                    self.assertNotIn(b'synthetic-credential-never-archive', path.read_bytes())
                    self.assertNotIn(b'Authorization', path.read_bytes())

    def test_malformed_readback_is_saved_before_json_parsing_fails(self):
        malformed = b'{"paging": {"total": 1}, "issues": ['
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.export(root, [io.BytesIO(self.wire()), io.BytesIO(malformed)])
            self.assertEqual(next(root.glob('sonar-page-attempts/*/readback-page-1.body')).read_bytes(), malformed)

    def test_http_error_body_is_private_but_exception_url_and_request_headers_are_not_saved(self):
        raw = b'{"error":"temporary provider failure"}'
        error = urllib.error.HTTPError('https://private.invalid/?credential=not-archived', 503,
                                       'sensitive exception diagnostic', {}, io.BytesIO(raw))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.export(root, [io.BytesIO(self.wire()), error])
            body = next(root.glob('sonar-page-attempts/*/readback-page-1.body'))
            self.assertEqual(body.read_bytes(), raw)
            receipt = sast.strict_json(body.with_suffix('.json').read_bytes())
            self.assertEqual(receipt['http_status'], 503)
            for path in root.rglob('*'):
                if path.is_file():
                    self.assertNotIn(b'not-archived', path.read_bytes())
                    self.assertNotIn(b'sensitive exception diagnostic', path.read_bytes())

    def test_shared_byte_budget_records_truncation_and_preserves_prior_response(self):
        first, second = self.wire(), self.wire('CRITICAL')
        maximum = len(first) + len(second) - 1
        with tempfile.TemporaryDirectory() as directory, patch.object(sast, 'MAX_SONAR_ARCHIVE_BYTES', maximum):
            root = Path(directory)
            self.export(root, [io.BytesIO(first), io.BytesIO(second)])
            attempt = next((root/'sonar-page-attempts').iterdir())
            self.assertEqual((attempt/'initial-page-1.body').read_bytes(), first)
            self.assertEqual((attempt/'readback-page-1.body').read_bytes(), second[:-1])
            receipt = sast.strict_json((attempt/'readback-page-1.json').read_bytes())
            self.assertTrue(receipt['truncated'])
            self.assertEqual(receipt['received_bytes'], len(second))
            self.assertEqual(sum(path.stat().st_size for path in attempt.glob('*.body')), maximum)

    def test_page_budget_records_unrequested_readback_without_more_transport(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(sast, 'MAX_SONAR_ARCHIVE_PAGES', 1):
            root = Path(directory)
            self.assertEqual(self.export(root, [io.BytesIO(self.wire())]), 3)
            attempt = next((root/'sonar-page-attempts').iterdir())
            self.assertTrue((attempt/'initial-page-1.body').exists())
            self.assertFalse((attempt/'readback-page-1.body').exists())
            receipt = sast.strict_json((attempt/'readback-page-1.json').read_bytes())
            self.assertEqual(receipt['status'], 'not-requested')
            self.assertEqual(receipt['reason'], 'archive-budget-exhausted')

    def test_raw_byte_budget_is_shared_across_issue_and_hotspot_attempts(self):
        issue = self.wire()
        hotspot = sast.canonical({'paging': {'pageIndex': 1, 'pageSize': 500, 'total': 1},
                                  'hotspots': [{'key': 'hotspot-one'}]})
        maximum = 2 * len(issue) + 2 * len(hotspot) - 1
        with tempfile.TemporaryDirectory() as directory, patch.object(sast, 'MAX_SONAR_ARCHIVE_BYTES', maximum):
            root = Path(directory)
            with patch.dict(sast.os.environ, {'SONAR_TOKEN': 'fixture'}), patch.object(sast.urllib.request, 'build_opener') as opener:
                opener.return_value.open.side_effect = self.prefix() + [io.BytesIO(raw) for raw in (issue, issue, hotspot, hotspot)]
                with self.assertRaises(ValueError): sast.export_sonar(sast.Sonar(), root, REV, '2.0.58', 'main')
                self.assertEqual(opener.return_value.open.call_count, 6)
            self.assertEqual(sum(path.stat().st_size for path in root.glob('sonar-page-attempts/*/*.body')), maximum)
            receipt = next(root.glob('sonar-page-attempts/hotspots-*/readback-page-1.json'))
            self.assertTrue(sast.strict_json(receipt.read_bytes())['truncated'])
            self.assertFalse((root/'sonar-inventory-readback.json').exists())

    def test_no_response_body_records_unavailability_without_private_exception_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            error = urllib.error.URLError('private transport context')
            with patch.dict(sast.os.environ, {'SONAR_TOKEN': 'fixture'}), patch.object(sast.urllib.request, 'build_opener') as opener:
                opener.return_value.open.side_effect = self.prefix() + [io.BytesIO(self.wire()), error]
                with self.assertRaises(urllib.error.URLError): sast.export_sonar(sast.Sonar(), root, REV, '2.0.58', 'main')
            receipt = next(root.glob('sonar-page-attempts/*/readback-page-1.json'))
            value = sast.strict_json(receipt.read_bytes())
            self.assertEqual(value['status'], 'response-unavailable')
            self.assertIsNone(value['received_bytes'])  # transport may have lost an unreturned partial body
            self.assertNotIn(b'private transport context', receipt.read_bytes())




class SonarClassificationExportTests(unittest.TestCase):
    """Exercise export/pagination and exact classification; release decisions stay separate.

    Native auth/permission/traceability and their CWE members are defined by:
    https://github.com/SonarSource/sonarqube/blob/master/server/sonar-server-common/src/main/java/org/sonar/server/security/SecurityStandards.java
    Issues inherit rule tags (including custom tags); names/messages alone are
    not classification evidence:
    https://docs.sonarsource.com/sonarqube-server/quality-standards-administration/managing-rules/built-in-rule-tags
    """
    def setUp(self):
        self.at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.created = (self.at - dt.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')

    def issue(self, tags, level='MEDIUM', **fields):
        return {'key': 'issue1', 'rule': 'python:Sfixture', 'component': 'project:file.py',
                'type': 'VULNERABILITY', 'issueStatus': 'OPEN', 'tags': tags,
                'creationDate': self.created, 'impacts': [{'softwareQuality': 'SECURITY', 'severity': level}], **fields}

    def hotspot(self, category, level='MEDIUM', **fields):
        return {'key': 'hotspot1', 'ruleKey': 'python:Sfixture', 'component': 'project:file.py',
                'securityCategory': category, 'vulnerabilityProbability': level,
                'status': 'TO_REVIEW', 'creationDate': self.created, **fields}

    def export(self, issue=None, hotspot=None):
        completed = self.at.isoformat()
        class API(sast.Sonar):
            def __init__(self):
                pass
            def get(self, endpoint, params):
                if endpoint == 'project_branches/list':
                    return {'branches': [{'name': 'main', 'isMain': True, 'type': 'LONG'}]}
                if endpoint == 'project_analyses/search':
                    return {'analyses': [{'key': 'analysis1', 'revision': REV, 'date': completed}]}
                if endpoint == 'qualitygates/project_status':
                    return {'projectStatus': {'status': 'OK'}}
                key, row = {'issues/search': ('issues', issue), 'hotspots/search': ('hotspots', hotspot)}[endpoint]
                return {'paging': {'pageIndex': params['p'], 'pageSize': params['ps'], 'total': int(row is not None)},
                        key: [copy.deepcopy(row)] if row is not None else []}
        with tempfile.TemporaryDirectory() as directory:
            findings = sast.export_sonar(API(), directory, REV, '2.0.58', 'main')
            for kind, row in [('issues', issue), ('hotspots', hotspot)]:
                raw = sast.strict_json((Path(directory) / ('sonar-' + kind + '.json')).read_bytes())
                self.assertEqual(raw[0][kind], [row] if row is not None else [])
            self.assertTrue((Path(directory) / 'sonar-inventory-readback.json').exists())
            return findings


    def assert_classified(self, findings, classification, level):
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['classification'], classification)
        self.assertEqual(findings[0]['severity'], level.lower())
        self.assertEqual(findings[0]['first_seen'], self.created)

    def test_security_info_impact_matches_legacy_info_export(self):
        modern = self.export(issue=self.issue(['auth'], 'INFO'))
        legacy = self.export(issue=self.issue(['auth'], impacts=[], severity='INFO'))
        self.assert_classified(modern, 'authentication', 'INFO')
        self.assertEqual(modern, legacy)

    def test_info_impact_does_not_override_stronger_security_severity(self):
        for level, expected in [('LOW', 'low'), ('MEDIUM', 'medium'), ('HIGH', 'high'), ('BLOCKER', 'critical')]:
            for levels in [('INFO', level), (level, 'INFO')]:
                with self.subTest(levels=levels):
                    issue = self.issue(['permission'], impacts=[{'softwareQuality': 'SECURITY', 'severity': value}
                                                               for value in levels])
                    findings = self.export(issue=issue)
                    self.assertEqual(findings[0]['severity'], expected)
                    self.assertEqual(findings[0]['classification'], 'authorization')
        issue = self.issue(['auth'], 'INFO')
        issue['impacts'].append({'softwareQuality': 'MAINTAINABILITY', 'severity': 'BLOCKER'})
        self.assertEqual(self.export(issue=issue)[0]['severity'], 'info')

    def test_unknown_security_impact_is_not_defaulted_to_info(self):
        with self.assertRaisesRegex(ValueError, 'unknown Sonar security severity'):
            self.export(issue=self.issue(['auth'], 'UNSUPPORTED'))

    def test_invalid_security_impact_alongside_info_never_falls_back_to_legacy(self):
        for invalid in ('UNSUPPORTED', '', None, True, {}, []):
            for levels in [('INFO', invalid), (invalid, 'INFO')]:
                with self.subTest(levels=levels), self.assertRaisesRegex(ValueError, 'unknown Sonar security severity'):
                    issue = self.issue([], severity='INFO', impacts=[{'softwareQuality': 'SECURITY', 'severity': value}
                                                                    for value in levels])
                    self.export(issue=issue)
        with self.assertRaisesRegex(ValueError, 'unknown Sonar security severity'):
            self.export(issue=self.issue([], severity='INFO', impacts=[{'softwareQuality': 'SECURITY', 'severity': 'INFO'},
                                                                       {'softwareQuality': 'SECURITY'}]))

    def test_native_rule_tags_classify_medium_and_low(self):
        for token, classification in [('auth', 'authentication'), ('authentication', 'authentication'),
                                      ('permission', 'authorization'), ('authz', 'authorization'),
                                      ('authorization', 'authorization'), ('traceability', 'required-audit')]:
            for level in ('MEDIUM', 'LOW'):
                with self.subTest(token=token, level=level):
                    self.assert_classified(self.export(issue=self.issue(['  ' + token.upper() + '  '], level)), classification, level)

    def test_native_hotspot_categories_classify_medium_and_low(self):
        for token, classification in [('auth', 'authentication'), ('permission', 'authorization'), ('traceability', 'required-audit')]:
            for level in ('MEDIUM', 'LOW'):
                with self.subTest(token=token, level=level):
                    self.assert_classified(self.export(hotspot=self.hotspot(token, level)), classification, level)

    def test_inherited_internal_rule_metadata_is_not_dropped(self):
        self.assert_classified(self.export(issue=self.issue(['security'], 'LOW', internalTags=['auth'])), 'authentication', 'LOW')

    def test_native_category_cwe_members_and_formats_classify(self):
        members = {'authentication': (287, 306, 307, 308, 290, 294, 798, 640, 620, 549, 522, 521, 263, 262, 261, 259),
                   'authorization': (285, 639, 862, 863, 732, 266, 269, 284, 668), 'required-audit': (778,)}
        for classification, identifiers in members.items():
            for identifier in identifiers:
                with self.subTest(identifier=identifier):
                    self.assertEqual(sast.classify_sonar(['cwe:' + str(identifier)]), classification)
        for token in ('CWE:0798', 'external/cwe/cwe-798', 'cwe/798', 'cwe 798'):
            with self.subTest(token=token):
                self.assert_classified(self.export(issue=self.issue([token], 'LOW')), 'authentication', 'LOW')
        self.assert_classified(self.export(issue=self.issue(['cwe:269'])), 'authorization', 'MEDIUM')
        self.assert_classified(self.export(issue=self.issue(['cwe:778'])), 'required-audit', 'MEDIUM')

    def test_unknown_metadata_keeps_unresolved_export_classification(self):
        for token in ('author', 'oauth-library', 'no-auth', 'authentication-example', 'permissionless',
                      'traceability-example', 'mycwe:287', 'cwe:2870', 'cwe', 'security', 'others', 'log-injection'):
            with self.subTest(token=token):
                findings = self.export(issue=self.issue([token], 'LOW'))
                self.assertEqual(findings[0]['classification'], 'unresolved')
        findings = self.export(hotspot=self.hotspot('unknown-category'))
        self.assertEqual(findings[0]['classification'], 'unresolved')
        findings[0]['first_seen'] = (self.at - dt.timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')

    def test_nonsecurity_issues_are_not_promoted_by_auth_words_or_metadata(self):
        issue = self.issue(['auth'], type='CODE_SMELL', impacts=[{'softwareQuality': 'MAINTAINABILITY', 'severity': 'HIGH'}],
                           message='Authentication permission traceability')
        self.assertEqual(self.export(issue=issue), [])

    def test_names_and_messages_cannot_supply_classification(self):
        findings = self.export(issue=self.issue([], message='auth permission traceability', rule='python:auth'))
        self.assertEqual(findings[0]['classification'], 'unresolved')
        for row in (self.issue(['auth'], issueStatus='FALSE_POSITIVE'), self.hotspot('permission', resolution='SAFE')):
            findings = self.export(**({'issue': row} if 'rule' in row else {'hotspot': row}))
            self.assertIn(findings[0]['classification'], ('false-positive', 'not-affected'))

    def test_malformed_classification_metadata_fails_closed(self):
        for tags in (None, 'auth', [None], [{'auth': True}]):
            with self.subTest(tags=tags), self.assertRaises(ValueError):
                sast.classify_sonar(tags)


if __name__ == '__main__':
    unittest.main()

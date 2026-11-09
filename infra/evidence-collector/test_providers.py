"""Read-only provider export regressions with real archive crypto and fake authenticated APIs."""
import copy
import datetime as dt
import io
from pathlib import Path
import unittest
from unittest import mock

import test_evidence as fixtures
e = fixtures.e


class ProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.EvidenceTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        fixtures.EvidenceTests.tearDownClass.__func__(cls)

    def setUp(self):
        fixtures.EvidenceTests.setUp(self)
        self.module = e.provider_exports()
        start = e.now() - dt.timedelta(minutes=3)
        end = start + dt.timedelta(minutes=1)
        self.run.update({'path': e.CODEQL_WORKFLOW, 'event': 'dynamic', 'head_branch': 'refs/pull/115/head', 'created_at': e.iso(start), 'run_started_at': e.iso(start), 'updated_at': e.iso(end), 'conclusion': 'failure'})
        self.config.update({'collect_codeql_provider': True, 'collect_terminal_logs': False, 'codeql_retry_seconds': 60})
        self.job = {'id': 99, 'run_id': 123, 'head_sha': self.run['head_sha'], 'name': 'Analyze (go)', 'status': 'completed', 'conclusion': 'failure', 'started_at': e.iso(start), 'completed_at': e.iso(end)}
        self.analysis = {'id': 71, 'ref': self.run['head_branch'], 'commit_sha': self.run['head_sha'], 'analysis_key': self.module.CODEQL_KEY, 'environment': e.canonical({'language': 'go', 'category': '/language:go'}).decode(), 'category': '/language:go', 'tool': {'name': 'CodeQL', 'version': 'fixture'}, 'error': '', 'warning': '', 'created_at': e.iso(start + dt.timedelta(seconds=20)), 'results_count': 1, 'rules_count': 2}
        self.raw = e.canonical({'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'CodeQL'}}, 'automationDetails': {'id': '/language:go/'}, 'versionControlProvenance': [{'repositoryUri': 'https://github.com/owner/repo', 'revisionId': self.run['head_sha'], 'branch': self.run['head_branch']}], 'results': [{'ruleId': 'fixture', 'message': {'text': 'private diagnostic finding'}}]}]})
        self.analyses = [self.analysis]
        self.others = []
        self.api.pages.side_effect = lambda route, key: [self.job] if route.endswith('/jobs') else []
        self.api.get.side_effect = self.get
        self.api.request.side_effect = self.request

    def get(self, route):
        if route.startswith('/actions/runs?event=dynamic'):
            return {'workflow_runs': [self.run] + self.others}
        if route.startswith('/code-scanning/analyses?'):
            return self.analyses
        if route.startswith('/commits/'):
            return []
        raise AssertionError('unexpected provider GET route')

    def request(self, route, **kwargs):
        if '/code-scanning/analyses/' in route:
            self.assertEqual(kwargs['accept'], 'application/sarif+json')
            self.assertEqual(kwargs['max_bytes'], e.MAX_FILE)
            self.assertFalse(kwargs['allow_storage_redirect'])
            return self.raw
        if route.endswith('/logs'):
            return b'compile failed: fixture compiler diagnostic\n'
        raise AssertionError('unexpected provider operation')

    def manifests(self, kind):
        values = []
        for record in self.archive.records():
            if record['collector_kind'] == kind:
                raw = e.age_decrypt((self.root / 'manifests' / (record['manifest_sha256'] + '.age')).read_bytes(), self.identity)
                values.append((record, e.parse_json(raw)))
        return values

    def due(self):
        path = self.module.state_path(self.archive, self.run)
        state = e.parse_json(path.read_bytes())
        state['next_retry_at'] = e.iso(e.now() - dt.timedelta(seconds=1))
        with self.archive.lock():
            self.archive.write('state/' + path.name, e.canonical(state), replace=True)

    def test_exact_dynamic_path_is_diagnostic_only_even_if_operator_accidentally_allowlists_it(self):
        config = dict(self.config, allowed_workflows=[e.CODEQL_WORKFLOW], allowed_events=['dynamic'])
        with self.assertRaises(e.EvidenceError):
            e.trusted_run(self.run, config)
        outcome = e.outcome_manifest(self.run, self.config, False)
        e.manifest_valid(outcome)
        for change in (dict(outcome, complete=True), dict(outcome, workflow='dynamic/other'), dict(outcome, details={'kind': 'platform-outcome', 'source_trusted': True})):
            with self.assertRaises(e.EvidenceError):
                e.manifest_valid(change)

    def test_failed_nonrelease_attempt_archives_raw_sarif_metadata_and_never_public_receipt(self):
        with mock.patch.object(e, 'verify_trust_anchor', side_effect=AssertionError('platform must not claim helper trust')):
            self.assertTrue(e.collect_attempt(self.config, self.api, self.archive, self.run))
        rows = self.manifests('codeql-analysis')
        self.assertEqual(len(rows), 1)
        record, manifest = rows[0]
        self.assertFalse(record['source_trusted'])
        self.assertFalse(manifest['complete'])
        self.assertFalse(manifest['details']['release_authority'])
        raw_file = next(x for x in manifest['files'] if x['name'].endswith('.sarif'))
        stored = e.age_decrypt((self.root / 'blobs' / (raw_file['sha256'] + '.age')).read_bytes(), self.identity)
        self.assertEqual(stored, self.raw)
        self.assertFalse(manifest['details']['provider_asserts_run_id'])
        with self.assertRaises(e.EvidenceError):
            e.validate_receipt(record['receipt'], {}, self.public)
        self.assertTrue(all(call.kwargs.get('raw') for call in self.api.request.call_args_list))
        self.assertIsNone(record['artifact_id'])
        self.assertEqual(self.manifests('codeql-summary')[0][1]['details']['status'], 'collected')

    def test_warning_and_error_metadata_still_fetch_sarif_and_stay_partial(self):
        self.analysis.update({'warning': 'private provider warning', 'error': 'private provider error'})
        self.assertTrue(e.collect_attempt(self.config, self.api, self.archive, self.run))
        details = self.manifests('codeql-analysis')[0][1]['details']
        self.assertEqual(details['status'], 'partial')
        self.assertIn('provider-warning', details['issues'])
        self.assertIn('provider-error', details['issues'])
        self.assertEqual(len(self.api.request.call_args_list), 1)
        self.assertEqual(self.manifests('codeql-summary')[0][1]['details']['status'], 'partial')

    def test_foreign_revision_ref_key_category_and_attempt_time_are_not_borrowed(self):
        bad = []
        for key, value in [('commit_sha', 'b' * 40), ('ref', 'refs/heads/main'), ('analysis_key', '.github/workflows/foreign.yml:analyze'), ('category', '/language:python'), ('created_at', e.iso(e.timestamp(self.job['started_at']) - dt.timedelta(seconds=1)))]:
            bad.append(dict(self.analysis, **{key: value, 'id': 100 + len(bad)}))
        self.analyses = bad
        self.assertFalse(e.collect_attempt(self.config, self.api, self.archive, self.run))
        self.assertEqual(self.manifests('codeql-analysis'), [])
        self.api.request.assert_not_called()
        self.assertEqual(self.manifests('codeql-summary')[0][1]['details']['missing_categories'], ['/language:go'])

    def test_overlapping_same_revision_ref_run_is_explicitly_ambiguous(self):
        self.others = [dict(self.run, id=124)]
        self.assertTrue(e.collect_attempt(self.config, self.api, self.archive, self.run))
        details = self.manifests('codeql-analysis')[0][1]['details']
        self.assertIn('ambiguous-run-association', details['issues'])
        self.assertEqual(details['status'], 'partial')

    def test_sarif_source_context_count_or_execution_failure_is_archived_partial(self):
        value = e.parse_json(self.raw)
        value['runs'][0]['versionControlProvenance'][0]['revisionId'] = 'b' * 40
        value['runs'][0]['automationDetails']['id'] = '/language:python/'
        value['runs'][0]['invocations'] = [{'executionSuccessful': False}]
        self.raw = e.canonical(value)
        self.assertFalse(e.collect_attempt(self.config, self.api, self.archive, self.run))
        details = self.manifests('codeql-analysis')[0][1]['details']
        self.assertEqual(details['status'], 'partial')
        self.assertTrue({'sarif-source-mismatch', 'sarif-context-mismatch', 'sarif-execution-failed'} <= set(details['issues']))

    def test_permission_added_after_old_run_first_attempt_retries_instead_of_freezing_missing(self):
        for name in ('created_at', 'run_started_at', 'updated_at'):
            self.run[name] = e.iso(e.timestamp(self.run[name]) - dt.timedelta(days=20))
        for name in ('started_at', 'completed_at'):
            self.job[name] = e.iso(e.timestamp(self.job[name]) - dt.timedelta(days=20))
        self.analysis['created_at'] = e.iso(e.timestamp(self.analysis['created_at']) - dt.timedelta(days=20))
        original = self.api.get.side_effect
        self.api.get.side_effect = lambda route: (_ for _ in ()).throw(e.GitHubError(403)) if route.startswith('/code-scanning/') else original(route)
        self.assertFalse(e.collect_attempt(self.config, self.api, self.archive, self.run))
        self.assertEqual(self.manifests('codeql-summary')[0][1]['details']['missing'], ['provider-permission-unavailable'])
        self.due()
        self.api.get.side_effect = original
        self.assertTrue(e.collect_attempt(self.config, self.api, self.archive, self.run))
        self.assertEqual(len(self.manifests('codeql-analysis')), 1)

    def test_missing_sarif_retries_and_deduplicates_after_recovery(self):
        self.api.request.side_effect = e.GitHubError(422)
        self.assertFalse(e.collect_attempt(self.config, self.api, self.archive, self.run))
        self.assertIn('sarif-unavailable', self.manifests('codeql-analysis')[0][1]['details']['issues'])
        self.due()
        self.api.request.side_effect = self.request
        self.assertTrue(e.collect_attempt(self.config, self.api, self.archive, self.run))
        stored = list((self.root / 'blobs').glob(self.module.engine(e.__dict__).digest(self.raw) + '.age'))
        self.assertEqual(len(stored), 1)
        count = len(self.archive.records())
        self.assertTrue(e.collect_attempt(self.config, self.api, self.archive, self.run))
        self.assertEqual(len(self.archive.records()), count)

    def test_budget_exhaustion_keeps_retryable_checkpoint(self):
        self.api.request.side_effect = e.APIBudgetExceeded('fixture budget')
        with self.assertRaises(e.APIBudgetExceeded):
            e.collect_attempt(self.config, self.api, self.archive, self.run)
        state = e.parse_json(self.module.state_path(self.archive, self.run).read_bytes())
        self.assertFalse(state.get('done', False))
        self.assertEqual(state['next_page'], 1)

    def test_dynamic_generic_job_logs_and_outcome_schema_are_supported_without_authority(self):
        config = dict(self.config, collect_terminal_logs=True)
        self.assertTrue(e.collect_attempt(config, self.api, self.archive, self.run))
        self.assertEqual(len(self.manifests('job-logs')), 1)
        self.assertTrue(any(row['workflow'] == e.CODEQL_WORKFLOW and row['complete'] is False and row['source_trusted'] is False for row in self.archive.records()))

    def test_snyk_snapshot_is_commit_status_only_with_safe_references_and_no_extra_scan(self):
        self.api.get.side_effect = lambda _route: [{'id': 1, 'context': 'security/snyk', 'state': 'failure', 'description': 'Bearer fixtureSecret1234', 'target_url': 'https://app.snyk.io/org/test/project/fixture?token=secret#bearer', 'creator': {'id': 2, 'login': 'snyk-bot'}}, {'id': 3, 'context': 'unrelated', 'state': 'success', 'target_url': 'https://unrelated.invalid/'}]
        self.module.collect_snyk_statuses(e.__dict__, self.config, self.api, self.archive, self.run)
        row, manifest = self.manifests('provider-status')[0]
        self.assertFalse(row['source_trusted'])
        self.assertFalse(manifest['details']['full_scm_report_exported'])
        self.assertIn('commit-sha-only', manifest['details']['association'])
        entry = manifest['files'][0]
        statuses = e.parse_json(e.age_decrypt((self.root / 'blobs' / (entry['sha256'] + '.age')).read_bytes(), self.identity))
        self.assertEqual(statuses[0]['target_reference'], 'https://app.snyk.io/org/test/project/fixture')
        self.assertNotIn('fixtureSecret', statuses[0]['description'])
        self.assertEqual(len(statuses), 1)
        self.api.request.assert_not_called()

    def test_provider_pagination_checkpoint_resumes_instead_of_repeating_first_page(self):
        config = dict(self.config, codeql_pages_per_poll=1)
        base = self.api.get.side_effect
        seen = []
        def pages(route):
            if route.startswith('/code-scanning/'):
                seen.append(route)
                if route.endswith('&page=1'):
                    return [dict(self.analysis, id=200 + i, commit_sha='b' * 40) for i in range(100)]
                return [self.analysis]
            return base(route)
        self.api.get.side_effect = pages
        self.assertFalse(e.collect_attempt(config, self.api, self.archive, self.run))
        self.assertEqual(e.parse_json(self.module.state_path(self.archive, self.run).read_bytes())['next_page'], 2)
        self.due()
        self.assertTrue(e.collect_attempt(config, self.api, self.archive, self.run))
        self.assertEqual(len(seen), 2)
        self.assertIn('page=2', seen[1])

    def test_budget_retry_reuses_archived_analyses_and_resumes_remaining_payloads(self):
        self.analyses = [self.analysis, dict(self.analysis, id=72)]
        calls = []
        def first_request(route, **kwargs):
            calls.append(route)
            if route.endswith('/72'):
                raise e.APIBudgetExceeded('fixture budget')
            return self.request(route, **kwargs)
        self.api.request.side_effect = first_request
        with self.assertRaises(e.APIBudgetExceeded):
            e.collect_attempt(self.config, self.api, self.archive, self.run)
        self.assertEqual(len(self.manifests('codeql-analysis')), 1)
        self.api.request.side_effect = self.request
        self.api.request.reset_mock()
        self.assertTrue(e.collect_attempt(self.config, self.api, self.archive, self.run))
        self.assertEqual(len(self.manifests('codeql-analysis')), 2)
        self.assertEqual([call.args[0].rsplit('/', 1)[-1] for call in self.api.request.call_args_list], ['72'])

    def test_completed_provider_pending_is_persisted_without_marking_poll_complete_for_that_run(self):
        base = self.api.get.side_effect
        self.api.get.side_effect = lambda route: (_ for _ in ()).throw(e.GitHubError(403)) if route.startswith('/code-scanning/') else base(route)
        with mock.patch.object(e, 'discover_runs', return_value=([self.run], e.now())):
            e.collect(self.config, self.api, self.archive)
        discovery = e.parse_json((self.root / 'state/discovery.json').read_bytes())
        self.assertEqual(discovery['pending'], [123])
        processed = e.parse_json((self.root / 'state/completed-polls.json').read_bytes())
        self.assertNotIn('123', processed)

    def test_sarif_representation_refuses_redirects_instead_of_leaking_authorization(self):
        import urllib.error
        client = e.GitHub('owner/repo', 'throwaway-fixture')
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.HTTPError('https://api.github.com/fixture', 302, 'Found', {'Location': 'https://logs.blob.core.windows.net/fixture'}, None)
        with mock.patch.object(e.urllib.request, 'build_opener', return_value=opener), self.assertRaises(e.GitHubError):
            client.request('/repos/owner/repo/code-scanning/analyses/71', raw=True, accept='application/sarif+json', max_bytes=e.MAX_FILE, allow_storage_redirect=False)
        self.assertEqual(opener.open.call_count, 1)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.headers['Accept'], 'application/sarif+json')

    def test_provider_report_references_extend_through_verified_release_deadline(self):
        self.assertTrue(e.collect_attempt(self.config, self.api, self.archive, self.run))
        published = e.iso(e.now())
        audit = {'release_id': 7, 'published_at': published, 'revision': self.run['head_sha'], 'provenance': 'operator-audit', 'audit_reference': 'private-fixture-publication-proof', 'audited_at': e.iso(e.now())}
        self.api.pages.side_effect = lambda route, key: [{'id': 7, 'published_at': published, 'draft': False, 'tag_name': 'v1.2.3'}] if route == '/releases' else [self.job]
        e.retain(dict(self.config, audited_release_publications=[audit]), self.api, self.archive)
        deadline = e.year_after(e.timestamp(published))
        self.assertTrue(all(e.timestamp(row['retain_until']) >= deadline for row in self.archive.records()))
        digest = e.digest(self.raw)
        self.assertEqual(len(list((self.root / 'blobs').glob(digest + '.age'))), 1)

    def test_mismatched_sarif_payload_is_retryable_until_source_correct_representation_recovers(self):
        valid = self.raw
        value = e.parse_json(valid)
        value['runs'][0]['versionControlProvenance'][0]['revisionId'] = 'b' * 40
        self.raw = e.canonical(value)
        self.assertFalse(e.collect_attempt(self.config, self.api, self.archive, self.run))
        self.due()
        self.raw = valid
        self.assertTrue(e.collect_attempt(self.config, self.api, self.archive, self.run))
        self.assertEqual(len(self.manifests('codeql-analysis')), 2)

    def test_diagnostic_records_consume_no_upstream_artifact_deletion_budget(self):
        self.assertTrue(e.collect_attempt(self.config, self.api, self.archive, self.run))
        self.api.get.reset_mock()
        self.api.request.reset_mock()
        e.cleanup(self.config, self.api, self.archive)
        self.api.get.assert_not_called()
        self.api.request.assert_not_called()

    def test_invalid_status_url_is_stripped_instead_of_aborting_collection(self):
        for url in ('https://[invalid', 'https://app.snyk.io:invalid/path', 'https://user:password@app.snyk.io/path', 'http://app.snyk.io/path'):
            self.assertIsNone(self.module.safe_reference(url))
        self.api.get.side_effect = lambda _route: [{'id': 1, 'context': 'snyk', 'target_url': 'https://[invalid'}]
        self.module.collect_snyk_statuses(e.__dict__, self.config, self.api, self.archive, self.run)
        self.assertEqual(len(self.manifests('provider-status')), 1)


if __name__ == '__main__':
    unittest.main()

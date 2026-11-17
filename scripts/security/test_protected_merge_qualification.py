"""Offline fixed-fixture qualification request/CLI boundaries; no provider access."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error

SPEC = importlib.util.spec_from_file_location('qualification_under_test', Path(__file__).with_name('protected_merge_qualification.py'))
q = importlib.util.module_from_spec(SPEC)
if SPEC.origin and Path(SPEC.origin).exists(): SPEC.loader.exec_module(q)
A, B, C = 'a'*40, 'b'*40, 'c'*40


def repository():
    return {'id': 1188082218, 'full_name': 'lorconksu/veyport', 'owner': {'id': 13374789, 'login': 'lorconksu'}, 'default_branch': 'main'}


# A fixed sibling import also works under isolated Python without sys.path changes.
_CONTEXT_SUPPORT_SPEC = importlib.util.spec_from_file_location(
    'security_context_test_support', Path(__file__).with_name('context_test_support.py'))
_CONTEXT_SUPPORT = importlib.util.module_from_spec(_CONTEXT_SUPPORT_SPEC)
_CONTEXT_SUPPORT_SPEC.loader.exec_module(_CONTEXT_SUPPORT)
change_context_fields = _CONTEXT_SUPPORT.change_context_fields


def fixture():
    repo = repository(); owner = repo['owner']
    event = {'ref': 'refs/heads/main', 'repository': copy.deepcopy(repo), 'sender': copy.deepcopy(owner),
             'inputs': {'case': 'wrong-head', 'pr_number': '42', 'head_sha': B}}
    env = {'PROTECTED_MERGE_QUALIFICATION_ENABLED': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
           'GITHUB_REF': 'refs/heads/main', 'GITHUB_REPOSITORY': 'lorconksu/veyport',
           'GITHUB_REPOSITORY_ID': '1188082218', 'GITHUB_REPOSITORY_OWNER_ID': '13374789',
           'GITHUB_ACTOR': 'lorconksu', 'GITHUB_ACTOR_ID': '13374789', 'GITHUB_TRIGGERING_ACTOR': 'lorconksu',
           'GITHUB_RUN_ID': '80', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'probe',
           'GITHUB_SHA': A, 'GITHUB_WORKFLOW_SHA': A,
           'GITHUB_WORKFLOW_REF': 'lorconksu/veyport/.github/workflows/protected-merge-qualification.yml@refs/heads/main'}
    pr = {'id': 9, 'node_id': 'PR_node', 'number': 42, 'state': 'open', 'draft': False, 'merged': False,
          'mergeable': True, 'head': {'ref': 'fixture-source', 'sha': B, 'repo': copy.deepcopy(repo)},
          'base': {'ref': 'qualification/protected-merge-20261116', 'sha': C, 'repo': copy.deepcopy(repo)}}
    run = {'id': 80, 'run_number': 7, 'run_attempt': 1, 'workflow_id': 90,
           'path': '.github/workflows/protected-merge-qualification.yml', 'event': 'workflow_dispatch',
           'head_sha': A, 'head_branch': 'main', 'status': 'in_progress', 'conclusion': None,
           'repository': copy.deepcopy(repo), 'head_repository': copy.deepcopy(repo),
           'actor': copy.deepcopy(owner), 'triggering_actor': copy.deepcopy(owner)}
    values = {'': copy.deepcopy(repo), 'actions/workflows/protected-merge-qualification.yml': {'id': 90, 'path': run['path'], 'state': 'active'},
              'actions/runs/80': run, 'pulls/42': pr,
              'git/ref/heads/main': {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': A}},
              'git/ref/heads/qualification/protected-merge-20261116': {'ref': 'refs/heads/qualification/protected-merge-20261116', 'object': {'type': 'commit', 'sha': C}}}
    api = mock.Mock(); api.get.side_effect = lambda path: copy.deepcopy(values[path])
    api.fresh_readonly.return_value = api
    return api, event, env, values


def settings_fixture():
    # Use the actual public-safe API response, including signatures and absent restrictions.
    classic = json.loads((Path(__file__).parent/'fixtures/github-main-protection-2022-11-28.json').read_bytes())
    env = {'PROTECTED_MERGE_APP_ID': '333', 'PROTECTED_MERGE_INSTALLATION_ID': '444', 'PROTECTED_MERGE_RULESET_ID': '555',
        'PROTECTED_MERGE_MINTED_INSTALLATION_ID': '444', 'PROTECTED_MERGE_APP_SLUG': 'merge-app',
        'PROTECTED_MERGE_APP_CLIENT_ID': 'client', 'PROTECTED_MERGE_QUALIFICATION_RULESET_ID': '666'}
    rule = {'id': 666, 'source_type': 'Repository', 'source': 'lorconksu/veyport', 'target': 'branch', 'enforcement': 'active',
        'conditions': {'ref_name': {'include': ['refs/heads/'+q.TARGET], 'exclude': []}},
        'rules': [{'type': 'update', 'parameters': {'update_allows_fetch_and_merge': False}}],
        'bypass_actors': [{'actor_id': 333, 'actor_type': 'Integration', 'bypass_mode': 'pull_request'}]}
    values = {'apps/merge-app': {'id': 333, 'client_id': 'client', 'slug': 'merge-app', 'owner': repository()['owner'], 'permissions': q.merge.APP_PERMISSIONS},
        'installation/repositories?per_page=100&page=1': {'total_count': 1, 'repositories': [repository()]},
        'branches/main/protection': classic, 'branches/'+q.BRANCH_PATH+'/protection': classic,
        'rulesets/666': rule, 'rules/branches/'+q.BRANCH_PATH+'?per_page=100&page=1': [
            {'type': 'update', 'parameters': {'update_allows_fetch_and_merge': False}, 'ruleset_id': 666,
             'ruleset_source_type': 'Repository', 'ruleset_source': 'lorconksu/veyport'}]}
    reads = mock.Mock(); reads.get.side_effect = lambda path: copy.deepcopy(values[path])
    return reads, env, values, rule, classic


def native_rows(sha):
    return [{'id': i+1, 'name': name, 'head_sha': sha, 'status': 'completed', 'conclusion': 'success',
             'app': {'id': 57789 if name == 'CodeQL' else 15368}}
            for i, name in enumerate(q.merge.CHECK_CONTEXTS)]


class QualificationTests(unittest.TestCase):
    def test_module_present(self):
        self.assertTrue(hasattr(q, 'context'), 'Missing fixed-target qualification implementation')

    def test_exact_context_and_independent_target_rejection(self):
        api, event, env, values = fixture()
        admitted = q.context(api, event, env)
        self.assertEqual((admitted['head_sha'], admitted['base_sha']), (B, C))
        for target in ['main', 'other', 'qualification/other', '../main', 'refs/heads/main']:
            with self.subTest(target=target):
                values['pulls/42']['base']['ref'] = target
                with self.assertRaises(ValueError): q.context(api, event, env)
                with self.assertRaises(ValueError): q.fixed_target(target)
        q.fixed_target('qualification/protected-merge-20261116')

    def test_owner_run_attempt_metadata_and_inputs_fail_closed(self):
        for key in fixture()[2]:
            api, event, env, _ = fixture(); env[key] = 'other'
            with self.subTest(env=key), self.assertRaises(ValueError): q.context(api, event, env)
        for key, value in [('case', 'merge'), ('head_sha', C), ('pr_number', '042'), ('target', 'main')]:
            api, event, env, _ = fixture(); event['inputs'][key] = value
            with self.subTest(input=key), self.assertRaises(ValueError): q.context(api, event, env)
        mutations = [('actions/runs/80', 'run_attempt', 2), ('actions/runs/80', 'triggering_actor', {'id': 1, 'login': 'x'}),
                     ('pulls/42', 'draft', True), ('pulls/42', 'mergeable', None)]
        for path, key, value in mutations:
            api, event, env, values = fixture(); values[path][key] = value
            with self.subTest(path=path, key=key), self.assertRaises(ValueError): q.context(api, event, env)

    def test_authenticated_context_bindings_refuse_both_mutation_consumers(self):
        workflow, run, pr = 'actions/workflows/protected-merge-qualification.yml', 'actions/runs/80', 'pulls/42'
        fixture_ref = 'git/ref/heads/'+q.TARGET
        cases = [
            ('repository', ('values', '', 'id'), 666),
            ('event-repository', ('event', 'repository', 'id'), 666),
            ('sender', ('event', 'sender', 'id'), 666),
            ('workflow-path', ('values', workflow, 'path'), '.github/workflows/other.yml'),
            ('workflow-state', ('values', workflow, 'state'), 'disabled_manually'),
            ('run-id', ('values', run, 'id'), 81),
            ('run-workflow', ('values', run, 'workflow_id'), 91),
            ('run-path', ('values', run, 'path'), '.github/workflows/other.yml'),
            ('run-event', ('values', run, 'event'), 'push'),
            ('run-control', ('values', run, 'head_sha'), C),
            ('run-branch', ('values', run, 'head_branch'), 'release'),
            ('run-status', ('values', run, 'status'), 'completed'),
            ('run-conclusion', ('values', run, 'conclusion'), 'cancelled'),
            ('run-repository', ('values', run, 'repository', 'id'), 666),
            ('run-head-repository', ('values', run, 'head_repository', 'id'), 666),
            ('original-owner', ('values', run, 'actor', 'id'), 666),
            ('triggering-owner', ('values', run, 'triggering_actor', 'id'), 666),
            ('main-ref', ('values', 'git/ref/heads/main', 'object', 'sha'), C),
            ('pr-number', ('values', pr, 'number'), 43),
            ('pr-state', ('values', pr, 'state'), 'closed'),
            ('pr-merged', ('values', pr, 'merged'), True),
            ('pr-head-repository', ('values', pr, 'head', 'repo', 'id'), 666),
            ('pr-base-repository', ('values', pr, 'base', 'repo', 'id'), 666),
            ('pr-head-input', ('values', pr, 'head', 'sha'), A),
            ('fixture-ref', ('values', fixture_ref, 'object', 'sha'), A),
        ]
        scenarios = [(binding, [(path, value)]) for binding, path, value in cases]
        # Keep PR/input equality and the current fixture ref valid. Only the
        # distinct-head/base invariant is violated by this coherent two-field setup.
        scenarios.append(('distinct-head-base', [
            (('values', pr, 'head', 'sha'), C), (('event', 'inputs', 'head_sha'), C)]))
        for binding, changes in scenarios:
            for consumer in ('probe', 'canary'):
                with self.subTest(binding=binding, consumer=consumer):
                    api, event, env, values = fixture()
                    reads, settings_env, _, _, _ = settings_fixture()
                    env.update(settings_env)
                    if consumer == 'probe':
                        env.update(GITHUB_TOKEN='read-token', PROTECTED_MERGE_TOKEN='app-token')
                    if consumer == 'canary':
                        env.update(GITHUB_JOB='admission', GITHUB_TOKEN='native-token')
                        event['inputs']['case'] = 'pending-canary'
                    head = C if binding == 'distinct-head-base' else A if binding == 'pr-head-input' else B
                    values['commits/'+head+'/check-runs?filter=all&per_page=100&page=1'] = {
                        'total_count': 12, 'check_runs': native_rows(head)}
                    state = {'event': event, 'env': env, 'values': values}
                    change_context_fields(self, state, changes)
                    # The real reader sees the selected copy, not the old closure.
                    api.get.side_effect = lambda path: copy.deepcopy(state['values'][path])
                    with mock.patch.object(q, 'FixtureMutationClient') as writer, \
                         mock.patch.object(q, 'NativeCanaryClient') as native:
                        with self.assertRaises(ValueError):
                            if consumer == 'probe': q.probe(api, reads, state['event'], state['env'])
                            else: q.produce_canary(api, state['event'], state['env'])
                        writer.assert_not_called(); native.assert_not_called()
                        reads.get.assert_not_called()

    def test_authenticated_context_consumers_accept_valid_controls(self):
        api, event, env, _ = fixture()
        reads, settings_env, _, _, _ = settings_fixture()
        env.update(settings_env, GITHUB_TOKEN='read-token', PROTECTED_MERGE_TOKEN='app-token')
        with mock.patch.object(q, 'FixtureMutationClient') as writer:
            writer.return_value.probe.return_value = (409, {})
            result = q.probe(api, reads, event, env)
            self.assertEqual(result['outcome'], 'head-mismatch-denied')
            self.assertTrue(result['mutation_attempted'])
            writer.assert_called_once_with('app-token')
        self.assertIn(mock.call('branches/main/protection'), reads.get.call_args_list)
        api, event, env, values = fixture()
        env.update(GITHUB_JOB='admission', GITHUB_TOKEN='native-token')
        event['inputs']['case'] = 'pending-canary'
        values['commits/'+B+'/check-runs?filter=all&per_page=100&page=1'] = {
            'total_count': 12, 'check_runs': native_rows(B)}
        with mock.patch.object(q, 'NativeCanaryClient') as native:
            native.return_value.create.return_value = 144
            result = q.produce_canary(api, event, env)
            self.assertEqual(result['outcome'], 'canary-created')
            self.assertEqual(result['check_run_id'], 144)
            native.assert_called_once_with('native-token')

    def test_fixture_authority_roles_are_independent(self):
        api, event, env, values = fixture()
        run, pr = values['actions/runs/80'], values['pulls/42']
        repos = [values[''], event['repository'], run['repository'], run['head_repository'],
                 pr['head']['repo'], pr['base']['repo']]
        owners = [repo['owner'] for repo in repos]+[event['sender'], run['actor'], run['triggering_actor']]
        for rows in (repos, owners):
            self.assertEqual(len({id(row) for row in rows}), len(rows))
        self.assertEqual(q.context(api, event, env)['head_sha'], B)

    def test_request_paths_bodies_consumed_once_and_independent_target_gate(self):
        for case, method, path, body in [
            ('wrong-head', 'PUT', 'pulls/42/merge', {'sha': C, 'merge_method': 'merge'}),
            ('direct-push', 'PATCH', 'git/refs/heads/qualification/protected-merge-20261116', {'sha': B, 'force': False}),
            ('native-merge', 'PUT', 'pulls/42/merge', {'sha': B, 'merge_method': 'merge'})]:
            client = q.FixtureMutationClient('app-token'); client.opener = mock.Mock()
            response = mock.MagicMock(); response.status = 200; response.read.return_value = b'{"merged":true,"sha":"'+A.encode()+b'"}'
            client.opener.open.return_value = response
            response.__enter__.return_value = response
            admitted = {'target': q.TARGET, 'case': case, 'pr_number': 42, 'head_sha': B, 'base_sha': C}
            client.probe(admitted)
            request = client.opener.open.call_args.args[0]
            self.assertEqual(request.full_url, 'https://api.github.com/repos/lorconksu/veyport/'+path)
            self.assertEqual(request.method, method); self.assertEqual(json.loads(request.data), body)
            with self.assertRaises(ValueError): client.probe(admitted)
            for target in ['main', 'other']:
                fresh = q.FixtureMutationClient('app-token'); fresh.opener = mock.Mock()
                with self.assertRaises(ValueError): fresh.probe({**admitted, 'target': target})
                fresh.opener.open.assert_not_called()
        for case in ['main-settings', 'other', '../../main']:
            client = q.FixtureMutationClient('token'); client.opener = mock.Mock()
            with self.assertRaises(ValueError): client.probe({'target': q.TARGET, 'case': case, 'pr_number': 42, 'head_sha': B, 'base_sha': C})
            client.opener.open.assert_not_called()

    def test_response_denial_not_generic_exception_or_permission_proof(self):
        admitted = {'case': 'direct-push', 'target': q.TARGET, 'pr_number': 42, 'head_sha': B, 'base_sha': C, 'run_id': 80}
        for code, message, expected in [(403, 'Resource not accessible by integration', 'unproven'),
                (422, 'Update is not a fast forward', 'unproven'), (200, 'ok', 'unproven'),
                (403, 'GH013: Cannot update this protected ref.', 'restriction-denied')]:
            result = q.classify(admitted, code, {'message': message}, unchanged=True)
            self.assertEqual(result['outcome'], expected)
        self.assertEqual(q.classify(admitted, 403, {'message': 'GH013: Cannot update this protected ref.'}, unchanged=False)['outcome'], 'unexpected-update')
        admitted['case'] = 'wrong-head'
        self.assertEqual(q.classify(admitted, 409, {}, unchanged=True)['outcome'], 'head-mismatch-denied')
        self.assertEqual(q.classify(admitted, 403, {}, unchanged=True)['outcome'], 'unproven')

    def test_native_proof_requires_exact_twelve_actual_producers(self):
        checks = [{'id': i+1, 'name': name, 'head_sha': B, 'status': 'completed', 'conclusion': 'success',
                   'app': {'id': 57789 if name == 'CodeQL' else 15368}} for i, name in enumerate(q.merge.CHECK_CONTEXTS)]
        q.native_checks(checks, B)
        for mutate in [lambda rows: rows.pop(), lambda rows: rows[0].update(conclusion='neutral'),
                       lambda rows: rows[0]['app'].update(id=123), lambda rows: rows[0].update(head_sha=C),
                       lambda rows: rows.append({**copy.deepcopy(rows[0]), 'id': 99})]:
            damaged = copy.deepcopy(checks); mutate(damaged)
            with self.assertRaises(ValueError): q.native_checks(damaged, B)

    def test_fixed_read_endpoint_allowlist_no_production_override(self):
        client = q.FixtureReadClient('token'); client.opener = mock.Mock()
        for path in ['branches/main/protection/extra', 'branches/other/protection', 'git/refs/heads/main',
                     'rulesets/1?target=main', 'https://evil.test', 'rules/branches/other']:
            with self.subTest(path=path), self.assertRaises(ValueError): client.get(path)
        client.opener.open.assert_not_called()
        # Shared production transport gains only two literal read endpoints.
        transport = q.common.Transport('token'); transport.opener = mock.Mock()
        for path in ['actions/workflows/other.yml', 'git/ref/heads/other']:
            with self.assertRaises(ValueError): transport.request('GET', path)
        transport.opener.open.assert_not_called()

    def test_cli_refuses_before_network_or_mutation_and_sanitizes(self):
        script = Path(__file__).with_name('protected_merge_qualification.py')
        with tempfile.TemporaryDirectory() as folder:
            event = Path(folder)/'event.json'; api, payload, env, _ = fixture(); event.write_text(json.dumps(payload))
            for change in [{'GITHUB_REF': 'refs/heads/other'}, {'GITHUB_RUN_ATTEMPT': '2'}, {'PROTECTED_MERGE_QUALIFICATION_ENABLED': 'false'}]:
                result = subprocess.run([sys.executable, '-I', '-B', str(script), 'probe'],
                    env={'PATH': os.defpath, **env, **change, 'GITHUB_EVENT_PATH': str(event), 'GITHUB_TOKEN': 'secret-sentinel', 'PROTECTED_MERGE_TOKEN': 'app-sentinel'}, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1); self.assertEqual(json.loads(result.stdout)['outcome'], 'refused')
                self.assertNotIn('sentinel', result.stdout+result.stderr)
            result = subprocess.run([sys.executable, '-I', '-B', str(script), '--target', 'main'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0); self.assertNotIn('Traceback', result.stderr)

    def test_http_error_and_uncertainty_consume_one_write_without_disclosing_body(self):
        admitted = {'target': q.TARGET, 'case': 'wrong-head', 'pr_number': 42, 'head_sha': B, 'base_sha': C}
        for error in [urllib.error.HTTPError('https://api.github.com', 409, 'conflict', {}, io.BytesIO(b'{"message":"private-sentinel"}')),
                      TimeoutError('private-sentinel')]:
            client = q.FixtureMutationClient('secret-sentinel'); client.opener = mock.Mock(); client.opener.open.side_effect = error
            if isinstance(error, urllib.error.HTTPError):
                status, body = client.probe(admitted); self.assertEqual(status, 409); self.assertEqual(body['message'], 'private-sentinel')
            else:
                with self.assertRaises(TimeoutError): client.probe(admitted)
            with self.assertRaises(ValueError): client.probe(admitted)
            self.assertEqual(client.opener.open.call_count, 1)
        self.assertIsNone(q.common.NoRedirect().redirect_request(None, None, None, None, None, None))

    def test_probes_reconcile_no_retry_real_native_merge_and_uncertainty(self):
        for scenario in ['wrong-head', 'native-merge', 'uncertain', 'postread-error', 'moved-head']:
            api, event, env, values = fixture(); event['inputs']['case'] = 'native-merge' if scenario == 'native-merge' else 'wrong-head'
            env['PROTECTED_MERGE_TOKEN'] = 'app-token'; env['GITHUB_TOKEN'] = 'read-token'
            writer = mock.Mock()
            def write(admitted):
                if scenario == 'native-merge':
                    pr = values['pulls/42']; pr.update(merged=True, state='closed', merge_commit_sha=A)
                    values['git/ref/heads/'+q.TARGET]['object']['sha'] = A
                    values['commits/'+A] = {'sha': A, 'parents': [{'sha': C}, {'sha': B}]}
                    return 200, {'merged': True, 'sha': A}
                if scenario == 'postread-error': api.get.side_effect = OSError('private-sentinel')
                if scenario == 'moved-head': values['pulls/42']['head']['sha'] = A
                if scenario == 'uncertain': raise TimeoutError('private-sentinel')
                return 409, {'message': 'private-sentinel'}
            writer.probe.side_effect = write
            with mock.patch.object(q, 'settings'), mock.patch.object(q, 'fixture_preflight'), mock.patch.object(q, 'FixtureMutationClient', return_value=writer):
                result = q.probe(api, mock.Mock(), event, env)
            self.assertEqual(writer.probe.call_count, 1)
            self.assertEqual(result['outcome'], {'native-merge': 'native-merge-confirmed', 'wrong-head': 'head-mismatch-denied',
                'uncertain': 'unproven', 'postread-error': 'unconfirmed', 'moved-head': 'unconfirmed'}[scenario])
            self.assertTrue(result['mutation_attempted']); self.assertNotIn('private-sentinel', json.dumps(result))
        api, event, env, values = fixture(); values['pulls/42']['base']['ref'] = 'main'
        with mock.patch.object(q, 'FixtureMutationClient') as constructor:
            with self.assertRaises(ValueError): q.probe(api, mock.Mock(), event, env)
            constructor.assert_not_called()

    def test_exhausted_probe_transport_budget_has_fresh_readonly_reconciliation(self):
        for budget in ('time', 'requests'):
            for scenario in ('native-merge', 'uncertain', 'wrong-head'):
                with self.subTest(budget=budget, scenario=scenario):
                    _, event, env, values = fixture()
                    event['inputs']['case'] = 'wrong-head' if scenario == 'wrong-head' else 'native-merge'
                    env.update(GITHUB_TOKEN='read-token', PROTECTED_MERGE_TOKEN='app-token')
                    values['commits/'+B+'/check-runs?filter=all&per_page=100&page=1'] = {'total_count': 12,
                        'check_runs': [{'id': i+1, 'name': name, 'head_sha': B, 'status': 'completed', 'conclusion': 'success',
                                       'app': {'id': 57789 if name == 'CodeQL' else 15368}}
                                      for i, name in enumerate(q.merge.CHECK_CONTEXTS)]}
                    clock, traffic, created = [0.0], [], []
                    case = self

                    class Response:
                        status = 200
                        def __init__(self, data): self.data = data
                        def __enter__(self): return self
                        def __exit__(self, *args): pass
                        def read(self, limit): return self.data[:limit]

                    class Opener:
                        def open(self, request, timeout):
                            path = request.full_url.removeprefix('https://api.github.com/repos/lorconksu/veyport').lstrip('/')
                            method = request.get_method()
                            traffic.append((method, path, request.get_header('Authorization')))
                            case.assertTrue(0 < timeout <= 30)
                            if method == 'PUT':
                                case.assertEqual(path, 'pulls/42/merge')
                                case.assertEqual(json.loads(request.data), {'sha': C if scenario == 'wrong-head' else B, 'merge_method': 'merge'})
                                if scenario == 'wrong-head':
                                    raise urllib.error.HTTPError(request.full_url, 409, 'conflict', {}, io.BytesIO(b'{}'))
                                values['pulls/42'].update(merged=True, state='closed', merge_commit_sha=A)
                                values['git/ref/heads/'+q.TARGET]['object']['sha'] = A
                                values['commits/'+A] = {'sha': A, 'parents': [{'sha': C}, {'sha': B}]}
                                if scenario == 'uncertain': raise TimeoutError('PRIVATE')
                                return Response(json.dumps({'sha': A, 'merged': True}).encode())
                            case.assertEqual(method, 'GET')
                            return Response(json.dumps(values[path]).encode())

                    def opener(*handlers):
                        created.append(len(traffic))
                        return Opener()

                    original_context, contexts = q.context, [0]
                    def exhaust_last_context(api, event, env):
                        admitted = original_context(api, event, env)
                        contexts[0] += 1
                        if contexts[0] == 2:
                            if budget == 'requests':
                                while api.transport.requests < 160: api.get('')
                            else: clock[0] = api.transport.deadline
                        return admitted

                    with mock.patch.object(q.common.time, 'monotonic', side_effect=lambda: clock[0]), \
                         mock.patch.object(q.urllib.request, 'build_opener', side_effect=opener), \
                         mock.patch.object(q, 'context', side_effect=exhaust_last_context), mock.patch.object(q, 'settings'), \
                         mock.patch('socket.create_connection', side_effect=AssertionError('socket connection attempted')):
                        api = q.common.MetadataClient('read-token')
                        result = q.probe(api, mock.Mock(), event, env)
                        with self.assertRaises(ValueError): api.get('')
                    self.assertEqual(contexts[0], 2)
                    self.assertEqual(sum(row[0] == 'PUT' for row in traffic), 1)
                    self.assertEqual(result['outcome'], 'head-mismatch-denied' if scenario == 'wrong-head' else 'native-merge-confirmed')
                    self.assertEqual(result['http_status'], 409 if scenario == 'wrong-head' else None if scenario == 'uncertain' else 200)
                    self.assertTrue(result['mutation_attempted'])
                    write_index = next(i for i, row in enumerate(traffic) if row[0] == 'PUT')
                    expected = ['pulls/42', 'git/ref/heads/'+q.TARGET]
                    if scenario != 'wrong-head': expected.append('commits/'+A)
                    self.assertEqual(traffic[write_index+1:], [('GET', path, 'Bearer read-token') for path in expected])
                    self.assertEqual(traffic[write_index][2], 'Bearer app-token')
                    self.assertEqual(len(created), 3)
                    self.assertEqual(created[-1], write_index+1)

    def test_real_cli_entrypoint_success_refusal_and_sanitized_postwrite_output(self):
        api, event, env, _ = fixture(); env.update(GITHUB_TOKEN='read-token', PROTECTED_MERGE_TOKEN='app-token')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'event'; path.write_text(json.dumps(event)); env['GITHUB_EVENT_PATH'] = str(path)
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(q.common, 'MetadataClient', return_value=api), mock.patch.object(q, 'settings'), mock.patch.object(q, 'fixture_preflight'), mock.patch.object(q, 'FixtureMutationClient') as constructor, mock.patch('sys.stdout', new_callable=io.StringIO) as output:
                constructor.return_value.probe.return_value = (409, {'message': 'private-sentinel'})
                self.assertEqual(q.main(['probe']), 0)
                result = json.loads(output.getvalue()); self.assertEqual(result['outcome'], 'head-mismatch-denied')
                self.assertNotIn('sentinel', output.getvalue())
            env['GITHUB_RUN_ATTEMPT'] = '2'
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(q.common, 'MetadataClient') as constructor, mock.patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(q.main(['probe']), 1); constructor.assert_not_called()
                self.assertFalse(json.loads(output.getvalue())['mutation_attempted'])

    def test_fixture_preflight_real_fast_forward_and_all_canary_states(self):
        api = mock.Mock(); admitted = {'case': 'direct-push', 'head_sha': B, 'base_sha': C}
        api.get.return_value = {'sha': B, 'parents': [{'sha': C, 'url': 'ignored-navigation'}]}
        q.fixture_preflight(api, admitted)
        for parents in [[], [{'sha': A}], [{'sha': C}, {'sha': A}]]:
            api.get.return_value['parents'] = parents
            with self.assertRaises(ValueError): q.fixture_preflight(api, admitted)
        base = [{'id': i+1, 'name': name, 'head_sha': B, 'status': 'completed', 'conclusion': 'success',
                 'app': {'id': 57789 if name == 'CodeQL' else 15368}} for i, name in enumerate(q.merge.CHECK_CONTEXTS)]
        for case in ['missing-canary', 'pending-canary', 'failed-canary']:
            rows = copy.deepcopy(base)
            if case != 'missing-canary': rows += [{'id': 100, 'name': q.CANARY, 'head_sha': B, 'app': {'id': 15368},
                    'status': 'in_progress' if case == 'pending-canary' else 'completed',
                    'conclusion': None if case == 'pending-canary' else 'failure'}]
            with mock.patch.object(q.common, 'pages', return_value=rows): q.fixture_preflight(api, {**admitted, 'case': case})
            if rows[-1]['name'] == q.CANARY:
                rows[-1]['app']['id'] = 123
                with mock.patch.object(q.common, 'pages', return_value=rows), self.assertRaises(ValueError): q.fixture_preflight(api, {**admitted, 'case': case})

    def test_fixture_settings_preserve_full_baseline_and_visible_exact_bypass(self):
        reads, env, values, rule, classic = settings_fixture()
        q.settings(reads, env, 'native-merge'); q.settings(reads, env, 'main-settings')
        for patch in [{'bypass_actors': []}, {'conditions': {'ref_name': {'include': ['refs/heads/main'], 'exclude': []}}}, {'enforcement': 'disabled'}]:
            with mock.patch.dict(rule, patch), self.assertRaises(ValueError): q.settings(reads, env, 'native-merge')
        values['branches/'+q.BRANCH_PATH+'/protection'] = copy.deepcopy(classic)
        target = values['branches/'+q.BRANCH_PATH+'/protection']['required_status_checks']
        target['contexts'].append(q.CANARY); target['checks'].append({'context': q.CANARY, 'app_id': 15368})
        q.settings(reads, env, 'missing-canary')
        target['checks'].pop(0)
        with self.assertRaises(ValueError): q.settings(reads, env, 'missing-canary')

    def test_actual_fixed_get_requests_and_workflow_diff_completeness(self):
        paths = ['actions/workflows/protected-merge-qualification.yml',
                 'git/ref/heads/qualification/protected-merge-20261116',
                 'pulls/42/files?per_page=100&page=1']
        transport = q.common.Transport('read-token'); transport.opener = mock.Mock()
        response = mock.MagicMock(); response.status = 200; response.read.return_value = b'{}'
        response.__enter__.return_value = response; transport.opener.open.return_value = response
        for path in paths:
            transport.request('GET', path)
            request = transport.opener.open.call_args.args[0]
            self.assertEqual(request.full_url, 'https://api.github.com/repos/lorconksu/veyport/'+path)
            self.assertEqual(request.method, 'GET'); self.assertIsNone(request.data)
            for method in ['PATCH', 'POST', 'PUT', 'DELETE']:
                with self.assertRaises(ValueError): transport.request(method, path)
        before = transport.opener.open.call_count
        for path in ['pulls/42/files/extra', 'pulls/0/files', 'pulls/42/files?target=main']:
            with self.assertRaises(ValueError): transport.request('GET', path)
        self.assertEqual(transport.opener.open.call_count, before)
        reads = q.FixtureReadClient('app-token'); reads.opener = mock.Mock(); reads.opener.open.return_value = response
        for path in ['branches/'+q.BRANCH_PATH+'/protection', 'rules/branches/'+q.BRANCH_PATH+'?per_page=100&page=1']:
            reads.get(path); request = reads.opener.open.call_args.args[0]
            self.assertEqual(request.method, 'GET'); self.assertTrue(request.full_url.endswith(path)); self.assertIsNone(request.data)
        admitted = {'case': 'workflow-file-merge', 'head_sha': B, 'pr_number': 42}
        api = mock.Mock(); values = {'pulls/42': {'changed_files': 1}, 'pulls/42/files?per_page=100&page=1': [{'filename': '.github/workflows/a.yml'}]}
        api.get.side_effect = lambda path: values[path]
        with mock.patch.object(q.common, 'pages', return_value=[]), mock.patch.object(q, 'native_checks'):
            q.fixture_preflight(api, admitted)
            for count, files in [(100, []), (True, []), (2, [{'filename': '.github/workflows/a.yml'}]), (1, [{'filename': 'README.md'}])]:
                values['pulls/42']['changed_files'] = count; values['pulls/42/files?per_page=100&page=1'] = files
                with self.assertRaises(ValueError): q.fixture_preflight(api, admitted)

    def test_main_settings_never_constructs_mutation_client_and_admit_cli_outputs(self):
        api, event, env, _ = fixture(); event['inputs']['case'] = 'main-settings'
        with mock.patch.object(q, 'settings') as settings, mock.patch.object(q, 'FixtureMutationClient') as writer:
            result = q.probe(api, mock.Mock(), event, env)
            self.assertEqual(result['outcome'], 'main-baseline-visible'); self.assertFalse(result['mutation_attempted'])
            self.assertIsNone(result['http_status'])
            api.fresh_readonly.assert_not_called()
            settings.assert_called_once(); writer.assert_not_called()
        with tempfile.TemporaryDirectory() as folder:
            eventfile = Path(folder)/'event'; eventfile.write_text(json.dumps(event)); output = Path(folder)/'output'
            env.update(GITHUB_JOB='admission', GITHUB_EVENT_PATH=str(eventfile), GITHUB_OUTPUT=str(output), GITHUB_TOKEN='read-token')
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(q.common, 'MetadataClient', return_value=api), mock.patch.object(q, 'FixtureReadClient') as reads, mock.patch.object(q, 'FixtureMutationClient') as writer:
                self.assertEqual(q.main(['admit']), 0); reads.assert_not_called(); writer.assert_not_called()
                self.assertEqual(output.read_text(), 'admitted=true\ncase=main-settings\n')

    def test_expected_canary_denial_requires_specific_platform_response_and_no_write(self):
        admitted = {'case': 'failed-canary', 'target': q.TARGET, 'pr_number': 42, 'head_sha': B, 'base_sha': C, 'run_id': 80}
        for status, message, unchanged, expected in [(405, 'Required status check is failing', True, 'canary-check-denied'),
                (403, 'Resource not accessible by integration', True, 'unproven'),
                (405, 'Not mergeable', True, 'unproven'),
                (405, 'Required status check is failing', False, 'unexpected-update')]:
            self.assertEqual(q.classify(admitted, status, {'message': message}, unchanged)['outcome'], expected)

    def test_native_canary_producer_single_fixed_post_and_consumer_identity(self):
        for case, expected in [('pending-canary', {'status': 'in_progress'}), ('failed-canary', {'status': 'completed', 'conclusion': 'failure'})]:
            api, event, env, _ = fixture(); event['inputs']['case'] = case; env['GITHUB_JOB'] = 'admission'; env['GITHUB_TOKEN'] = 'native-token'
            admitted = q.context(api, event, env)
            client = q.NativeCanaryClient('native-token'); client.opener = mock.Mock()
            response = mock.MagicMock(); response.status = 201; response.__enter__.return_value = response
            returned = {'id': 101, 'name': q.CANARY, 'head_sha': B, 'status': expected['status'], 'conclusion': expected.get('conclusion'), 'app': {'id': 15368}}
            response.read.return_value = json.dumps(returned).encode(); client.opener.open.return_value = response
            client.create(admitted)
            request = client.opener.open.call_args.args[0]
            self.assertEqual(request.full_url, 'https://api.github.com/repos/lorconksu/veyport/check-runs'); self.assertEqual(request.method, 'POST')
            self.assertEqual(json.loads(request.data), {'name': q.CANARY, 'head_sha': B, **expected})
            with self.assertRaises(ValueError): client.create(admitted)
            self.assertEqual(client.opener.open.call_count, 1)
            native = [{'id': i+1, 'name': name, 'head_sha': B, 'status': 'completed', 'conclusion': 'success', 'app': {'id': 57789 if name == 'CodeQL' else 15368}} for i,name in enumerate(q.merge.CHECK_CONTEXTS)]
            with mock.patch.object(q.common, 'pages', return_value=[*native,returned]): q.fixture_preflight(api, admitted)
            duplicate = {**copy.deepcopy(returned), 'id': 102}
            with mock.patch.object(q.common, 'pages', return_value=[*native, returned, duplicate]), self.assertRaises(ValueError):
                q.fixture_preflight(api, admitted)
            returned['app']['id'] = 999
            with mock.patch.object(q.common, 'pages', return_value=[*native,returned]), self.assertRaises(ValueError): q.fixture_preflight(api, admitted)

    def test_producer_authentication_case_existing_check_refusal_and_no_uncertain_retry(self):
        native = [{'id': i+1, 'name': name, 'head_sha': B, 'status': 'completed', 'conclusion': 'success',
                   'app': {'id': 57789 if name == 'CodeQL' else 15368}} for i, name in enumerate(q.merge.CHECK_CONTEXTS)]
        api, event, env, values = fixture(); env.update(GITHUB_JOB='admission', GITHUB_TOKEN='native-token'); event['inputs']['case']='pending-canary'
        response = mock.MagicMock(); response.status = 201; response.__enter__.return_value = response
        canary = {'id': 44, 'name': q.CANARY, 'head_sha': B, 'status': 'in_progress', 'conclusion': None, 'app': {'id': 15368}}
        response.read.return_value = json.dumps(canary).encode()
        opener = mock.Mock(); opener.open.return_value = response
        with mock.patch.object(q.common, 'pages', return_value=copy.deepcopy(native)), mock.patch.object(q.urllib.request, 'build_opener', return_value=opener):
            result = q.produce_canary(api, event, env)
        self.assertEqual(result, {'schema_version': 1, 'case': 'pending-canary', 'target': q.TARGET,
                                 'head_sha': B, 'mutation_attempted': True, 'outcome': 'canary-created', 'check_run_id': 44})
        self.assertEqual(opener.open.call_count, 1)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, 'https://api.github.com/repos/lorconksu/veyport/check-runs')
        self.assertEqual(request.method, 'POST')
        self.assertEqual(json.loads(request.data), {'name': q.CANARY, 'head_sha': B, 'status': 'in_progress'})
        for mutation in ['main', 'fork', 'actor', 'attempt', 'probe-job', 'app-token', 'existing']:
            api, event, env, values = fixture(); env.update(GITHUB_JOB='admission', GITHUB_TOKEN='native-token'); event['inputs']['case']='pending-canary'
            rows = copy.deepcopy(native)
            if mutation=='main': values['pulls/42']['base']['ref']='main'
            elif mutation=='fork': values['pulls/42']['head']['repo']={'id': 3}
            elif mutation=='actor': env['GITHUB_ACTOR']='other'
            elif mutation=='attempt': env['GITHUB_RUN_ATTEMPT']='2'
            elif mutation=='probe-job': env['GITHUB_JOB']='probe'
            elif mutation=='app-token': env['PROTECTED_MERGE_TOKEN']='app-token'
            elif mutation=='existing': rows.append(copy.deepcopy(canary))
            with self.subTest(mutation=mutation), mock.patch.object(q.common,'pages',return_value=rows), mock.patch.object(q,'NativeCanaryClient') as writer:
                with self.assertRaises(ValueError): q.produce_canary(api,event,env)
                writer.assert_not_called()
        for case in ['missing-canary','native-merge','main-settings']:
            api,event,env,_=fixture();env.update(GITHUB_JOB='admission',GITHUB_TOKEN='native-token');event['inputs']['case']=case
            with mock.patch.object(q,'NativeCanaryClient') as writer:
                q.produce_canary(api,event,env);writer.assert_not_called()
        api,event,env,_=fixture();env.update(GITHUB_JOB='admission',GITHUB_TOKEN='native-token');event['inputs']['case']='pending-canary'
        admitted=q.context(api,event,env)
        writer=q.NativeCanaryClient('native-token');writer.opener=mock.Mock();writer.opener.open.side_effect=TimeoutError('private-sentinel')
        with self.assertRaises(TimeoutError):writer.create(admitted)
        with self.assertRaises(ValueError):writer.create(admitted)
        self.assertEqual(writer.opener.open.call_count,1)
        for case in ['missing-canary','native-merge']:
            refused=q.NativeCanaryClient('native-token');refused.opener=mock.Mock()
            response = mock.MagicMock(); response.status = 201; response.__enter__.return_value = response
            response.read.return_value = json.dumps({**canary, 'status': 'completed'}).encode()
            refused.opener.open.return_value = response
            with self.subTest(case=case):
                with self.assertRaises(ValueError):refused.create({**admitted,'case':case})
                refused.opener.open.assert_not_called()

    def test_malformed_three_parent_positive_proof_refused(self):
        api,event,env,values=fixture();event['inputs']['case']='native-merge';admitted=q.context(api,event,env)
        values['pulls/42'].update(merged=True,state='closed',merge_commit_sha=A)
        values['git/ref/heads/'+q.TARGET]['object']['sha']=A
        for parents in [[{'sha':C},None,{'sha':B}],[{'sha':C},{'sha':B},None],[{'sha':C},{}],[{'sha':C},{'sha':B.upper()}]]:
            values['commits/'+A]={'sha':A,'parents':parents}
            with self.subTest(parents=parents),self.assertRaises(ValueError):q.reconcile(api,admitted,200,{'sha':A})

    def test_actual_producer_cli_and_uncertainty_fail_closed_without_retry(self):
        for uncertain in [False, True]:
            api,event,env,_=fixture();env.update(GITHUB_JOB='admission',GITHUB_TOKEN='native-token');event['inputs']['case']='failed-canary'
            rows=[{'id':i+1,'name':name,'head_sha':B,'status':'completed','conclusion':'success','app':{'id':57789 if name=='CodeQL' else 15368}} for i,name in enumerate(q.merge.CHECK_CONTEXTS)]
            writer=mock.Mock()
            if uncertain: writer.create.side_effect=TimeoutError('private-sentinel')
            else: writer.create.return_value=101
            with tempfile.TemporaryDirectory() as folder:
                path=Path(folder)/'event';path.write_text(json.dumps(event));env['GITHUB_EVENT_PATH']=str(path)
                with mock.patch.dict(os.environ,env,clear=True),mock.patch.object(q.common,'MetadataClient',return_value=api),mock.patch.object(q.common,'pages',return_value=rows),mock.patch.object(q,'NativeCanaryClient',return_value=writer),mock.patch('sys.stdout',new_callable=io.StringIO) as output:
                    self.assertEqual(q.main(['produce-canary']),1 if uncertain else 0)
                    result=json.loads(output.getvalue());self.assertEqual(result['outcome'],'canary-unconfirmed' if uncertain else 'canary-created')
                    self.assertTrue(result['mutation_attempted']);self.assertNotIn('sentinel',output.getvalue())
            self.assertEqual(writer.create.call_count,1)
        api,event,env,values=fixture();env.update(GITHUB_JOB='admission',GITHUB_TOKEN='native-token');event['inputs']['case']='pending-canary'
        with mock.patch.object(q.common,'pages',return_value=[]),mock.patch.object(q,'NativeCanaryClient') as writer:
            with self.assertRaises(ValueError):q.produce_canary(api,event,env)
            writer.assert_not_called()
        client=q.NativeCanaryClient('native-token');client.opener=mock.Mock();response=mock.MagicMock();response.status=201;response.__enter__.return_value=response
        response.read.return_value=json.dumps({'id':101,'name':q.CANARY,'head_sha':B,'status':'in_progress','conclusion':None,'app':{'id':999}}).encode();client.opener.open.return_value=response
        with self.assertRaises(ValueError):client.create(q.context(api,event,env))
        with self.assertRaises(ValueError):client.create(q.context(api,event,env))
        self.assertEqual(client.opener.open.call_count,1)

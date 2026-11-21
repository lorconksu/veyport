"""Offline settings diagnostic through the real qualification CLI."""
from contextlib import redirect_stderr, redirect_stdout
import http.client
import io
import json
import os
from pathlib import Path
import re
import tempfile
import time
import unittest
from unittest import mock
import urllib.error
import urllib.request
import urllib.response

from test_protected_merge_qualification import B, C, fixture, q, repository, settings_fixture

API = 'https://api.github.com'
REPO = API+'/repos/lorconksu/veyport'
APP = API+'/apps/merge-app'
SCOPE = API+'/installation/repositories?per_page=100&page=1'
MAIN = REPO+'/branches/main/protection'
RULE = REPO+'/rulesets/666'
EFFECTIVE = REPO+'/rules/branches/qualification%2Fprotected-merge-20261116?per_page=100&page=1'
CLASSIC = REPO+'/branches/qualification%2Fprotected-merge-20261116/protection'
GRAPHQL = API+'/graphql'
READS = [APP, SCOPE, MAIN, RULE, EFFECTIVE, CLASSIC, GRAPHQL]
PRIVATE = 'private-sentinel\n::error::untrusted'
APP_TOKEN = 'private-app-token-sentinel'
READ_TOKEN = 'private-read-token-sentinel'
MISSING = object()


def actor(**changes):
    return {'actor': {'__typename': 'App', 'databaseId': 333}, 'bypassMode': 'PULL_REQUEST',
            'deployKey': False, 'organizationAdmin': False, 'enterpriseOwner': False,
            'enterpriseRole': False, 'enterpriseRoleDatabaseId': None,
            'repositoryRoleDatabaseId': None, 'repositoryRoleName': None, **changes}


def connection(nodes=None, **changes):
    return {'totalCount': 1, 'nodes': [actor()] if nodes is None else nodes,
            'pageInfo': {'hasNextPage': False, 'hasPreviousPage': False}, **changes}


def graph(bypass=MISSING):
    return {'data': {'repository': {'databaseId': 1188082218, 'nameWithOwner': 'lorconksu/veyport',
            'ruleset': {'databaseId': 666, 'bypassActors': connection() if bypass is MISSING else bypass}}}}


class Response(io.BytesIO):
    status = 200


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.api, self.event, self.env, self.metadata = fixture()
        _, settings_env, values, self.rule, _ = settings_fixture()
        self.event['inputs']['case'] = 'settings-diagnostic'
        self.env.update(settings_env, GITHUB_TOKEN=READ_TOKEN, PROTECTED_MERGE_TOKEN=APP_TOKEN)
        self.values = {APP: values['apps/merge-app'], SCOPE: values['installation/repositories?per_page=100&page=1'],
                       MAIN: values['branches/main/protection'], RULE: self.rule,
                       EFFECTIVE: values['rules/branches/'+q.BRANCH_PATH+'?per_page=100&page=1'],
                       CLASSIC: values['branches/'+q.BRANCH_PATH+'/protection'], GRAPHQL: graph()}

    def offline_cli(self, expected_reads=READS, *, raise_at_open=None, open_response=None, https_handler=None):
        traffic = []
        build_opener = urllib.request.build_opener

        def fake_open(request, timeout):
            url = request.full_url
            traffic.append(url)
            self.assertTrue(0 < timeout <= 30)
            self.assertEqual(request.get_header('Authorization'), 'Bearer '+APP_TOKEN)
            if url == GRAPHQL:
                self.assertEqual(request.get_method(), 'POST')
                data = json.loads(request.data)
                self.assertEqual(set(data), {'query', 'variables'})
                self.assertEqual(data['variables'], {'id': 666})
                query = re.sub(r'\s+', '', data['query'])
                self.assertTrue(query.startswith('query'))
                self.assertIn('repository(owner:"lorconksu",name:"veyport")', query)
                self.assertIn('ruleset(databaseId:$id)', query)
                self.assertIn('bypassActors(first:100)', query)
                self.assertIn('pageInfo{hasNextPagehasPreviousPage}', query)
                self.assertIn('...onApp{databaseId}', query)
                for field in ('databaseId', 'totalCount', '__typename', 'bypassMode', 'deployKey',
                              'organizationAdmin', 'enterpriseOwner', 'enterpriseRole',
                              'enterpriseRoleDatabaseId', 'repositoryRoleDatabaseId', 'repositoryRoleName'):
                    self.assertIn(field, query)
            else:
                self.assertEqual(request.get_method(), 'GET')
                self.assertIsNone(request.data)
            value = self.values[url]
            if raise_at_open == url:
                raise value
            if https_handler and url == GRAPHQL:
                return redirect_opener.open(request, timeout=timeout)
            if open_response and url == GRAPHQL:
                return open_response()
            return Response(value if type(value) is bytes else json.dumps(value).encode())

        def fixture_opener(*handlers):
            nonlocal redirect_opener
            if https_handler:
                redirect_opener = build_opener(urllib.request.ProxyHandler({}), https_handler, *handlers)
            return mock.Mock(open=fake_open)

        redirect_opener = None
        stdout, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as folder:
            event_file = Path(folder)/'event.json'
            event_file.write_text(json.dumps(self.event))
            env = {**self.env, 'GITHUB_EVENT_PATH': str(event_file)}
            with mock.patch.dict(os.environ, env, clear=True), redirect_stdout(stdout), redirect_stderr(stderr), \
                 mock.patch.object(q.common, 'MetadataClient', return_value=self.api), \
                 mock.patch.object(q.urllib.request, 'build_opener', side_effect=fixture_opener), \
                 mock.patch.object(q, 'FixtureMutationClient', side_effect=AssertionError('App writer constructed')), \
                 mock.patch.object(q, 'NativeCanaryClient', side_effect=AssertionError('native writer constructed')), \
                 mock.patch('socket.create_connection', side_effect=AssertionError('real socket requested')):
                code = q.main(['probe'])
        self.assertEqual(traffic, expected_reads)
        self.assertEqual(stderr.getvalue(), '')
        self.assertNotIn('sentinel', stdout.getvalue())
        self.assertNotIn('::error::', stdout.getvalue())
        report = json.loads(stdout.getvalue())
        self.assertIs(report['mutation_attempted'], False)
        self.assertNotIn('merge_commit_sha', report)
        if code == 0:
            self.assertEqual(report['outcome'], 'diagnostic-collected')
            self.assertEqual(report['evidence_scope'], 'settings-visibility-only')
        return code, report

    def test_cli_collects_only_fixed_reads_and_reports_complete_sole_app(self):
        code, report = self.offline_cli()
        self.assertEqual(code, 0)
        self.assertEqual((report['case'], report['target'], report['run_id'], report['pr_number'],
                          report['head_sha'], report['base_sha']),
                         ('settings-diagnostic', q.TARGET, 80, 42, B, C))
        stages = report['stages']
        self.assertEqual(set(stages), {'admission', 'app_configuration', 'app_identity', 'installation_scope',
                        'fixture_configuration', 'main_classic', 'fixture_ruleset', 'fixture_effective',
                        'fixture_classic', 'graphql_bypass'})
        for name in ('app_identity', 'installation_scope', 'main_classic', 'fixture_classic'):
            self.assertEqual(stages[name], {'result': 'verified', 'http_status': 200})
        self.assertEqual(stages['fixture_ruleset'], {
            'result': 'observed', 'http_status': 200, 'identity_matches': True, 'branch_target_matches': True,
            'conditions_match': True, 'restrictive_update_matches': True, 'enforcement': 'active',
            'roster': 'visible', 'sole_app_pr_only': True})
        self.assertEqual(stages['fixture_effective'], {'result': 'observed', 'http_status': 200,
                         'restrictive_update_matches': True, 'empty': False})
        self.assertEqual(stages['graphql_bypass'], {'result': 'observed', 'http_status': 200,
                         'repository_identity': 'verified', 'ruleset_identity': 'verified',
                         'roster': 'visible', 'sole_app_pr_only': True})

    def test_fixture_drift_and_disabled_enforcement_still_collect_alternate_visibility(self):
        self.rule.update(enforcement='disabled', target='tag', conditions={'wrong': PRIVATE}, rules=[])
        self.rule.pop('bypass_actors')
        self.values[EFFECTIVE] = []
        self.values[MAIN] = {'bogus': PRIVATE}
        self.values[CLASSIC] = {'bogus': PRIVATE}
        code, report = self.offline_cli()
        self.assertEqual(code, 0)
        stages = report['stages']
        for name in ('main_classic', 'fixture_classic'):
            self.assertEqual(stages[name], {'result': 'validation-failed', 'http_status': 200})
        self.assertEqual(stages['fixture_ruleset'], {
            'result': 'observed', 'http_status': 200, 'identity_matches': True, 'branch_target_matches': False,
            'conditions_match': False, 'restrictive_update_matches': False, 'enforcement': 'disabled',
            'roster': 'missing', 'sole_app_pr_only': False})
        self.assertEqual(stages['fixture_effective'], {'result': 'observed', 'http_status': 200,
                         'restrictive_update_matches': False, 'empty': True})
        self.assertIs(stages['graphql_bypass']['sole_app_pr_only'], True)

    def test_rest_actor_visibility_distinguishes_missing_null_malformed_and_excess(self):
        app = {'actor_type': 'Integration', 'actor_id': 333, 'bypass_mode': 'pull_request'}
        for roster, state in [(MISSING, 'missing'), (None, 'null'), ({'body': PRIVATE}, 'malformed'),
                              ([PRIVATE], 'malformed'), ([{**app, 'actor_type': PRIVATE}], 'malformed'),
                              ([{**app, 'actor_id': True}], 'malformed'), ([{**app, 'bypass_mode': PRIVATE}], 'malformed'),
                              ([{**app, 'actor_id': None}], 'incomplete'), ([None], 'incomplete'),
                              ([{**app, 'actor_id': i+1} for i in range(101)], 'limit-exceeded'),
                              ([], 'visible'), ([{**app, 'actor_id': 2}], 'visible'),
                              ([{**app, 'bypass_mode': 'always'}], 'visible'),
                              ([app, {'actor_type': 'DeployKey', 'actor_id': None, 'bypass_mode': 'always'}], 'visible'),
                              ([app, {'actor_type': 'User', 'actor_id': 1, 'bypass_mode': 'pull_request'}], 'visible')]:
            with self.subTest(state=state, size=len(roster) if type(roster) is list else None):
                if roster is MISSING:
                    self.rule.pop('bypass_actors', None)
                else:
                    self.rule['bypass_actors'] = roster
                code, report = self.offline_cli()
                stage = report['stages']['fixture_ruleset']
                self.assertEqual(code, 0)
                self.assertEqual(stage['roster'], state)
                self.assertIs(stage['sole_app_pr_only'], False)
                self.assertIs(report['stages']['graphql_bypass']['sole_app_pr_only'], True)

    def test_wrong_rest_rule_identity_does_not_attribute_the_roster(self):
        self.rule['source'] = PRIVATE
        _, report = self.offline_cli()
        stage = report['stages']['fixture_ruleset']
        self.assertEqual(stage, {'result': 'validation-failed', 'http_status': 200, 'identity_matches': False})
        self.assertIs(report['stages']['graphql_bypass']['sole_app_pr_only'], True)

    def test_graphql_identifies_complete_nonmatching_rosters(self):
        for nodes in [[], [actor(bypassMode='ALWAYS')], [actor(actor={'__typename': 'App', 'databaseId': 555})],
                      [actor(), actor(actor={'__typename': 'User', 'id': 'U_123'})],
                      [actor(), actor(actor=None, bypassMode='ALWAYS', deployKey=True)],
                      [actor(), actor(actor=None, organizationAdmin=True)],
                      [actor(), actor(actor=None, enterpriseOwner=True)],
                      [actor(), actor(actor=None, enterpriseRole=True, enterpriseRoleDatabaseId='91')],
                      [actor(), actor(actor=None, repositoryRoleDatabaseId=2, repositoryRoleName='write')]]:
            with self.subTest(nodes=nodes):
                self.values[GRAPHQL] = graph(connection(nodes, totalCount=len(nodes)))
                _, report = self.offline_cli()
                stage = report['stages']['graphql_bypass']
                self.assertEqual(stage['roster'], 'visible')
                self.assertIs(stage['sole_app_pr_only'], False)

    def test_graphql_incomplete_or_malformed_connection_cannot_prove_sole_app(self):
        for edit, state in [
            (lambda rule: rule.pop('bypassActors'), 'missing'),
            (lambda rule: rule.update(bypassActors=None), 'null'),
            (lambda rule: rule.update(bypassActors=[]), 'malformed'),
            (lambda rule: rule['bypassActors'].pop('nodes'), 'incomplete'),
            (lambda rule: rule['bypassActors'].update(nodes=None), 'incomplete'),
            (lambda rule: rule['bypassActors'].update(nodes=[None]), 'incomplete'),
            (lambda rule: rule['bypassActors'].update(nodes=[PRIVATE]), 'malformed'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(actor=None)]), 'incomplete'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(actor=PRIVATE)]), 'malformed'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(actor={'__typename': 'App'})]), 'incomplete'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(actor={'__typename': 'App', 'databaseId': None})]), 'incomplete'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(actor={'__typename': 'App', 'databaseId': True})]), 'malformed'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(actor={'__typename': PRIVATE, 'id': PRIVATE})]), 'malformed'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(actor={'__typename': 'User'})]), 'incomplete'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(bypassMode=None)]), 'incomplete'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(bypassMode=PRIVATE)]), 'malformed'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(enterpriseRoleDatabaseId='91')]), 'malformed'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(repositoryRoleDatabaseId=True)]), 'malformed'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(deployKey=True)]), 'malformed'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor(repositoryRoleName='write')]), 'malformed'),
            (lambda rule: rule['bypassActors'].update(totalCount=True), 'malformed'),
            (lambda rule: rule['bypassActors'].update(totalCount=-1), 'malformed'),
            (lambda rule: rule['bypassActors'].update(totalCount=0), 'incomplete'),
            (lambda rule: rule['bypassActors'].update(totalCount=2), 'incomplete'),
            (lambda rule: rule['bypassActors'].update(totalCount=101), 'limit-exceeded'),
            (lambda rule: rule['bypassActors'].update(nodes=[actor()]*101), 'limit-exceeded'),
            (lambda rule: rule['bypassActors'].pop('pageInfo'), 'incomplete'),
            (lambda rule: rule['bypassActors']['pageInfo'].pop('hasNextPage'), 'incomplete'),
            (lambda rule: rule['bypassActors']['pageInfo'].update(hasNextPage=True), 'incomplete'),
            (lambda rule: rule['bypassActors']['pageInfo'].update(hasPreviousPage=True), 'incomplete'),
            (lambda rule: rule['bypassActors']['pageInfo'].update(hasNextPage=0), 'malformed'),
        ]:
            with self.subTest(state=state):
                self.values[GRAPHQL] = graph()
                edit(self.values[GRAPHQL]['data']['repository']['ruleset'])
                _, report = self.offline_cli()
                stage = report['stages']['graphql_bypass']
                self.assertEqual(stage['roster'], state)
                self.assertIs(stage['sole_app_pr_only'], False)

    def test_graphql_ignores_roster_when_repository_or_ruleset_identity_is_unproven(self):
        for field in ('repository', 'ruleset'):
            for kind in ('missing', 'null', 'malformed', 'mismatch'):
                with self.subTest(field=field, kind=kind):
                    self.values[GRAPHQL] = graph()
                    data = self.values[GRAPHQL]['data']
                    parent = data if field == 'repository' else data['repository']
                    if kind == 'missing':
                        parent.pop(field)
                    elif kind == 'null':
                        parent[field] = None
                    elif kind == 'malformed':
                        parent[field] = PRIVATE
                    else:
                        parent[field]['databaseId'] += 1
                    _, report = self.offline_cli()
                    stage = report['stages']['graphql_bypass']
                    self.assertEqual(stage[field+'_identity'], kind)
                    self.assertEqual(stage['result'], 'validation-failed')
                    self.assertNotIn('roster', stage)
                    self.assertIs(stage['sole_app_pr_only'], False)

    def test_graphql_identity_requires_numeric_ids_and_exact_repository_name(self):
        for owner, field, value, state in [('repository', 'nameWithOwner', PRIVATE, 'mismatch'),
                                           ('repository', 'nameWithOwner', None, 'null'),
                                           ('repository', 'databaseId', True, 'malformed'),
                                           ('ruleset', 'databaseId', None, 'null'),
                                           ('ruleset', 'databaseId', '666', 'malformed')]:
            with self.subTest(owner=owner, field=field, state=state):
                self.values[GRAPHQL] = graph()
                repo = self.values[GRAPHQL]['data']['repository']
                (repo if owner == 'repository' else repo['ruleset'])[field] = value
                _, report = self.offline_cli()
                stage = report['stages']['graphql_bypass']
                self.assertEqual(stage[owner+'_identity'], state)
                self.assertEqual(stage['result'], 'validation-failed')
                self.assertNotIn('roster', stage)
                self.assertIs(stage['sole_app_pr_only'], False)

    def test_graphql_partial_errors_take_precedence_over_data(self):
        for errors, result in [([{'message': PRIVATE, 'path': [PRIVATE]}], 'graphql-errors'),
                               ([], 'validation-failed'), (PRIVATE, 'validation-failed'), (None, 'validation-failed')]:
            with self.subTest(result=result):
                self.values[GRAPHQL] = {**graph(), 'errors': errors}
                _, report = self.offline_cli()
                self.assertEqual(report['stages']['graphql_bypass'],
                    {'result': result, 'http_status': 200, 'sole_app_pr_only': False})

    def test_reports_http_status_and_sanitizes_transport_and_response_failure(self):
        for url, stage in [(RULE, 'fixture_ruleset'), (GRAPHQL, 'graphql_bypass')]:
            for status in (401, 403, 302):
                with self.subTest(url=url, status=status):
                    self.values[url] = urllib.error.HTTPError(url, status, PRIVATE,
                        {'Location': 'https://unexpected.example/'+PRIVATE}, io.BytesIO(PRIVATE.encode()))
                    _, report = self.offline_cli(raise_at_open=url)
                    observation = report['stages'][stage]
                    self.assertEqual(observation['result'], 'http-error')
                    self.assertEqual(observation['http_status'], status)
            self.values[url] = TimeoutError(PRIVATE)
            _, report = self.offline_cli(raise_at_open=url)
            observation = report['stages'][stage]
            self.assertEqual(observation['result'], 'transport-error')
            self.assertNotIn('http_status', observation)
            for raw in [b'x'*(q.common.MAX_JSON+1), b'{"duplicate":1,"duplicate":2}', b'['+PRIVATE.encode()]:
                with self.subTest(url=url, raw_length=len(raw)):
                    self.values[url] = raw
                    _, report = self.offline_cli()
                    observation = report['stages'][stage]
                    self.assertEqual(observation['result'], 'validation-failed')
                    self.assertEqual(observation['http_status'], 200)
            self.values[url] = self.rule if url == RULE else graph()

    def test_body_timeout_keeps_already_observed_http_status(self):
        class BrokenResponse(Response):
            def read(self, maximum):
                raise TimeoutError(PRIVATE)

        _, report = self.offline_cli(open_response=BrokenResponse)
        self.assertEqual(report['stages']['graphql_bypass'],
                         {'result': 'transport-error', 'http_status': 200, 'sole_app_pr_only': False})

    def test_http_response_rejects_truncated_content_length_even_with_valid_json(self):
        payload = json.dumps(graph()).encode()

        class WireResponse:
            def __init__(self, length):
                headers = f'HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n'.encode()
                self.stream = io.BytesIO(headers+payload)

            def makefile(self, mode):
                return self.stream

        def response(length):
            wire = http.client.HTTPResponse(WireResponse(length))
            wire.begin()
            return wire

        _, report = self.offline_cli(open_response=lambda: response(len(payload)))
        self.assertIs(report['stages']['graphql_bypass']['sole_app_pr_only'], True)

        _, report = self.offline_cli(open_response=lambda: response(len(payload)+8))
        self.assertEqual(report['stages']['graphql_bypass'],
                         {'result': 'transport-error', 'http_status': 200, 'sole_app_pr_only': False})

        oversized = response(q.common.MAX_JSON+1)
        with mock.patch.object(oversized, 'read', side_effect=AssertionError('oversized body was read')):
            _, report = self.offline_cli(open_response=lambda: oversized)
        self.assertEqual(report['stages']['graphql_bypass'],
                         {'result': 'validation-failed', 'http_status': 200, 'sole_app_pr_only': False})

    def test_wall_clock_timeout_interrupts_slow_header_or_body(self):
        completed = []

        def slow_response():
            time.sleep(1)
            completed.append(True)
            return Response(b'{}')

        class SlowBody(Response):
            def read(self, maximum):
                slow_response()
                return super().read(maximum)

        for phase, response, status in [('headers', slow_response, {}), ('body', SlowBody, {'http_status': 200})]:
            with self.subTest(phase=phase), mock.patch.object(q, 'DIAGNOSTIC_REQUEST_SECONDS', 0.1):
                _, report = self.offline_cli(open_response=response)
                self.assertEqual(report['stages']['graphql_bypass'],
                    {'result': 'transport-error', 'sole_app_pr_only': False, **status})
                self.assertEqual(completed, [])

    def test_real_redirect_handler_does_not_forward_graphql_token_or_body(self):
        class RedirectingHTTPS(urllib.request.HTTPSHandler):
            def __init__(self, status, location):
                super().__init__()
                self.status, self.location = status, location
                self.traffic = []

            def https_open(self, request):
                self.traffic.append((request.full_url, request.get_method(), request.get_header('Authorization')))
                self.assert_first_request(request)
                response = urllib.response.addinfourl(io.BytesIO(PRIVATE.encode()),
                    {'location': self.location}, request.full_url, self.status)
                response.msg = PRIVATE
                return response

            @staticmethod
            def assert_first_request(request):
                if request.full_url != GRAPHQL:
                    raise AssertionError('redirect followed')

        for status in (301, 302, 303, 307, 308):
            for location in ('https://unexpected.example/collection', 'https://['):
                with self.subTest(status=status, location=location):
                    redirect = RedirectingHTTPS(status, location)
                    code, report = self.offline_cli(https_handler=redirect)
                    self.assertEqual(code, 0)
                    self.assertEqual(redirect.traffic, [(GRAPHQL, 'POST', 'Bearer '+APP_TOKEN)])
                    self.assertEqual(report['stages']['graphql_bypass'],
                                     {'result': 'http-error', 'http_status': status, 'sole_app_pr_only': False})

    def test_admission_rejects_moved_head_or_rerun_before_privileged_reads(self):
        for failure in ('head', 'attempt'):
            with self.subTest(failure=failure):
                if failure == 'head':
                    self.metadata['pulls/42']['head']['sha'] = C
                else:
                    self.env['GITHUB_RUN_ATTEMPT'] = '2'
                code, report = self.offline_cli([])
                self.assertEqual(code, 1)
                self.assertEqual(report['outcome'], 'refused')

    def test_invalid_identity_and_scope_stop_before_any_settings_read(self):
        app = self.values[APP]
        scope = self.values[SCOPE]
        for url, value, name, reads in [(APP, {**app, 'client_id': PRIVATE}, 'app_identity', [APP]),
                (APP, {**app, 'owner': {**app['owner'], 'id': 1}}, 'app_identity', [APP]),
                (APP, {**app, 'permissions': {'administration': 'write'}}, 'app_identity', [APP]),
                (SCOPE, {**scope, 'total_count': 2}, 'installation_scope', [APP, SCOPE]),
                (SCOPE, {**scope, 'repositories': [{**repository(), 'id': 1}]}, 'installation_scope', [APP, SCOPE])]:
            with self.subTest(name=name):
                self.values[APP], self.values[SCOPE] = app, scope
                self.values[url] = value
                code, report = self.offline_cli(reads)
                self.assertEqual(code, 1)
                self.assertEqual(report['outcome'], 'diagnostic-refused')
                self.assertEqual(report['stages'][name], {'result': 'validation-failed', 'http_status': 200})
                self.assertNotIn('graphql_bypass', report['stages'])

        for url, name, reads in [(APP, 'app_identity', [APP]), (SCOPE, 'installation_scope', [APP, SCOPE])]:
            with self.subTest(name=name):
                self.values[APP], self.values[SCOPE] = app, scope
                self.values[url] = urllib.error.HTTPError(url, 403, PRIVATE, {}, io.BytesIO(PRIVATE.encode()))
                code, report = self.offline_cli(reads, raise_at_open=url)
                self.assertEqual(code, 1)
                self.assertEqual(report['stages'][name], {'result': 'http-error', 'http_status': 403})
                self.assertNotIn('graphql_bypass', report['stages'])

    def test_transport_rejects_unbounded_ids_and_unlisted_paths_before_io(self):
        with mock.patch.object(q.urllib.request, 'build_opener') as factory:
            reader = q.DiagnosticReadClient(APP_TOKEN)
            for path in ('https://unexpected.example', 'rulesets/0', 'rulesets/2147483648',
                         'rulesets/666?includes_parents=true', 'git/refs/heads/main'):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    reader.get(path)
            for rule_id in (True, '666', 0, 2147483648):
                with self.subTest(rule_id=rule_id), self.assertRaises(ValueError):
                    reader.graphql_fixture_ruleset(rule_id)
            factory.return_value.open.assert_not_called()

    def test_lowest_read_boundary_refuses_caller_supplied_post_and_unlisted_paths(self):
        payload = b'{"query":"mutation { updateRepositoryRuleset }"}'
        forbidden = [
            (('repos/lorconksu/veyport/check-runs', payload), {}),
            (('graphql', payload), {}),
            ((), {'path': 'graphql'}),
            ((), {'path': 'branches/main/protection', 'graphql_rule_id': 666}),
            ((), {'path': 'https://unexpected.example'}),
            ((), {'graphql_rule_id': payload}),
        ]
        with mock.patch.object(q.urllib.request, 'build_opener') as factory:
            reader = q.DiagnosticReadClient(APP_TOKEN)
            factory.return_value.open.side_effect = lambda *args, **kwargs: Response(b'{}')
            for args, kwargs in forbidden:
                with self.subTest(args=args, kwargs=kwargs), self.assertRaises((TypeError, ValueError)):
                    reader._read(*args, **kwargs)
            factory.return_value.open.assert_not_called()
            self.assertEqual(reader.requests, 0)

    def test_transport_request_and_elapsed_budgets_prevent_further_reads(self):
        clock = [0.0]

        with mock.patch.object(q.time, 'monotonic', side_effect=lambda: clock[0]), \
             mock.patch.object(q.urllib.request, 'build_opener') as factory:
            reader = q.DiagnosticReadClient(APP_TOKEN)
            send = factory.return_value.open
            send.side_effect = lambda *args, **kwargs: Response(b'{}')
            for _ in range(7):
                self.assertEqual(reader.get('branches/main/protection'), ({'result': 'observed', 'http_status': 200}, {}))
            without_status = ({'result': 'budget-exhausted'}, None)
            self.assertEqual(reader.graphql_fixture_ruleset(666), without_status)
            self.assertEqual(send.call_count, 7)

            reader = q.DiagnosticReadClient(APP_TOKEN)

            def finish_at_deadline(*args, **kwargs):
                clock[0] = 120.0
                return Response(b'{}')

            send.side_effect = finish_at_deadline
            self.assertEqual(reader.get('branches/main/protection'),
                             ({'result': 'budget-exhausted', 'http_status': 200}, None))
            self.assertEqual(reader.graphql_fixture_ruleset(666), without_status)
            self.assertEqual(send.call_count, 8)

    def test_invalid_config_and_non_graphql_int_rule_id_refuse_settings_reads(self):
        bad_configs = [('PROTECTED_MERGE_MINTED_INSTALLATION_ID', '99', 'app_configuration', []),
                       ('PROTECTED_MERGE_QUALIFICATION_RULESET_ID', '555', 'fixture_configuration', [APP, SCOPE]),
                       ('PROTECTED_MERGE_QUALIFICATION_RULESET_ID', '2147483648', 'fixture_configuration', [APP, SCOPE])]
        for name, value, stage, expected_reads in bad_configs:
            with self.subTest(name=name, value=value), mock.patch.dict(self.env, {name: value}):
                code, report = self.offline_cli(expected_reads)
                self.assertEqual(code, 1)
                self.assertEqual(report['outcome'], 'diagnostic-refused')
                self.assertEqual(report['stages'][stage], {'result': 'validation-failed'})
                self.assertNotIn('graphql_bypass', report['stages'])

    def test_diagnostic_cannot_call_native_canary_or_app_mutation_directly(self):
        admitted = {'case': 'settings-diagnostic', 'target': q.TARGET, 'head_sha': B, 'base_sha': C, 'pr_number': 42}
        with mock.patch.object(q.urllib.request, 'build_opener') as opener:
            with self.assertRaises(ValueError):
                q.FixtureMutationClient(APP_TOKEN).probe(admitted)
            with self.assertRaises(ValueError):
                q.NativeCanaryClient(READ_TOKEN).create(admitted)
            opener.return_value.open.assert_not_called()
        self.env['GITHUB_JOB'] = 'admission'
        self.env.pop('PROTECTED_MERGE_TOKEN')
        with mock.patch.object(q, 'NativeCanaryClient') as native, self.assertRaises(ValueError):
            q.produce_canary(self.api, self.event, self.env)
        native.assert_not_called()

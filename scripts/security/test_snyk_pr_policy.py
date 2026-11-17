"""Offline behavior/security contracts for the automatic trusted PR publisher."""
import copy
from email.message import Message
import hashlib
from http import HTTPStatus
import http.client
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
import zipfile
import warnings
import contextlib
import urllib.parse
import urllib.request
import urllib.response

PATH = Path(__file__).with_name('snyk_pr_policy.py')
REPO = {'id': 1188082218, 'full_name': 'lorconksu/veyport',
        'owner': {'id': 13374789}, 'default_branch': 'main'}
HEAD, CONTROL, BASE = 'a' * 40, 'b' * 40, 'c' * 40


class MetadataTransportTests(unittest.TestCase):
    """Keep real urllib handlers, replacing HTTPS I/O and denying sockets."""

    def setUp(self):
        spec = importlib.util.spec_from_file_location('snyk_ci_transport_under_test',
                                                     PATH.with_name('snyk_ci_common.py'))
        self.common = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.common)
        self.root = 'https://api.github.com/repos/lorconksu/veyport'
        self.routes = {self.root: (200, b'{"full_name":"lorconksu/veyport"}'),
                       self.root + '/': (404, b'{}')}
        self.requests = []
        case = self

        class HTTPS(urllib.request.HTTPSHandler):
            def https_open(self, request):
                case.requests.append(request)
                status, body = case.routes[request.full_url]
                response = urllib.response.addinfourl(io.BytesIO(body), Message(), request.full_url, status)
                response.msg = HTTPStatus(status).phrase
                return response

        class RejectHTTP(urllib.request.HTTPHandler):
            def http_open(self, request):
                raise AssertionError('HTTP transport disabled in tests')

        original = urllib.request.build_opener
        opener = mock.patch.object(urllib.request, 'build_opener',
                                   side_effect=lambda *handlers: original(*handlers, HTTPS(), RejectHTTP()))
        opener.start()
        self.addCleanup(opener.stop)
        sockets = mock.patch('socket.create_connection', side_effect=AssertionError('socket connection attempted'))
        sockets.start()
        self.addCleanup(sockets.stop)
        self.api = self.common.MetadataClient('synthetic-transport-token')

    def test_empty_repository_route_uses_canonical_url_without_trailing_slash(self):
        # An unconditional separator sends the request to the distinct 404 route.
        self.assertEqual(self.api.get(''), {'full_name': 'lorconksu/veyport'})
        request, = self.requests
        self.assertEqual(request.full_url, 'https://api.github.com/repos/lorconksu/veyport')
        self.assertEqual(request.get_method(), 'GET')
        self.assertEqual(request.get_header('Authorization'), 'Bearer synthetic-transport-token')
        self.assertEqual(request.get_header('Accept'), 'application/vnd.github+json')
        self.assertEqual(request.get_header('User-agent'), 'veyport-snyk-pr-policy')
        self.assertEqual(request.get_header('X-github-api-version'), '2022-11-28')

    def test_nonempty_routes_preserve_exact_path_and_query(self):
        for path in ('actions/runs/200', 'actions/runs/200/artifacts?per_page=100&page=2',
                     'commits/' + HEAD + '/check-runs?filter=all&per_page=100&page=1'):
            with self.subTest(path=path):
                url = self.root + '/' + path
                self.routes[url] = (200, b'{"ok":true}')
                self.assertEqual(self.api.get(path), {'ok': True})
                self.assertEqual(self.requests[-1].full_url, url)
                self.assertEqual(self.requests[-1].get_header('Authorization'), 'Bearer synthetic-transport-token')

    def test_http_is_rejected_before_any_socket_connection(self):
        with self.assertRaisesRegex(AssertionError, '^HTTP transport disabled in tests$'):
            self.api.transport.opener.open('http://api.github.com/repos/lorconksu/veyport')
        self.assertEqual(self.requests, [])

    def test_fresh_readonly_has_independent_bounded_transport_and_same_credentials(self):
        clock = [0.0]
        with mock.patch.object(self.common.time, 'monotonic', side_effect=lambda: clock[0]):
            original = self.common.MetadataClient('synthetic-transport-token')
            for _ in range(160): original.get('')
            clock[0] = 120.0
            fresh = original.fresh_readonly()
            with self.assertRaises(ValueError): original.get('')
            before = len(self.requests)
            for method, path in (('POST', 'check-runs'), ('PATCH', 'check-runs/888'),
                                 ('PUT', 'pulls/7/merge'), ('GET', 'https://evil.test/'),
                                 ('GET', 'installation/repositories')):
                with self.subTest(method=method, path=path), self.assertRaises(ValueError):
                    fresh.transport.request(method, path)
            self.assertEqual(len(self.requests), before)
            for _ in range(160):
                self.assertEqual(fresh.get(''), {'full_name': 'lorconksu/veyport'})
            with self.assertRaises(ValueError): fresh.get('')
            self.assertEqual(len(self.requests), before+160)
            self.assertTrue(all(request.get_header('Authorization') == 'Bearer synthetic-transport-token'
                                and request.get_method() == 'GET' for request in self.requests))
            clock[0] = 240.0
            fresh.transport.requests = 0  # Isolate expiry from the independent count limit.
            with self.assertRaises(ValueError): fresh.get('')
            self.assertEqual(len(self.requests), before+160)


def fixtures():
    env = {'GITHUB_EVENT_NAME': 'workflow_run', 'GITHUB_REF': 'refs/heads/main',
           'GITHUB_SHA': CONTROL, 'GITHUB_REPOSITORY': 'lorconksu/veyport',
           'GITHUB_RUN_ID': '200', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'admission',
           'SNYK_PR_POLICY_ENABLED': 'true'}
    upstream = {'id': 100, 'run_number': 10, 'run_attempt': 1, 'workflow_id': 251054731,
                'path': '.github/workflows/ci.yml', 'event': 'pull_request',
                'head_sha': HEAD, 'head_branch': 'feature/PRIVATE-BRANCH',
                'repository': copy.deepcopy(REPO), 'head_repository': copy.deepcopy(REPO),
                'pull_requests': [], 'status': 'in_progress', 'conclusion': None}
    driver = {'id': 200, 'run_number': 20, 'run_attempt': 1, 'workflow_id': 300,
              'path': '.github/workflows/snyk-pr-policy.yml', 'event': 'workflow_run',
              'head_sha': CONTROL, 'head_branch': 'main', 'repository': copy.deepcopy(REPO),
              'head_repository': copy.deepcopy(REPO), 'status': 'in_progress', 'conclusion': None}
    pr = {'id': 777, 'number': 7, 'state': 'open',
          'head': {'sha': HEAD, 'ref': upstream['head_branch'], 'repo': copy.deepcopy(REPO)},
          'base': {'sha': BASE, 'ref': 'main', 'repo': copy.deepcopy(REPO)}}
    event = {'action': 'in_progress', 'repository': copy.deepcopy(REPO),
             'workflow_run': copy.deepcopy(upstream), 'sender': {'login': 'untrusted-actor'}}
    return env, event, upstream, driver, pr


# A fixed sibling import also works under isolated Python without sys.path changes.
_CONTEXT_SUPPORT_SPEC = importlib.util.spec_from_file_location(
    'security_context_test_support', Path(__file__).with_name('context_test_support.py'))
_CONTEXT_SUPPORT = importlib.util.module_from_spec(_CONTEXT_SUPPORT_SPEC)
_CONTEXT_SUPPORT_SPEC.loader.exec_module(_CONTEXT_SUPPORT)
change_context_fields = _CONTEXT_SUPPORT.change_context_fields


class Metadata:
    def __init__(self):
        self.env, self.event, self.upstream, self.driver, self.pr = fixtures()
        self.repository = copy.deepcopy(REPO)
        self.workflow = {'id': 300, 'path': '.github/workflows/snyk-pr-policy.yml', 'state': 'active'}
        self.runs = [self.upstream]
        self.drivers = [self.driver]
        self.prs = [self.pr]
        self.other_prs = {}
        self.jobs = []
        self.artifacts = []
        self.raw = b''
        self.markers = []
        self.other_runs = {}
        self.calls = []

    def fresh_readonly(self): return self

    def get(self, path, **kwargs):
        self.calls.append(path)
        base = path.split('?')[0]
        if base == '': return copy.deepcopy(self.repository)
        if base == 'actions/workflows/snyk-pr-policy.yml':
            return copy.deepcopy(self.workflow)
        if base == 'actions/runs/100': return copy.deepcopy(self.upstream)
        if base == 'actions/runs/200': return copy.deepcopy(self.driver)
        if base.startswith('actions/runs/') and base[13:].isdigit(): return copy.deepcopy(self.other_runs[int(base[13:])])
        if base.startswith('commits/') and base.endswith('/pulls'): return copy.deepcopy(self.prs)
        if base == 'pulls/7': return copy.deepcopy(self.pr)
        if base.startswith('pulls/') and base[6:].isdigit(): return copy.deepcopy(self.other_prs[int(base[6:])])
        if base.endswith('/jobs'): return {'total_count': len(self.jobs), 'jobs': copy.deepcopy(self.jobs)}
        if base.endswith('/artifacts'): return {'total_count': len(self.artifacts), 'artifacts': copy.deepcopy(self.artifacts)}
        if base.endswith('/zip'): return self.raw
        if base == 'actions/workflows/251054731/runs':
            return {'total_count': len(self.runs), 'workflow_runs': copy.deepcopy(self.runs)}
        if base == 'actions/workflows/300/runs':
            return {'total_count': len(self.drivers), 'workflow_runs': copy.deepcopy(self.drivers)}
        if base.endswith('/check-runs'):
            source_sha = base.split('/')[1]
            markers = [row for row in self.markers if row.get('head_sha') == source_sha]
            return {'total_count': len(markers), 'check_runs': copy.deepcopy(markers)}
        raise AssertionError(path)


class Checks:
    def __init__(self):
        self.record = None
        self.writes = []
        self.counter = 887

    def fresh_publication(self): return self

    def create(self, body):
        self.writes.append(('POST', copy.deepcopy(body)))
        self.counter += 1
        self.record = {**body, 'id': self.counter, 'app': {'id': 15368}, 'conclusion': None}
        return copy.deepcopy(self.record)

    def get(self, identity): return copy.deepcopy(self.record)

    def update(self, identity, body):
        self.writes.append(('PATCH', copy.deepcopy(body)))
        self.record.update(body)
        return copy.deepcopy(self.record)


class PRPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PATH.exists(): raise AssertionError('Missing trusted PR policy helper')
        spec = importlib.util.spec_from_file_location('snyk_pr_policy', PATH)
        cls.p = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.p)

    def setUp(self):
        self.api, self.checks = Metadata(), Checks()

    def admission(self):
        result = self.p.admit(self.api, self.checks, self.api.event, self.api.env)
        self.assertEqual(result['decision'], 'scan')
        admission = json.loads(result['admission_json'])
        self.assertEqual(admission['purpose'], 'automatic-pr')
        return admission

    def add_other_pr(self, *, fork=False, sha=HEAD):
        second = {**copy.deepcopy(self.api.pr), 'id': 778, 'number': 8}
        second['head'].update(ref='feature/OTHER-PRIVATE-BRANCH', sha=sha)
        if fork:
            second['head']['repo'] = {'id': 666, 'full_name': 'fork/veyport', 'owner': {'id': 555}}
        self.api.prs.append(second)
        self.api.other_prs[8] = second
        return second

    def cli(self, mode, admission=None):
        with tempfile.TemporaryDirectory() as folder:
            event, output = Path(folder)/'event.json', Path(folder)/'output'
            event.write_text(json.dumps(self.api.event))
            env = {**self.api.env, 'GITHUB_EVENT_PATH': str(event), 'GITHUB_OUTPUT': str(output)}
            if admission is not None: env['ADMISSION_JSON'] = json.dumps(admission)
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(self.p, 'MetadataClient', return_value=self.api), \
                    mock.patch.object(self.p, 'ChecksClient', return_value=self.checks), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = self.p.main([mode])
            return result, output.read_text() if output.exists() else '', stdout.getvalue(), stderr.getvalue()

    def assert_no_success(self):
        self.assertFalse(any(body.get('conclusion') == 'success' for _, body in self.checks.writes))

    def evidence(self, admission):
        policy = self.p.policy
        rows = [{'path': project, **policy.assess(
            {'ok': True, 'org': 'lorconksu', 'dependencyCount': 3, 'vulnerabilities': [],
             'licensesPolicy': {'orgLicenseRules': None, 'severities': None},
             'filtered': {'ignore': [], 'patch': []}, 'hasUnknownVersions': False,
             'targetFile': Path(project).name,
             'packageManager': 'gomodules' if project.endswith('go.mod') else 'npm' if project.endswith('package.json') else 'pip'},
            0, project)} for project in policy.PROJECTS]
        state = {'source_sha': HEAD, 'control_sha': CONTROL, 'preparation_complete': True,
                 'manifests_unchanged': True, 'versions': {'snyk': '1.1308.3', 'go': 'go1.26.11',
                 'node': 'v25.2.0', 'npm': '11.0.0', 'python': 'Python 3.12.9', 'age': 'v1.2.0'}}
        summary = policy.public_summary(state, {'projects': rows, 'license_controls': {'status': 'verified'}})
        raw = json.dumps(summary).encode()
        cipher = b'age-encryption.org/v1\nsynthetic-ciphertext'
        envelope = self.p.make_envelope(admission, raw, cipher, b'synthetic-scanner')
        files = {'summary.json': raw, 'evidence.tar.gz.age': cipher,
                 'publication.json': self.p.canonical(envelope)}
        jobs = []
        for index, (name, steps) in enumerate(self.p.REQUIRED_STEPS.items(), 1):
            jobs.append({'id': index, 'run_id': admission['driver_run_id'], 'run_attempt': admission['driver_attempt'], 'head_sha': CONTROL,
                         'name': name, 'status': 'completed', 'conclusion': 'success',
                         'steps': [{'name': s, 'number': n, 'status': 'completed', 'conclusion': 'success'}
                                   for n, s in enumerate(steps, 1)]})
        return files, jobs

    def test_empty_pr_array_uses_authenticated_commit_mapping_and_no_actor_allowlist(self):
        admission = self.admission()
        self.assertEqual(admission['source_sha'], HEAD)
        self.assertTrue(any(path.startswith('commits/'+HEAD+'/pulls') for path in self.api.calls))
        self.assertNotIn('PRIVATE-BRANCH', json.dumps(admission))
        self.assertEqual(self.checks.record['status'], 'in_progress')
        self.assertEqual(self.checks.record['name'], 'Snyk PR scan')
        self.assertEqual(self.checks.record['app']['id'], 15368)
        self.assertIn('Informational only', self.checks.record['output']['summary'])

    def test_fork_gets_app_failure_and_no_scan(self):
        for obj in [self.api.upstream['head_repository'], self.api.event['workflow_run']['head_repository'], self.api.pr['head']['repo']]:
            obj['id'] = 666
            obj['full_name'] = 'fork/veyport'
        self.api.prs = [self.api.pr]
        result = self.p.admit(self.api, self.checks, self.api.event, self.api.env)
        self.assertEqual(result['decision'], 'rejected')
        self.assertEqual(self.checks.record['conclusion'], 'failure')

    def test_duplicate_id_closed_changed_head_retargeted_and_wrong_identity_reject(self):
        mutations = [lambda a: a.prs.append(copy.deepcopy(a.pr)),
                     lambda a: a.pr.update(state='closed'),
                     lambda a: a.pr['head'].update(sha='d'*40),
                     lambda a: a.pr['base'].update(ref='release'),
                     lambda a: a.upstream.update(workflow_id=666),
                     lambda a: a.upstream['repository'].update(id=666),
                     lambda a: a.driver.update(path='.github/workflows/attacker.yml'),
                     lambda a: a.env.update(GITHUB_SHA='d'*40)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.setUp(); mutate(self.api)
                with self.assertRaises(ValueError): self.p.admit(self.api, self.checks, self.api.event, self.api.env)
                self.assertFalse(any(body.get('conclusion') == 'success' for _, body in self.checks.writes))

    def test_authenticated_controller_context_refuses_before_check_writes(self):
        # Directly related automatic-controller bindings only. Fork support and
        # untrusted dispatch actors retain their existing successful controls.
        cases = [
            ('repository', ('repository', 'id'), 666),
            ('repository-name', ('repository', 'full_name'), 'other/veyport'),
            ('repository-owner', ('repository', 'owner', 'id'), 666),
            ('default-branch', ('repository', 'default_branch'), 'release'),
            ('event-repository', ('event', 'repository', 'id'), 666),
            ('event-action', ('event', 'action'), 'completed'),
            ('workflow-path', ('workflow', 'path'), '.github/workflows/other.yml'),
            ('workflow-state', ('workflow', 'state'), 'disabled_manually'),
            ('driver-id', ('driver', 'id'), 201),
            ('driver-workflow', ('driver', 'workflow_id'), 301),
            ('driver-event', ('driver', 'event'), 'workflow_dispatch'),
            ('driver-branch', ('driver', 'head_branch'), 'release'),
            ('driver-repository', ('driver', 'repository', 'id'), 666),
            ('driver-head-repository', ('driver', 'head_repository', 'id'), 666),
            ('environment-event', ('env', 'GITHUB_EVENT_NAME'), 'workflow_dispatch'),
            ('environment-ref', ('env', 'GITHUB_REF'), 'refs/heads/release'),
            ('environment-repository', ('env', 'GITHUB_REPOSITORY'), 'other/veyport'),
        ]
        for binding, path, value in cases:
            with self.subTest(binding=binding):
                self.setUp()
                state = {key: getattr(self.api, key) for key in
                         ('repository', 'workflow', 'env', 'event', 'driver', 'upstream', 'pr')}
                change_context_fields(self, state, [(path, value)])
                for key, item in state.items(): setattr(self.api, key, item)
                with self.assertRaises(ValueError):
                    self.p.context(self.api, self.api.event, self.api.env)
                with self.assertRaises(ValueError):
                    self.p.admit(self.api, self.checks, self.api.event, self.api.env)
                self.assertEqual(self.checks.writes, [])

    def test_ambiguous_trigger_mapping_rejects_without_check_write_or_scan_output(self):
        second = {**copy.deepcopy(self.api.pr), 'id': 778, 'number': 8}
        self.api.prs.append(second)
        self.api.other_prs[8] = second
        with tempfile.TemporaryDirectory() as folder:
            event = Path(folder) / 'event.json'
            output = Path(folder) / 'output'
            event.write_text(json.dumps(self.api.event))
            env = {**self.api.env, 'GITHUB_EVENT_PATH': str(event), 'GITHUB_OUTPUT': str(output)}
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(self.p, 'MetadataClient', return_value=self.api), \
                    mock.patch.object(self.p, 'ChecksClient', return_value=self.checks), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(self.p.main(['admit']), 1)
            self.assertIn('pulls/7', self.api.calls)
            self.assertIn('pulls/8', self.api.calls)
            self.assertEqual(self.checks.writes, [])
            self.assertFalse(output.exists() and output.read_text())
            self.assertEqual(stdout.getvalue(), '')
            self.assertEqual(stderr.getvalue(),
                             'Snyk PR policy failed; check trusted workflow configuration and rerun the entire workflow.\n')

    def test_shared_sha_admission_blocks_prior_success_across_refs_and_forks(self):
        # Removing SHA-wide collision rejection would scan and leave the old pass reusable.
        for fork in (False, True):
            for newer_upstream in (False, True):
                with self.subTest(fork=fork, newer_upstream=newer_upstream):
                    self.setUp()
                    self.admission()
                    self.api.markers = [{**self.checks.record, 'status': 'completed', 'conclusion': 'success'}]
                    self.api.driver['run_attempt'] = 2
                    self.api.env['GITHUB_RUN_ATTEMPT'] = '2'
                    second = self.add_other_pr(fork=fork)
                    if newer_upstream:
                        self.api.runs.append({**self.api.upstream, 'id': 101, 'run_number': 11,
                                              'head_branch': second['head']['ref'],
                                              'head_repository': second['head']['repo']})
                    result, output, stdout, stderr = self.cli('admit')
                    self.assertEqual(result, 0)
                    self.assertIn('decision=rejected\n', output)
                    self.assertNotIn('decision=scan', output)
                    self.assertEqual(self.checks.record['head_sha'], HEAD)
                    self.assertEqual(self.checks.record['app']['id'], 15368)
                    self.assertEqual(self.checks.record['conclusion'], 'failure')
                    self.assertEqual(self.checks.record['status'], 'completed')
                    self.assertEqual((stdout, stderr), ('', ''))
                    self.assert_no_success()

    def test_collision_detected_during_admission_creates_blocking_rejection(self):
        self.admission()
        self.api.markers = [{**self.checks.record, 'status': 'completed', 'conclusion': 'success'}]
        self.api.driver['run_attempt'] = 2
        self.api.env['GITHUB_RUN_ATTEMPT'] = '2'
        original = self.api.get
        opened = False
        def race(path, **kwargs):
            nonlocal opened
            result = original(path, **kwargs)
            if '/pulls?' in path and not opened:
                opened = True
                second = self.add_other_pr()
                self.api.runs.append({**self.api.upstream, 'id': 101, 'run_number': 11,
                                      'head_branch': second['head']['ref']})
            return result
        self.api.get = race
        result, output, _, _ = self.cli('admit')
        self.assertEqual(result, 0)
        self.assertIn('decision=rejected\n', output)
        self.assertEqual(self.checks.record['conclusion'], 'failure')
        self.assert_no_success()

    def test_collision_detected_in_last_admission_reread_is_rejected(self):
        original = self.api.get
        opened = False
        def race(path, **kwargs):
            nonlocal opened
            result = original(path, **kwargs)
            if '/check-runs?' in path and not opened:
                opened = True
                self.add_other_pr()
            return result
        self.api.get = race
        result, output, _, _ = self.cli('admit')
        self.assertEqual(result, 0)
        self.assertIn('decision=rejected\n', output)
        self.assertEqual(self.checks.record['conclusion'], 'failure')
        self.assert_no_success()

    def test_cross_ref_newer_upstream_prevents_publisher_success(self):
        for fork in (False, True):
            with self.subTest(fork=fork):
                self.setUp(); admission = self.prepare_publisher()
                self.api.runs.append({**self.api.upstream, 'id': 101, 'run_number': 11,
                                      'head_branch': 'feature/OTHER-PRIVATE-BRANCH',
                                      'head_repository': {'id': 666} if fork else copy.deepcopy(REPO)})
                result, _, stdout, _ = self.cli('publish', admission)
                self.assertEqual(result, 1)
                self.assertNotIn('Snyk PR scan passed.', stdout)
                self.assert_no_success()

    def test_cross_pr_newer_admission_prevents_publisher_success(self):
        admission = self.prepare_publisher()
        identity = {k: admission[k] for k in self.p.IDENTITY_KEYS}
        newer = {**identity, 'pr_number': 8, 'source_ref_sha256': 'd'*64,
                 'driver_run_id': 201, 'driver_run_number': 21}
        self.api.other_runs[201] = {**self.api.driver, 'id': 201, 'run_number': 21}
        self.api.markers = [{**self.p.check_body(newer), 'id': 889, 'app': {'id': 15368}}]
        result, _, stdout, _ = self.cli('publish', admission)
        self.assertEqual(result, 1)
        self.assertNotIn('Snyk PR scan passed.', stdout)
        self.assert_no_success()

    def test_second_same_sha_pr_appears_during_download_never_green(self):
        for fork in (False, True):
            with self.subTest(fork=fork):
                self.setUp(); admission = self.prepare_publisher(); original = self.api.get
                def race(path, **kwargs):
                    result = original(path, **kwargs)
                    if path.endswith('/zip'): self.add_other_pr(fork=fork)
                    return result
                self.api.get = race
                result, _, stdout, _ = self.cli('publish', admission)
                self.assertEqual(result, 1)
                self.assertNotIn('Snyk PR scan passed.', stdout)
                self.assert_no_success()

    def test_different_sha_pr_run_and_marker_do_not_invalidate_publisher(self):
        admission = self.prepare_publisher()
        self.add_other_pr(sha='d'*40)
        self.api.runs.append({**self.api.upstream, 'id': 101, 'run_number': 11,
                              'head_sha': 'd'*40, 'head_branch': 'feature/OTHER'})
        # The fake API selects the requested commit's checks from both SHAs.
        identity = {k: admission[k] for k in self.p.IDENTITY_KEYS}
        unrelated = {**identity, 'pr_number': 8, 'source_sha': 'd'*40,
                     'driver_run_id': 201, 'driver_run_number': 21}
        self.api.markers = [{**self.p.check_body(unrelated), 'id': 889, 'app': {'id': 15368}}]
        self.api.other_runs[201] = {**self.api.driver, 'id': 201, 'run_number': 21}
        result, _, stdout, _ = self.cli('publish', admission)
        self.assertEqual(result, 0)
        self.assertEqual(stdout, 'Snyk PR scan passed.\n')
        self.assertEqual(self.checks.record['conclusion'], 'success')

    def test_newer_collision_driver_from_older_upstream_supersedes_after_removal(self):
        # Comparing driver chronology only under equal upstream runs lets this
        # older publisher overwrite a newer blocking rejection after closure.
        old = self.prepare_publisher()
        old_check = copy.deepcopy(self.checks.record)
        old_event = copy.deepcopy(self.api.event)
        second = self.add_other_pr()
        upstream = {**self.api.upstream, 'id': 99, 'run_number': 9,
                    'head_branch': second['head']['ref']}
        self.api.other_runs[99] = upstream
        self.api.other_runs[201] = {**self.api.driver, 'id': 201, 'run_number': 21}
        self.api.runs.append(upstream)
        self.api.event['workflow_run'] = copy.deepcopy(upstream)
        self.api.env.update(GITHUB_JOB='admission', GITHUB_RUN_ID='201')
        result, output, _, _ = self.cli('admit')
        self.assertEqual(result, 0)
        self.assertIn('decision=rejected\n', output)
        self.assertEqual(self.checks.record['conclusion'], 'failure')
        self.api.markers = [copy.deepcopy(self.checks.record)]
        second['state'] = 'closed'
        self.api.event = old_event
        self.api.env.update(GITHUB_JOB='publish', GITHUB_RUN_ID='200')
        self.checks.record = old_check
        result, _, stdout, _ = self.cli('publish', old)
        self.assertEqual(result, 1)
        self.assertNotIn('Snyk PR scan passed.', stdout)
        self.assert_no_success()

    def test_removed_collision_requires_fresh_complete_attempt(self):
        old = self.prepare_publisher()
        self.add_other_pr()
        self.api.env.update(GITHUB_JOB='admission', GITHUB_RUN_ATTEMPT='2')
        self.api.driver['run_attempt'] = 2
        result, output, _, _ = self.cli('admit')
        self.assertEqual(result, 0)
        self.assertIn('decision=rejected\n', output)
        rejected = copy.deepcopy(self.checks.record)
        self.api.markers = [rejected]
        self.api.prs = [self.api.pr]
        self.api.other_prs[8]['state'] = 'closed'
        self.api.env['GITHUB_JOB'] = 'publish'
        self.assertEqual(self.cli('publish', old)[0], 1)
        self.assert_no_success()
        self.api.env.update(GITHUB_JOB='admission', GITHUB_RUN_ATTEMPT='3')
        self.api.driver['run_attempt'] = 3
        fresh = self.prepare_publisher()
        self.assertNotEqual(old['check_id'], fresh['check_id'])
        self.assertNotEqual(old['external_id'], fresh['external_id'])
        self.assertEqual(self.cli('publish', fresh)[0], 0)
        self.assertEqual(self.checks.record['conclusion'], 'success')

    def test_distinct_ci_run_and_new_attempt_supersede_old(self):
        for extra in [{'id': 101, 'run_number': 11}, {'run_attempt': 2}]:
            with self.subTest(extra=extra):
                self.setUp()
                if 'id' in extra: self.api.runs.append({**self.api.upstream, **extra})
                else: self.api.upstream.update(extra)
                with self.assertRaises(ValueError): self.p.admit(self.api, self.checks, self.api.event, self.api.env)

    def test_envelope_accepts_clean_and_detects_each_binding_tamper(self):
        admission = self.admission()
        files, jobs = self.evidence(admission)
        self.assertEqual(self.p.final_verdict(admission, files, jobs, 'success'), 'success')
        for name in files:
            bad = dict(files); bad[name] += b'private-canary'
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.p.validate_envelope(admission, bad)
        wrong = copy.deepcopy(admission); wrong['driver_attempt'] = 2
        with self.assertRaises(ValueError): self.p.validate_envelope(wrong, files)

    def test_partial_rerun_missing_failed_skipped_neutral_cleanup_never_green(self):
        admission = self.admission(); files, jobs = self.evidence(admission)
        self.assertEqual(self.p.final_verdict(admission, files, jobs, 'success'), 'success')
        for outcome in ['skipped', 'neutral', 'cancelled', 'failure', None]:
            for name in self.p.REQUIRED_STEPS:
                bad = copy.deepcopy(jobs)
                next(j for j in bad if j['name'] == name)['steps'][-1]['conclusion'] = outcome
                self.assertEqual(self.p.final_verdict(admission, files, bad, 'success'), 'failure')
        for mutate in [lambda x: x.pop(), lambda x: x[1].update(run_attempt=2),
                       lambda x: x[1]['steps'].pop(), lambda x: x.append(copy.deepcopy(x[1])),
                       lambda x: x[1]['steps'].append({**copy.deepcopy(x[1]['steps'][0]), 'number': 99})]:
            bad = copy.deepcopy(jobs); mutate(bad)
            self.assertEqual(self.p.final_verdict(admission, files, bad, 'success'), 'failure')
        self.assertEqual(self.p.final_verdict(admission, files, jobs, 'failure'), 'failure')

    def test_wrong_app_external_identity_and_reused_green_are_rejected(self):
        for patch in [{'app': {'id': 999}}, {'head_sha': 'd'*40}, {'external_id': 'attacker'}, {'id': 999},
                      {'status': 'completed', 'conclusion': 'success'}]:
            self.setUp(); admission = self.admission(); self.checks.record.update(patch)
            with self.assertRaises(ValueError): self.p.validate_check(self.checks.record, admission, pending=True)

    def test_strict_json_duplicate_nonfinite_and_bounds(self):
        for raw in [b'{"id":1,"id":2}', b'{"x":NaN}', b'{"x":1e999}', b'[]junk', b'\xff']:
            with self.subTest(raw=raw), self.assertRaises(ValueError): self.p.strict_json(raw)

    def test_shared_summary_binds_explicit_source_and_control_without_admission(self):
        common_path = PATH.with_name('snyk_ci_common.py')
        self.assertTrue(common_path.is_file(), 'Missing shared evidence validator')
        spec = importlib.util.spec_from_file_location('snyk_ci_common_test', common_path)
        common = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(common)
        admission = self.admission()
        files, _ = self.evidence(admission)
        summary = common.validate_summary(files['summary.json'], HEAD, CONTROL)
        self.assertEqual(summary['source_sha'], HEAD)
        self.assertEqual(summary['control_sha'], CONTROL)
        self.assertEqual(summary['policy']['exit_code'], 0)
        for source, control in [('d'*40, CONTROL), (HEAD, 'd'*40)]:
            with self.subTest(source=source, control=control), self.assertRaises(ValueError):
                common.validate_summary(files['summary.json'], source, control)
        with self.assertRaises(ValueError):
            common.validate_summary(b'{"source_sha":1,"source_sha":2}', HEAD, CONTROL)

    def test_shared_import_uses_trusted_sibling_under_isolated_python(self):
        self.assertTrue(PATH.with_name('snyk_ci_common.py').is_file(), 'Missing shared evidence validator')
        admission = self.admission()
        files, _ = self.evidence(admission)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ('snyk_ci_common.py', 'snyk_policy.py'):
                (root/name).write_text("raise RuntimeError('untrusted import')\n")
            script = '''import importlib.util, json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location('trusted_pr', Path(sys.argv[2]))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
summary = module.validate_summary(sys.stdin.buffer.read(), json.loads(sys.argv[3]))
print(summary['source_sha'])
'''
            result = subprocess.run([sys.executable, '-I', '-B', '-c', script, folder,
                                     str(PATH.resolve()), json.dumps(admission)],
                                    cwd=folder, input=files['summary.json'], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, (HEAD+'\n').encode())
            self.assertEqual(result.stderr, b'')

    def test_zip_allowlist_path_duplicate_symlink_and_bomb_bounds(self):
        admission = self.admission(); files, _ = self.evidence(admission)
        def archive(entries):
            output=io.BytesIO()
            with warnings.catch_warnings(), zipfile.ZipFile(output, 'w') as z:
                warnings.simplefilter('ignore', UserWarning)
                for name, data in entries: z.writestr(name, data)
            return output.getvalue()
        raw=archive(list(files.items()))
        self.assertEqual(self.p.archive_files(raw), files)
        for extra in ['../raw.json', 'raw.json', 'summary.json']:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.p.archive_files(archive([*files.items(), (extra, b'PRIVATE')]))

    def test_cli_failure_is_fixed_and_disabled_admission_is_inert(self):
        with tempfile.TemporaryDirectory() as folder:
            event=Path(folder)/'event.json'; output=Path(folder)/'outputs'
            event.write_text('{"private-canary":"secret"}')
            env={**os.environ, **self.api.env, 'GITHUB_EVENT_PATH':str(event), 'GITHUB_OUTPUT':str(output)}
            env['SNYK_PR_POLICY_ENABLED']='false'
            result=subprocess.run(['python3','-B',str(PATH),'admit'],env=env,capture_output=True)
            self.assertEqual(result.returncode,0)
            self.assertEqual(output.read_text(),'decision=ignore\nsource_sha=\nadmission_json=\n')
            env['SNYK_PR_POLICY_ENABLED']='true'
            result=subprocess.run(['python3','-B',str(PATH),'admit'],env=env,capture_output=True)
            self.assertEqual(result.returncode,1)
            self.assertNotIn(b'private-canary',result.stdout+result.stderr)
            self.assertNotIn(b'secret',result.stdout+result.stderr)


    def prepare_publisher(self):
        admission=self.admission(); files, jobs=self.evidence(admission)
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as archive:
            for name, raw in files.items(): archive.writestr(name,raw)
        self.api.raw=output.getvalue(); self.api.jobs=jobs
        self.api.artifacts=[{'id':444,'name':f"snyk-pr-policy-{admission['driver_run_id']}-{admission['driver_attempt']}",'expired':False,
                             'size_in_bytes':len(self.api.raw),'digest':'sha256:'+hashlib.sha256(self.api.raw).hexdigest(),
                             'workflow_run':{'id':200,'repository_id':1188082218,'head_repository_id':1188082218,
                                             'head_branch':'main','head_sha':CONTROL}}]
        self.api.env.update(GITHUB_JOB='publish',SCAN_RESULT='success')
        return admission

    def test_publisher_reads_exact_attempt_and_rechecks_currentness_before_success(self):
        admission=self.prepare_publisher()
        self.assertEqual(self.p.publish(self.api,self.checks,admission,self.api.event,self.api.env),'success')
        self.assertIn('actions/runs/200/attempts/1/jobs?per_page=100&page=1',self.api.calls)
        self.assertEqual(self.checks.writes[-1][1]['conclusion'],'success')
        with self.assertRaises(ValueError): self.p.publish(self.api,self.checks,admission,self.api.event,self.api.env)

    def test_bad_artifact_metadata_digests_and_missing_jobs_publish_failure(self):
        mutations=[lambda a:a.artifacts[0].update(digest='sha256:'+'0'*64),
                   lambda a:a.artifacts[0].update(expired=True),
                   lambda a:a.artifacts[0].update(name='snyk-pr-policy-200-2'),
                   # Distinct IDs pass pagination so only exact-name uniqueness fails.
                   lambda a:a.artifacts.append({**copy.deepcopy(a.artifacts[0]), 'id':445}),
                   lambda a:a.jobs.clear(), lambda a:a.jobs[1]['steps'].pop()]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.setUp(); admission=self.prepare_publisher(); mutate(self.api)
                self.assertEqual(self.p.publish(self.api,self.checks,admission,self.api.event,self.api.env),'failure')
                self.assertEqual(self.checks.writes[-1][1]['conclusion'],'failure')

    def test_each_artifact_provenance_binding_completes_failure_without_success(self):
        for field, value in [('id', 199), ('repository_id', 666), ('head_repository_id', 666),
                             ('head_branch', 'release'), ('head_sha', HEAD)]:
            with self.subTest(field=field):
                self.setUp()
                admission = self.prepare_publisher()
                # Change one valid field; retain the current name, digest, size and envelope.
                self.api.artifacts[0]['workflow_run'][field] = value
                self.assertEqual(self.p.publish(self.api, self.checks, admission, self.api.event, self.api.env), 'failure')
                self.assertEqual(self.checks.record['id'], admission['check_id'])
                self.assertEqual(self.checks.record['status'], 'completed')
                self.assertEqual(self.checks.record['conclusion'], 'failure')
                self.assertEqual([method for method, _ in self.checks.writes], ['POST', 'PATCH'])
                self.assert_no_success()

    def test_broken_artifact_response_completes_failure_and_preserves_previous_green(self):
        for error in (http.client.IncompleteRead(b'PRIVATE', 1), http.client.BadStatusLine('PRIVATE')):
            with self.subTest(error=type(error).__name__):
                self.setUp(); admission = self.prepare_publisher()
                previous = {**copy.deepcopy(self.checks.record), 'id': 800, 'status': 'completed', 'conclusion': 'success'}
                self.api.markers = [copy.deepcopy(previous)]
                api = self.p.MetadataClient('read-token')
                traffic = []
                case = self

                class Response:
                    status = 200
                    def __init__(self, path): self.path = path
                    def __enter__(self): return self
                    def __exit__(self, *args): pass
                    def read(self, limit):
                        if self.path == 'actions/artifacts/444/zip': raise error
                        return json.dumps(case.api.get(self.path)).encode()[:limit]

                def send(request, timeout):
                    self.assertEqual(request.get_method(), 'GET')
                    path = request.full_url.removeprefix('https://api.github.com/repos/lorconksu/veyport').lstrip('/')
                    traffic.append(path)
                    return Response(path)

                with mock.patch.object(api.transport.opener, 'open', side_effect=send), \
                     mock.patch.object(self.p.urllib.request, 'build_opener', return_value=api.transport.opener), \
                     mock.patch('socket.create_connection', side_effect=AssertionError('socket connection attempted')):
                    conclusion = self.p.publish(api, self.checks, admission, self.api.event, self.api.env)
                self.assertEqual(conclusion, 'failure')
                self.assertIn('actions/artifacts/444/zip', traffic)
                self.assertEqual(self.checks.record['id'], admission['check_id'])
                self.assertEqual(self.checks.record['status'], 'completed')
                self.assertEqual(self.checks.record['conclusion'], 'failure')
                self.assertEqual(self.api.markers, [previous])
                self.assertEqual([method for method, _ in self.checks.writes], ['POST', 'PATCH'])
                self.assert_no_success()

    def test_evidence_transport_exhaustion_has_fresh_final_publication_and_guards(self):
        for budget in ('time', 'requests'):
            for guard in ('current', 'stale-head', 'completed-check'):
                with self.subTest(budget=budget, guard=guard):
                    self.setUp(); admission = self.prepare_publisher()
                    clock, traffic, created = [0.0], [], []
                    case = self
                    clients = {}

                    class Response:
                        status = 200
                        def __init__(self, path, data): self.path, self.data = path, data
                        def __enter__(self): return self
                        def __exit__(self, *args): pass
                        def read(self, limit):
                            if self.path.startswith('actions/runs/200/artifacts?'):
                                if budget == 'time': clock[0] = clients['api'].transport.deadline
                                else:
                                    while clients['api'].transport.requests < 160: clients['api'].get('')
                                if guard == 'stale-head': case.api.pr['head']['sha'] = 'e'*40
                                if guard == 'completed-check': case.checks.record.update(status='completed', conclusion='success')
                            return self.data[:limit]

                    class Opener:
                        def open(self, request, timeout):
                            path = request.full_url.removeprefix('https://api.github.com/repos/lorconksu/veyport').lstrip('/')
                            method = request.get_method()
                            traffic.append((method, path, request.get_header('Authorization')))
                            case.assertTrue(0 < timeout <= 30)
                            if path.startswith('check-runs/'):
                                case.assertEqual(path, 'check-runs/'+str(admission['check_id']))
                                if method == 'PATCH':
                                    body = json.loads(request.data)
                                    case.assertEqual(body['conclusion'], 'failure')
                                    value = case.checks.update(admission['check_id'], body)
                                else:
                                    case.assertEqual(method, 'GET')
                                    value = case.checks.get(admission['check_id'])
                            else:
                                case.assertEqual(method, 'GET')
                                value = case.api.get(path)
                            return Response(path, json.dumps(value).encode())

                    def opener(*handlers):
                        created.append((len(traffic), clock[0]))
                        return Opener()

                    with mock.patch.object(self.p.common.time, 'monotonic', side_effect=lambda: clock[0]), \
                         mock.patch.object(self.p.urllib.request, 'build_opener', side_effect=opener), \
                         mock.patch('socket.create_connection', side_effect=AssertionError('socket connection attempted')):
                        clients['api'] = self.p.MetadataClient('read-token')
                        checks = self.p.ChecksClient('read-token')
                        if guard == 'current':
                            conclusion = self.p.publish(clients['api'], checks, admission, self.api.event, self.api.env)
                        else:
                            with self.assertRaises(ValueError):
                                self.p.publish(clients['api'], checks, admission, self.api.event, self.api.env)
                        with self.assertRaises(ValueError): clients['api'].get('')
                    patches = [row for row in traffic if row[0] == 'PATCH']
                    self.assertEqual(len(patches), 1 if guard == 'current' else 0)
                    if guard == 'current':
                        self.assertEqual(conclusion, 'failure')
                        self.assertEqual(self.checks.record['status'], 'completed')
                        self.assertEqual(self.checks.record['conclusion'], 'failure')
                    if guard == 'completed-check':
                        self.assertEqual(self.checks.record['status'], 'completed')
                        self.assertEqual(self.checks.record['conclusion'], 'success')
                    self.assertEqual(len(created), 4)
                    self.assertGreater(created[2][0], created[1][0])
                    self.assertTrue(all(row[2] == 'Bearer read-token' for row in traffic))
                    self.assert_no_success()

    def test_final_publication_reader_failure_leaves_pending_without_patch(self):
        for failure in ('metadata-factory', 'checks-factory', 'final-check-read'):
            with self.subTest(failure=failure):
                self.setUp(); admission = self.prepare_publisher()
                target = self.api if failure == 'metadata-factory' else self.checks
                method = {'metadata-factory': 'fresh_readonly', 'checks-factory': 'fresh_publication', 'final-check-read': 'get'}[failure]
                error = http.client.IncompleteRead(b'PRIVATE', 1) if failure == 'final-check-read' else OSError('PRIVATE')
                effect = [copy.deepcopy(self.checks.record), error] if failure == 'final-check-read' else error
                with mock.patch.object(target, method, side_effect=effect), self.assertRaises(type(error)):
                    self.p.publish(self.api, self.checks, admission, self.api.event, self.api.env)
                self.assertEqual(self.checks.record['status'], 'in_progress')
                self.assertEqual([method for method, _ in self.checks.writes], ['POST'])
                self.assert_no_success()

    def test_head_race_during_download_never_writes_success(self):
        admission=self.prepare_publisher(); original=self.api.get
        def race(path,**kwargs):
            result=original(path,**kwargs)
            if path.endswith('/zip'): self.api.pr['head']['sha']='d'*40
            return result
        self.api.get=race
        with self.assertRaises(ValueError): self.p.publish(self.api,self.checks,admission,self.api.event,self.api.env)
        self.assertEqual(len(self.checks.writes),1)

    def test_newer_admitted_same_sha_blocks_across_prs_but_wrong_app_does_not(self):
        admission=self.admission(); identity={k:admission[k] for k in self.p.IDENTITY_KEYS}
        newer={**identity,'driver_run_id':201,'driver_run_number':21}
        self.api.other_runs[201]={**self.api.driver,'id':201,'run_number':21}
        marker={**self.p.check_body(newer),'id':889,'app':{'id':15368}}
        self.api.markers=[marker]
        with self.assertRaises(ValueError): self.p.currentness(self.api,identity)
        marker['external_id']=self.p.external_identity({**newer,'pr_number':8})
        with self.assertRaises(ValueError): self.p.currentness(self.api,identity)
        marker.update(external_id='attacker',app={'id':999})
        self.p.currentness(self.api,identity)
        marker['app']={'id':15368}
        with self.assertRaises(ValueError): self.p.currentness(self.api,identity)

    def test_full_driver_rerun_requires_new_admission_and_partial_publisher_rejects(self):
        old=self.admission(); self.api.markers=[copy.deepcopy(self.checks.record)]
        self.api.driver['run_attempt']=2; self.api.env['GITHUB_RUN_ATTEMPT']='2'
        result=self.p.admit(self.api,self.checks,self.api.event,self.api.env)
        fresh=json.loads(result['admission_json'])
        self.assertNotEqual(old['external_id'],fresh['external_id'])
        self.assertNotEqual(old['check_id'],fresh['check_id'])
        files,jobs=self.evidence(old)
        self.assertEqual(self.p.final_verdict(fresh,files,jobs,'success'),'failure')
        self.api.env['GITHUB_JOB']='publish'
        with self.assertRaises(ValueError): self.p.publish(self.api,self.checks,old,self.api.event,self.api.env)

    def test_same_attempt_rebinding_cannot_create_another_check(self):
        admission=self.admission()
        identity={k:admission[k] for k in self.p.IDENTITY_KEYS}
        self.api.markers=[{**self.checks.record,'external_id':self.p.external_identity({**identity,'base_sha':'d'*40})}]
        with self.assertRaises(ValueError):self.p.admit(self.api,self.checks,self.api.event,self.api.env)
        self.assertEqual(len(self.checks.writes),1)

    def test_floating_check_ids_cannot_match_integer_identity(self):
        admission=self.admission()
        for patch in [{'id':888.0},{'app':{'id':999.0}}]:
            with self.subTest(patch=patch),self.assertRaises(ValueError):
                self.p.validate_check({**self.checks.record,**patch},admission,pending=True)

    def test_same_admission_attempt_cannot_create_second_check(self):
        self.admission(); self.api.markers=[copy.deepcopy(self.checks.record)]
        with self.assertRaises(ValueError): self.p.admit(self.api,self.checks,self.api.event,self.api.env)
        self.assertEqual(len(self.checks.writes),1)

    def test_policy_blocking_and_processing_outcomes_cannot_publish_success(self):
        admission=self.admission(); files,jobs=self.evidence(admission)
        from test_snyk_policy import report,issue
        for findings,code in [([issue('high')],1),([issue('critical')],1),
                              ([issue('high','license')],1),([issue('medium','license',license='Unknown')],1),
                              ([issue('medium')],0),([],0)]:
            summary=json.loads(files['summary.json'])
            assessed=self.p.policy.assess(report(issues=findings),1 if findings else 0,'hub/go.mod')
            row=summary['projects'][0]
            row.update({k:assessed[k] for k in [*self.p.policy.COUNTS,'status','technically_complete']})
            summary['policy']=self.p.policy.policy_result(summary['projects'],controls_verified=True)
            raw=self.p.canonical(summary); cipher=files['evidence.tar.gz.age']
            envelope=self.p.make_envelope(admission,raw,cipher,b'synthetic-scanner')
            evidence={**files,'summary.json':raw,'publication.json':self.p.canonical(envelope)}
            self.assertEqual(self.p.final_verdict(admission,evidence,jobs,'success'),'success' if code==0 else 'failure')
        for mutate in [lambda s:s['projects'].pop(),lambda s:s.update(processing_status='incomplete'),
                       lambda s:s['versions'].update(snyk='unavailable')]:
            summary=json.loads(files['summary.json']);mutate(summary)
            bad={**files,'summary.json':self.p.canonical(summary)}
            self.assertEqual(self.p.final_verdict(admission,bad,jobs,'success'),'failure')

    def test_embedded_admission_requires_exact_integer_schema(self):
        admission=self.admission();files,_=self.evidence(admission)
        envelope=json.loads(files['publication.json'])
        envelope['admission']['pr_number']=float(admission['pr_number'])
        files['publication.json']=self.p.canonical(envelope)
        with self.assertRaises(ValueError):self.p.validate_envelope(admission,files)

    def test_strict_policy_and_job_types_cannot_use_boolean_for_integer(self):
        admission=self.admission(); files,jobs=self.evidence(admission)
        summary=json.loads(files['summary.json']);summary['policy']['exit_code']=False
        raw=self.p.canonical(summary)
        with self.assertRaises(ValueError): self.p.make_envelope(admission,raw,files['evidence.tar.gz.age'],b'scanner')
        jobs[1]['run_attempt']=True
        self.assertEqual(self.p.final_verdict(admission,files,jobs,'success'),'failure')

    def test_pagination_finishes_all_pages_and_rejects_truncation_duplicate_or_changing_total(self):
        class Paged:
            def __init__(self,values):self.values=iter(values)
            def get(self,path):return next(self.values)
        full=[{'id':n} for n in range(1,101)]
        result=self.p.pages(Paged([{'total_count':101,'jobs':full},{'total_count':101,'jobs':[{'id':101}]}]),'actions/runs/200/attempts/1/jobs','jobs')
        self.assertEqual(len(result),101)
        for values in [[{'total_count':101,'jobs':full},{'total_count':101,'jobs':[]}],
                       [{'total_count':101,'jobs':full},{'total_count':101,'jobs':[{'id':1}]}],
                       [{'total_count':101,'jobs':full},{'total_count':102,'jobs':[{'id':101}]}],
                       [{'total_count':1001,'jobs':[{'id':n+i*100} for n in range(1,101)]} for i in range(10)]]:
            with self.assertRaises(ValueError): self.p.pages(Paged(values),'actions/runs/200/attempts/1/jobs','jobs')

    def test_http_clients_constrain_native_token_routes_and_never_forward_auth_on_artifact_redirect(self):
        class Response(io.BytesIO):
            status=200
        class Opener:
            def __init__(self,responses):self.responses=iter(responses);self.requests=[]
            def open(self,request,timeout):
                self.requests.append(request)
                value=next(self.responses)
                if isinstance(value,Exception):raise value
                return Response(value)
        client=self.p.MetadataClient('read-token')
        redirect=urllib.error.HTTPError('https://api.github.com',302,'redirect',{'Location':'https://production.blob.core.windows.net/archive?sig=PRIVATE'},None)
        opener=Opener([redirect,b'zip']);client.transport.opener=opener
        self.assertEqual(client.get('actions/artifacts/444/zip',raw=True),b'zip')
        self.assertEqual(opener.requests[0].get_header('Authorization'),'Bearer read-token')
        self.assertIsNone(opener.requests[1].get_header('Authorization'))
        checks=self.p.ChecksClient('read-token');check_opener=Opener([b'{}']);checks.transport.opener=check_opener
        checks.get(888)
        self.assertEqual(check_opener.requests[0].get_header('Authorization'),'Bearer read-token')
        for path in ['https://evil.test/', '../issues', 'check-runs/888','actions/runs/200?evil=1']:
            with self.assertRaises(ValueError):client.get(path)
        with self.assertRaises(ValueError):checks.transport.request('GET','actions/runs/200')
        for target in ['https://evil.test/','https://blob.core.windows.net.evil.test/',
                       'http://production.blob.core.windows.net/','https://user@production.blob.core.windows.net/']:
            error=urllib.error.HTTPError('https://api.github.com',302,'redirect',{'Location':target},None)
            opener=Opener([error]);client.transport.opener=opener
            with self.assertRaises(ValueError):client.get('actions/artifacts/444/zip',raw=True)
            self.assertEqual(len(opener.requests),1)
        response=urllib.error.HTTPError('https://api.github.com',302,'redirect',{'Location':'https://evil.test/'},None)
        client.transport.opener=Opener([response])
        with self.assertRaises(ValueError):client.get('actions/runs/200')
        self.assertIsNone(self.p.NoRedirect().redirect_request(None,None,302,'',{},'https://evil.test'))

    def test_cli_admit_and_publish_use_real_transport_and_strict_output_handoff(self):
        case=self
        class Response(io.BytesIO):
            def __init__(self,data,status=200):super().__init__(data);self.status=status
        class Router:
            def open(self,request,timeout):
                root='https://api.github.com/repos/lorconksu/veyport'
                if request.full_url == root:
                    path=''
                elif request.full_url == root+'/':
                    raise urllib.error.HTTPError(request.full_url,404,'Not Found',{},None)
                else:
                    case.assertTrue(request.full_url.startswith(root+'/'))
                    path=request.full_url[len(root)+1:]
                if path=='check-runs' or path.startswith('check-runs/'):
                    case.assertEqual(request.get_header('Authorization'),'Bearer read-token')
                    if request.method=='POST':value=case.checks.create(json.loads(request.data));status=201
                    elif request.method=='PATCH':value=case.checks.update(int(path.split('/')[-1]),json.loads(request.data));status=200
                    else:value=case.checks.get(int(path.split('/')[-1]));status=200
                    return Response(json.dumps(value).encode(),status)
                case.assertEqual(request.get_header('Authorization'),'Bearer read-token')
                value=case.api.get(path,raw=path.endswith('/zip'))
                return Response(value if type(value) is bytes else json.dumps(value).encode())
        with tempfile.TemporaryDirectory() as folder:
            event=Path(folder)/'event.json';event.write_text(json.dumps(self.api.event))
            output=Path(folder)/'output'
            env={**self.api.env,'GITHUB_TOKEN':'read-token',
                 'GITHUB_EVENT_PATH':str(event),'GITHUB_OUTPUT':str(output)}
            with mock.patch.dict(os.environ,env,clear=True),mock.patch.object(self.p.urllib.request,'build_opener',return_value=Router()):
                self.assertEqual(self.p.main(['admit']),0)
            lines=dict(line.split('=',1) for line in output.read_text().splitlines())
            self.assertEqual(lines['decision'],'scan');self.assertEqual(lines['source_sha'],HEAD)
            self.assertNotIn('PRIVATE',output.read_text())
            admission=json.loads(lines['admission_json']);files,jobs=self.evidence(admission)
            raw=io.BytesIO()
            with zipfile.ZipFile(raw,'w') as archive:
                for name,data in files.items():archive.writestr(name,data)
            self.api.raw=raw.getvalue();self.api.jobs=jobs
            self.api.artifacts=[{'id':444,'name':f"snyk-pr-policy-{admission['driver_run_id']}-{admission['driver_attempt']}",'expired':False,'size_in_bytes':len(self.api.raw),
                'digest':'sha256:'+hashlib.sha256(self.api.raw).hexdigest(),
                'workflow_run':{'id':200,'repository_id':1188082218,'head_repository_id':1188082218,'head_branch':'main','head_sha':CONTROL}}]
            env.update(GITHUB_JOB='publish',ADMISSION_JSON=lines['admission_json'],SCAN_RESULT='success')
            stdout=io.StringIO();stderr=io.StringIO()
            with mock.patch.dict(os.environ,env,clear=True),mock.patch.object(self.p.urllib.request,'build_opener',return_value=Router()),contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                self.assertEqual(self.p.main(['publish']),0)
            self.assertEqual(stdout.getvalue(),'Snyk PR scan passed.\n');self.assertEqual(stderr.getvalue(),'')

    def test_cli_invalid_arguments_are_sanitized(self):
        result=subprocess.run(['python3','-B',str(PATH),'private-canary'],capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn(b'private-canary',result.stdout+result.stderr)

    def test_http_strict_json_size_status_auth_and_second_redirect_fail_closed(self):
        class Response(io.BytesIO):
            status=200
        class Opener:
            def __init__(self,value):self.value=value;self.calls=[]
            def open(self,request,timeout):
                self.calls.append(request)
                if isinstance(self.value,Exception):raise self.value
                return Response(self.value)
        client=self.p.MetadataClient('read-token')
        for value in [b'{"id":1,"id":2}', b'{' + b'x'*(self.p.MAX_JSON+1),
                      urllib.error.HTTPError('https://api.github.com',403,'PRIVATE-BODY',{},None)]:
            client.transport.opener=Opener(value)
            with self.assertRaises(ValueError):client.get('actions/runs/200')
        for token in ['', 'token\nPRIVATE', 'token space']:
            with self.assertRaises(ValueError):self.p.MetadataClient(token)
        client.transport.deadline=0
        client.transport.opener=Opener(b'{}')
        with self.assertRaises(ValueError):client.get('actions/runs/200')
        self.assertEqual(client.transport.opener.calls,[])

    def test_zip_rejects_symlink_truncated_archive_and_oversized_member(self):
        admission=self.admission();files,_=self.evidence(admission)
        for special in ['symlink','oversized']:
            output=io.BytesIO()
            with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED) as archive:
                for name,raw in files.items():
                    if name=='summary.json' and special=='symlink':
                        info=zipfile.ZipInfo(name);info.create_system=3;info.external_attr=(0o120777<<16)
                        archive.writestr(info,b'/private')
                    else:archive.writestr(name,b'x'*(self.p.MAX_JSON+1) if name=='summary.json' and special=='oversized' else raw)
            with self.assertRaises(ValueError):self.p.archive_files(output.getvalue())
        for raw in [b'PKbroken',output.getvalue()[:-10]]:
            with self.assertRaises(ValueError):self.p.archive_files(raw)

    def test_cli_envelope_uses_environment_identity_and_never_prints_private_values(self):
        admission=self.admission(); files,_=self.evidence(admission)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'public').mkdir();(root/'tools').mkdir()
            for name in ['summary.json','evidence.tar.gz.age']:(root/'public'/name).write_bytes(files[name])
            (root/'tools/snyk').write_bytes(b'synthetic-scanner')
            env={**os.environ,**self.api.env,'GITHUB_JOB':'scan','ADMISSION_JSON':json.dumps(admission),'TRIAL_ROOT':str(root)}
            env.pop('SNYK_TOKEN',None);env.pop('GITHUB_TOKEN',None)
            result=subprocess.run(['python3','-B',str(PATH),'envelope'],env=env,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,b'')
            files['publication.json']=(root/'public/publication.json').read_bytes()
            self.p.validate_envelope(admission,files)
            env['GITHUB_TOKEN']='private-canary'
            result=subprocess.run(['python3','-B',str(PATH),'envelope'],env=env,capture_output=True)
            self.assertEqual(result.returncode,1)
            self.assertNotIn(b'private-canary',result.stdout+result.stderr)


# These tests deliberately read only the workflow's scalar/step boundary syntax;
# actionlint separately validates YAML and GitHub expression types. No YAML package
# is required on the credential-free hosted Python interpreter.
WORKFLOW = PATH.parents[2] / '.github/workflows/snyk-pr-policy.yml'


def workflow_jobs():
    import re
    text = WORKFLOW.read_text()
    return {match[1]: match[2] for match in re.finditer(
        r'^  ([a-z]+):\n(.*?)(?=^  [a-z]+:\n|\Z)', text.split('jobs:\n', 1)[1], re.M | re.S)}


def workflow_steps(job):
    import re
    return {match[1]: match[2] for match in re.finditer(
        r'^      - name: ([^\n]+)\n(.*?)(?=^      - name: |\Z)', job, re.M | re.S)}


def scalar(block, key, indent):
    import re
    found = re.search(r'^' + ' ' * indent + re.escape(key) + r': (.*)$', block, re.M)
    if not found:
        raise AssertionError('Missing workflow field: ' + key)
    return found[1]


def shell_body(step):
    import textwrap
    return textwrap.dedent(step.split('        run: |\n', 1)[1])


def expression(expression, context):
    """Evaluate the restricted comparisons used here, including GitHub case folding."""
    import re
    expression = expression.removeprefix('${{').removesuffix('}}').strip()
    tokens = re.findall(r"'[^']*'|[A-Za-z_][A-Za-z_0-9.-]*(?:\(\))?|==|!=|&&|\|\||[()]", expression)
    if ''.join(tokens) != re.sub(r'\s+', '', expression):
        # Spaces inside literal values are intentionally absent in tested guards.
        raise AssertionError('Unsupported expression')
    translated = []
    for token in tokens:
        if token == 'always()': translated.append('True')
        elif token == 'success()': translated.append(str(context.get('success()', True)))
        elif token in ('&&', '||'): translated.append('and' if token == '&&' else 'or')
        elif token in ('==', '!=', '(', ')'): translated.append(token)
        elif token.startswith("'"): translated.append(repr(token[1:-1].lower()))
        else: translated.append(repr(str(context.get(token, '')).lower()))
    status = True if re.search(r'(always|success)\(\)', expression) else context.get('success()', True)
    return status and bool(eval(' '.join(translated), {'__builtins__': {}}, {}))


class PRWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(WORKFLOW.exists(), 'Missing automatic PR workflow')
        self.jobs = workflow_jobs()
        self.steps = {key: workflow_steps(value) for key, value in self.jobs.items()}

    def run_shell(self, step, env, cwd=None):
        return subprocess.run(['/bin/bash', '-c', shell_body(step)],
                              env={'PATH': os.defpath, **env}, cwd=cwd,
                              capture_output=True, text=True, timeout=20)

    def test_only_in_progress_ci_and_trusted_main_admission(self):
        import re
        text = WORKFLOW.read_text()
        trigger = text.split('on:\n', 1)[1].split('\npermissions:', 1)[0]
        self.assertEqual(re.findall(r'^  ([a-z_]+):', trigger, re.M), ['workflow_run'])
        self.assertEqual(scalar(trigger, 'workflows', 4), '[CI]')
        self.assertEqual(scalar(trigger, 'types', 4), '[in_progress]')
        self.assertEqual(set(self.jobs), {'admission', 'scan', 'publish'})
        good = {'github.event_name': 'workflow_run', 'github.event.action': 'in_progress',
                'github.repository': 'lorconksu/veyport', 'github.repository_id': '1188082218',
                'github.repository_owner_id': '13374789', 'github.ref': 'refs/heads/main',
                'github.event.workflow_run.workflow_id': '251054731',
                'github.event.workflow_run.path': '.github/workflows/ci.yml',
                'github.event.workflow_run.event': 'pull_request', 'vars.SNYK_PR_POLICY_ENABLED': 'true'}
        guard = scalar(self.jobs['admission'], 'if', 4)
        self.assertTrue(expression(guard, good))
        for key in good:
            for bad in ['', 'other', 'false']:
                with self.subTest(key=key, bad=bad):
                    self.assertFalse(expression(guard, {**good, key: bad}))
        # Source actor has no authority and fork admission must run to publish failure.
        self.assertTrue(expression(guard, {**good, 'github.actor': 'outsider',
                                           'github.event.workflow_run.head_repository.id': '666'}))

    def test_exact_enable_and_controller_revision_gate_before_informational_write(self):
        gate = self.steps['admission']['Validate trusted controller and activation']
        ordered = list(self.steps['admission'])
        self.assertLess(ordered.index('Validate trusted controller and activation'), ordered.index('Admit current PR and create informational check'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); controller = root/'controller'; controller.mkdir()
            subprocess.run(['git', 'init', '-q', str(controller)], check=True)
            # A synthetic empty tree commit needs no staging and no user configuration.
            tree = subprocess.check_output(['git', '-C', str(controller), 'mktree'], input=b'').decode().strip()
            git_env = {**os.environ, 'GIT_AUTHOR_NAME': 'test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
                       'GIT_COMMITTER_NAME': 'test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid'}
            sha = subprocess.check_output(['git', '-C', str(controller), 'commit-tree', tree, '-m', 'synthetic'], env=git_env).decode().strip()
            subprocess.run(['git', '-C', str(controller), 'update-ref', 'HEAD', sha], check=True)
            output = root/'output'
            for enabled in ['true', 'TRUE', 'True', 'false', '', 'true\nprivate-canary']:
                output.write_text('')
                result = self.run_shell(gate, {'CONTROL': str(controller), 'CONTROL_SHA': sha,
                    'GITHUB_OUTPUT': str(output), 'SNYK_PR_POLICY_ENABLED': enabled})
                self.assertEqual(result.returncode == 0, enabled == 'true')
                self.assertEqual(output.read_text(), 'enabled=true\n' if enabled == 'true' else '')
                self.assertNotIn('private-canary', result.stdout + result.stderr)
            for sha_value in ['a'*40, 'bad', '$(touch injected)']:
                output.write_text('')
                result = self.run_shell(gate, {'CONTROL': str(controller), 'CONTROL_SHA': sha_value,
                    'GITHUB_OUTPUT': str(output), 'SNYK_PR_POLICY_ENABLED': 'true'})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output.read_text(), '')

    def test_native_informational_token_has_no_app_authority(self):
        import re
        text = WORKFLOW.read_text()
        for forbidden in ['SNYK_POLICY_APP_', 'SNYK_POLICY_CHECK_TOKEN', 'create-github-app-token', 'environment:']:
            self.assertNotIn(forbidden, text)
        self.assertEqual(dict(re.findall(r'^      ([a-z-]+): (read|write)$', self.jobs['scan'], re.M)), {'contents': 'read'})
        for job in ['admission', 'publish']:
            self.assertNotIn('SNYK_TOKEN', self.jobs[job])
            self.assertEqual(dict(re.findall(r'^      ([a-z-]+): (read|write)$', self.jobs[job], re.M)),
                             {'contents': 'read', 'actions': 'read', 'pull-requests': 'read', 'checks': 'write'})
            consumer = next(body for body in self.steps[job].values() if 'snyk_pr_policy.py' in body)
            self.assertEqual(scalar(consumer, 'GITHUB_TOKEN', 10), '${{ github.token }}')
        credential_steps = [name for name, body in self.steps['scan'].items() if 'secrets.' in body]
        self.assertEqual(credential_steps, ['Scan current source and bound license controls'])
        for job in self.jobs.values(): self.assertNotIn('continue-on-error', job)

    def test_admission_handoff_and_publication_run_after_scan_failure(self):
        scan_guard = scalar(self.jobs['scan'], 'if', 4)
        publish_guard = scalar(self.jobs['publish'], 'if', 4)
        good = {'needs.admission.result': 'success', 'needs.admission.outputs.decision': 'scan',
                'needs.admission.outputs.admission_json': '{"trusted":"identity"}'}
        scan_context = {**good, 'github.repository': 'lorconksu/veyport',
                        'github.event.workflow_run.head_repository.full_name': 'lorconksu/veyport',
                        'github.event.workflow_run.head_repository.id': 1188082218}
        self.assertTrue(expression(scan_guard, scan_context))
        for decision in ['rejected', 'ignore', '']:
            self.assertFalse(expression(scan_guard, {**scan_context, 'needs.admission.outputs.decision': decision}))
        for scan in ['success', 'failure', 'cancelled', 'skipped']:
            self.assertTrue(expression(publish_guard, {**good, 'needs.scan.result': scan, 'success()': False}))
        for key in good:
            self.assertFalse(expression(publish_guard, {**good, key: ''}))
        for job in ['scan', 'publish']:
            self.assertEqual(scalar(self.jobs[job], 'ADMISSION_JSON', 6), '${{ needs.admission.outputs.admission_json }}')
        self.assertEqual(scalar(self.jobs['publish'], 'SCAN_RESULT', 6), '${{ needs.scan.result }}')
        admission = self.jobs['admission']
        for key in ['decision', 'source_sha', 'admission_json']:
            self.assertEqual(scalar(admission, key, 6), '${{ steps.admit.outputs.' + key + ' }}')

    def test_scan_rejects_untrusted_event_repository_even_with_successful_admission(self):
        # Removing either provenance comparison must permit a bad event and fail this test.
        _, event, _, _, _ = fixtures()
        repository = event['workflow_run']['head_repository']
        good = {'needs.admission.result': 'success', 'needs.admission.outputs.decision': 'scan',
                'github.repository': event['repository']['full_name'],
                'github.event.workflow_run.head_repository.full_name': repository['full_name'],
                'github.event.workflow_run.head_repository.id': repository['id']}
        guard = scalar(self.jobs['scan'], 'if', 4)
        self.assertTrue(expression(guard, good))
        for key, bad_values in {
            'github.event.workflow_run.head_repository.full_name': ['', 'fork/veyport', 'lorconksu/other'],
            'github.event.workflow_run.head_repository.id': ['', 0, 666],
            'github.repository': ['', 'fork/veyport'],
            'needs.admission.result': ['', 'failure', 'cancelled', 'skipped'],
            'needs.admission.outputs.decision': ['', 'rejected', 'ignore'],
        }.items():
            for bad in bad_values:
                with self.subTest(key=key, bad=bad):
                    self.assertFalse(expression(guard, {**good, key: bad}))
            with self.subTest(missing=key):
                missing = {name: value for name, value in good.items() if name != key}
                self.assertFalse(expression(guard, missing))
        for head_repository in ({}, {'full_name': 'fork/veyport', 'id': 666}):
            with self.subTest(head_repository=head_repository):
                context = {name: value for name, value in good.items()
                           if not name.startswith('github.event.workflow_run.head_repository.')}
                context.update({'github.event.workflow_run.head_repository.' + name: value
                                for name, value in head_repository.items()})
                self.assertFalse(expression(guard, context))

    def test_exact_checkouts_and_all_required_steps_are_explicit(self):
        spec = importlib.util.spec_from_file_location('workflow_contract', PATH)
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        for job, required in helper.REQUIRED_STEPS.items():
            for name in required: self.assertIn(name, self.steps[job])
            self.assertEqual(scalar(self.jobs[job], 'name', 4), job)
        for job in self.jobs:
            checkouts = [(name, body) for name, body in self.steps[job].items() if 'uses: actions/checkout@' in body]
            self.assertEqual(len(checkouts), 2 if job == 'scan' else 1)
            for name, checkout in checkouts:
                self.assertEqual(scalar(checkout, 'repository', 10), 'lorconksu/veyport')
                self.assertEqual(scalar(checkout, 'persist-credentials', 10), 'false')
                self.assertEqual(scalar(checkout, 'ref', 10), '${{ needs.admission.outputs.source_sha }}'
                    if name == 'Checkout exact admitted source' else '${{ github.sha }}')
        self.assertEqual(scalar(self.jobs['scan'], 'SOURCE_SHA', 6), '${{ needs.admission.outputs.source_sha }}')

    def test_actual_cli_shell_handoff_does_not_execute_admission_json(self):
        for job, mode, step_name in [('admission', 'admit', 'Admit current PR and create informational check'),
                ('scan', 'envelope', 'Bind publication envelope'), ('publish', 'publish', 'Publish informational PR scan')]:
            step = self.steps[job][step_name]
            body = shell_body(step)
            self.assertNotIn('${{', body)
            self.assertIn('/usr/bin/python3.12 -I -B', body)
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); scripts = root/'scripts/security'; scripts.mkdir(parents=True)
                (scripts/'snyk_pr_policy.py').write_text('import json,os,sys\nfrom pathlib import Path\nPath(os.environ["PROBE"]).write_text(json.dumps({"args":sys.argv[1:],"admission":os.environ["ADMISSION_JSON"]}))\n')
                sentinel = root/'injected'; probe = root/'probe'
                admission = '{"private":"$(touch '+str(sentinel)+'); `touch '+str(sentinel)+'`"}'
                local_step = step.replace('/usr/bin/python3.12', os.sys.executable)
                result = self.run_shell(local_step, {'CONTROL': str(root), 'CONTROL_SHA': 'a'*40,
                    'ADMISSION_JSON': admission, 'PROBE': str(probe)})
                # Admission/publisher additionally bind controller revision before execution.
                if result.returncode != 0:
                    self.fail(result.stderr)
                self.assertEqual(json.loads(probe.read_text()), {'args': [mode], 'admission': admission})
                self.assertFalse(sentinel.exists())

    def test_artifact_inventory_and_envelope_upload_conditions(self):
        steps = self.steps['scan']; names = list(steps)
        self.assertLess(names.index('Seal private evidence and generate allowlisted summary'), names.index('Bind publication envelope'))
        self.assertLess(names.index('Bind publication envelope'), names.index('Upload only encrypted evidence and allowlisted aggregates'))
        envelope = steps['Bind publication envelope']; upload = steps['Upload only encrypted evidence and allowlisted aggregates']
        self.assertEqual(scalar(upload, 'name', 10), 'snyk-pr-policy-${{ github.run_id }}-${{ github.run_attempt }}')
        paths = upload.split('          path: |\n', 1)[1].split('          if-no-files-found:', 1)[0]
        self.assertEqual([line.strip().rsplit('/', 1)[-1] for line in paths.splitlines()],
                         ['summary.json', 'evidence.tar.gz.age', 'publication.json'])
        for step in [envelope, upload]:
            guard = scalar(step, 'if', 8)
            good = {'steps.encrypt.outcome': 'success', 'steps.envelope.outcome': 'success', 'success()': False}
            self.assertTrue(expression(guard, good))
            required = ['steps.encrypt.outcome'] + (['steps.envelope.outcome'] if step is upload else [])
            for key in required:
                for outcome in ['failure', 'cancelled', 'skipped', 'neutral', '']:
                    self.assertFalse(expression(guard, {**good, key: outcome}))

    def test_final_gate_fails_every_missing_or_non_success_lifecycle_outcome(self):
        gate = self.steps['scan']['Final policy and evidence gate']
        import re
        bindings = dict(re.findall(r'^          ([A-Z_]+): (.+)$', gate, re.M))
        self.assertEqual(bindings.get('SEALED_POLICY_EXIT'), '${{ steps.encrypt.outputs.sealed_policy_exit }}')
        expected = ['initialize', 'controller', 'source', 'preflight', 'go', 'node', 'bootstrap', 'tests',
                    'prepare', 'scan', 'policy', 'encrypt', 'envelope', 'upload', 'cleanup']
        self.assertEqual({value for key, value in bindings.items() if key != 'SEALED_POLICY_EXIT'},
                         {'${{ steps.'+key+'.outcome }}' for key in expected})
        good = {key: ('0' if key == 'SEALED_POLICY_EXIT' else 'success') for key in bindings}
        self.assertEqual(self.run_shell(gate, good).returncode, 0)
        for key in good:
            for bad in ['', 'failure', 'skipped', 'cancelled', 'neutral', '1', '2']:
                with self.subTest(key=key, value=bad):
                    self.assertNotEqual(self.run_shell(gate, {**good, key: bad}).returncode, 0)
        self.assertEqual(scalar(gate, 'if', 8), 'always()')
        self.assertEqual(scalar(self.steps['scan']['Remove public resolver workspace and private plaintext'], 'if', 8), 'always()')

    def test_initializer_creates_isolated_private_paths_without_credentials(self):
        import shutil
        step = self.steps['scan']['Initialize private evidence']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root/'env'; output.touch()
            result = self.run_shell(step, {'RUNNER_TEMP': str(root), 'GITHUB_ENV': str(output),
                    'SOURCE_SHA': 'a'*40, 'CONTROL_SHA': 'b'*40})
            self.assertEqual(result.returncode, 0, result.stderr)
            env = dict(line.split('=', 1) for line in output.read_text().splitlines())
            self.addCleanup(shutil.rmtree, env['PUBLIC_PYTHON_ROOT'], ignore_errors=True)
            private = Path(env['TRIAL_ROOT'])
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)
            self.assertEqual(env['HOME'], str(private/'home'))
            self.assertNotEqual(env['NPM_CONFIG_USERCONFIG'], env['NPM_CONFIG_GLOBALCONFIG'])
            for key in ['NPM_CONFIG_USERCONFIG', 'NPM_CONFIG_GLOBALCONFIG']:
                path = Path(env[key]); self.assertEqual(path.read_bytes(), b'')
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__': unittest.main()

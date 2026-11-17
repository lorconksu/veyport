"""Offline contracts for exact-request merge authority; no provider writes."""
import contextlib
import copy
import importlib.util
import io
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import zipfile

PATH = Path(__file__).with_name('protected_merge.py')
HEAD, CONTROL, MERGED = 'a' * 40, 'b' * 40, 'd' * 40
REPO = {'id': 1188082218, 'full_name': 'lorconksu/veyport',
        'owner': {'id': 13374789, 'login': 'lorconksu'}, 'default_branch': 'main'}
OWNER = {'id': 13374789, 'login': 'lorconksu'}
CHECKS = ['test', 'integration', 'smoke', 'e2e', 'vulnerability-scan', 'sonarcloud',
          'CodeQL', 'Analyze (actions)', 'Analyze (go)', 'Analyze (javascript-typescript)',
          'Analyze (python)', 'Analyze (ruby)']
# Literal lifecycle names are the integration contract, independent of the helper.
STEPS = {
    'admission': ['Checkout trusted main controller', 'Admit exact owner request'],
    'scan': ['Initialize private evidence', 'Checkout trusted main controller',
             'Checkout exact admitted source', 'Verify source and inventory before tool setup',
             'Setup Go', 'Setup Node',
             'Bootstrap authenticated packages and checksummed latest stable CLI',
             'Test trusted helper boundaries before credentials',
             'Prepare eight dependency targets without credentials',
             'Scan current source and bound license controls',
             'Evaluate all findings and bound license controls',
             'Seal private evidence and generate allowlisted summary',
             'Bind protected merge evidence',
             'Upload only encrypted evidence and allowlisted aggregates',
             'Remove public resolver workspace and private plaintext', 'Final policy and evidence gate'],
    'verify': ['Checkout trusted main controller', 'Verify fresh protected merge evidence'],
}


def fixtures(operation='merge'):
    env = {'PROTECTED_MERGE_ENABLED': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
           'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': CONTROL, 'GITHUB_WORKFLOW_SHA': CONTROL,
           'GITHUB_WORKFLOW_REF': 'lorconksu/veyport/.github/workflows/protected-merge.yml@refs/heads/main',
           'GITHUB_REPOSITORY': 'lorconksu/veyport', 'GITHUB_REPOSITORY_ID': '1188082218',
           'GITHUB_REPOSITORY_OWNER_ID': '13374789', 'GITHUB_ACTOR': 'lorconksu',
           'GITHUB_ACTOR_ID': '13374789', 'GITHUB_TRIGGERING_ACTOR': 'lorconksu',
           'GITHUB_RUN_ID': '200', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'admission',
           'PROTECTED_MERGE_APP_ID': '999', 'PROTECTED_MERGE_INSTALLATION_ID': '888',
           'PROTECTED_MERGE_RULESET_ID': '777', 'PROTECTED_MERGE_APP_CLIENT_ID': 'Iv1.example',
           'PROTECTED_MERGE_MINTED_INSTALLATION_ID': '888', 'PROTECTED_MERGE_APP_SLUG': 'veyport-merger'}
    event = {'ref': 'refs/heads/main', 'repository': copy.deepcopy(REPO), 'sender': copy.deepcopy(OWNER),
             'inputs': {'operation': operation, 'pr_number': '7', 'head_sha': HEAD}}
    run = {'id': 200, 'run_number': 20, 'run_attempt': 1, 'workflow_id': 300,
           'path': '.github/workflows/protected-merge.yml', 'event': 'workflow_dispatch',
           'head_sha': CONTROL, 'head_branch': 'main', 'repository': copy.deepcopy(REPO),
           'head_repository': copy.deepcopy(REPO), 'actor': copy.deepcopy(OWNER),
           'triggering_actor': copy.deepcopy(OWNER), 'status': 'in_progress', 'conclusion': None}
    pr = {'id': 555, 'node_id': 'PR_exact_7', 'number': 7, 'state': 'open', 'draft': False,
          'merged': False, 'merge_commit_sha': None,
          'head': {'repo': copy.deepcopy(REPO), 'ref': 'feature/private', 'sha': HEAD},
          'base': {'repo': copy.deepcopy(REPO), 'ref': 'main', 'sha': CONTROL}}
    return env, event, run, pr


# A fixed sibling import also works under isolated Python without sys.path changes.
_CONTEXT_SUPPORT_SPEC = importlib.util.spec_from_file_location(
    'security_context_test_support', Path(__file__).with_name('context_test_support.py'))
_CONTEXT_SUPPORT = importlib.util.module_from_spec(_CONTEXT_SUPPORT_SPEC)
_CONTEXT_SUPPORT_SPEC.loader.exec_module(_CONTEXT_SUPPORT)
change_context_fields = _CONTEXT_SUPPORT.change_context_fields


class Metadata:
    def __init__(self, operation='merge'):
        self.env, self.event, self.run, self.pr = fixtures(operation)
        self.repository = copy.deepcopy(REPO)
        self.workflow = {'id': 300, 'path': '.github/workflows/protected-merge.yml', 'state': 'active'}
        self.main = CONTROL
        self.jobs, self.artifacts, self.raw, self.calls = [], [], b'', []
        self.before_get = None
        self.commit = {'sha': MERGED, 'parents': [{'sha': CONTROL}, {'sha': HEAD}]}

    def fresh_readonly(self): return self

    def get(self, path, raw=False):
        self.calls.append(path)
        if self.before_get: self.before_get(self, path)
        base = path.split('?')[0]
        if base == '': return copy.deepcopy(self.repository)
        if base == 'actions/workflows/protected-merge.yml':
            return copy.deepcopy(self.workflow)
        if base == 'actions/runs/200': return copy.deepcopy(self.run)
        if base == 'git/ref/heads/main': return {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': self.main}}
        if base == 'pulls/7': return copy.deepcopy(self.pr)
        if base.endswith('/jobs'): return {'total_count': len(self.jobs), 'jobs': copy.deepcopy(self.jobs)}
        if base.endswith('/artifacts'): return {'total_count': len(self.artifacts), 'artifacts': copy.deepcopy(self.artifacts)}
        if base == 'actions/artifacts/444/zip': return self.raw
        if base == 'commits/'+MERGED: return copy.deepcopy(self.commit)
        raise AssertionError(path)


class AppReads:
    def __init__(self):
        self.app = {'id': 999, 'slug': 'veyport-merger', 'client_id': 'Iv1.example',
                    'owner': copy.deepcopy(OWNER),
                    'permissions': {'contents': 'write', 'administration': 'read', 'metadata': 'read'}}
        self.repositories = [copy.deepcopy(REPO)]
        # Public-safe raw GitHub API response captured 2026-11-16, not a baseline builder.
        self.protection = json.loads((PATH.parent/'fixtures/github-main-protection-2022-11-28.json').read_bytes())
        self.rule = {'id': 777, 'target': 'branch', 'source_type': 'Repository', 'source': 'lorconksu/veyport',
                     'enforcement': 'active', 'bypass_actors': [{'actor_id': 999, 'actor_type': 'Integration',
                                                             'bypass_mode': 'pull_request'}],
                     'conditions': {'ref_name': {'include': ['refs/heads/main'], 'exclude': []}},
                     'rules': [{'type': 'update', 'parameters': {'update_allows_fetch_and_merge': False}}]}
        self.rulesets = [copy.deepcopy(self.rule)]
        self.active = [{'type': 'update', 'parameters': {'update_allows_fetch_and_merge': False},
                        'ruleset_id': 777, 'ruleset_source_type': 'Repository', 'ruleset_source': 'lorconksu/veyport'}]
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        base = path.split('?')[0]
        if base == 'apps/veyport-merger': return copy.deepcopy(self.app)
        if base == 'installation/repositories': return {'total_count': len(self.repositories), 'repositories': copy.deepcopy(self.repositories)}
        if base == 'branches/main/protection': return copy.deepcopy(self.protection)
        if base == 'rulesets': return copy.deepcopy(self.rulesets)
        if base == 'rulesets/777': return copy.deepcopy(self.rule)
        if base == 'rules/branches/main': return copy.deepcopy(self.active)
        raise AssertionError(path)


class Writer:
    def __init__(self, api): self.api, self.writes, self.error, self.reply = api, [], None, None
    def merge(self, number, sha):
        self.writes.append((number, sha))
        if self.error: raise self.error
        self.api.pr.update(state='closed', merged=True, merge_commit_sha=MERGED)
        self.api.main = MERGED
        return self.reply if self.reply is not None else {'sha': MERGED, 'merged': True, 'message': 'PRIVATE'}


class ProtectedMergeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PATH.exists(): raise AssertionError('Missing exact-request protected merge authority')
        spec = importlib.util.spec_from_file_location('protected_merge_under_test', PATH)
        cls.p = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.p)

    def setUp(self):
        self.api, self.app = Metadata(), AppReads()
        self.writer = Writer(self.api)

    def admission(self):
        result = self.p.admit(self.api, self.api.event, self.api.env)
        self.assertEqual(result['source_sha'], HEAD)
        return json.loads(result['admission_json'])

    def evidence(self, admission):
        policy = self.p.common.policy
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
        raw, cipher = json.dumps(summary).encode(), b'age-encryption.org/v1\nsynthetic-ciphertext'
        files = {'summary.json': raw, 'evidence.tar.gz.age': cipher,
                 'publication.json': self.p.common.canonical(self.p.make_evidence(admission, raw, cipher, b'scanner'))}
        self.install_files(files)
        self.api.jobs = [{'id': i, 'run_id': 200, 'run_attempt': 1, 'head_sha': CONTROL,
                          'name': name, 'status': 'completed', 'conclusion': 'success',
                          'steps': [{'number': n, 'name': s, 'status': 'completed', 'conclusion': 'success'}
                                    for n, s in enumerate(steps, 1)]}
                         for i, (name, steps) in enumerate(STEPS.items(), 1)]
        self.api.jobs.append({'id': 4, 'run_id': 200, 'run_attempt': 1, 'head_sha': CONTROL,
            'name': 'merge', 'status': 'in_progress', 'conclusion': None,
            'steps': [{'number': i, 'name': name, 'status': 'completed', 'conclusion': 'success'}
                      for i, name in enumerate(['Checkout trusted main controller',
                          'Preflight fresh protected merge evidence', 'Mint protected merge token'], 1)] +
                     [{'number': 4, 'name': 'Merge exact owner request once', 'status': 'in_progress', 'conclusion': None}]})
        return files

    def install_files(self, files):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, 'w') as archive:
            for name, value in files.items(): archive.writestr(name, value)
        self.api.raw = raw.getvalue()
        self.api.artifacts = [{'id': 444, 'name': 'protected-merge-200-1', 'expired': False,
            'size_in_bytes': len(self.api.raw), 'digest': 'sha256:'+self.p.common.digest(self.api.raw),
            'workflow_run': {'id': 200, 'repository_id': 1188082218, 'head_repository_id': 1188082218,
                             'head_branch': 'main', 'head_sha': CONTROL}}]

    def prepared(self, job='merge'):
        admission = self.admission()
        self.evidence(admission)
        self.api.env['GITHUB_JOB'] = job
        return admission

    def merge(self, admission):
        return self.p.merge_once(self.api, self.app, self.writer, self.api.event, self.api.env, admission)

    def cli(self, mode, admission=None, extra=None):
        with tempfile.TemporaryDirectory() as folder:
            event, output = Path(folder)/'event', Path(folder)/'output'
            event.write_text(json.dumps(self.api.event))
            env = {**self.api.env, 'GITHUB_EVENT_PATH': str(event), 'GITHUB_OUTPUT': str(output),
                   'GITHUB_TOKEN': 'read-token', 'ADMISSION_JSON': json.dumps(admission)}
            if extra: env.update(extra)
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(self.p, 'MetadataClient', return_value=self.api), \
                 mock.patch.object(self.p, 'AppReadClient', return_value=self.app), \
                 mock.patch.object(self.p, 'MergeClient', return_value=self.writer) as constructor, \
                 contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = self.p.main([mode])
            return code, output.read_text() if output.exists() else '', stdout.getvalue(), stderr.getvalue(), constructor.call_count

    def test_exact_request_admission_is_read_only_and_opaque(self):
        admission = self.admission()
        self.assertEqual(admission['pr_node_id'], 'PR_exact_7')
        self.assertEqual(admission['purpose'], 'protected-merge')
        self.assertEqual(admission['run_attempt'], 1)
        self.assertNotIn('feature/private', json.dumps(admission))
        self.assertEqual(self.writer.writes, [])

    def test_request_owner_context_and_source_forgery_reject(self):
        mutations = [lambda a: a.env.update(GITHUB_RUN_ATTEMPT='2'),
            lambda a: a.run.update(run_attempt=2), lambda a: a.run['actor'].update(id=666),
            lambda a: a.run['triggering_actor'].update(id=666),
            lambda a: a.event['sender'].update(id=666), lambda a: a.env.update(GITHUB_ACTOR_ID='666'),
            lambda a: a.env.update(GITHUB_TRIGGERING_ACTOR='someone'),
            lambda a: a.event['inputs'].update(operation='Merge'),
            lambda a: a.event['inputs'].update(pr_number='07'), lambda a: a.event['inputs'].update(pr_number=True),
            lambda a: a.event['inputs'].update(head_sha=HEAD.upper()),
            lambda a: a.event['inputs'].update(run_id='100'), lambda a: a.pr.update(draft=True),
            lambda a: a.pr.update(state='closed'), lambda a: a.pr.update(merged=True),
            lambda a: a.pr['head'].update(sha='e'*40), lambda a: a.pr['head']['repo'].update(id=666),
            lambda a: a.pr['base'].update(ref='release'), lambda a: a.pr['base'].update(sha='e'*40),
            lambda a: setattr(a, 'main', 'e'*40), lambda a: a.run.update(head_sha='e'*40),
            lambda a: a.run.update(path='.github/workflows/snyk-pr-policy.yml'),
            lambda a: a.env.update(GITHUB_WORKFLOW_REF='attacker'), lambda a: a.env.update(GITHUB_EVENT_NAME='workflow_run'),
            lambda a: a.env.update(GITHUB_JOB='publish'), lambda a: a.env.update(GITHUB_REPOSITORY_ID='666'),
            lambda a: a.env.update(GITHUB_REPOSITORY_OWNER_ID='666'),
            lambda a: a.env.update(GITHUB_WORKFLOW_SHA='e'*40), lambda a: a.run.update(status='completed'),
            lambda a: a.run.update(conclusion='cancelled'), lambda a: a.event.update(ref='refs/heads/feature')]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.api = Metadata(); mutate(self.api)
                with self.assertRaises(ValueError): self.admission()

    def test_authenticated_context_bindings_refuse_before_app_reads_or_merge(self):
        # Each role is independently mutable; valid foreign values exercise authority,
        # rather than failing a type/shape check before the binding under audit.
        cases = [
            ('repository', ('repository', 'id'), 666),
            ('repository-name', ('repository', 'full_name'), 'other/veyport'),
            ('repository-owner', ('repository', 'owner', 'id'), 666),
            ('repository-owner-login', ('repository', 'owner', 'login'), 'someone'),
            ('default-branch', ('repository', 'default_branch'), 'release'),
            ('event-repository', ('event', 'repository', 'id'), 666),
            ('workflow-path', ('workflow', 'path'), '.github/workflows/other.yml'),
            ('workflow-state', ('workflow', 'state'), 'disabled_manually'),
            ('run-id', ('run', 'id'), 201),
            ('run-workflow', ('run', 'workflow_id'), 301),
            ('run-event', ('run', 'event'), 'workflow_run'),
            ('run-branch', ('run', 'head_branch'), 'release'),
            ('run-repository', ('run', 'repository', 'id'), 666),
            ('run-head-repository', ('run', 'head_repository', 'id'), 666),
            ('original-owner-login', ('run', 'actor', 'login'), 'someone'),
            ('triggering-owner-login', ('run', 'triggering_actor', 'login'), 'someone'),
            ('sender-login', ('event', 'sender', 'login'), 'someone'),
            ('pr-number', ('pr', 'number'), 8),
            ('pr-base-repository', ('pr', 'base', 'repo', 'id'), 666),
            ('environment-ref', ('env', 'GITHUB_REF'), 'refs/heads/release'),
            ('environment-repository', ('env', 'GITHUB_REPOSITORY'), 'other/veyport'),
            ('environment-owner-login', ('env', 'GITHUB_ACTOR'), 'someone'),
        ]
        for binding, path, value in cases:
            for consumer in ('admit', 'merge'):
                with self.subTest(binding=binding, consumer=consumer):
                    self.setUp()
                    admission = self.prepared() if consumer == 'merge' else None
                    state = {key: getattr(self.api, key) for key in
                             ('repository', 'workflow', 'env', 'event', 'run', 'pr')}
                    change_context_fields(self, state, [(path, value)])
                    for key, item in state.items(): setattr(self.api, key, item)
                    with self.assertRaises(ValueError):
                        if consumer == 'admit': self.admission()
                        else: self.merge(admission)
                    self.assertEqual(self.app.calls, [])
                    self.assertEqual(self.writer.writes, [])

    def test_strict_admission_rejects_extra_boolean_and_automatic_identity(self):
        admission = self.admission()
        for key, value in [('purpose', 'automatic-pr'), ('run_attempt', 2), ('owner_id', True),
                           ('schema_version', True), ('pr_id', False), ('extra', 1), ('pr_node_id', '\nsecret')]:
            wrong = {**admission, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError): self.p.validate_admission(wrong)

    def test_preview_verifies_fresh_evidence_without_app_or_mutation(self):
        self.api = Metadata('verify'); self.writer = Writer(self.api)
        admission = self.prepared('verify')
        self.assertEqual(admission['purpose'], 'protected-merge-preview')
        code, output, _, _, constructed = self.cli('verify', admission)
        self.assertEqual(code, 0)
        self.assertEqual(dict(line.split('=', 1) for line in output.splitlines()),
            {'verified': 'true', 'purpose': 'protected-merge-preview', 'source_sha': HEAD})
        self.assertEqual(constructed, 0); self.assertEqual(self.app.calls, [])
        self.assertEqual(self.writer.writes, [])
        self.api.env['GITHUB_JOB'] = 'merge'
        with self.assertRaises(ValueError): self.merge(admission)
        self.assertEqual(self.writer.writes, [])

    def test_strict_operation_is_the_only_source_of_verified_workflow_purpose(self):
        for operation, purpose in [('verify', 'protected-merge-preview'), ('merge', 'protected-merge')]:
            self.api = Metadata(operation)
            admission = self.prepared(operation)
            code, output, _, _, constructed = self.cli('verify', admission)
            self.assertEqual(code, 0)
            self.assertEqual(dict(line.split('=', 1) for line in output.splitlines()),
                {'verified': 'true', 'purpose': purpose, 'source_sha': HEAD})
            self.assertEqual(constructed, 0)
        for operation in ['MERGE', 'Merge', 'VERIFY', '', 'merge\n', '$(touch injected)']:
            self.api = Metadata(); self.api.event['inputs']['operation'] = operation
            code, output, _, _, constructed = self.cli('admit')
            self.assertEqual(code, 1)
            self.assertEqual(output, '')
            self.assertEqual(constructed, 0)
        self.assertEqual(self.app.calls, [])
        self.assertEqual(self.writer.writes, [])

    def test_old_sha_new_pr_and_old_run_evidence_cannot_authorize(self):
        admission = self.prepared()
        for key, value in [('pr_number', 8), ('pr_id', 556), ('pr_node_id', 'PR_other'),
                           ('run_id', 199), ('run_number', 19), ('purpose', 'protected-merge-preview')]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError): self.merge({**admission, key: value})
                self.assertEqual(self.writer.writes, [])

    def test_embedded_evidence_identity_must_match_current_admission(self):
        for key, value in [('pr_number', 8), ('pr_id', 556), ('pr_node_id', 'PR_other'),
                           ('run_id', 199), ('run_number', 19),
                           ('source_ref_sha256', self.p.common.digest(b'feature/other'))]:
            with self.subTest(key=key):
                self.setUp()
                admission = self.prepared()
                foreign = {**admission, key: value}
                # Rebuild the envelope for the foreign identity, while retaining
                # current-run API provenance and valid archive/digest bindings.
                files = self.evidence(foreign)
                self.p.validate_evidence(foreign, files)
                self.assertEqual(self.p.context(self.api, self.api.event, self.api.env), admission)
                with self.assertRaises(ValueError): self.merge(admission)
                self.assertEqual(self.app.calls, [])
                self.assertEqual(self.writer.writes, [])

    def test_successful_merge_uses_exact_number_head_and_reports_sanitized_commit(self):
        admission = self.prepared()
        self.assertEqual(self.p.protection_config(self.api.env), (999, 777, 'veyport-merger', 'Iv1.example'))
        result = self.merge(admission)
        self.assertEqual(result, {'result': 'merged', 'merge_commit_sha': MERGED})
        self.assertEqual(self.writer.writes, [(7, HEAD)])
        self.assertIn('commits/'+MERGED, self.api.calls)
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_policy_and_envelope_faults_block_before_any_privileged_reads(self):
        for mutation in ['high', 'license', 'control', 'incomplete', 'tamper', 'automatic', 'cipher', 'scanner']:
            with self.subTest(mutation=mutation):
                self.setUp()
                admission = self.prepared()
                files = self.evidence(admission)
                changed = copy.deepcopy(files)
                summary = json.loads(changed['summary.json'])
                envelope = json.loads(changed['publication.json'])
                if mutation in ('high', 'license'):
                    field = 'blocking_vulnerability_records' if mutation == 'high' else 'blocking_license_records'
                    summary['projects'][0][field] = 1
                    summary['projects'][0]['vulnerability_path_records' if mutation == 'high' else 'license_path_records'] = 1
                    summary['projects'][0]['status'] = 'scan_complete_with_findings'
                elif mutation == 'control': summary['license_controls'] = self.p.common.policy.control_status(False)
                elif mutation == 'incomplete': summary['processing_status'] = 'incomplete'
                elif mutation == 'tamper': envelope['summary']['sha256'] = '0'*64
                elif mutation == 'automatic': envelope['purpose'] = 'automatic-pr'
                elif mutation == 'cipher':
                    changed['evidence.tar.gz.age'] = b'plaintext'
                    envelope['ciphertext'] = {'sha256': self.p.common.digest(b'plaintext'), 'size': 9}
                elif mutation == 'scanner': envelope['scanner']['size'] = True
                if mutation in ('high', 'license', 'control', 'incomplete'):
                    summary['policy'] = self.p.common.policy.policy_result(summary['projects'],
                        controls_verified=summary['license_controls']['status'] == 'verified')
                    self.assertEqual(summary['policy']['exit_code'],
                                     {'high': 1, 'license': 1, 'control': 2, 'incomplete': 0}[mutation])
                changed['summary.json'] = json.dumps(summary).encode()
                if mutation in ('high', 'license', 'control', 'incomplete'):
                    # These are schema-valid policy refusals, not hash tampering.
                    # make_evidence validates row totals/policy and rebinds bytes.
                    envelope = self.p.make_evidence(admission, changed['summary.json'],
                                                    changed['evidence.tar.gz.age'], b'scanner')
                changed['publication.json'] = json.dumps(envelope).encode()
                self.install_files(changed)
                with self.assertRaises(ValueError): self.merge(admission)
                self.assertEqual(self.app.calls, []); self.assertEqual(self.writer.writes, [])

    def test_native_check_app_ids_are_refused_before_privileged_reads(self):
        for app_id in (15368, 57789):
            for boundary in ('configuration', 'merge'):
                with self.subTest(app_id=app_id, boundary=boundary):
                    self.setUp()
                    admission = self.prepared()
                    self.api.env['PROTECTED_MERGE_APP_ID'] = str(app_id)
                    # Keep all downstream identity/rule checks otherwise valid,
                    # so an App metadata mismatch cannot mask the refusal.
                    self.app.app['id'] = app_id
                    self.app.rule['bypass_actors'][0]['actor_id'] = app_id
                    self.app.rulesets = [copy.deepcopy(self.app.rule)]
                    with self.assertRaises(ValueError):
                        if boundary == 'configuration': self.p.protection_config(self.api.env)
                        else: self.merge(admission)
                    self.assertEqual(self.app.calls, [])
                    self.assertEqual(self.writer.writes, [])

    def test_missing_failed_cancelled_skipped_duplicate_or_wrong_attempt_lifecycle_blocks(self):
        for kind in ['missing', 'duplicate', 'job_failed', 'cancelled', 'step_skipped', 'step_failed',
                     'extra_failed', 'duplicate_step', 'attempt', 'head', 'run', 'verify']:
            with self.subTest(kind=kind):
                self.setUp()
                admission = self.prepared()
                scan = self.api.jobs[1]
                if kind == 'missing': scan['steps'].pop()
                # Distinct IDs/numbers let the exact-name guards decide.
                elif kind == 'duplicate': self.api.jobs.append({**copy.deepcopy(scan), 'id': 5})
                elif kind == 'job_failed': scan['conclusion'] = 'failure'
                elif kind == 'cancelled': scan['conclusion'] = 'cancelled'
                elif kind == 'step_skipped': scan['steps'][0]['conclusion'] = 'skipped'
                elif kind == 'step_failed': scan['steps'][0]['conclusion'] = 'failure'
                elif kind == 'extra_failed': scan['steps'].append({'name': 'extra', 'number': 99, 'status': 'completed', 'conclusion': 'failure'})
                elif kind == 'duplicate_step': scan['steps'].append({**copy.deepcopy(scan['steps'][0]), 'number': 99})
                elif kind == 'attempt': scan['run_attempt'] = 2
                elif kind == 'head': scan['head_sha'] = HEAD
                elif kind == 'run': scan['run_id'] = 199
                elif kind == 'verify': self.api.jobs[2]['conclusion'] = 'skipped'
                with self.assertRaises(ValueError): self.merge(admission)
                self.assertEqual(self.app.calls, [])
                self.assertEqual(self.writer.writes, [])

    def test_artifact_missing_duplicate_provenance_digest_and_expiry_fail_closed(self):
        for key, value in [('name', 'protected-merge-199-1'), ('expired', True), ('digest', None),
                           # Incomplete provenance is separate from each foreign-field binding below.
                           ('digest', 'sha256:'+'0'*64), ('workflow_run', {'id': 200}), ('size_in_bytes', 1)]:
            with self.subTest(key=key, value=value):
                self.setUp()
                admission = self.prepared()
                self.api.artifacts[0][key] = value
                with self.assertRaises(ValueError): self.merge(admission)
                self.assertEqual(self.app.calls, [])
                self.assertEqual(self.writer.writes, [])
        self.setUp()
        admission = self.prepared()
        # Distinct IDs pass pagination so the exact-name uniqueness guard decides.
        self.api.artifacts.append({**copy.deepcopy(self.api.artifacts[0]), 'id': 445})
        with self.assertRaises(ValueError): self.merge(admission)
        self.assertEqual(self.app.calls, [])
        self.assertEqual(self.writer.writes, [])

    def test_each_artifact_provenance_binding_blocks_before_app_reads_and_merge(self):
        for field, value in [('id', 199), ('repository_id', 666), ('head_repository_id', 666),
                             ('head_branch', 'release'), ('head_sha', HEAD)]:
            with self.subTest(field=field):
                self.setUp()
                admission = self.prepared()
                # Change one valid field; retain the current name, digest, size and envelope.
                self.api.artifacts[0]['workflow_run'][field] = value
                with self.assertRaises(ValueError): self.merge(admission)
                self.assertEqual(self.app.calls, [])
                self.assertEqual(self.writer.writes, [])

    def test_captured_classic_api_response_accepts_without_fabricated_fields(self):
        self.assertNotIn('restrictions', self.app.protection)
        self.assertIs(self.app.protection['required_signatures']['enabled'], False)
        try:
            self.p.validate_classic(self.app.protection)
        except ValueError:
            self.fail('Unchanged captured GitHub classic protection must validate')
        admission = self.prepared()
        self.merge(admission)
        self.assertEqual(self.writer.writes, [(7, HEAD)])

    def test_classic_navigation_order_and_explicit_null_restrictions_are_harmless(self):
        value = copy.deepcopy(self.app.protection)
        value['url'] = 'https://example.invalid/navigation'
        for item in value.values():
            if isinstance(item, dict): item.pop('url', None)
        value['required_status_checks'].pop('contexts_url')
        value['required_status_checks']['contexts'].reverse()
        value['required_status_checks']['checks'].reverse()
        self.p.validate_classic(dict(reversed(list(value.items()))))
        value['restrictions'] = None
        self.p.validate_classic(value)

    def test_classic_missing_required_control_or_metadata_blocks_before_write(self):
        pristine = self.app.protection
        paths = [(key,) for key in pristine if key != 'url']
        paths += [(key, nested) for key, item in pristine.items() if isinstance(item, dict)
                  for nested in item if nested not in ('url', 'contexts_url')]
        paths += [('required_status_checks', 'checks', 0, key) for key in ('context', 'app_id')]
        admission = self.prepared()
        for path in paths:
            with self.subTest(missing=path):
                self.app.protection = copy.deepcopy(pristine)
                parent = self.app.protection
                for key in path[:-1]: parent = parent[key]
                del parent[path[-1]]
                with self.assertRaises(ValueError): self.merge(admission)
                self.assertEqual(self.writer.writes, [])

    def test_classic_changed_or_malformed_boolean_controls_block_before_write(self):
        pristine = self.app.protection
        paths = [(key, 'enabled') for key, value in pristine.items()
                 if isinstance(value, dict) and 'enabled' in value]
        paths += [('required_status_checks', 'strict')]
        paths += [('required_pull_request_reviews', key) for key in
                  ('dismiss_stale_reviews', 'require_code_owner_reviews', 'require_last_push_approval')]
        admission = self.prepared()
        for key, field in paths:
            for value in (not pristine[key][field], 0, 1, 'false', None, [], {}):
                with self.subTest(control=key, field=field, malformed=value):
                    self.app.protection = copy.deepcopy(pristine)
                    self.app.protection[key][field] = value
                    with self.assertRaises(ValueError): self.merge(admission)
                    self.assertEqual(self.writer.writes, [])
        for value in (True, False, 1, '0', None, [], {}):
            self.app.protection = copy.deepcopy(pristine)
            self.app.protection['required_pull_request_reviews']['required_approving_review_count'] = value
            with self.subTest(review_count=value), self.assertRaises(ValueError): self.merge(admission)
            self.assertEqual(self.writer.writes, [])

    def test_classic_unknown_controls_restrictions_and_signature_shapes_block(self):
        pristine = self.app.protection
        mutations = [lambda p: p.update(unknown_control={'enabled': True}),
                     lambda p: p.update(unknown_control={'enabled': False}),
                     lambda p: p['required_signatures'].update(unknown_control=True)]
        for value in ({}, {'users': [], 'teams': [], 'apps': []}, [], False, 0, 'null'):
            mutations.append(lambda p, value=value: p.update(restrictions=value))
        for value in (None, False, [], {}, {'enabled': False, 'extra': False}):
            mutations.append(lambda p, value=value: p.update(required_signatures=value))
        admission = self.prepared()
        for mutate in mutations:
            self.app.protection = copy.deepcopy(pristine); mutate(self.app.protection)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError): self.merge(admission)
            self.assertEqual(self.writer.writes, [])

    def test_protection_baseline_and_hidden_or_broadened_bypass_fail_closed(self):
        admission = self.prepared()
        mutations = [lambda a: a.protection['enforce_admins'].update(enabled=False),
            lambda a: a.protection['required_status_checks'].update(strict=False),
            lambda a: a.protection['required_status_checks']['checks'][0].update(app_id=999),
            lambda a: a.protection['required_status_checks']['checks'].pop(),
            lambda a: a.protection['allow_force_pushes'].update(enabled=True),
            lambda a: a.protection['required_conversation_resolution'].update(enabled=False),
            lambda a: a.protection.update(restrictions={'users': []}),
            lambda a: a.rule.pop('bypass_actors'), lambda a: a.rule.update(bypass_actors=[]),
            lambda a: a.rule['bypass_actors'][0].update(actor_id=666),
            lambda a: a.rule['bypass_actors'][0].update(bypass_mode='always'),
            lambda a: a.rule['bypass_actors'].append({'actor_type': 'User', 'actor_id': 13374789, 'bypass_mode': 'always'}),
            lambda a: a.rule.update(enforcement='disabled'),
            lambda a: a.rule['conditions']['ref_name']['include'].append('refs/heads/other'),
            lambda a: a.rule['rules'][0]['parameters'].update(update_allows_fetch_and_merge=True),
            lambda a: a.rule['rules'].append({'type': 'required_status_checks'}),
            lambda a: a.active.append({'type': 'required_signatures', 'ruleset_id': 778}),
            lambda a: a.rulesets.append({'id': 778, 'target': 'branch', 'enforcement': 'active'}),
            lambda a: a.app.update(id=666), lambda a: a.app.update(client_id='wrong'),
            lambda a: a.app['permissions'].update(workflows='write'),
            lambda a: a.app['owner'].update(id=666), lambda a: a.repositories.append({**REPO, 'id': 666})]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.app = AppReads(); mutate(self.app)
                with self.assertRaises(ValueError): self.merge(admission)
                self.assertEqual(self.writer.writes, [])

    def test_update_rule_response_forms_reach_exact_head_merge(self):
        for detail_omitted, effective_omitted in [(False, False), (True, False), (False, True), (True, True)]:
            with self.subTest(detail_omitted=detail_omitted, effective_omitted=effective_omitted):
                self.setUp()
                admission = self.prepared()
                if detail_omitted: self.app.rule['rules'][0].pop('parameters')
                if effective_omitted: self.app.active[0].pop('parameters')
                try:
                    result = self.merge(admission)
                except ValueError:
                    self.assertEqual(self.writer.writes, [])
                    self.fail('Valid update-rule response refused before merge write')
                self.assertEqual(result['result'], 'merged')
                self.assertEqual(self.writer.writes, [(7, HEAD)])

    def test_malformed_update_responses_refuse_before_merge_write(self):
        malformed = [
            {}, {'parameters': {'update_allows_fetch_and_merge': False}}, {'type': 'other'},
            {'type': 'update', 'unknown': False},
            *[{'type': 'update', 'parameters': value} for value in [
                None, {}, False, [], {'unknown': False},
                {'update_allows_fetch_and_merge': False, 'unknown': False},
                *[{'update_allows_fetch_and_merge': value} for value in [True, 0, 1, 'false', 'true', None]]]],
        ]
        for site in ('detail', 'effective'):
            for response in malformed + [None, [], 'update']:
                with self.subTest(site=site, response=response):
                    self.setUp()
                    admission = self.prepared()
                    self.app.rule['rules'][0].pop('parameters')
                    self.app.active[0].pop('parameters')
                    if site == 'detail': self.app.rule['rules'] = [copy.deepcopy(response)]
                    else:
                        metadata = {k: v for k, v in self.app.active[0].items() if k != 'type'}
                        self.app.active = [{**metadata, **response}] if type(response) is dict else [response]
                    with self.assertRaises(ValueError): self.merge(admission)
                    self.assertEqual(self.writer.writes, [])

    def test_omitted_update_parameters_preserve_full_rule_authority(self):
        mutations = [
            lambda a: a.rule.update(rules=[]),
            lambda a: a.rule['rules'].append({'type': 'update'}),
            lambda a: a.rule.update(rules={'type': 'update'}),
            lambda a: a.rule.update(rules=None),
            lambda a: a.active.clear(),
            lambda a: a.active.append(copy.deepcopy(a.active[0])),
            lambda a: a.active[0].pop('ruleset_id'),
            lambda a: a.active[0].update(ruleset_id=778),
            lambda a: a.active[0].update(ruleset_id=777.0),
            lambda a: a.active[0].pop('ruleset_source_type'),
            lambda a: a.active[0].pop('ruleset_source'),
            lambda a: a.active[0].update(ruleset_source_type='Organization'),
            lambda a: a.active[0].update(ruleset_source='other/repo'),
            lambda a: a.active[0].update(unknown=False),
            lambda a: a.rule.update(source_type='Organization'),
            lambda a: a.rule.update(source='other/repo'),
            lambda a: a.rule.update(target='tag'),
            lambda a: a.rule['conditions']['ref_name']['exclude'].append('refs/heads/main'),
            lambda a: a.rule['bypass_actors'][0].update(bypass_mode='always'),
            lambda a: a.rule['bypass_actors'].append({'actor_type': 'User', 'actor_id': 13374789, 'bypass_mode': 'always'}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.setUp()
                admission = self.prepared()
                self.app.rule['rules'][0].pop('parameters')
                self.app.active[0].pop('parameters')
                mutate(self.app)
                with self.assertRaises(ValueError): self.merge(admission)
                self.assertEqual(self.writer.writes, [])

    def test_minted_relationship_configuration_is_not_supplied_by_artifacts(self):
        admission = self.prepared()
        for key, value in [('PROTECTED_MERGE_MINTED_INSTALLATION_ID', '887'),
                           ('PROTECTED_MERGE_APP_SLUG', '../other'), ('PROTECTED_MERGE_APP_ID', '0'),
                           ('PROTECTED_MERGE_APP_CLIENT_ID', ''), ('PROTECTED_MERGE_ENABLED', 'TRUE')]:
            old = self.api.env[key]; self.api.env[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.merge(admission)
            self.api.env[key] = old
        self.assertEqual(self.writer.writes, [])

    def test_source_or_owner_changes_during_evidence_or_protection_reads_block_write(self):
        admission = self.prepared()
        for kind in ['head', 'node', 'base', 'main', 'owner', 'attempt']:
            with self.subTest(kind=kind):
                self.api = Metadata(); self.writer = Writer(self.api); admission = self.prepared()
                original = self.app.get
                def read(path):
                    value = original(path)
                    if path == 'branches/main/protection':
                        if kind == 'head': self.api.pr['head']['sha'] = 'e'*40
                        if kind == 'node': self.api.pr['node_id'] = 'PR_other'
                        if kind == 'base': self.api.pr['base']['ref'] = 'release'
                        if kind == 'main': self.api.main = 'e'*40
                        if kind == 'owner': self.api.run['triggering_actor']['id'] = 666
                        if kind == 'attempt': self.api.run['run_attempt'] = 2
                    return value
                with mock.patch.object(self.app, 'get', side_effect=read):
                    with self.assertRaises(ValueError): self.merge(admission)
                self.assertEqual(self.writer.writes, [])

    def test_head_change_while_downloading_evidence_prevents_privileged_reads(self):
        admission = self.prepared()
        def change(api, path):
            if path.endswith('/zip'): api.pr['head']['sha'] = 'e'*40
        self.api.before_get = change
        with self.assertRaises(ValueError): self.merge(admission)
        self.assertEqual(self.app.calls, []); self.assertEqual(self.writer.writes, [])

    def test_all_applicable_rules_pagination_exhaustion_refuses_without_write(self):
        admission = self.prepared()
        original = self.app.get
        def full(path):
            if path.startswith('rules/branches/main?'): return self.app.active * 100
            return original(path)
        with mock.patch.object(self.app, 'get', side_effect=full), self.assertRaises(ValueError):
            self.merge(admission)
        self.assertEqual(self.writer.writes, [])

    def test_uncertain_write_reconciles_read_only_and_never_retries(self):
        admission = self.prepared()
        def uncertain(number, sha):
            self.writer.writes.append((number, sha))
            self.api.pr.update(state='closed', merged=True, merge_commit_sha=MERGED)
            raise urllib.error.URLError('PRIVATE network details')
        with mock.patch.object(self.writer, 'merge', side_effect=uncertain): result = self.merge(admission)
        self.assertEqual(result, {'result': 'merged', 'merge_commit_sha': MERGED})
        self.assertEqual(self.writer.writes, [(7, HEAD)])

    def test_exhausted_prewrite_transport_budget_has_fresh_readonly_reconciliation(self):
        # Reusing the preflight Transport loses confirmation after a real PUT
        # when either its elapsed-time or request budget is exhausted.
        for budget in ('time', 'requests'):
            for response in ('normal', 'malformed', 'uncertain'):
                with self.subTest(budget=budget, response=response):
                    self.setUp(); admission = self.prepared()
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
                            traffic.append((method, path, request.get_header('Authorization'), timeout))
                            if method == 'PUT':
                                case.assertEqual(path, 'pulls/7/merge')
                                case.assertEqual(json.loads(request.data), {'sha': HEAD, 'merge_method': 'merge'})
                                case.api.pr.update(state='closed', merged=True, merge_commit_sha=MERGED)
                                if response == 'uncertain': raise http.client.IncompleteRead(b'PRIVATE', 1)
                                return Response(b'{}' if response == 'malformed' else json.dumps({'sha': MERGED}).encode())
                            case.assertEqual(method, 'GET')
                            value = case.api.get(path, raw=path.endswith('/zip'))
                            return Response(value if type(value) is bytes else json.dumps(value).encode())

                    def opener(*handlers):
                        created.append((len(traffic), clock[0]))
                        return Opener()

                    original_context, contexts = self.p.context, [0]
                    def exhaust_last_context(api, event, env):
                        result = original_context(api, event, env)
                        contexts[0] += 1
                        if contexts[0] == 3:
                            if budget == 'requests':
                                while api.transport.requests < 160: api.get('')
                            else:
                                clock[0] = api.transport.deadline
                        return result

                    with mock.patch.object(self.p.common.time, 'monotonic', side_effect=lambda: clock[0]), \
                         mock.patch.object(self.p.urllib.request, 'build_opener', side_effect=opener), \
                         mock.patch.object(self.p, 'context', side_effect=exhaust_last_context), \
                         mock.patch('socket.create_connection', side_effect=AssertionError('socket connection attempted')):
                        api = self.p.MetadataClient('read-token')
                        merger = self.p.MergeClient('app-token')
                        result = self.p.merge_once(api, self.app, merger, self.api.event, self.api.env, admission)
                        with self.assertRaises(ValueError): api.get('')
                    self.assertEqual(contexts[0], 3)
                    writes = [row for row in traffic if row[0] == 'PUT']
                    self.assertEqual(len(writes), 1)
                    self.assertEqual(result, {'result': 'merged', 'merge_commit_sha': MERGED})
                    write_index = next(i for i, row in enumerate(traffic) if row[0] == 'PUT')
                    self.assertEqual([(row[0], row[1], row[2]) for row in traffic[write_index+1:]],
                                     [('GET', 'pulls/7', 'Bearer read-token'),
                                      ('GET', 'commits/'+MERGED, 'Bearer read-token')])
                    self.assertEqual(writes[0][2], 'Bearer app-token')
                    self.assertEqual(len(created), 3)
                    self.assertEqual(created[-1][0], write_index+1)
                    self.assertTrue(all(0 < row[3] <= 30 for row in traffic))

    def test_head_409_and_unresolved_uncertainty_do_not_retry_or_claim_success(self):
        for error in [urllib.error.HTTPError('private', 409, 'private', {}, None), urllib.error.URLError('private')]:
            self.api = Metadata(); self.writer = Writer(self.api); admission = self.prepared()
            self.writer.error = error
            result = self.merge(admission)
            self.assertEqual(result, {'result': 'unconfirmed', 'merge_commit_sha': ''})
            self.assertEqual(self.writer.writes, [(7, HEAD)])

    def test_actual_parent_or_pr_outcome_rejects_without_write_retry(self):
        for kind in ['parents', 'base_parent', 'head_parent', 'node']:
            self.api = Metadata(); self.writer = Writer(self.api); admission = self.prepared()
            if kind == 'parents': self.api.commit['parents'].pop()
            if kind == 'base_parent': self.api.commit['parents'][0]['sha'] = 'e'*40
            if kind == 'head_parent': self.api.commit['parents'][1]['sha'] = 'e'*40
            if kind == 'node':
                original = self.writer.merge
                def changed(number, sha):
                    reply = original(number, sha); self.api.pr['node_id'] = 'PR_other'; return reply
                self.writer.merge = changed
            with self.subTest(kind=kind):
                result = self.merge(admission)
                self.assertEqual(result['result'], 'unconfirmed')
                self.assertEqual(len(self.writer.writes), 1)

    def test_ambiguous_semantic_response_reconciles_actual_committed_outcome(self):
        for reply in [{'merged': False, 'sha': MERGED}, {'merged': True, 'sha': 'invalid'},
                      {}, {'sha': MERGED}, {'merged': True}, {'merged': 1, 'sha': MERGED}, []]:
            with self.subTest(reply=reply):
                self.api = Metadata(); self.writer = Writer(self.api); admission = self.prepared()
                self.writer.reply = reply
                self.assertEqual(self.merge(admission), {'result': 'merged', 'merge_commit_sha': MERGED})
                self.assertEqual(self.writer.writes, [(7, HEAD)])
                self.assertEqual(self.api.calls[-2:], ['pulls/7', 'commits/'+MERGED])

    def test_semantic_response_reconciliation_keeps_any_valid_returned_sha_binding(self):
        for merged in [True, False, None]:
            with self.subTest(merged=merged):
                self.api = Metadata(); self.writer = Writer(self.api); admission = self.prepared()
                self.writer.reply = {'merged': merged, 'sha': 'e'*40}
                self.assertEqual(self.merge(admission), {'result': 'unconfirmed', 'merge_commit_sha': ''})
                self.assertEqual(self.writer.writes, [(7, HEAD)])
                self.assertEqual(self.api.calls[-1], 'pulls/7')

    def test_genuinely_unresolved_semantic_response_is_reconciled_read_only(self):
        admission = self.prepared()
        def unresolved(number, sha):
            self.writer.writes.append((number, sha))
            return {'merged': True, 'sha': 'invalid'}
        self.writer.merge = unresolved
        self.assertEqual(self.merge(admission), {'result': 'unconfirmed', 'merge_commit_sha': ''})
        self.assertEqual(self.writer.writes, [(7, HEAD)])
        self.assertEqual(self.api.calls[-1], 'pulls/7')

    def test_outcome_http_protocol_errors_report_unconfirmed_after_normal_and_uncertain_writes(self):
        for response in ['normal', 'uncertain']:
            for endpoint in ['pulls/7', 'commits/'+MERGED]:
                with self.subTest(response=response, endpoint=endpoint):
                    self.api = Metadata(); self.writer = Writer(self.api); admission = self.prepared()
                    if response == 'uncertain':
                        original = self.writer.merge
                        def uncertain(number, sha):
                            original(number, sha)
                            raise urllib.error.URLError('PRIVATE response lost')
                        self.writer.merge = uncertain
                    def protocol_fault(api, path):
                        if self.writer.writes and path == endpoint:
                            raise http.client.IncompleteRead(b'PRIVATE', 1)
                    self.api.before_get = protocol_fault
                    code, output, stdout, stderr, _ = self.cli('merge-once', admission,
                                                                          {'PROTECTED_MERGE_TOKEN': 'app-token'})
                    self.assertEqual(code, 1)
                    self.assertIn('result=unconfirmed\n', output)
                    self.assertIn('merge_commit_sha=\n', output)
                    self.assertNotIn('PRIVATE', stdout+stderr+output)
                    self.assertEqual(self.writer.writes, [(7, HEAD)])

    def test_cli_requires_separate_credentials_and_sanitizes_all_failures(self):
        admission = self.prepared()
        code, _, out, err, constructed = self.cli('merge-once', admission)
        self.assertEqual(code, 1); self.assertEqual(constructed, 0)
        self.assertNotIn('PRIVATE', out+err); self.assertEqual(self.writer.writes, [])
        code, output, out, err, constructed = self.cli('merge-once', admission, {'PROTECTED_MERGE_TOKEN': 'app-token'})
        self.assertEqual(code, 0); self.assertIn('merge_commit_sha='+MERGED, output)
        self.assertEqual(constructed, 1); self.assertNotIn('PRIVATE', out+err)

    def test_well_bound_policy_blocks_and_medium_is_informational(self):
        admission = self.prepared('verify')
        original = self.evidence(admission)
        for kind in ['high-vulnerability', 'critical-vulnerability', 'high-license', 'unknown-license',
                     'controls', 'processing', 'medium']:
            with self.subTest(kind=kind):
                files = copy.deepcopy(original)
                summary = json.loads(files['summary.json'])
                row = summary['projects'][0]
                if kind in ('high-vulnerability', 'critical-vulnerability', 'medium'):
                    row['vulnerability_path_records'] = 1
                    row['nonblocking_vulnerability_records' if kind == 'medium' else 'blocking_vulnerability_records'] = 1
                    row['status'] = 'scan_complete_with_findings'
                if kind in ('high-license', 'unknown-license'):
                    row['license_path_records'] = row['blocking_license_records'] = 1
                    row['status'] = 'scan_complete_with_findings'
                if kind == 'controls': summary['license_controls'] = self.p.common.policy.control_status(False)
                if kind == 'processing': summary['processing_status'] = 'incomplete'
                summary['policy'] = self.p.common.policy.policy_result(summary['projects'], controls_verified=kind != 'controls')
                files['summary.json'] = json.dumps(summary).encode()
                files['publication.json'] = self.p.common.canonical(self.p.make_evidence(
                    admission, files['summary.json'], files['evidence.tar.gz.age'], b'scanner'))
                self.install_files(files)
                if kind == 'medium':
                    self.assertEqual(self.p.verify(self.api, self.api.event, self.api.env, admission)['verified'], 'true')
                else:
                    with self.assertRaises(ValueError): self.p.verify(self.api, self.api.event, self.api.env, admission)
                self.assertEqual(self.writer.writes, [])

    def test_current_merge_job_prior_steps_and_active_step_are_mandatory(self):
        admission = self.prepared()
        pristine = copy.deepcopy(self.api.jobs)
        for kind in ['missing_job', 'completed', 'prior_failed', 'prior_missing', 'active_missing',
                     'active_queued', 'active_completed', 'extra_skipped', 'duplicate_number', 'duplicate_active']:
            with self.subTest(kind=kind):
                self.api.jobs = copy.deepcopy(pristine)
                job = self.api.jobs[-1]
                if kind == 'missing_job': self.api.jobs.pop()
                if kind == 'completed': job.update(status='completed', conclusion='success')
                if kind == 'prior_failed': job['steps'][2]['conclusion'] = 'failure'
                if kind == 'prior_missing': job['steps'].pop(1)
                if kind == 'active_missing': job['steps'].pop()
                if kind == 'active_queued': job['steps'][-1]['status'] = 'queued'
                if kind == 'active_completed': job['steps'][-1].update(status='completed', conclusion='success')
                if kind == 'extra_skipped': job['steps'].append({'name': 'extra', 'number': 8, 'conclusion': 'skipped'})
                if kind == 'duplicate_number': job['steps'][2]['number'] = 1
                if kind == 'duplicate_active': job['steps'].append({**copy.deepcopy(job['steps'][-1]), 'number': 99})
                with self.assertRaises(ValueError): self.merge(admission)
                self.assertEqual(self.app.calls, []); self.assertEqual(self.writer.writes, [])

    def test_final_job_is_rechecked_after_privileged_protection_reads(self):
        admission = self.prepared()
        original = self.app.get
        def cancel(path):
            value = original(path)
            if path == 'branches/main/protection': self.api.jobs[-1]['status'] = 'completed'
            return value
        with mock.patch.object(self.app, 'get', side_effect=cancel), self.assertRaises(ValueError):
            self.merge(admission)
        self.assertEqual(self.writer.writes, [])

    def test_protection_numeric_boolean_coercions_never_count_as_strict_schemas(self):
        for kind in ['rule', 'active']:
            self.app = AppReads()
            target = self.app.rule['rules'][0] if kind == 'rule' else self.app.active[0]
            target['parameters']['update_allows_fetch_and_merge'] = 0
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.p.validate_protections(self.app, self.api.env)

    def test_http_incomplete_write_response_is_reconciled_without_retry(self):
        admission = self.prepared()
        def incomplete(number, sha):
            self.writer.writes.append((number, sha))
            self.api.pr.update(state='closed', merged=True, merge_commit_sha=MERGED)
            raise http.client.IncompleteRead(b'private', 1)
        self.writer.merge = incomplete
        self.assertEqual(self.merge(admission)['result'], 'merged')
        self.assertEqual(self.writer.writes, [(7, HEAD)])

    def test_expected_base_has_no_atomic_api_predicate_and_postcheck_detects_trusted_writer_race(self):
        admission = self.prepared()
        original = self.writer.merge
        def race(number, sha):
            self.api.pr['base']['sha'] = 'e'*40
            self.api.commit['parents'][0]['sha'] = 'e'*40
            return original(number, sha)
        self.writer.merge = race
        self.assertEqual(self.merge(admission), {'result': 'unconfirmed', 'merge_commit_sha': ''})
        self.assertEqual(self.writer.writes, [(7, HEAD)])

    def test_make_evidence_cli_uses_current_source_and_exclusive_bounded_files(self):
        admission = self.prepared('scan')
        files = self.evidence(admission)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'public').mkdir(); (root/'tools').mkdir()
            (root/'tools/snyk').write_bytes(b'scanner')
            for name in ['summary.json', 'evidence.tar.gz.age']: (root/'public'/name).write_bytes(files[name])
            code, _, _, _, count = self.cli('make-evidence', admission, {'TRIAL_ROOT': str(root)})
            self.assertEqual(code, 0); self.assertEqual(count, 0)
            publication = json.loads((root/'public/publication.json').read_bytes())
            self.assertEqual(publication['admission'], admission)
            self.assertEqual(self.cli('make-evidence', admission, {'TRIAL_ROOT': str(root)})[0], 1)
            (root/'public/publication.json').unlink()
            (root/'public/summary.json').unlink()
            (root/'public/summary.json').symlink_to(root/'tools/snyk')
            self.assertEqual(self.cli('make-evidence', admission, {'TRIAL_ROOT': str(root)})[0], 1)
            self.assertFalse((root/'public/publication.json').exists())

    def test_cli_admit_and_preview_never_instantiate_privileged_clients(self):
        self.api = Metadata('verify')
        code, output, _, _, count = self.cli('admit')
        self.assertEqual(code, 0); self.assertEqual(count, 0)
        self.assertIn('admission_json=', output)
        admission = json.loads(output.split('admission_json=', 1)[1].splitlines()[0])
        self.evidence(admission); self.api.env['GITHUB_JOB'] = 'verify'
        for secret in [{'PROTECTED_MERGE_TOKEN': 'wrong'}, {'SNYK_TOKEN': 'private'},
                       {'PROTECTED_MERGE_APP_PRIVATE_KEY': 'private'}]:
            result = self.cli('verify', admission, secret)
            self.assertEqual(result[0], 1); self.assertEqual(result[-1], 0)
            self.assertNotIn('private', result[2]+result[3])
        self.assertEqual(self.writer.writes, [])

    def test_real_cli_and_http_clients_separate_tokens_and_issue_only_one_conditional_put(self):
        admission = self.prepared()
        requests = []
        def send(request, **kwargs):
            requests.append(request)
            parts = urllib.parse.urlsplit(request.full_url)
            self.assertEqual(parts.scheme, 'https'); self.assertEqual(parts.netloc, 'api.github.com')
            root = '/repos/lorconksu/veyport'
            if parts.path == root:
                path = ''
            elif parts.path == root+'/':
                raise urllib.error.HTTPError(request.full_url, 404, 'Not Found', {}, None)
            elif parts.path.startswith(root+'/'):
                path = parts.path[len(root)+1:]
            else:
                self.assertTrue(parts.path.startswith('/apps/') or parts.path == '/installation/repositories')
                path = parts.path[1:]
            if parts.query: path += '?'+parts.query
            if request.get_method() == 'PUT':
                self.assertEqual(request.get_header('Authorization'), 'Bearer app-token')
                self.assertEqual(path, 'pulls/7/merge')
                self.assertEqual(json.loads(request.data), {'sha': HEAD, 'merge_method': 'merge'})
                result = self.writer.merge(7, HEAD)
            elif request.get_header('Authorization') == 'Bearer app-token':
                self.assertIn(path.split('?')[0], ['apps/veyport-merger', 'installation/repositories',
                              'branches/main/protection', 'rulesets', 'rulesets/777', 'rules/branches/main'])
                result = self.app.get(path)
            else:
                self.assertEqual(request.get_header('Authorization'), 'Bearer read-token')
                result = self.api.get(path, raw=path.endswith('/zip'))
            return Response(result if type(result) is bytes else json.dumps(result).encode())
        with tempfile.TemporaryDirectory() as folder:
            event, output = Path(folder)/'event', Path(folder)/'output'
            event.write_text(json.dumps(self.api.event))
            env = {**self.api.env, 'GITHUB_EVENT_PATH': str(event), 'GITHUB_OUTPUT': str(output),
                   'ADMISSION_JSON': json.dumps(admission), 'GITHUB_TOKEN': 'read-token',
                   'PROTECTED_MERGE_TOKEN': 'app-token'}
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(self.p.urllib.request, 'build_opener', return_value=type('OfflineOpener', (), {'open': staticmethod(send)})()), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self.p.main(['merge-once']), 0)
            self.assertIn('merge_commit_sha='+MERGED, output.read_text())
        self.assertEqual([r.get_method() for r in requests].count('PUT'), 1)
        self.assertTrue(all(r.get_method() in ('GET', 'PUT') for r in requests))
        self.assertEqual(self.writer.writes, [(7, HEAD)])

    def test_actual_cli_rejects_bad_mode_and_untrusted_import_search_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ['snyk_ci_common', 'snyk_pr_policy', 'snyk_policy']:
                (root/(name+'.py')).write_text('raise RuntimeError("ATTACKER_IMPORT")\n')
            result = subprocess.run([sys.executable, '-I', '-B', str(PATH), 'not-a-mode'], cwd=root,
                                    env={'PYTHONPATH': str(root)}, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2); self.assertNotIn('ATTACKER_IMPORT', result.stderr)
            self.assertNotIn('Traceback', result.stderr)


class Response:
    def __init__(self, data, status=200): self.data, self.status = data, status
    def read(self, size): return self.data[:size]
    def __enter__(self): return self
    def __exit__(self, *args): pass


class HTTPBoundaryTests(unittest.TestCase):
    setUpClass = classmethod(ProtectedMergeTests.setUpClass.__func__)
    def test_merge_client_has_one_fixed_put_no_redirect_or_retry(self):
        client = self.p.MergeClient('secret-app-token')
        captured = []
        def send(request, **kwargs):
            captured.append(request)
            return Response(b'{"sha":"'+MERGED.encode()+b'","merged":true,"message":"ok"}')
        with mock.patch.object(client.opener, 'open', side_effect=send):
            self.assertTrue(client.merge(7, HEAD)['merged'])
            with self.assertRaises(ValueError): client.merge(7, HEAD)
        self.assertEqual(len(captured), 1)
        request = captured[0]
        self.assertEqual(request.full_url, 'https://api.github.com/repos/lorconksu/veyport/pulls/7/merge')
        self.assertEqual(request.method, 'PUT')
        self.assertEqual(json.loads(request.data), {'sha': HEAD, 'merge_method': 'merge'})
        self.assertIsNone(self.p.common.NoRedirect().redirect_request(None, None, None, None, None, None))

    def test_merge_http_errors_bad_responses_and_tokens_are_bounded(self):
        for token in ['', 'has space', 'x'*16385, None]:
            with self.subTest(token=type(token)), self.assertRaises(ValueError): self.p.MergeClient(token)
        for payload in [b'{"merged":true,"merged":false}', b'[]', b'NaN', b'x'*(1048576+1)]:
            client = self.p.MergeClient('token')
            with mock.patch.object(client.opener, 'open', return_value=Response(payload)):
                with self.assertRaises(ValueError): client.merge(7, HEAD)
        for status in [302, 403, 409, 500]:
            client = self.p.MergeClient('token')
            error = urllib.error.HTTPError('private', status, 'private', {'Location': 'https://evil.invalid'}, None)
            with mock.patch.object(client.opener, 'open', side_effect=error) as send:
                with self.assertRaises(urllib.error.HTTPError): client.merge(7, HEAD)
                self.assertEqual(send.call_count, 1)
                with self.assertRaises(ValueError): client.merge(7, HEAD)

    def test_read_clients_reject_all_mutation_arbitrary_paths_and_hosts(self):
        client = self.p.AppReadClient('token')
        for path in ['https://evil.invalid', '../app', 'apps/../private', 'pulls/7/merge',
                     'branches/main/protection?token=secret', 'installation/repositories?page=0',
                     'rulesets/777#fragment', 'rulesets/777?includes_parents=false']:
            with self.subTest(path=path), self.assertRaises(ValueError): client.get(path)
        ordinary = self.p.MetadataClient('token')
        with mock.patch.object(ordinary.transport.opener, 'open', return_value=Response(b'{}')) as send:
            ordinary.get('actions/workflows/protected-merge.yml')
            ordinary.get('git/ref/heads/main')
            ordinary.get('commits/'+MERGED)
            self.assertEqual(send.call_count, 3)
            for method in ['PUT', 'POST', 'PATCH', 'DELETE']:
                with self.assertRaises(ValueError): ordinary.transport.request(method, 'pulls/7/merge')

    def test_app_read_budget_deadline_overflow_and_redirect_all_fail_closed(self):
        for failure in ['budget', 'deadline', 'overflow', 'redirect', 'status']:
            client = self.p.AppReadClient('token')
            with self.subTest(failure=failure):
                if failure == 'budget': client.requests = 80
                if failure == 'deadline': client.deadline = 0
                response = Response(b'x'*(1048576+1) if failure == 'overflow' else b'{}',
                                    status=403 if failure == 'status' else 200)
                error = urllib.error.HTTPError('private', 302, 'private', {'Location': 'https://evil.invalid'}, None)
                with mock.patch.object(client.opener, 'open', side_effect=error if failure == 'redirect' else None,
                                       return_value=response) as send:
                    with self.assertRaises((ValueError, urllib.error.HTTPError)): client.get('branches/main/protection')
                    self.assertEqual(send.call_count, 0 if failure in ('budget', 'deadline') else 1)


if __name__ == '__main__': unittest.main()

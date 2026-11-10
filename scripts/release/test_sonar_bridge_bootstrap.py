"""Self-contained bootstrap CI coverage of the trusted Sonar credential boundary."""
import copy
import base64
import io
import os
from pathlib import Path
import stat
import tempfile
import urllib.error
import warnings
import unittest
from unittest.mock import patch
import zipfile

import sonar_bridge as bridge

# Inert candidate-data fixture matching the immutable technical profile accepted
# by the bridge. It does not change current-main sonar-project.properties or
# patch the helper's pin, and grants no source-coverage approval.
PINNED_PROFILE = (
    b'sonar.organization=lorconksu\n'
    b'sonar.projectKey=lorconksu_veyport\n'
    b'sonar.projectName=Veyport\n'
    b'\n'
    b'sonar.sources=hub,agent,cli,web/src,proto\n'
    b'sonar.tests=hub,agent,cli,web/src,proto\n'
    b'# The TLS receipt fixture imports testing/httptest and is used only by *_test.go;\n'
    b'# no production command depends on this dedicated test-support package.\n'
    b'sonar.test.inclusions=**/*_test.go,**/__tests__/**,**/test/**,hub/internal/testaudit/**\n'
    b'sonar.exclusions=**/vendor/**,**/*.pb.go,**/node_modules/**,**/dist/**,**/__tests__/**,**/test/setup.ts\n'
    b'\n'
    b'sonar.go.coverage.reportPaths=coverage-hub.out,coverage-hub-cmd.out,coverage-agent.out,coverage-cli.out,coverage-proto.out,coverage-integration.out,coverage-agent-integration.out\n'
    b'\n'
    b'# Handwritten application code remains measurable, including bootstrap and error paths.\n'
    b'# Retain only embedded assets, test support, SQL migrations, declaration-only types,\n'
    b'# styles and the shell installer (not represented by Go/JS coverage imports).\n'
    b'sonar.coverage.exclusions=hub/embed.go,**/integration/testhelpers.go,**/integration/*_test.go,hub/internal/migrate/migrations/**,web/src/types/api.ts,web/src/index.css,web/src/styles/**,hub/static/install.sh\n'
    b'sonar.cpd.exclusions=hub/internal/server/handlers_audit.go,web/src/pages/settings-notifications-tab.tsx,hub/internal/store/audit.go,hub/internal/store/servers.go\n'
    b'sonar.issue.ignore.multicriteria=e1\n'
    b'sonar.issue.ignore.multicriteria.e1.ruleKey=go:S4830\n'
    b'sonar.issue.ignore.multicriteria.e1.resourceKey=agent/internal/client/client.go\n'
    b'\n'
    b'sonar.javascript.lcov.reportPaths=web/coverage/lcov.info\n'
)

SOURCE = 'a' * 40
CONTROL = 'b' * 40
MERGE = 'd' * 40
REPO = {'full_name': bridge.REPOSITORY, 'private': False}


def source_run(path='.github/workflows/ci.yml', event='pull_request'):
    value = {'id': 123, 'run_attempt': 2, 'head_sha': SOURCE, 'head_branch': 'feat/test', 'path': path,
             'event': event, 'repository': REPO, 'head_repository': REPO, 'status': 'in_progress', 'conclusion': None}
    if path != '.github/workflows/ci.yml':
        value['referenced_workflows'] = [{'path': bridge.REPOSITORY + '/.github/workflows/ci.yml@' + SOURCE,
                                         'sha': SOURCE, 'ref': 'refs/heads/feat/test'}]
    return value


def producer_run():
    return {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL, 'head_branch': 'main', 'path': bridge.WORKFLOW,
            'event': 'workflow_run', 'repository': REPO, 'head_repository': REPO, 'status': 'completed', 'conclusion': 'success'}


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as zipped:
        for name, value in files.items():
            zipped.writestr(name, value)
    return output.getvalue()


def verification_fixture(run, record):
    """Already-verified CLI output fixture; never used as a signature verifier."""
    revision = MERGE if run['event'] == 'pull_request' else SOURCE
    ref = ('refs/pull/115/merge' if run['event'] == 'pull_request' else
           'refs/heads/main' if run['path'].endswith('/ci.yml') else run['referenced_workflows'][0]['ref'])
    signer = f'https://github.com/{bridge.REPOSITORY}/.github/workflows/ci.yml@{ref}'
    certificate = {'issuer': 'https://token.actions.githubusercontent.com',
                   'sourceRepositoryURI': 'https://github.com/' + bridge.REPOSITORY,
                   'sourceRepositoryIdentifier': bridge.REPOSITORY_ID, 'sourceRepositoryVisibilityAtSigning': 'public',
                   'runnerEnvironment': 'github-hosted', 'buildTrigger': run['event'],
                   'runInvocationURI': f"https://github.com/{bridge.REPOSITORY}/actions/runs/123/attempts/2",
                   'buildConfigURI': f"https://github.com/{bridge.REPOSITORY}/{run['path']}@{ref}",
                   'buildConfigDigest': revision, 'buildSignerDigest': revision, 'sourceRepositoryDigest': revision,
                   'sourceRepositoryRef': ref, 'buildSignerURI': signer,
                   'subjectAlternativeName': signer}
    return [{'verificationResult': {'signature': {'certificate': certificate},
              'verifiedTimestamps': [{'type': 'Tlog', 'timestamp': '2026-11-10T01:10:00Z'}],
              'statement': {'predicateType': 'https://slsa.dev/provenance/v1',
                            'subject': [{'name': record['name'] + '.zip', 'digest': {'sha256': record['digest'][7:]}}],
                            'predicate': {'non_authoritative_candidate_claim': True}}}}]



def producer_bytes(path):
    return ('reviewed producer source: ' + path + '\n').encode()


def producer_blob(path):
    raw = producer_bytes(path)
    return bridge.hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\x00' + raw, usedforsecurity=False).hexdigest()


def producer_registry():
    return {'schema': 2, 'authority': 'approved-workflow-and-producer-source-bytes/v2',
            'workflow_sha256': {v: bridge.sha(b'reviewed control bytes') for v in bridge.SOURCE_WORKFLOWS},
            'producer_sha256': {v: bridge.sha(producer_bytes(v)) for v in bridge.PRODUCER_CONTROLS}}


def producer_controls_fixture():
    return {'authority': 'reviewed-committed-orchestration-source-only/v1', 'revision': SOURCE,
            'tree': 'f' * 40, 'registry_sha256': bridge.sha(bridge.canonical(producer_registry())),
            'controls': {path: {'git_blob': producer_blob(path), 'mode': '100644',
                               'sha256': bridge.sha(producer_bytes(path))} for path in bridge.PRODUCER_CONTROLS}}


def public_coverage_fixture(api):
    return [{'group': group, 'artifact_id': api.artifacts[i]['id'], 'digest': api.artifacts[i]['digest'], 'job_id': 10 + i,
             'provenance': {'step_number': 4, 'step_log_sha256': 'e' * 64, 'producer_controls': producer_controls_fixture(),
                 'certificate': {'run_uri': f'https://github.com/{bridge.REPOSITORY}/actions/runs/123/attempts/2'}}}
            for i, group in enumerate(bridge.COVERAGE)]


class FakeAPI:
    def __init__(self, run=None):
        self.run = run or source_run()
        self.producer = producer_run()
        self.pr = {'number': 115, 'state': 'open', 'merged': False, 'merged_at': None,
                   'head': {'sha': SOURCE, 'ref': 'feat/test', 'repo': REPO}, 'base': {'ref': 'main', 'repo': REPO}}
        self.calls = []
        self.artifacts = []
        self.payloads = {}
        prefix = '' if self.run['path'].endswith('/ci.yml') else 'required-ci / '
        self.jobs = [{'id': 10 + i, 'name': prefix + name, 'status': 'completed', 'conclusion': 'success',
                      'head_sha': SOURCE, 'run_id': 123, 'run_attempt': 2, 'started_at': '2026-11-10T01:00:00Z',
                      'completed_at': '2026-11-10T01:10:00Z'} for i, name in enumerate(('test', 'integration'))]
        for i, group in enumerate(bridge.COVERAGE):
            self.jobs[i]['steps'] = [{'name': bridge.UPLOAD_STEPS[group], 'number': 4,
                                     'status': 'completed', 'conclusion': 'success'}]
        self.jobs.append({'id': 12, 'name': prefix + 'sonar-coverage-attestation', 'status': 'completed',
                          'conclusion': 'success', 'head_sha': SOURCE, 'run_id': 123, 'run_attempt': 2})
        self.verification_mutator = None
        for i, (group, names) in enumerate(bridge.COVERAGE.items()):
            prefix = 'coverage-v1-' if group == 'unit' else 'coverage-integration-v1-'
            self.add_artifact(100 + i, prefix + '123-2', 123, {name: 'coverage input\n' for name in names})

    def add_artifact(self, identifier, name, rid, files):
        raw = archive(files)
        record = {'id': identifier, 'name': name, 'expired': False, 'size_in_bytes': len(raw), 'digest': 'sha256:' + bridge.sha(raw),
                  'workflow_run': {'id': rid, 'head_sha': SOURCE if rid == 123 else CONTROL},
                  'created_at': '2026-11-10T01:02:00Z', 'updated_at': '2026-11-10T01:03:00Z'}
        self.artifacts.append(record)
        self.payloads[identifier] = raw
        return record

    def verify_coverage(self, raw, record, run):
        result = verification_fixture(run, record)
        if self.verification_mutator:
            self.verification_mutator(result)
        return result

    def get(self, path, raw=False, maximum=None):
        self.calls.append(path)
        if path in ('actions/runs/123', 'actions/runs/123/attempts/2'):
            return copy.deepcopy(self.run)
        if path in ('actions/runs/456', 'actions/runs/456/attempts/1'):
            return copy.deepcopy(self.producer)
        if path.startswith('actions/runs/123/attempts/2/jobs?'):
            return {'total_count': len(self.jobs), 'jobs': copy.deepcopy(self.jobs)}
        if path.startswith('actions/runs/456/attempts/1/jobs?'):
            return {'total_count': 1, 'jobs': [{'id': 88, 'name': 'scan', 'head_sha': CONTROL, 'status': 'completed', 'conclusion': 'success', 'run_id': 456, 'run_attempt': 1, 'steps': [{'name': 'Submit isolated Sonar analysis', 'status': 'completed', 'conclusion': 'success'}]}]}
        if path.startswith('actions/runs/123/artifacts?'):
            rows = [v for v in self.artifacts if v['workflow_run']['id'] == 123]
            return {'total_count': len(rows), 'artifacts': copy.deepcopy(rows)}
        if path.startswith('actions/artifacts?name='):
            name = path.split('name=', 1)[1].split('&', 1)[0]
            rows = [v for v in self.artifacts if v['name'] == name]
            return {'total_count': len(rows), 'artifacts': copy.deepcopy(rows)}
        if path.startswith('actions/artifacts/'):
            parts = path.split('/')
            return self.payloads[int(parts[2])] if raw else copy.deepcopy(next(v for v in self.artifacts if v['id'] == int(parts[2])))
        if path.startswith('pulls?'):
            return [copy.deepcopy(self.pr)]
        if path == 'pulls/115':
            return copy.deepcopy(self.pr)
        if path == 'commits/main' or path.startswith('commits/refs%2Ftags%2F'):
            return {'sha': SOURCE}
        if path.startswith('compare/'):
            return {'status': 'ahead', 'merge_base_commit': {'sha': path.removeprefix('compare/').split('...')[0]}}
        if path.startswith('git/commits/'):
            revision = path.rsplit('/', 1)[1]
            return {'sha': revision, 'tree': {'sha': 'f' * 40}, 'parents': [{'sha': CONTROL}, {'sha': SOURCE}] if revision == MERGE else [{'sha': CONTROL}]}
        if path.startswith('actions/jobs/') and '/steps/' in path:
            job_id = int(path.split('/')[2])
            index = job_id - 10
            record = self.artifacts[index]
            identifier = getattr(self, 'step_ids', {}).get(job_id, record['id'])
            return (f"2026-11-10T01:03:00Z SHA256 digest of uploaded artifact is {record['digest'][7:]}\n"
                    f"2026-11-10T01:03:00Z Artifact {record['name']} has been successfully uploaded! "
                    f"Final size is {record['size_in_bytes']} bytes. Artifact ID is {identifier}\n").encode()
        if path == 'git/trees/' + 'f' * 40 + '?recursive=1':
            parents = sorted({path.rsplit('/', index)[0] for path in bridge.PRODUCER_CONTROLS
                              for index in range(1, path.count('/') + 1)})
            return {'sha': 'f' * 40, 'truncated': False, 'tree':
                    [{'path': path, 'type': 'tree', 'mode': '040000', 'sha': 'e' * 40} for path in parents]
                    + [{'path': path, 'type': 'blob', 'mode': '100644', 'sha': producer_blob(path),
                        'size': len(producer_bytes(path))} for path in bridge.PRODUCER_CONTROLS]}
        if path.startswith('git/blobs/'):
            name = next(v for v in bridge.PRODUCER_CONTROLS if producer_blob(v) == path.rsplit('/', 1)[1])
            raw = producer_bytes(name)
            return {'sha': producer_blob(name), 'encoding': 'base64', 'size': len(raw),
                    'content': base64.b64encode(raw).decode()}
        if path.startswith('contents/'):
            name = path.removeprefix('contents/').split('?')[0]
            raw = b'reviewed control bytes'
            if name == bridge.APPROVALS:
                raw = bridge.canonical(producer_registry())
            return {'type': 'file', 'path': name, 'encoding': 'base64', 'size': len(raw), 'content': base64.b64encode(raw).decode()}
        raise AssertionError(path)


def producer_env(root):
    return {'GITHUB_EVENT_NAME': 'workflow_run', 'GITHUB_REPOSITORY': bridge.REPOSITORY, 'GITHUB_REF': 'refs/heads/main',
            'GITHUB_SHA': CONTROL, 'GITHUB_WORKFLOW_REF': bridge.REPOSITORY + '/' + bridge.WORKFLOW + '@refs/heads/main',
            'GITHUB_RUN_ID': '456', 'GITHUB_RUN_ATTEMPT': '1', 'SONAR_CREDENTIAL_MODE': 'bridge',
            'SONAR_BRIDGE_TOOLING_REVISION': CONTROL, 'RUNNER_TEMP': str(root)}


class SonarBridgeTests(unittest.TestCase):
    def test_other_job_upload_in_same_run_and_time_window_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI()
            # Expected test uploader did not create artifact 100; another job
            # uploaded it during the same successful test job's time window.
            api.step_ids = {10: 999, 11: 101}
            with patch.dict(os.environ, producer_env(directory), clear=True), self.assertRaises(ValueError):
                bridge.intake(api, {'action': 'in_progress', 'repository': REPO,
                                   'workflow_run': copy.deepcopy(api.run)}, Path(directory) / 'intake', timeout=1)

    def test_coverage_signature_rejects_every_certificate_identity_swap(self):
        mutations = {'issuer': 'https://attacker.invalid', 'sourceRepositoryURI': 'https://github.com/attacker/fork',
                     'sourceRepositoryIdentifier': '99', 'sourceRepositoryVisibilityAtSigning': 'private',
                     'runnerEnvironment': 'self-hosted', 'runInvocationURI': 'https://github.com/' + bridge.REPOSITORY + '/actions/runs/123/attempts/1',
                     'buildTrigger': 'push', 'buildConfigDigest': SOURCE, 'buildSignerDigest': SOURCE,
                     'sourceRepositoryDigest': SOURCE, 'sourceRepositoryRef': 'refs/heads/main',
                     'buildConfigURI': 'https://github.com/attacker/ci.yml@refs/heads/main',
                     'buildSignerURI': 'https://github.com/attacker/ci.yml@refs/heads/main',
                     'subjectAlternativeName': {'type': 'URI', 'value': 'https://attacker.invalid'}}
        for field, value in mutations.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                api = FakeAPI()
                api.verification_mutator = lambda rows: rows[0]['verificationResult']['signature']['certificate'].update({field: value})
                with patch.dict(os.environ, producer_env(directory), clear=True), self.assertRaises(ValueError):
                    bridge.intake(api, {'action': 'in_progress', 'repository': REPO,
                                       'workflow_run': copy.deepcopy(api.run)}, Path(directory) / 'intake', timeout=1)

    def test_predicate_claims_do_not_replace_verified_certificate_or_subject(self):
        for attack in ('unsigned-predicate', 'subject-digest', 'subject-name', 'missing-timestamp', 'duplicate-signature'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                api = FakeAPI()
                def mutate(rows):
                    result = rows[0]['verificationResult']
                    if attack == 'unsigned-predicate':
                        result['statement']['predicate'] = {'certificate': copy.deepcopy(result['signature']['certificate'])}
                        result['signature']['certificate']['issuer'] = 'https://attacker.invalid'
                    elif attack == 'subject-digest':
                        result['statement']['subject'][0]['digest']['sha256'] = '0' * 64
                    elif attack == 'subject-name':
                        result['statement']['subject'][0]['name'] = 'different.zip'
                    elif attack == 'missing-timestamp':
                        result['verifiedTimestamps'] = []
                    else:
                        rows.append(copy.deepcopy(rows[0]))
                api.verification_mutator = mutate
                with patch.dict(os.environ, producer_env(directory), clear=True), self.assertRaises(ValueError):
                    bridge.intake(api, {'action': 'in_progress', 'repository': REPO,
                                       'workflow_run': copy.deepcopy(api.run)}, Path(directory) / 'intake', timeout=1)

    def test_executed_merge_workflow_requires_independently_approved_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI()
            original = api.get
            def changed(path, **kwargs):
                value = original(path, **kwargs)
                if path == 'contents/.github/workflows/ci.yml?ref=' + MERGE:
                    raw = b'candidate added a fabricated coverage upload job'
                    value.update(size=len(raw), content=base64.b64encode(raw).decode())
                return value
            api.get = changed
            with patch.dict(os.environ, producer_env(directory), clear=True), self.assertRaises(ValueError):
                bridge.intake(api, {'action': 'in_progress', 'repository': REPO,
                                   'workflow_run': copy.deepcopy(api.run)}, Path(directory) / 'intake', timeout=1)

    def test_reusable_release_and_staging_signatures_bind_both_workflows(self):
        for path in ('.github/workflows/release.yml', '.github/workflows/staging.yml'):
            api = FakeAPI(source_run(path, 'workflow_dispatch'))
            record = api.artifacts[0]
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, producer_env(directory), clear=True):
                proof = bridge.coverage_provenance(api, api.run, record, api.jobs[0], 'unit', api.payloads[record['id']])
                self.assertEqual(proof['certificate']['workflow_revision'], SOURCE)
                self.assertEqual(proof['certificate']['signer_revision'], SOURCE)
                self.assertIn('contents/' + path + '?ref=' + SOURCE, api.calls)
                self.assertIn('contents/.github/workflows/ci.yml?ref=' + SOURCE, api.calls)
                api.run['referenced_workflows'][0]['ref'] = 'refs/heads/other'
                wrong = verification_fixture(api.run, record)
                wrong[0]['verificationResult']['signature']['certificate']['sourceRepositoryRef'] = 'refs/heads/feat/test'
                with self.assertRaises(ValueError):
                    bridge.coverage_certificate(api, wrong, api.run, record)

    def test_expected_upload_step_and_digest_are_rechecked_before_scan(self):
        for attack in ('missing', 'skipped', 'duplicate', 'other-artifact', 'changed-digest'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                api = FakeAPI()
                root = Path(directory) / 'intake'
                with patch.dict(os.environ, producer_env(directory), clear=True):
                    plan = bridge.intake(api, {'action': 'in_progress', 'repository': REPO,
                                              'workflow_run': copy.deepcopy(api.run)}, root, timeout=1)
                    if attack == 'missing':
                        api.jobs[0]['steps'] = []
                    elif attack == 'skipped':
                        api.jobs[0]['steps'][0]['conclusion'] = 'skipped'
                    elif attack == 'duplicate':
                        api.jobs[0]['steps'].append(copy.deepcopy(api.jobs[0]['steps'][0]))
                    elif attack == 'other-artifact':
                        api.step_ids = {10: 999}
                    else:
                        (root / 'provenance/unit.zip').write_bytes(b'changed transport')
                    with self.assertRaises(ValueError):
                        bridge.validate_plan(api, plan, root)

    def test_missing_or_failed_signing_job_never_admits_scan(self):
        api = FakeAPI()
        api.jobs[-1]['status'] = 'queued'
        self.assertIsNone(bridge.coverage_ready(api, api.run))
        api.jobs[-1]['status'] = 'completed'
        for value in ('failure', 'cancelled', 'skipped'):
            api.jobs[-1]['conclusion'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                bridge.coverage_ready(api, api.run)
        api.jobs.pop()
        self.assertIsNone(bridge.coverage_ready(api, api.run))

    def test_unpinned_verifier_and_archive_are_refused_before_execution(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'RUNNER_TEMP': directory}, clear=True):
            executable = bridge.verifier_path()
            executable.parent.mkdir()
            executable.write_bytes(b'candidate-controlled verifier')
            with self.assertRaises(ValueError):
                bridge.official_coverage_verification(b'coverage', {'name': 'coverage'}, 'synthetic-read-token')
            executable.unlink()
            with patch.object(bridge.urllib.request, 'urlopen', return_value=io.BytesIO(b'changed release archive')):
                with self.assertRaises(ValueError):
                    bridge.install_verifier()
            self.assertFalse(executable.exists())

    def test_verifier_transport_requires_successful_bounded_json(self):
        import sys
        with tempfile.TemporaryDirectory() as directory:
            environment = {'PATH': '/usr/bin:/bin'}
            result = bridge.verifier_output([sys.executable, '-I', '-S', '-c', 'print("[1]")'], environment, directory)
            self.assertEqual(result, [1])
            for command in ('raise SystemExit(1)', 'print("invalid-json")', 'print("x" * (5 << 20))'):
                with self.subTest(command=command), self.assertRaises(ValueError):
                    bridge.verifier_output([sys.executable, '-I', '-S', '-c', command], environment, directory)

    def test_only_explicit_bridge_mode_is_accepted(self):
        self.assertEqual(bridge.mode('bridge'), 'bridge')
        for value in ('', 'legacy', 'auto', 'BRIDGE', None, False):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bridge.mode(value)

    def test_source_run_uses_head_sha_not_mutable_embedded_pr_metadata(self):
        api = FakeAPI()
        api.run['pull_requests'] = [{'head': {'sha': 'c' * 40}}]
        self.assertEqual(bridge.run_source(api, 123, 2, SOURCE)['head_sha'], SOURCE)
        self.assertIn('pullrequest.key=115', bridge.context(api, api.run)['args'])
        api.pr['head']['sha'] = 'c' * 40
        with self.assertRaises(ValueError):
            bridge.context(api, api.run)

    def test_source_and_producer_substitutions_reject(self):
        for key, value in [('head_sha', CONTROL), ('run_attempt', 1), ('path', bridge.WORKFLOW), ('event', 'workflow_run'),
                           ('status', 'queued'), ('head_repository', {'full_name': 'attacker/fork'})]:
            api = FakeAPI()
            api.run[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bridge.run_source(api, 123, 2, SOURCE)
        for key, value in [('head_sha', 'not-a-sha'), ('run_attempt', 2), ('path', '.github/workflows/ci.yml'),
                           ('head_branch', 'feature'), ('event', 'pull_request'), ('conclusion', 'failure')]:
            api = FakeAPI()
            api.producer[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bridge.producer(api, 456, 1, CONTROL, completed=True)

    def test_reusable_caller_job_and_reference_binding(self):
        for path in ('.github/workflows/release.yml', '.github/workflows/staging.yml'):
            api = FakeAPI(source_run(path, 'workflow_dispatch'))
            self.assertEqual(bridge.run_source(api, 123, 2, SOURCE)['path'], path)
            self.assertEqual(len(bridge.coverage_ready(api, api.run)), 2)
            api.run['referenced_workflows'][0]['sha'] = CONTROL
            with self.assertRaises(ValueError):
                bridge.run_source(api, 123, 2, SOURCE)
        api = FakeAPI()
        api.jobs[0]['name'] = 'other / test'
        self.assertIsNone(bridge.coverage_ready(api, api.run))
        api.jobs[0]['name'] = 'test'
        api.jobs[0]['run_attempt'] = 1
        with self.assertRaises(ValueError):
            bridge.coverage_ready(api, api.run)

    def test_source_main_supersession_and_feature_never_target_main(self):
        api = FakeAPI(source_run(event='push'))
        with self.assertRaises(ValueError):
            bridge.context(api, api.run)
        api.run['head_branch'] = 'main'
        self.assertEqual(bridge.context(api, api.run)['args'], '-Dsonar.branch.name=main')
        original = api.get
        api.get = lambda path, **kwargs: {'sha': CONTROL} if path == 'commits/main' else original(path, **kwargs)
        with self.assertRaises(ValueError):
            bridge.context(api, api.run)

    def test_stable_and_prototype_callers_keep_full_source_and_independent_gate(self):
        def sonar(endpoint, params):
            return {'components/show': {'component': {'key': 'lorconksu_veyport', 'visibility': 'public'}},
                    'settings/values': {'settings': [{'key': 'sonar.branch.longLivedBranches.regex', 'value': '(branch|release)-.*'}]},
                    'project_branches/list': {'branches': []}}[endpoint]
        for path in ('.github/workflows/release.yml', '.github/workflows/staging.yml'):
            api = FakeAPI(source_run(path, 'workflow_dispatch'))
            if path.endswith('/release.yml'):
                api.run['head_branch'] = 'v2.0.58'
                api.run['referenced_workflows'][0]['ref'] = 'refs/tags/v2.0.58'
            plan = bridge.context(api, api.run, sonar=sonar)
            self.assertEqual(plan['args'], '-Dsonar.branch.name=release-ssdf-candidate-' + SOURCE)
            self.assertEqual(plan['quality_gate_wait'], 'false')
            self.assertEqual(plan['gate_args'], '-Dsonar.branch.name=main' if path.endswith('/release.yml') else bridge.pr_context(api, SOURCE, 'feat/test'))
        api = FakeAPI(source_run('.github/workflows/staging.yml', 'workflow_dispatch'))
        api.run['head_branch'] = 'prototype-ssdf.1'
        api.run['referenced_workflows'][0]['ref'] = 'refs/tags/prototype-ssdf.1'
        self.assertIn('pullrequest.key=115', bridge.context(api, api.run, sonar=sonar)['gate_args'])
        api.run['referenced_workflows'][0]['ref'] = 'refs/tags/arbitrary'
        with self.assertRaises(ValueError):
            bridge.context(api, api.run, sonar=sonar)

    def test_current_attempt_intake_hashes_and_revalidates_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = FakeAPI()
            event = {'action': 'in_progress', 'repository': REPO, 'workflow_run': copy.deepcopy(api.run)}
            with patch.dict(os.environ, producer_env(root), clear=True):
                plan = bridge.intake(api, event, root / 'intake', timeout=1)
                self.assertEqual(plan['source']['run_attempt'], 2)
                self.assertEqual(len(plan['coverage']), 2)
                bridge.validate_plan(api, plan)
                wrong = copy.deepcopy(plan)
                wrong['coverage'][0]['digest'] = 'sha256:' + '0' * 64
                with self.assertRaises(ValueError):
                    bridge.validate_plan(api, wrong)
                api.run['run_attempt'] = 3
                with self.assertRaises(ValueError):
                    bridge.validate_plan(api, plan)

    def test_old_attempt_artifacts_and_failed_coverage_cannot_scan(self):
        for mutate in (lambda api: api.artifacts[0].update(name='coverage-v1-123-1'),
                       lambda api: api.artifacts[0].update(created_at='2026-11-09T00:00:00Z'),
                       lambda api: api.jobs[0].update(conclusion='failure'),
                       lambda api: api.artifacts[0].update(digest='sha256:' + '0' * 64)):
            with tempfile.TemporaryDirectory() as directory:
                api = FakeAPI()
                mutate(api)
                with patch.dict(os.environ, producer_env(directory), clear=True), self.assertRaises(ValueError):
                    bridge.intake(api, {'action': 'in_progress', 'repository': REPO, 'workflow_run': copy.deepcopy(api.run)}, Path(directory) / 'intake', timeout=1)

    def test_untrusted_same_name_claim_ignored_trusted_orphan_holds(self):
        api = FakeAPI()
        source = bridge.source_identity(api.run)
        binding = {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL, 'path': bridge.WORKFLOW, 'tooling_revision': CONTROL}
        api.add_artifact(222, 'sonar-claim-v1-123-2', 123, {'claim.json': '{}'})
        self.assertEqual(bridge.claims(api, source, CONTROL), [])
        api.add_artifact(223, 'sonar-claim-v1-123-2', 456, {'claim.json': bridge.canonical({'schema': 1, 'source': source, 'producer': binding})})
        self.assertEqual(len(bridge.claims(api, source, CONTROL)), 1)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, producer_env(directory), clear=True), self.assertRaises(ValueError):
            bridge.intake(api, {'action': 'in_progress', 'repository': REPO, 'workflow_run': copy.deepcopy(api.run)}, Path(directory) / 'intake', timeout=1)

    def test_result_independent_api_readback_and_all_identity_swaps(self):
        api = FakeAPI()
        source = bridge.source_identity(api.run)
        result = {'schema': 1, 'source': source, 'producer': {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL, 'path': bridge.WORKFLOW, 'tooling_revision': CONTROL},
                  'context': bridge.context(api, api.run), 'task_id': 'bounded_task_123', 'scanner_action': bridge.ACTION, 'scanner_outcome': 'success', 'coverage_provenance': public_coverage_fixture(api), 'authority': 'technical-scan-identity-only'}
        record = api.add_artifact(200, 'sonar-bridge-v1-123-2', 456, {'descriptor.json': bridge.canonical(result)})
        expected = {**result, 'scan_status': 'success', 'producer_conclusion': 'success', 'scan_job_conclusion': 'success'}
        self.assertEqual(bridge.verify_result(api, record, source, CONTROL), expected)
        self.assertEqual(bridge.wait_result(api, 123, 2, SOURCE, CONTROL, timeout=1), expected)
        for mutate in (lambda v: v['source'].update(head_sha=CONTROL), lambda v: v['source'].update(run_attempt=1),
                       lambda v: v['source'].update(path=bridge.WORKFLOW), lambda v: v['source'].update(head_branch='other'), lambda v: v['producer'].update(head_sha=SOURCE),
                       lambda v: v['producer'].update(path='.github/workflows/ci.yml'), lambda v: v['context'].update(args='-Dsonar.branch.name=main'),
                       lambda v: v.update(task_id='bad\nidentity')):
            changed = copy.deepcopy(result)
            mutate(changed)
            api.artifacts = [v for v in api.artifacts if v['id'] != 200]
            record = api.add_artifact(200, 'sonar-bridge-v1-123-2', 456, {'descriptor.json': bridge.canonical(changed)})
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                bridge.verify_result(api, record, source, CONTROL)

    def test_failed_quality_gate_and_cancelled_producer_keep_task_but_never_succeed(self):
        for scanner, job, conclusion, expected in [('success', 'success', 'success', 'success'),
                                                  ('failure', 'failure', 'failure', 'failure'),
                                                  ('success', 'cancelled', 'cancelled', 'cancelled')]:
            with self.subTest(scanner=scanner, producer=conclusion):
                api = FakeAPI()
                api.producer['conclusion'] = conclusion
                source = bridge.source_identity(api.run)
                result = {'schema': 1, 'source': source, 'producer': {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL, 'path': bridge.WORKFLOW, 'tooling_revision': CONTROL},
                          'context': bridge.context(api, api.run), 'task_id': 'exact_failed_or_success_task', 'scanner_action': bridge.ACTION,
                          'scanner_outcome': scanner, 'coverage_provenance': public_coverage_fixture(api), 'authority': 'technical-scan-identity-only'}
                record = api.add_artifact(200, 'sonar-bridge-v1-123-2', 456, {'descriptor.json': bridge.canonical(result)})
                original = api.get
                def status(path, **kwargs):
                    value = original(path, **kwargs)
                    if path.startswith('actions/runs/456/attempts/1/jobs?'):
                        value['jobs'][0]['conclusion'] = job
                        value['jobs'][0]['steps'][0]['conclusion'] = scanner
                    return value
                api.get = status
                verified = bridge.verify_result(api, record, source, CONTROL)
                self.assertEqual(verified['task_id'], result['task_id'])
                self.assertEqual(verified['scan_status'], expected)
                # A copied descriptor cannot relabel a failed platform step.
                if scanner == 'failure':
                    changed = copy.deepcopy(result)
                    changed['scanner_outcome'] = 'success'
                    api.artifacts = [v for v in api.artifacts if v['id'] != 200]
                    record = api.add_artifact(200, 'sonar-bridge-v1-123-2', 456, {'descriptor.json': bridge.canonical(changed)})
                    with self.assertRaises(ValueError):
                        bridge.verify_result(api, record, source, CONTROL)

    def test_invocation_task_descriptor_survives_failed_scan_and_missing_task_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = FakeAPI()
            with patch.dict(os.environ, {**producer_env(root), 'SCAN_OUTCOME': 'failure'}, clear=True):
                bridge.intake(api, {'action': 'in_progress', 'repository': REPO, 'workflow_run': copy.deepcopy(api.run)}, root / 'intake', timeout=1)
                task = root / 'report-task.txt'
                task.write_text('serverUrl=https://sonarcloud.io\nprojectKey=lorconksu_veyport\nceTaskId=failed_gate_task\n')
                result = bridge.descriptor(api, root / 'intake/intake.json', task)
                self.assertEqual(result['scanner_outcome'], 'failure')
                self.assertEqual(result['task_id'], 'failed_gate_task')
                task.write_text('serverUrl=https://sonarcloud.io\nprojectKey=lorconksu_veyport\n')
                with self.assertRaises(ValueError):
                    bridge.descriptor(api, root / 'intake/intake.json', task)

    def test_zip_traversal_links_duplicate_and_oversized_descriptor_reject(self):
        for files in ({'../report': 'input'}, {'unexpected': 'input'}, {'report': 'a\x00b'}):
            with self.subTest(files=files), self.assertRaises(ValueError):
                bridge.extract(archive(files), {'report'})
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as zipped:
            info = zipfile.ZipInfo('report')
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zipped.writestr(info, 'outside')
        with self.assertRaises(ValueError):
            bridge.extract(data.getvalue(), {'report'})

    def test_prepare_uses_only_profile_pinned_source_data_and_exact_transferred_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = FakeAPI()
            with patch.dict(os.environ, producer_env(root), clear=True):
                plan = bridge.intake(api, {'action': 'in_progress', 'repository': REPO, 'workflow_run': copy.deepcopy(api.run)}, root / 'intake', timeout=1)
                workspace = root / 'candidate'
                workspace.mkdir()
                profile = workspace / 'sonar-project.properties'
                profile.write_bytes(PINNED_PROFILE)
                self.assertEqual(bridge.prepare(api, root / 'intake/intake.json', workspace), plan)
                self.assertTrue((workspace / 'web/coverage/lcov.info').is_file())
                (root / 'sonar-scan-metadata').rmdir()
                (root / 'intake/unit/coverage-hub.out').write_text('changed coverage')
                with self.assertRaises(ValueError):
                    bridge.prepare(api, root / 'intake/intake.json', workspace)
                (workspace / 'sonar-project.properties').write_text('sonar.host.url=https://attacker.invalid')
                with self.assertRaises(ValueError):
                    bridge.prepare(api, root / 'intake/intake.json', workspace)

    def test_control_pin_rotation_cannot_erase_old_trusted_claim(self):
        api = FakeAPI()
        source = bridge.source_identity(api.run)
        binding = {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL, 'path': bridge.WORKFLOW, 'tooling_revision': CONTROL}
        api.add_artifact(223, 'sonar-claim-v1-123-2', 456, {'claim.json': bridge.canonical({'schema': 1, 'source': source, 'producer': binding})})
        self.assertEqual(len(bridge.claims(api, source, 'c' * 40)), 1)
        api.artifacts[-1]['workflow_run']['id'] = 123
        self.assertEqual(bridge.claims(api, source, CONTROL), [])

    def test_actual_main_producer_pin_and_event_cannot_be_spoofed(self):
        with tempfile.TemporaryDirectory() as directory:
            env = producer_env(directory)
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(bridge.own_producer(FakeAPI())['head_sha'], CONTROL)
            for key, value in [('GITHUB_SHA', SOURCE), ('GITHUB_REF', 'refs/heads/feature'),
                               ('GITHUB_EVENT_NAME', 'pull_request'), ('SONAR_CREDENTIAL_MODE', 'legacy'),
                               ('GITHUB_WORKFLOW_REF', bridge.REPOSITORY + '/.github/workflows/ci.yml@refs/heads/main')]:
                with self.subTest(key=key), patch.dict(os.environ, {**env, key: value}, clear=True), self.assertRaises(ValueError):
                    bridge.own_producer(FakeAPI())

    def test_application_only_main_advance_keeps_tooling_pin_but_control_changes(self):
        api = FakeAPI()
        advanced = 'c' * 40
        api.producer['head_sha'] = advanced
        binding = bridge.producer(api, 456, 1, CONTROL, completed=True)
        self.assertEqual(binding['head_sha'], advanced)
        self.assertEqual(binding['tooling_revision'], CONTROL)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {**producer_env(directory), 'GITHUB_SHA': advanced}, clear=True):
            self.assertEqual(bridge.own_producer(api), binding)
        original = api.get
        def changed(path, **kwargs):
            value = original(path, **kwargs)
            if path.startswith('contents/') and path.endswith('?ref=' + advanced):
                raw = b'changed bridge helper or workflow'
                value.update(size=len(raw), content=base64.b64encode(raw).decode())
            return value
        api.get = changed
        with self.assertRaises(ValueError):
            bridge.producer(api, 456, 1, CONTROL)

    def test_destination_concurrency_is_per_actual_pr_or_exact_branch(self):
        self.assertEqual(bridge.destination({'args': '-Dsonar.branch.name=main'}), 'branch-main')
        self.assertEqual(bridge.destination({'args': '-Dsonar.branch.name=release-ssdf-candidate-' + SOURCE}), 'branch-release-ssdf-candidate-' + SOURCE)
        self.assertEqual(bridge.destination(bridge.context(FakeAPI(), source_run())), 'pr-115')
        with self.assertRaises(ValueError):
            bridge.destination({'args': '-Dsonar.branch.name=untrusted'})

    def test_candidate_symlink_device_and_report_redirects_reject_before_scanner(self):
        for attack in ('proc', 'home', 'outside', 'fifo', 'gitmodules', 'profile-host', 'profile-plugin', 'profile-report',
                       'profile-exclusions', 'profile-coverage', 'profile-tests', 'profile-suppression', 'profile-rule', 'profile-path'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                api = FakeAPI()
                with patch.dict(os.environ, producer_env(root), clear=True):
                    bridge.intake(api, {'action': 'in_progress', 'repository': REPO, 'workflow_run': copy.deepcopy(api.run)}, root / 'intake', timeout=1)
                    workspace = root / 'candidate'
                    workspace.mkdir()
                    profile = workspace / 'sonar-project.properties'
                    profile.write_bytes(PINNED_PROFILE)
                    if attack in ('proc', 'home', 'outside'):
                        outside = {'proc': '/proc/self/environ', 'home': '/home/runner/.config/credentials', 'outside': str(root / 'private-token')}[attack]
                        (workspace / 'scanner-data').symlink_to(outside)
                    elif attack == 'fifo':
                        os.mkfifo(workspace / 'scanner-data')
                    elif attack == 'gitmodules':
                        (workspace / '.gitmodules').write_text('[submodule "outside"]')
                    else:
                        property_name = {'profile-host': 'sonar.host.url', 'profile-plugin': 'sonar.plugins.downloadOnlyRequired',
                                         'profile-report': 'sonar.scanner.metadataFilePath', 'profile-exclusions': 'sonar.exclusions',
                                         'profile-coverage': 'sonar.coverage.exclusions', 'profile-tests': 'sonar.test.inclusions',
                                         'profile-suppression': 'sonar.issue.ignore.multicriteria',
                                         'profile-rule': 'sonar.issue.ignore.multicriteria.e1.ruleKey',
                                         'profile-path': 'sonar.issue.ignore.multicriteria.e1.resourceKey'}[attack]
                        with (workspace / profile.name).open('a') as stream:
                            stream.write('\n' + property_name + '=/proc/self/environ\n')
                    with self.assertRaises(ValueError):
                        bridge.prepare(api, root / 'intake/intake.json', workspace)
                    self.assertFalse((root / 'sonar-scan-metadata').exists())

    def test_zip_duplicate_and_declared_oversize_rejected_before_member_read(self):
        output = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(output, 'w') as zipped:
                zipped.writestr('one', 'input')
                zipped.writestr('one', 'duplicate')
        with patch.object(zipfile.ZipFile, 'read', side_effect=AssertionError('must reject directory first')), self.assertRaises(ValueError):
            bridge.extract(output.getvalue(), {'one', 'two'})
        # Mutate only the ZIP central-directory declared size; no large file is
        # allocated/decompressed. The complete directory preflight rejects it.
        raw = bytearray(archive({'report': 'input'}))
        index = raw.index(b'PK\x01\x02')
        raw[index + 24:index + 28] = (65 << 20).to_bytes(4, 'little')
        with patch.object(zipfile.ZipFile, 'read', side_effect=AssertionError('must reject size first')), self.assertRaises(ValueError):
            bridge.extract(bytes(raw), {'report'})

    def test_source_retry_during_result_readback_rejects_old_result(self):
        api = FakeAPI()
        source = bridge.source_identity(api.run)
        result = {'schema': 1, 'source': source, 'producer': {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL, 'path': bridge.WORKFLOW, 'tooling_revision': CONTROL},
                  'context': bridge.context(api, api.run), 'task_id': 'bounded_task', 'scanner_action': bridge.ACTION, 'scanner_outcome': 'success', 'coverage_provenance': public_coverage_fixture(api), 'authority': 'technical-scan-identity-only'}
        record = api.add_artifact(200, 'sonar-bridge-v1-123-2', 456, {'descriptor.json': bridge.canonical(result)})
        original = api.get
        def moved(path, **kwargs):
            value = original(path, **kwargs)
            if path == 'actions/artifacts/200/zip':
                api.run['run_attempt'] = 3
            return value
        api.get = moved
        with self.assertRaises(ValueError):
            bridge.verify_result(api, record, source, CONTROL)

    def test_fixed_origin_download_strips_credential_and_forbids_next_redirect(self):
        requests = []
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, maximum): return b'bounded archive'
        class Opener:
            def open(self, request, timeout):
                requests.append(request)
                if len(requests) == 1:
                    raise urllib.error.HTTPError(request.full_url, 302, 'artifact', {'Location': 'https://fixture.blob.core.windows.net/archive'}, None)
                return Response()
        with patch.object(bridge.urllib.request, 'build_opener', return_value=Opener()):
            self.assertEqual(bridge.API(token='synthetic-api-token').get('actions/artifacts/1/zip', raw=True), b'bounded archive')
        self.assertEqual(requests[0].get_header('Authorization'), 'Bearer synthetic-api-token')
        self.assertIsNone(requests[1].get_header('Authorization'))
        self.assertIsNone(bridge.NoRedirect().redirect_request(None, None, None, None, None, None))
        class BadOpener:
            def open(self, request, timeout):
                raise urllib.error.HTTPError(request.full_url, 302, 'artifact', {'Location': 'https://attacker.invalid/archive'}, None)
        with patch.object(bridge.urllib.request, 'build_opener', return_value=BadOpener()), self.assertRaises(ValueError):
            bridge.API(token='synthetic-api-token').get('actions/artifacts/1/zip', raw=True)




class BootstrapBoundaryTests(unittest.TestCase):
    def test_bootstrap_is_dormant_without_explicit_bridge_mode(self):
        for value in ('', 'legacy', None, 'auto'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bridge.mode(value)
        self.assertEqual(bridge.mode('bridge'), 'bridge')

    def test_producer_requires_actual_main_platform_identity_before_api_use(self):
        with patch.dict(bridge.os.environ, {'GITHUB_EVENT_NAME': 'pull_request',
                                           'GITHUB_SHA': 'a' * 40,
                                           'SONAR_BRIDGE_TOOLING_REVISION': 'b' * 40}, clear=True):
            with self.assertRaises(ValueError):
                bridge.own_producer(None)

    def test_credentialed_workflow_is_main_producer_with_protected_environment(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / bridge.WORKFLOW).read_text()
        self.assertIn("if: vars.SONAR_CREDENTIAL_MODE == 'bridge'", workflow)
        self.assertIn('environment: ssdf-sonar-scan', workflow)
        self.assertIn('types: [in_progress]', workflow)
        self.assertNotIn('workflow_dispatch:', workflow)
        self.assertEqual(workflow.count('SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}'), 1)


    def test_helper_import_is_from_this_checkout(self):
        self.assertEqual(Path(bridge.__file__).resolve(),
                         Path(__file__).resolve().with_name('sonar_bridge.py'))

    def test_committed_candidate_fixture_matches_immutable_profile(self):
        self.assertEqual(bridge.sha(PINNED_PROFILE), bridge.PROFILE)


class SignedCoverageTransferTests(unittest.TestCase):
    def setup_transfer(self, root):
        api = FakeAPI()
        # Distinct signed members make swapped-name/group bugs observable.
        for index, (group, names) in enumerate(bridge.COVERAGE.items()):
            raw = archive({name: (group + ':' + name + '\n').encode() for name in names})
            row = api.artifacts[index]
            row.update(digest='sha256:' + bridge.sha(raw), size_in_bytes=len(raw))
            api.payloads[row['id']] = raw
        plan = bridge.intake(api, {'action': 'in_progress', 'repository': REPO,
                                 'workflow_run': copy.deepcopy(api.run)}, root / 'intake', timeout=1)
        workspace = root / 'candidate'
        workspace.mkdir()
        (workspace / 'sonar-project.properties').write_bytes(PINNED_PROFILE)
        return api, plan, workspace

    def replace_transfer(self, root, plan, group, name, raw):
        (root / 'intake' / group / name).write_bytes(raw)
        next(row for row in plan['coverage'] if row['group'] == group)['files'][name] = {
            'sha256': bridge.sha(raw), 'size': len(raw)}

    def save_plan(self, root, plan):
        (root / 'intake/intake.json').write_bytes(bridge.canonical(plan))

    def assert_no_scanner_inputs(self, root, workspace):
        for names in bridge.COVERAGE.values():
            for name in names:
                self.assertFalse((workspace / name).exists(), name)
        self.assertFalse((root / 'sonar-scan-metadata').exists())

    def test_report_and_intake_hash_substitution_rejected_against_signed_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, producer_env(root), clear=True):
                api, plan, workspace = self.setup_transfer(root)
                signed = {group: (root / 'intake/provenance' / (group + '.zip')).read_bytes()
                          for group in bridge.COVERAGE}
                for group, names in bridge.COVERAGE.items():
                    for name in names:
                        self.replace_transfer(root, plan, group, name, b'fabricated passing coverage\n')
                self.save_plan(root, plan)
                with self.assertRaisesRegex(ValueError, 'Coverage member metadata differs from verified signed archive'):
                    bridge.prepare(api, root / 'intake/intake.json', workspace)
                self.assert_no_scanner_inputs(root, workspace)
                self.assertEqual(signed, {group: (root / 'intake/provenance' / (group + '.zip')).read_bytes()
                                         for group in bridge.COVERAGE})

    def test_swapped_member_or_group_reports_and_hashes_are_rejected(self):
        for left, right in [
                (('unit', 'coverage-hub.out'), ('unit', 'coverage-agent.out')),
                (('unit', 'coverage-hub.out'), ('integration', 'coverage-integration.out'))]:
            with self.subTest(left=left, right=right), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch.dict(os.environ, producer_env(root), clear=True):
                    api, plan, workspace = self.setup_transfer(root)
                    a = (root / 'intake' / left[0] / left[1]).read_bytes()
                    b = (root / 'intake' / right[0] / right[1]).read_bytes()
                    self.replace_transfer(root, plan, *left, b)
                    self.replace_transfer(root, plan, *right, a)
                    self.save_plan(root, plan)
                    with self.assertRaisesRegex(ValueError, 'Coverage member metadata differs from verified signed archive'):
                        bridge.prepare(api, root / 'intake/intake.json', workspace)
                    self.assert_no_scanner_inputs(root, workspace)

    def test_declared_hash_or_size_must_match_signed_member_in_plan_validation(self):
        for field, value in [('sha256', '0' * 64), ('size', 1)]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch.dict(os.environ, producer_env(root), clear=True):
                    api, plan, workspace = self.setup_transfer(root)
                    plan['coverage'][0]['files']['coverage-hub.out'][field] = value
                    with self.assertRaisesRegex(ValueError, 'Coverage member metadata differs from verified signed archive'):
                        bridge.validate_plan(api, plan, root / 'intake')
                    self.assert_no_scanner_inputs(root, workspace)

    def test_late_transferred_report_change_is_rejected_before_any_destination_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, producer_env(root), clear=True):
                api, _, workspace = self.setup_transfer(root)
                # The second group is checked after all first-group reports.
                (root / 'intake/integration/coverage-integration.out').write_bytes(b'substituted\n')
                with self.assertRaisesRegex(ValueError, 'Coverage transfer bytes differ from verified signed archive'):
                    bridge.prepare(api, root / 'intake/intake.json', workspace)
                self.assert_no_scanner_inputs(root, workspace)

    def test_missing_extra_or_link_transferred_report_leaves_no_scanner_inputs(self):
        for mutation in ('missing', 'extra', 'link'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch.dict(os.environ, producer_env(root), clear=True):
                    api, _, workspace = self.setup_transfer(root)
                    report = root / 'intake/integration/coverage-integration.out'
                    if mutation == 'extra':
                        (report.parent / 'extra.out').write_bytes(b'unexpected')
                    else:
                        report.unlink()
                        if mutation == 'link':
                            report.symlink_to(root / 'intake/unit/coverage-hub.out')
                    with self.assertRaises(ValueError):
                        bridge.prepare(api, root / 'intake/intake.json', workspace)
                    self.assert_no_scanner_inputs(root, workspace)

    def test_signed_zip_member_set_and_type_controls_remain_required(self):
        for mutation in ('missing', 'extra', 'duplicate', 'traversal', 'link'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch.dict(os.environ, producer_env(root), clear=True):
                    api, plan, workspace = self.setup_transfer(root)
                    files = bridge.extract(api.payloads[100], bridge.COVERAGE['unit'])
                    output = io.BytesIO()
                    with zipfile.ZipFile(output, 'w') as zipped:
                        for name, value in files.items():
                            if mutation == 'missing' and name == 'coverage-hub.out':
                                continue
                            if mutation == 'link' and name == 'coverage-hub.out':
                                member = zipfile.ZipInfo(name)
                                member.external_attr = (stat.S_IFLNK | 0o777) << 16
                                zipped.writestr(member, value)
                            else:
                                zipped.writestr(name, value)
                        if mutation in ('extra', 'traversal'):
                            zipped.writestr('../escape' if mutation == 'traversal' else 'extra.out', b'extra')
                        if mutation == 'duplicate':
                            with warnings.catch_warnings():
                                warnings.simplefilter('ignore', UserWarning)
                                zipped.writestr('coverage-hub.out', b'duplicate')
                    raw = output.getvalue()
                    api.payloads[100] = raw
                    api.artifacts[0].update(digest='sha256:' + bridge.sha(raw), size_in_bytes=len(raw))
                    item = plan['coverage'][0]
                    item['digest'] = api.artifacts[0]['digest']
                    # The fixture represents an otherwise authenticated upload;
                    # malformed ZIP membership still cannot become scanner input.
                    item['provenance'] = bridge.coverage_provenance(api, api.run, api.artifacts[0],
                                                                  api.jobs[0], 'unit', raw)
                    (root / 'intake/provenance/unit.zip').write_bytes(raw)
                    self.save_plan(root, plan)
                    with self.assertRaises(ValueError):
                        bridge.prepare(api, root / 'intake/intake.json', workspace)
                    self.assert_no_scanner_inputs(root, workspace)

    def test_legitimate_signed_members_map_to_exact_scanner_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, producer_env(root), clear=True):
                api, plan, workspace = self.setup_transfer(root)
                self.assertEqual(bridge.prepare(api, root / 'intake/intake.json', workspace), plan)
                for group, names in bridge.COVERAGE.items():
                    for name in names:
                        self.assertEqual((workspace / name).read_bytes(), (group + ':' + name + '\n').encode())
                self.assertTrue((root / 'sonar-scan-metadata').is_dir())

if __name__ == '__main__':
    unittest.main()

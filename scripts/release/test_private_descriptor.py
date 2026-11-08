"""Descriptor-only trust-boundary tests; synthetic API data, no LAN or credentials."""
import copy
import datetime as dt
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest.mock import patch
import zipfile

import private_descriptor as approval
import risk_acceptance as risk

AT = dt.datetime(2026, 11, 8, 12, tzinfo=dt.timezone.utc)
REVISION = 'a' * 40
BUNDLE = 'review-' + 'b' * 32
DIGEST = 'c' * 64
END = '2026-11-22T12:00:00Z'
CANARY = 'PRIVATE-SYNTHETIC-CANARY'
ROOT = Path(__file__).resolve().parents[2]


class FakeGitHub:
    def __init__(self, completed=False):
        owner = {'login': risk.OWNER_LOGIN, 'id': risk.OWNER_ID, 'type': 'User'}
        self.repository = {'full_name': risk.REPOSITORY, 'default_branch': 'main', 'owner': copy.deepcopy(owner)}
        self.run = {'id': 123, 'repository': {'full_name': risk.REPOSITORY}, 'path': approval.WORKFLOW,
                    'head_branch': 'main', 'head_sha': REVISION, 'run_attempt': 1, 'event': 'workflow_dispatch',
                    'status': 'completed' if completed else 'in_progress', 'conclusion': 'success' if completed else None,
                    'actor': copy.deepcopy(owner), 'triggering_actor': copy.deepcopy(owner), 'created_at': '2026-11-08T11:59:00Z'}
        self.environment = {'id': 789, 'name': risk.ENVIRONMENT,
                            'protection_rules': [{'type': 'required_reviewers', 'prevent_self_review': False,
                              'reviewers': [{'type': 'User', 'reviewer': copy.deepcopy(owner)}]}],
                            'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True}}
        self.branches = {'branch_policies': [{'name': 'main', 'type': 'branch'}]}
        # Documented GET runs/{id}/approvals response. There is no review-time
        # or attempt field; exact original run/attempt binding is independent.
        self.approvals = [{'state': 'approved', 'comment': CANARY, 'user': copy.deepcopy(owner),
                           'environments': [{'id': 789, 'name': risk.ENVIRONMENT}]}]
        self.ancestry = 'identical'
        self.changes = {}
        self.requests = []
        self.descriptor = approval.public_descriptor(BUNDLE, DIGEST, END)
        self.entries = None
        self.artifacts = {'total_count': 1, 'artifacts': [{'id': 456, 'name': 'ssdf-private-approval-' + BUNDLE,
                            'expired': False, 'size_in_bytes': 1024}]}

    def content(self, path, revision):
        self.requests.append(('content', path, revision))
        if path not in approval.TRUSTED_FILES or revision not in ('main', REVISION):
            raise AssertionError('unexpected candidate or plaintext content fetch')
        return self.changes.get((path, revision), (ROOT / path).read_bytes())

    def get(self, path, raw=False):
        self.requests.append(('get', path, raw))
        fixed = {'': self.repository, 'actions/runs/123': self.run,
                 'actions/runs/123/approvals': self.approvals,
                 'compare/' + REVISION + '...main': {'status': self.ancestry},
                 'environments/' + risk.ENVIRONMENT: self.environment,
                 'environments/' + risk.ENVIRONMENT + '/deployment-branch-policies': self.branches,
                 'actions/runs/123/artifacts?per_page=100': self.artifacts}
        if path in fixed:
            return copy.deepcopy(fixed[path])
        if path == 'actions/artifacts/456/zip' and raw:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as archive:
                for name, data, mode in self.entries or [('approval.json', risk.canonical(self.descriptor), stat.S_IFREG)]:
                    info = zipfile.ZipInfo(name)
                    info.external_attr = mode << 16
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore', UserWarning)
                        archive.writestr(info, data)
            return buffer.getvalue()
        raise AssertionError('unexpected endpoint')


class PrivateDescriptorTests(unittest.TestCase):
    def prepare(self, api=None, **changes):
        values = {'bundle_id': BUNDLE, 'bundle_sha256': DIGEST, 'expires_at': END, 'run_id': 123, 'at': AT}
        values.update(changes)
        return approval.prepare_private(api or FakeGitHub(), **values)

    def verify(self, api=None, descriptor=None, **changes):
        values = {'run_id': 123, 'at': AT}
        values.update(changes)
        return approval.verify_private_descriptor(api or FakeGitHub(True),
                   approval.public_descriptor(BUNDLE, DIGEST, END) if descriptor is None else descriptor, **values)

    def test_original_owner_protected_dispatch_emits_only_four_public_fields(self):
        api = FakeGitHub()
        descriptor = self.prepare(api)
        self.assertEqual(descriptor, {'id': BUNDLE, 'bundle_sha256': DIGEST, 'expires_at': END, 'status': 'approved'})
        self.assertNotIn(CANARY, risk.canonical(descriptor).decode())
        self.assertEqual(set(path for kind, path, _ in api.requests if kind == 'content'), set(approval.TRUSTED_FILES))
        self.assertEqual(self.verify(), descriptor)

    def test_descriptor_shape_and_boundaries_reject_arbitrary_private_inputs(self):
        for field, values in {'bundle_id': (CANARY, '../secret', 'RA-0001', BUNDLE.upper(), BUNDLE + 'x', None),
                              'bundle_sha256': (CANARY, DIGEST.upper(), DIGEST[:-1], None),
                              'expires_at': (CANARY, '2026-11-22', '2026-11-22T12:00:00+00:00', '2026-99-22T12:00:00Z', None)}.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(approval.ApprovalError) as error:
                    self.prepare(**{field: value})
                self.assertEqual(str(error.exception), 'private approval unavailable')

    def test_expiry_window_future_creation_and_stale_dispatch_fail(self):
        for expires in ('2026-11-08T12:00:00Z', '2026-11-08T11:59:59Z', '2027-02-06T12:00:01Z'):
            with self.subTest(expires=expires), self.assertRaises(approval.ApprovalError):
                self.prepare(expires_at=expires)
        self.prepare(expires_at='2027-02-06T12:00:00Z')  # exact90day maximum, not policy approval
        for created in ('2026-11-08T12:00:01Z', '2026-11-07T11:59:59Z', None):
            api = FakeGitHub();api.run['created_at'] = created
            with self.subTest(created=created), self.assertRaises(approval.ApprovalError):
                self.prepare(api)
        with self.assertRaises(approval.ApprovalError):
            self.verify(at=dt.datetime(2026, 11, 22, 12, tzinfo=dt.timezone.utc))

    def test_original_dispatch_id_ref_attempt_and_event_are_required(self):
        changes = [('id', 124), ('head_branch', 'feature'), ('path', risk.WORKFLOW), ('run_attempt', 2), ('run_attempt', True),
                   ('event', 'push'), ('event', 'pull_request'), ('head_sha', 'not-a-commit'),
                   ('repository', {'full_name': 'other/repo'}), ('status', 'queued')]
        for field, value in changes:
            api = FakeGitHub();api.run[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(approval.ApprovalError):
                self.prepare(api)
        for value in (True, 0, -1, '123', None):
            with self.subTest(run_id=value), self.assertRaises(approval.ApprovalError):
                self.prepare(run_id=value)

    def test_both_actors_require_pinned_numeric_owner_login_and_user_type(self):
        for actor in ('actor', 'triggering_actor'):
            for field, value in [('id', 1), ('login', 'other'), ('type', 'Bot')]:
                api = FakeGitHub();api.run[actor][field] = value
                with self.subTest(actor=actor, field=field), self.assertRaises(approval.ApprovalError):
                    self.prepare(api)

    def test_repository_owner_and_main_ancestry_must_match(self):
        for field, value in [('full_name', 'other/repo'), ('default_branch', 'feature')]:
            api = FakeGitHub();api.repository[field] = value
            with self.subTest(field=field), self.assertRaises(approval.ApprovalError):self.prepare(api)
        for field, value in [('id', 1), ('login', 'other'), ('type', 'Organization')]:
            api = FakeGitHub();api.repository['owner'][field] = value
            with self.subTest(field=field), self.assertRaises(approval.ApprovalError):self.prepare(api)
        for status in ('behind', 'diverged', None):
            api = FakeGitHub();api.ancestry = status
            with self.subTest(status=status), self.assertRaises(approval.ApprovalError):self.prepare(api)
        api = FakeGitHub();api.ancestry = 'ahead';self.prepare(api)

    def test_each_installed_workflow_helper_and_dependency_must_match_current_main(self):
        for path in approval.TRUSTED_FILES:
            for revision in (REVISION, 'main'):
                api = FakeGitHub();api.changes[(path, revision)] = b'changed trusted bytes'
                with self.subTest(path=path, revision=revision), self.assertRaises(approval.ApprovalError):
                    self.prepare(api)
            api = FakeGitHub()
            with patch.object(approval, 'local_bytes', side_effect=lambda name: b'changed locally' if name == path else (ROOT / name).read_bytes()):
                with self.subTest(local_path=path), self.assertRaises(approval.ApprovalError):self.prepare(api)

    def test_owner_only_protection_cannot_be_removed_or_widened(self):
        mutations = [lambda a: a.environment.update(protection_rules=[]),
                     lambda a: a.environment['protection_rules'][0].update(prevent_self_review=True),
                     lambda a: a.environment['protection_rules'].append(copy.deepcopy(a.environment['protection_rules'][0])),
                     lambda a: a.environment['protection_rules'][0].update(reviewers=[]),
                     lambda a: a.environment['protection_rules'][0]['reviewers'][0].update(type='Team'),
                     lambda a: a.environment['protection_rules'][0]['reviewers'][0]['reviewer'].update(id=1),
                     lambda a: a.environment['protection_rules'][0]['reviewers'].append({'type':'User','reviewer':{'id':1}}),
                     lambda a: a.environment.update(deployment_branch_policy={'protected_branches':True,'custom_branch_policies':False}),
                     lambda a: a.branches.update(branch_policies=[]),
                     lambda a: a.branches['branch_policies'].append({'name':'feature','type':'branch'}),
                     lambda a: a.branches['branch_policies'][0].update(type='tag'),
                     lambda a: a.branches['branch_policies'][0].update(name='ma*')]
        for index, mutate in enumerate(mutations):
            api = FakeGitHub();mutate(api)
            with self.subTest(index=index), self.assertRaises(approval.ApprovalError):self.prepare(api)

    def test_retroactive_protection_without_run_review_cannot_authorize(self):
        # Current environment is correctly protected and the run/artifact is
        # otherwise genuine. Adding protection later supplies no history.
        for completed in (False, True):
            api = FakeGitHub(completed);api.approvals = []
            with self.subTest(completed=completed), self.assertRaises(approval.ApprovalError):
                self.verify(api) if completed else self.prepare(api)

    def test_run_review_requires_exact_owner_and_current_environment_identity(self):
        mutations = [lambda a:a.approvals[0]['user'].update(id=1),
                     lambda a:a.approvals[0]['user'].update(login='other'),
                     lambda a:a.approvals[0]['user'].update(type='Bot'),
                     lambda a:a.approvals[0]['environments'][0].update(id=790),
                     lambda a:a.approvals[0]['environments'][0].update(id=True),
                     lambda a:a.approvals[0]['environments'][0].update(name='other'),
                     lambda a:a.environment.update(id=790),
                     lambda a:a.environment.update(id=True),
                     lambda a:a.environment.update(name='other')]
        for completed in (False, True):
            for index, mutate in enumerate(mutations):
                api=FakeGitHub(completed);mutate(api)
                with self.subTest(completed=completed,index=index),self.assertRaises(approval.ApprovalError):
                    self.verify(api) if completed else self.prepare(api)

    def test_rejected_ambiguous_or_malformed_run_review_history_fails_closed(self):
        histories = [None, {}, [None], [{'state':'approved'}]]
        for state in ('rejected','pending','APPROVED',None):
            api=FakeGitHub();api.approvals[0]['state']=state;histories.append(api.approvals)
        original=FakeGitHub().approvals[0]
        histories += [[original,copy.deepcopy(original)],
                      [original,{**copy.deepcopy(original),'state':'rejected'}],
                      [{**copy.deepcopy(original),'environments':[]}],
                      [{**copy.deepcopy(original),'environments':[original['environments'][0],{'id':790,'name':'other'}]}]]
        for completed in (False,True):
            for index,history in enumerate(histories):
                api=FakeGitHub(completed);api.approvals=copy.deepcopy(history)
                with self.subTest(completed=completed,index=index),self.assertRaises(approval.ApprovalError):
                    self.verify(api) if completed else self.prepare(api)

    def test_unavailable_review_history_never_logs_userdata_or_emits_a_descriptor(self):
        for completed in (False,True):
            api=FakeGitHub(completed)
            original_get=api.get
            def get(path,raw=False):
                if path=='actions/runs/123/approvals':raise ValueError(CANARY)
                return original_get(path,raw)
            with patch.object(api,'get',side_effect=get),self.assertRaises(approval.ApprovalError) as error:
                self.verify(api) if completed else self.prepare(api)
            self.assertEqual(str(error.exception),'private approval unavailable')
        api=FakeGitHub();result=self.prepare(api)
        self.assertNotIn(CANARY,risk.canonical(result).decode())
        self.assertIn(('get','actions/runs/123/approvals',False),api.requests)

    def test_verification_rechecks_live_metadata_and_requires_original_success(self):
        for field, value in [('status','in_progress'), ('conclusion','failure'), ('run_attempt',2),
                             ('created_at','2026-11-08T12:00:01Z')]:
            api = FakeGitHub(True);api.run[field] = value
            with self.subTest(field=field), self.assertRaises(approval.ApprovalError):self.verify(api)
        api = FakeGitHub(True);api.environment['protection_rules'] = []
        with self.assertRaises(approval.ApprovalError):self.verify(api)

    def test_descriptor_tamper_unknown_fields_and_provider_artifact_mismatch_fail(self):
        for field, value in [('id','review-'+'d'*32), ('bundle_sha256','d'*64), ('expires_at','2026-11-21T12:00:00Z'),
                             ('status','pending'), ('extra',CANARY)]:
            descriptor = approval.public_descriptor(BUNDLE,DIGEST,END);descriptor[field] = value
            with self.subTest(field=field), self.assertRaises(approval.ApprovalError):self.verify(descriptor=descriptor)
        api = FakeGitHub(True);api.descriptor['bundle_sha256'] = 'd'*64
        with self.assertRaises(approval.ApprovalError):self.verify(api)

    def test_missing_ambiguous_expired_or_unbounded_artifact_inventory_fails(self):
        mutations = [lambda a:a.artifacts.update(total_count=101), lambda a:a.artifacts.update(total_count=True),
                     lambda a:a.artifacts.update(total_count=0, artifacts=[]),
                     lambda a:a.artifacts.update(total_count=2),
                     lambda a:a.artifacts['artifacts'][0].update(expired=True),
                     lambda a:a.artifacts['artifacts'][0].update(id=True),
                     lambda a:a.artifacts['artifacts'][0].update(size_in_bytes=risk.MAX_BYTES+1),
                     lambda a:a.artifacts['artifacts'].append(copy.deepcopy(a.artifacts['artifacts'][0]))]
        for index, mutate in enumerate(mutations):
            api = FakeGitHub(True);mutate(api)
            with self.subTest(index=index), self.assertRaises(approval.ApprovalError):self.verify(api)

    def test_artifact_paths_links_extra_files_duplicate_json_and_size_fail(self):
        valid = risk.canonical(approval.public_descriptor(BUNDLE,DIGEST,END))
        for entries in [[('../approval.json',valid,stat.S_IFREG)], [('approval.json',valid,stat.S_IFLNK)],
                        [('approval.json',valid,stat.S_IFREG),('extra',b'private',stat.S_IFREG)],
                        [('approval.json',valid,stat.S_IFREG),('approval.json',valid,stat.S_IFREG)],
                        [('approval.json',b'{"id":1,"id":2}',stat.S_IFREG)],
                        [('approval.json',b'x'*65537,stat.S_IFREG)]]:
            api = FakeGitHub(True);api.entries=entries
            with self.subTest(names=[entry[0] for entry in entries]), self.assertRaises(approval.ApprovalError):self.verify(api)
        api=FakeGitHub(True)
        with patch.object(api,'get',side_effect=ValueError(CANARY)), self.assertRaises(approval.ApprovalError) as error:
            self.verify(api)
        self.assertNotIn(CANARY,str(error.exception))

    def test_local_file_checks_bound_and_reject_substituted_final_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'file';target.write_bytes(b'x')
            alias=Path(directory)/'alias';alias.symlink_to(target)
            with self.assertRaises(approval.ApprovalError):approval.local_bytes(str(target))
            real_open=os.open
            with patch.object(approval.os,'open',side_effect=lambda _path,flags:real_open(alias,flags)):
                with self.assertRaises(OSError):approval.local_bytes(approval.TRUSTED_FILES[0])
            with patch.object(approval.os,'open',side_effect=lambda _path,flags:real_open(target,flags)),\
                    patch.object(risk,'MAX_BYTES',0),self.assertRaises(approval.ApprovalError):
                approval.local_bytes(approval.TRUSTED_FILES[0])

    def test_legacy_cli_prepare_produces_no_approval_and_keeps_main_scope_constants(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'approval.json'
            result=subprocess.run([sys.executable,str(ROOT/'scripts/release/risk_acceptance.py'),'prepare',
                '--record',str(Path(directory)/'missing.md'),'--approval',str(output)],
                env={**os.environ,'GH_TOKEN':'synthetic-not-used'},capture_output=True,timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(output.exists())
            self.assertNotIn(b'synthetic-not-used',result.stdout+result.stderr)
        self.assertNotIn('source:pip:infra/evidence-viewer',risk.SOURCE_SCOPES)
        self.assertEqual(risk.WORKFLOW,'.github/workflows/risk-approval.yml')

    def test_workflow_inputs_are_opaque_and_no_legacy_route_or_write_authority_remains(self):
        workflow=(ROOT/approval.WORKFLOW).read_text()
        input_section=workflow.split('    inputs:\n',1)[1].split('\npermissions:',1)[0]
        self.assertEqual(set(re.findall(r'^      ([a-z_0-9]+):$',input_section,re.M)),{'bundle_id','bundle_sha256','expires_at'})
        self.assertIn('ref: ${{ github.sha }}',workflow)
        self.assertIn('persist-credentials: false',workflow)
        self.assertIn("github.ref == 'refs/heads/main'",workflow)
        self.assertIn('github.run_attempt == 1',workflow)
        self.assertIn("github.actor == 'lorconksu' && github.triggering_actor == 'lorconksu'",workflow)
        self.assertIn('environment: ssdf-risk-approval',workflow)
        # The read endpoints use Actions:read, not Administration. References:
        # https://docs.github.com/en/rest/deployments/environments#get-an-environment
        # https://docs.github.com/en/rest/deployments/branch-policies#list-deployment-branch-policies
        permissions=workflow.split('\npermissions:\n',1)[1].split('\n\n',1)[0]
        self.assertEqual(permissions,'  contents: read\n  actions: read')
        self.assertNotIn(': write',workflow)
        self.assertNotIn('secrets.',workflow)
        self.assertNotIn('api.content',workflow)
        old=(ROOT/approval.LEGACY_WORKFLOW).read_text()
        self.assertNotIn('inputs:',old)
        self.assertNotIn('checkout',old)
        self.assertIn('permissions: {}',old)
        self.assertIn('run: exit 1',old)

    def test_actual_workflow_body_writes_only_safe_descriptor_and_masks_failure(self):
        workflow=(ROOT/approval.WORKFLOW).read_text()
        body=workflow.split("          python3 - <<'PY'\n",1)[1].split('\n          PY',1)[0]
        body='\n'.join(line[10:] for line in body.splitlines())
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'RUNNER_TEMP':directory,
             'BUNDLE_ID':BUNDLE,'BUNDLE_SHA256':DIGEST,'EXPIRES_AT':END,'GITHUB_RUN_ID':'123'}),\
             patch.object(sys,'path',list(sys.path)),patch.object(risk,'GitHub',return_value=FakeGitHub()),\
             patch.object(risk,'now',return_value=AT):
            exec(compile(body,'private-workflow','exec'),{})
            path=Path(directory)/'private-approval/approval.json'
            self.assertEqual(json.loads(path.read_bytes()),approval.public_descriptor(BUNDLE,DIGEST,END))
            self.assertEqual(path.parent.stat().st_mode & 0o777,0o700)
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'RUNNER_TEMP':directory,
             'BUNDLE_ID':CANARY,'BUNDLE_SHA256':DIGEST,'EXPIRES_AT':END,'GITHUB_RUN_ID':'123'}),\
             patch.object(sys,'path',list(sys.path)),patch.object(risk,'GitHub',return_value=FakeGitHub()),\
             patch.object(risk,'now',return_value=AT):
            with self.assertRaises(SystemExit) as error:exec(compile(body,'private-workflow','exec'),{})
            self.assertEqual(str(error.exception),'private approval unavailable')
            self.assertFalse((Path(directory)/'private-approval/approval.json').exists())


if __name__=='__main__':
    unittest.main()

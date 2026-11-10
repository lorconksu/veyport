"""Direct committed orchestration admission, not candidate runtime/test truth."""
import base64
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sonar_bridge as bridge
from test_sonar_bridge_bootstrap import (CONTROL, MERGE, REPO, SOURCE, FakeAPI,
    producer_controls_fixture, producer_env, producer_registry,
    public_coverage_fixture)


class ProducerControlTests(unittest.TestCase):
    def changed(self, api, selected, raw=b'print("fabricated coverage; tests not executed")\n'):
        original = api.get
        blob_id = bridge.hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\x00' + raw, usedforsecurity=False).hexdigest()
        def get(path, **kwargs):
            if path == 'git/blobs/' + blob_id:
                api.calls.append(path)
                return {'sha': blob_id, 'size': len(raw), 'encoding': 'base64', 'content': base64.b64encode(raw).decode()}
            value = original(path, **kwargs)
            if path.startswith('git/trees/'):
                for row in value['tree']:
                    if row['path'] == selected:
                        row.update(sha=blob_id, size=len(raw))
            return value
        api.get = get

    def mutate(self, api, target, mutation):
        original = api.get
        def get(path, **kwargs):
            value = original(path, **kwargs)
            if target(path):
                mutation(value)
            return value
        api.get = get

    def intake(self, api, root):
        return bridge.intake(api, {'action': 'in_progress', 'repository': REPO,
            'workflow_run': copy.deepcopy(api.run)}, root / 'intake', timeout=10)

    def test_unchanged_controls_admit_actual_checkout_head_not_workflow_merge(self):
        api = FakeAPI()
        with patch.dict(os.environ, {'SONAR_BRIDGE_TOOLING_REVISION': CONTROL}, clear=True):
            proof = bridge.producer_controls(api, api.run)
        self.assertEqual(proof, producer_controls_fixture())
        self.assertIn('git/commits/' + SOURCE, api.calls)
        self.assertNotIn('git/commits/' + MERGE, api.calls)
        self.assertEqual(set(proof['controls']), set(bridge.PRODUCER_CONTROLS))
        self.assertIn('source-only', proof['authority'])

    def test_each_fabricated_committed_driver_rejected_before_extract_or_claim(self):
        for control in bridge.PRODUCER_CONTROLS:
            with self.subTest(control=control), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); api = FakeAPI(); self.changed(api, control)
                with patch.dict(os.environ, producer_env(root), clear=True), patch.object(bridge, 'extract') as extract:
                    with self.assertRaisesRegex(ValueError, 'Committed producer control differs'):
                        self.intake(api, root)
                    extract.assert_not_called()
                self.assertFalse((root / 'intake/claim.json').exists())
                self.assertFalse((root / 'intake/intake.json').exists())

    def test_missing_alternate_and_path_traversal_registry_fail_closed(self):
        for fault in ('missing', 'extra', 'traversal', 'digest', 'legacy', 'not-object'):
            with self.subTest(fault=fault):
                api = FakeAPI()
                original = api.get
                def get(path, **kwargs):
                    value = original(path, **kwargs)
                    if path.startswith('contents/' + bridge.APPROVALS):
                        registry = producer_registry()
                        if fault == 'missing': registry['producer_sha256'].pop(bridge.PRODUCER_CONTROLS[0])
                        elif fault == 'extra': registry['producer_sha256']['scripts/release/other.py'] = 'a' * 64
                        elif fault == 'traversal': registry['producer_sha256']['../capture_step.py'] = registry['producer_sha256'].pop(bridge.PRODUCER_CONTROLS[0])
                        elif fault == 'digest': registry['producer_sha256'][bridge.PRODUCER_CONTROLS[0]] = 'not-a-sha'
                        elif fault == 'legacy': registry.pop('producer_sha256'); registry['schema'] = 1
                        else: registry['producer_sha256'] = []
                        raw = bridge.canonical(registry)
                        value.update(size=len(raw), content=base64.b64encode(raw).decode())
                    return value
                api.get = get
                with self.assertRaises(ValueError): bridge.producer_controls(api, api.run, CONTROL)
                self.assertFalse(any(v.startswith('git/trees/') for v in api.calls))

    def test_nonregular_leaf_and_parent_modes_fail_closed(self):
        for mode, kind in [('120000', 'blob'), ('160000', 'commit'), ('040000', 'tree'), ('100644', 'tree')]:
            with self.subTest(mode=mode, kind=kind):
                api = FakeAPI()
                def mutate(value):
                    next(row for row in value['tree'] if row['path'] == bridge.PRODUCER_CONTROLS[0]).update(mode=mode, type=kind)
                self.mutate(api, lambda path: path.startswith('git/trees/'), mutate)
                with self.assertRaisesRegex(ValueError, 'regular Git blob'): bridge.producer_controls(api, api.run, CONTROL)
        api = FakeAPI()
        self.mutate(api, lambda path: path.startswith('git/trees/'),
            lambda value: next(row for row in value['tree'] if row['path'] == 'scripts').update(mode='120000', type='blob'))
        with self.assertRaisesRegex(ValueError, 'parent'): bridge.producer_controls(api, api.run, CONTROL)

    def test_complete_tree_and_canonical_paths_required(self):
        for fault in ('truncated', 'missing', 'duplicate', 'absolute', 'traversal', 'backslash', 'wrong-tree', 'too-many', 'bad-oid'):
            with self.subTest(fault=fault):
                api = FakeAPI()
                def mutate(value):
                    if fault == 'truncated': value['truncated'] = True
                    elif fault == 'missing': value['tree'] = value['tree'][:-1]
                    elif fault == 'duplicate': value['tree'].append(copy.deepcopy(value['tree'][0]))
                    elif fault == 'absolute': value['tree'][0]['path'] = '/scripts'
                    elif fault == 'traversal': value['tree'][0]['path'] = 'scripts/../scripts'
                    elif fault == 'backslash': value['tree'][0]['path'] = 'scripts\\release'
                    elif fault == 'wrong-tree': value['sha'] = '0' * 40
                    elif fault == 'too-many': value['tree'] = value['tree'] * 10001
                    else: value['tree'][-1]['sha'] = 'not-oid'
                self.mutate(api, lambda path: path.startswith('git/trees/'), mutate)
                with self.assertRaises(ValueError): bridge.producer_controls(api, api.run, CONTROL)

    def test_blob_identity_size_encoding_and_content_required(self):
        for fault in ('oid', 'size', 'encoding', 'base64', 'bytes', 'bound'):
            with self.subTest(fault=fault):
                api = FakeAPI()
                def mutate(value):
                    if fault == 'oid': value['sha'] = '0' * 40
                    elif fault == 'size': value['size'] += 1
                    elif fault == 'encoding': value['encoding'] = 'none'
                    elif fault == 'base64': value['content'] = 'bad base64!'
                    elif fault == 'bytes': value['content'] = base64.b64encode(b'x' * value['size']).decode()
                    else: value['content'] = 'x' * ((2 << 20) + 1)
                self.mutate(api, lambda path: path.startswith('git/blobs/'), mutate)
                with self.assertRaises(ValueError): bridge.producer_controls(api, api.run, CONTROL)

    def test_legacy_unapproved_workflow_rejected_without_fetching_new_controls(self):
        api = FakeAPI()
        def mutate(value):
            raw = b'unapproved legacy CI workflow'
            value.update(size=len(raw), content=base64.b64encode(raw).decode())
        self.mutate(api, lambda path: path.startswith('contents/.github/workflows/ci.yml'), mutate)
        with patch.dict(os.environ, {'SONAR_BRIDGE_TOOLING_REVISION': CONTROL}, clear=True), self.assertRaises(ValueError):
            bridge.coverage_provenance(api, api.run, api.artifacts[0], api.jobs[0], 'unit', api.payloads[100])
        self.assertFalse(any(v.startswith('git/trees/') or v.startswith('git/blobs/') for v in api.calls))

    def test_proof_propagates_and_plan_revalidates_before_scanner_issuance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); api = FakeAPI()
            with patch.dict(os.environ, producer_env(root), clear=True):
                plan = self.intake(api, root)
                self.assertLessEqual(len(bridge.canonical(plan)), 8192)
                for item in plan['coverage']:
                    self.assertEqual(item['provenance']['producer_controls'], producer_controls_fixture())
                bridge.validate_plan(api, plan)
                self.changed(api, bridge.PRODUCER_CONTROLS[0])
                with self.assertRaisesRegex(ValueError, 'Committed producer control differs'):
                    bridge.validate_plan(api, plan)

    def test_descriptor_requires_same_fresh_control_proof_and_final_attempt(self):
        api = FakeAPI(); source = bridge.source_identity(api.run)
        result = {'schema': 1, 'source': source, 'producer': {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL,
            'path': bridge.WORKFLOW, 'tooling_revision': CONTROL}, 'context': bridge.context(api, api.run),
            'task_id': 'bounded_task', 'scanner_action': bridge.ACTION, 'scanner_outcome': 'success',
            'coverage_provenance': public_coverage_fixture(api), 'authority': 'technical-scan-identity-only'}
        record = api.add_artifact(200, 'sonar-bridge-v1-123-2', 456, {'descriptor.json': bridge.canonical(result)})
        self.assertEqual(bridge.verify_result(api, record, source, CONTROL)['scan_status'], 'success')
        self.changed(api, bridge.PRODUCER_CONTROLS[-1])
        with self.assertRaisesRegex(ValueError, 'Committed producer control differs'):
            bridge.verify_result(api, record, source, CONTROL)

    def test_descriptor_rejects_missing_tampered_and_extra_control_proof(self):
        for attack in ('missing', 'mode', 'revision', 'extra'):
            with self.subTest(attack=attack):
                api = FakeAPI(); source = bridge.source_identity(api.run)
                coverage = public_coverage_fixture(api)
                proof = coverage[0]['provenance']['producer_controls']
                if attack == 'missing': coverage[0]['provenance'].pop('producer_controls')
                elif attack == 'mode': proof['controls'][bridge.PRODUCER_CONTROLS[0]]['mode'] = '120000'
                elif attack == 'revision': proof['revision'] = MERGE
                else: proof['controls']['scripts/release/extra.py'] = copy.deepcopy(next(iter(proof['controls'].values())))
                result = {'schema': 1, 'source': source, 'producer': {'id': 456, 'run_attempt': 1,
                    'head_sha': CONTROL, 'path': bridge.WORKFLOW, 'tooling_revision': CONTROL},
                    'context': bridge.context(api, api.run), 'task_id': 'bounded_task',
                    'scanner_action': bridge.ACTION, 'scanner_outcome': 'success',
                    'coverage_provenance': coverage, 'authority': 'technical-scan-identity-only'}
                record = api.add_artifact(200, 'sonar-bridge-v1-123-2', 456, {'descriptor.json': bridge.canonical(result)})
                with self.assertRaisesRegex(ValueError, 'Descriptor committed producer control admission differs'):
                    bridge.verify_result(api, record, source, CONTROL)

    def test_attempt_change_during_control_fetch_cannot_pass_final_plan_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); api = FakeAPI()
            with patch.dict(os.environ, producer_env(root), clear=True):
                plan = self.intake(api, root)
                original = api.get
                def get(path, **kwargs):
                    value = original(path, **kwargs)
                    if path.startswith('git/blobs/'):
                        api.run['run_attempt'] = 3
                    return value
                api.get = get
                with self.assertRaises(ValueError): bridge.validate_plan(api, plan)

    def test_attempt_change_during_final_descriptor_control_fetch_fails_closed(self):
        api = FakeAPI(); source = bridge.source_identity(api.run)
        result = {'schema': 1, 'source': source, 'producer': {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL,
            'path': bridge.WORKFLOW, 'tooling_revision': CONTROL}, 'context': bridge.context(api, api.run),
            'task_id': 'bounded_task', 'scanner_action': bridge.ACTION, 'scanner_outcome': 'success',
            'coverage_provenance': public_coverage_fixture(api), 'authority': 'technical-scan-identity-only'}
        record = api.add_artifact(200, 'sonar-bridge-v1-123-2', 456, {'descriptor.json': bridge.canonical(result)})
        original = api.get
        def get(path, **kwargs):
            value = original(path, **kwargs)
            if path.startswith('git/blobs/'):
                api.run['run_attempt'] = 3
            return value
        api.get = get
        with self.assertRaises(ValueError): bridge.verify_result(api, record, source, CONTROL)

    def test_candidate_configuration_changes_are_not_new_orchestration_pins(self):
        api = FakeAPI(); original = api.get
        def get(path, **kwargs):
            value = original(path, **kwargs)
            if path.startswith('git/trees/'):
                value['tree'].append({'path': 'web/package-lock.json', 'type': 'blob', 'mode': '100644',
                                     'sha': '9' * 40, 'size': 37})
            return value
        api.get = get
        self.assertEqual(bridge.producer_controls(api, api.run, CONTROL), producer_controls_fixture())
        self.assertFalse(any(v == 'git/blobs/' + '9' * 40 for v in api.calls))


if __name__ == '__main__':
    unittest.main()

"""Trusted negative lifecycle evidence and descriptor propagation regressions."""
import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import sonar_bridge as bridge
from test_sonar_bridge_bootstrap import CONTROL, SOURCE, FakeAPI, public_coverage_fixture

ROOT = Path(__file__).resolve().parents[2]


def result(api):
    return {'schema': 1, 'source': bridge.source_identity(api.run),
            'producer': {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL,
                         'path': bridge.WORKFLOW, 'tooling_revision': CONTROL},
            'context': bridge.context(api, api.run), 'task_id': 'lifecycle_task_123',
            'scanner_action': bridge.ACTION, 'scanner_outcome': 'success',
            'coverage_provenance': public_coverage_fixture(api), 'authority': 'technical-scan-identity-only'}


def marker(api, identifier=225, source_attempt=2, producer_attempt=1, rid=456):
    value = {'schema': 1, 'source': {'id': 123, 'run_attempt': source_attempt, 'head_sha': SOURCE},
             'producer': {'id': rid, 'run_attempt': producer_attempt, 'head_sha': CONTROL},
             'authority': 'negative-lifecycle-only'}
    return api.add_artifact(identifier, 'sonar-lifecycle-v1-123-' + str(source_attempt), rid,
                            {'lifecycle.json': bridge.canonical(value)})


class LifecycleTests(unittest.TestCase):
    def setup_wait(self, claim=True, lifecycle=False, completed=False):
        api = FakeAPI()
        api.producer.update(status='completed' if completed else 'in_progress', conclusion='failure' if completed else None)
        clock = [0]
        if claim:
            api.add_artifact(223, 'sonar-claim-v1-123-2', 456, {'claim.json': bridge.canonical(
                {'schema': 1, 'source': bridge.source_identity(api.run), 'producer': result(api)['producer']})})
        if lifecycle: marker(api)
        return api, clock

    def wait(self, api, clock, timeout=600):
        def sleep(seconds): clock[0] += seconds
        with patch.object(bridge.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(bridge.time, 'sleep', side_effect=sleep):
            return bridge.wait_result(api, 123, 2, SOURCE, CONTROL, timeout=timeout)

    def descriptor(self, api):
        api.producer.update(status='completed', conclusion='success')
        api.add_artifact(224, 'sonar-bridge-v1-123-2', 456, {'descriptor.json': bridge.canonical(result(api))})

    def test_completion_after_first_descriptor_listing_is_not_an_orphan(self):
        api, clock = self.setup_wait()
        api.add_artifact(224, 'sonar-bridge-v1-123-2', 456, {'descriptor.json': bridge.canonical(result(api))})
        original = api.get; listed = [False]
        def get(path, **kwargs):
            if 'name=sonar-claim-' in path and listed[0]:
                api.producer.update(status='completed', conclusion='success')
            value = original(path, **kwargs)
            if 'name=sonar-bridge-' in path: listed[0] = True
            return value
        api.get = get
        self.assertEqual(self.wait(api, clock)['scan_status'], 'success')
        self.assertEqual(clock[0], 60)

    def test_upload_after_first_listing_is_relisted_after_completed_observation(self):
        api, clock = self.setup_wait()
        original = api.get; listed = [False]; uploaded = [False]
        def get(path, **kwargs):
            if 'name=sonar-claim-' in path and listed[0] and not uploaded[0]:
                uploaded[0] = True; self.descriptor(api)
            value = original(path, **kwargs)
            if 'name=sonar-bridge-' in path: listed[0] = True
            return value
        api.get = get
        self.assertEqual(self.wait(api, clock)['scan_status'], 'success')
        self.assertEqual(clock[0], 60)

    def test_propagation_grace_admits_ready_descriptor_without_fixed_delay(self):
        for delay in (0, 60, 120):
            with self.subTest(delay=delay):
                api, clock = self.setup_wait(completed=True)
                original = api.get; uploaded = [False]
                def get(path, **kwargs):
                    if clock[0] >= delay and not uploaded[0]:
                        uploaded[0] = True; self.descriptor(api)
                    return original(path, **kwargs)
                api.get = get
                self.assertEqual(self.wait(api, clock)['scan_status'], 'success')
                self.assertEqual(clock[0], delay)

    def test_completed_empty_claim_or_lifecycle_stops_after_bounded_grace(self):
        for claim in (True, False):
            with self.subTest(claim=claim):
                api, clock = self.setup_wait(claim=claim, lifecycle=not claim, completed=True)
                with self.assertRaisesRegex(ValueError, 'ended without a usable descriptor'):
                    self.wait(api, clock, timeout=10800)
                self.assertEqual(clock[0], 120)
                self.assertGreaterEqual(sum('name=sonar-bridge-' in p for p in api.calls), 3)

    def test_marker_never_accepts_uncompleted_descriptor_or_authorizes_a_scan(self):
        api, clock = self.setup_wait(claim=False, lifecycle=True)
        api.add_artifact(224, 'sonar-bridge-v1-123-2', 456, {'descriptor.json': bridge.canonical(result(api))})
        with patch.object(bridge, 'verify_result') as verifier, self.assertRaisesRegex(ValueError, 'wait expired'):
            self.wait(api, clock, timeout=180)
        verifier.assert_not_called()
        self.assertEqual(clock[0], 120)

    def test_missing_untrusted_or_previous_source_attempt_marker_cannot_fail_current_attempt(self):
        for kind in ('missing', 'candidate', 'previous-source-attempt', 'previous-producer-attempt'):
            with self.subTest(kind=kind):
                api, clock = self.setup_wait(claim=False, completed=True)
                if kind == 'candidate': marker(api, rid=123)
                if kind == 'previous-source-attempt': marker(api, source_attempt=1)
                if kind == 'previous-producer-attempt':
                    marker(api)
                    api.producer['run_attempt'] = 2
                    original = api.get
                    def get(path, **kwargs):
                        if path == 'actions/runs/456/attempts/2': return copy.deepcopy(api.producer)
                        return original(path, **kwargs)
                    api.get = get
                with self.assertRaisesRegex(ValueError, 'wait expired'):
                    self.wait(api, clock, timeout=240)
                self.assertEqual(clock[0], 180)

    def test_lifecycle_source_sha_and_producer_closure_must_match_before_use(self):
        for change in ('source-sha', 'control-file'):
            with self.subTest(change=change):
                api, clock = self.setup_wait(claim=False, completed=True)
                row = marker(api)
                if change == 'source-sha':
                    value = {'schema': 1, 'source': {'id': 123, 'run_attempt': 2, 'head_sha': CONTROL},
                             'producer': {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL},
                             'authority': 'negative-lifecycle-only'}
                    api.artifacts.remove(row)
                    api.add_artifact(225, row['name'], 456, {'lifecycle.json': bridge.canonical(value)})
                else:
                    original = api.get
                    def get(path, **kwargs):
                        value = original(path, **kwargs)
                        if path.startswith('contents/') and path.endswith('?ref=' + CONTROL): value['path'] = 'foreign'
                        return value
                    api.get = get
                with self.assertRaises(ValueError): self.wait(api, clock)
                self.assertEqual(clock[0], 0)
                if change == 'control-file': self.assertNotIn('actions/artifacts/225/zip', api.calls)

    def test_long_preclaim_wait_caches_immutable_control_but_checks_current_identity(self):
        api, clock = self.setup_wait(claim=False, lifecycle=True)
        original = api.get; uploaded = [False]
        def get(path, **kwargs):
            if clock[0] >= 1800 and not uploaded[0]:
                uploaded[0] = True; self.descriptor(api)
            return original(path, **kwargs)
        api.get = get
        self.assertEqual(self.wait(api, clock, timeout=3000)['scan_status'], 'success')
        self.assertEqual(api.calls.count('actions/artifacts/225/zip'), 1)
        self.assertGreaterEqual(api.calls.count('actions/artifacts/225'), 30)
        self.assertLess(len(api.calls), 400)

    def test_source_retry_or_claim_identity_change_during_grace_is_rejected(self):
        for kind in ('source-attempt', 'producer-attempt', 'claim-removal'):
            with self.subTest(kind=kind):
                api, clock = self.setup_wait(completed=True)
                original = api.get
                def get(path, **kwargs):
                    if clock[0] >= 60:
                        if kind == 'source-attempt': api.run['run_attempt'] = 3
                        if kind == 'producer-attempt': api.producer['run_attempt'] = 2
                        if kind == 'claim-removal': api.artifacts[:] = [v for v in api.artifacts if v['id'] != 223]
                    return original(path, **kwargs)
                api.get = get
                with self.assertRaises(ValueError): self.wait(api, clock)
                self.assertEqual(clock[0], 60)

    def test_terminal_first_observation_is_not_reset_by_temporary_absence(self):
        for kind in ('listing', 'status'):
            with self.subTest(kind=kind):
                api, clock = self.setup_wait(claim=False, lifecycle=True, completed=True)
                original = api.get
                def get(path, **kwargs):
                    if kind == 'status':
                        api.producer['status'] = 'in_progress' if clock[0] == 60 else 'completed'
                    if kind == 'listing' and clock[0] == 60 and 'name=sonar-lifecycle-' in path:
                        return {'total_count': 0, 'artifacts': []}
                    return original(path, **kwargs)
                api.get = get
                with self.assertRaisesRegex(ValueError, 'ended without a usable descriptor'):
                    self.wait(api, clock, timeout=10800)
                self.assertEqual(clock[0], 120)

    def test_cached_lifecycle_never_hides_mutable_artifact_or_producer_changes(self):
        for kind in ('artifact-digest', 'producer-sha', 'source-attempt'):
            with self.subTest(kind=kind):
                api, clock = self.setup_wait(claim=False, lifecycle=True)
                original = api.get
                def get(path, **kwargs):
                    if clock[0] >= 60:
                        if kind == 'artifact-digest':
                            next(row for row in api.artifacts if row['id'] == 225)['digest'] = 'sha256:' + 'f' * 64
                        if kind == 'producer-sha': api.producer['head_sha'] = SOURCE
                        if kind == 'source-attempt': api.run['run_attempt'] = 3
                    return original(path, **kwargs)
                api.get = get
                with self.assertRaises(ValueError): self.wait(api, clock)
                self.assertEqual(clock[0], 60)

    def test_grace_does_not_extend_absolute_deadline_or_retry_permission_errors(self):
        api, clock = self.setup_wait(completed=True)
        with self.assertRaisesRegex(ValueError, 'wait expired'): self.wait(api, clock, timeout=100)
        self.assertEqual(clock[0], 60)
        api, clock = self.setup_wait(claim=False, lifecycle=True, completed=True)
        original = api.get
        def denied(path, **kwargs):
            if 'name=sonar-lifecycle-' in path: raise ValueError('permission denied')
            return original(path, **kwargs)
        api.get = denied
        with self.assertRaisesRegex(ValueError, 'permission denied'): self.wait(api, clock)
        self.assertEqual(clock[0], 0)


class LifecycleWriterTests(unittest.TestCase):
    def writer(self):
        workflow = (ROOT / '.github/workflows/sonar-bridge.yml').read_text()
        self.assertLess(workflow.index('Record exact platform source attempt'), workflow.index('actions/checkout@'))
        self.assertLess(workflow.index('sonar-lifecycle-v1-'), workflow.index('Validate source attempt'))
        block = workflow.split("python3 -I -S - <<'PYCODE'\n", 1)[1].split('          PYCODE', 1)[0]
        return '\n'.join(line[10:] for line in block.splitlines())

    def event(self):
        return {'action': 'in_progress', 'repository': {'full_name': bridge.REPOSITORY},
                'workflow_run': {'id': 123, 'run_attempt': 2, 'head_sha': SOURCE}}

    def environment(self, root):
        return dict(os.environ, GITHUB_REPOSITORY=bridge.REPOSITORY, GITHUB_EVENT_NAME='workflow_run',
                    GITHUB_REF='refs/heads/main', GITHUB_WORKFLOW_REF=bridge.REPOSITORY + '/' + bridge.WORKFLOW + '@refs/heads/main',
                    GITHUB_RUN_ID='456', GITHUB_RUN_ATTEMPT='1', GITHUB_SHA=CONTROL,
                    GITHUB_EVENT_PATH=str(root / 'event.json'), RUNNER_TEMP=str(root), GITHUB_OUTPUT=str(root / 'output'))

    def invalid_events(self):
        valid = json.dumps(self.event(), separators=(',', ':'))
        duplicate = valid.replace('"action":"in_progress"', '"action":"ignored","action":"in_progress"', 1)
        # Otherwise-valid JSON exactly one byte beyond the stat admission bound;
        # removing that guard must let the full bounded read reach the writer.
        padded = {**self.event(), 'padding': ''}
        overhead = len(json.dumps(padded, separators=(',', ':')).encode())
        padded['padding'] = 'x' * ((1 << 20) + 1 - overhead)
        oversized = json.dumps(padded, separators=(',', ':'))
        self.assertEqual(len(oversized.encode()), (1 << 20) + 1)
        rejection = 'ValueError: Exact main workflow event required for lifecycle marker'
        return [('duplicate-key', duplicate, rejection),
                ('non-object', '[]', "AttributeError: 'list' object has no attribute 'get'"),
                ('oversize', oversized, rejection)]

    def test_native_marker_uses_exact_event_without_checkout_or_candidate_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'event.json').write_text(json.dumps(self.event()))
            proc = subprocess.run([sys.executable, '-I', '-S', '-c', self.writer()], env=self.environment(root),
                                  cwd=root, capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            marker_path = root / 'sonar-lifecycle/lifecycle.json'
            value = json.loads(marker_path.read_bytes())
            self.assertEqual(value['source'], {'id': 123, 'run_attempt': 2, 'head_sha': SOURCE})
            self.assertEqual(value['producer'], {'id': 456, 'run_attempt': 1, 'head_sha': CONTROL})
            self.assertEqual(value['authority'], 'negative-lifecycle-only')
            self.assertEqual(stat.S_IMODE(marker_path.stat().st_mode), 0o600)
            self.assertLess(len(marker_path.read_bytes()), 2048)
            self.assertEqual((root / 'output').read_text(), 'source_key=123-2\n')

    def test_native_marker_rejects_invalid_events_before_any_write(self):
        for label, raw, rejection in self.invalid_events():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'event.json').write_text(raw)
                rejected = subprocess.run([sys.executable, '-I', '-S', '-c', self.writer()], env=self.environment(root),
                                          cwd=root, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(rejection, rejected.stderr)
                self.assertNotIn('FileExistsError', rejected.stderr)
                self.assertFalse((root / 'sonar-lifecycle').exists())
                self.assertFalse((root / 'output').exists())


if __name__ == '__main__':
    unittest.main()

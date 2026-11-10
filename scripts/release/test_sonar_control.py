"""Real isolated consumer loading and CI-only evidence adapter regressions."""
import copy
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import ci_evidence
import ci_evidence_crypto as client
import sonar_bridge
import sonar_control
import sonar_job_evidence as capture

ROOT = Path(__file__).resolve().parents[2]
REVISION = 'a' * 40
CONTEXT = '-Dsonar.pullrequest.key=115 -Dsonar.pullrequest.branch=feature -Dsonar.pullrequest.base=main'


def commit_fixture(path):
    environment = {'PATH': os.environ['PATH'], 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    subprocess.run(['git', 'init', '-q', str(path)], env=environment, check=True, capture_output=True)
    subprocess.run(['git', '-C', str(path), 'add', '.'], env=environment, check=True, capture_output=True)
    subprocess.run(['git', '-C', str(path), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture'],
                   env=environment, check=True, capture_output=True)
    return subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], env=environment, text=True).strip()


class Provider:
    def __init__(self, gate):
        self.gate = gate
        self.analysis_date = dt.datetime.now(dt.timezone.utc).isoformat()

    def get(self, endpoint, params):
        task = {'id': 'task-1', 'componentKey': capture.PROJECT, 'status': 'SUCCESS',
                'analysisId': 'analysis-1', 'pullRequest': '115'}
        if endpoint == 'ce/component':
            return {'queue': [], 'current': task}
        if endpoint == 'components/show':
            return {'component': {'key': capture.PROJECT, 'visibility': 'public'}}
        if endpoint == 'qualitygates/project_status':
            return {'projectStatus': {'status': self.gate}}
        if endpoint == 'project_pull_requests/list':
            return {'pullRequests': [{'key': '115', 'commit': {'sha': REVISION}, 'branch': 'feature', 'base': 'main',
                     'analysisDate': self.analysis_date, 'status': {'qualityGateStatus': self.gate}}]}
        return {'paging': {'pageIndex': params['p'], 'pageSize': params['ps'], 'total': 0},
                {'issues/search': 'issues', 'hotspots/search': 'hotspots'}[endpoint]: []}


class TrustedConsumerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.workspace = self.root / 'workspace'
        self.source = self.workspace / 'candidate-source'
        self.trusted = self.workspace / 'trusted-control'
        self.runtime = self.root / 'runner'
        self.runtime.mkdir()
        self.marker = self.root / 'candidate-executed'
        for name in sonar_control.CLOSURE:
            target = self.trusted / 'scripts/release' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / 'scripts/release' / name).read_bytes())
            for folder in (self.source, self.source / 'scripts/release'):
                folder.mkdir(parents=True, exist_ok=True)
                (folder / name).write_text("import os\nfrom pathlib import Path\nPath(os.environ['MARKER']).write_text('candidate ran')\nprint('task_id=forged')\nif os.environ.get('GITHUB_OUTPUT'): Path(os.environ['GITHUB_OUTPUT']).write_text('task_id=forged\\nscan_status=success\\n')\n")
        (self.source / 'sitecustomize.py').write_text("raise RuntimeError('candidate startup hook executed')\n")
        self.pin = commit_fixture(self.trusted)
        self.revision = commit_fixture(self.source)
        self.environment = {'PATH': os.environ['PATH'], 'HOME': str(self.root), 'GITHUB_WORKSPACE': str(self.workspace), 'RUNNER_TEMP': str(self.runtime),
            'GITHUB_REPOSITORY': 'lorconksu/veyport', 'SONAR_CREDENTIAL_MODE': 'bridge',
            'SONAR_BRIDGE_TOOLING_REVISION': self.pin, 'EXPECTED_SOURCE_SHA': self.revision,
            'GITHUB_RUN_ID': '0', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_OUTPUT': str(self.root / 'outputs'),
            'MARKER': str(self.marker), 'PYTHONPATH': str(self.source)}

    def launch(self, *args, environment=None):
        return subprocess.run([sys.executable, '-I', '-S', str(self.trusted / 'scripts/release/sonar_control.py'), *args],
                              cwd=self.source, env={**self.environment, **(environment or {})}, capture_output=True, timeout=15)

    def test_malicious_candidate_helpers_and_pythonpath_never_execute(self):
        for program in ('wait', 'capture', 'encrypt'):
            result = self.launch(program, '--help')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b'usage:', result.stdout)
            self.assertFalse(self.marker.exists())
        self.assertFalse(Path(self.environment['GITHUB_OUTPUT']).exists())

    def test_invalid_actual_run_cannot_become_candidate_forged_success(self):
        result = self.launch('wait', '--revision', self.revision, '--output', str(self.runtime / 'descriptor.json'), '--timeout', '1')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b'Sonar bridge failed closed', result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertFalse((self.runtime / 'descriptor.json').exists())
        self.assertFalse(Path(self.environment['GITHUB_OUTPUT']).exists())

    def test_wrong_main_pin_or_source_revision_stops_before_loading(self):
        for name in ('SONAR_BRIDGE_TOOLING_REVISION', 'EXPECTED_SOURCE_SHA'):
            result = self.launch('encrypt', '--help', environment={name: '0' * 40})
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.marker.exists())

    def test_unapproved_program_and_import_link_are_refused(self):
        self.assertNotEqual(self.launch('../candidate-source/scripts/release/sonar_bridge.py').returncode, 0)
        target = self.trusted / 'scripts/release/risk_acceptance.py'
        target.unlink()
        target.symlink_to(self.source / 'risk_acceptance.py')
        self.assertNotEqual(self.launch('wait', '--help').returncode, 0)
        self.assertFalse(self.marker.exists())


class ExportAndClientTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def manifest(self, raw=b'report'):
        digest = hashlib.sha256(raw).hexdigest()
        staging = self.root / 'staging'
        (staging / 'parts').mkdir(parents=True, exist_ok=True)
        (staging / 'parts' / digest).write_bytes(raw)
        return {'schema': 1, 'repository': 'lorconksu/veyport', 'workflow': '.github/workflows/ci.yml',
                'run_id': 123, 'run_attempt': 1, 'revision': REVISION, 'candidate_id': 'run-123-1', 'complete': False,
                'files': [{'name': 'parts/' + digest, 'sha256': digest, 'size': len(raw)}],
                'details': {'kind': 'job-chunk', 'job': 'sonar', 'chunk_index': 0, 'chunk_count': 1,
                            'github_sha': 'b' * 40, 'checkout_revision': REVISION, 'status': 'failure',
                            'missing': [], 'original_files': [], 'omitted_files': [],
                            'diagnostic_policy': 'redacted-text-only/v1', 'dast': 'deferred-owner-decision'}}, staging

    def test_partial_ci_adapter_rejects_complete_and_foreign_authorities(self):
        original, staging = self.manifest()
        for attack in ('complete', 'candidate', 'publication', 'delivery', 'unknown-field', 'malformed-runtime-sha', 'boolean-schema'):
            value = copy.deepcopy(original)
            if attack == 'complete':
                value['complete'] = True
            elif attack in ('candidate', 'publication'):
                value['details']['kind'] = attack
            elif attack == 'delivery':
                value['workflow'] = '.github/workflows/delivery.yml'
            elif attack == 'boolean-schema':
                value['schema'] = True
            elif attack == 'malformed-runtime-sha':
                value['details']['github_sha'] = 'not-a-sha'
            else:
                value['candidate_revision'] = REVISION
            with self.subTest(attack=attack), self.assertRaises(ValueError):
                client.pack(value, staging)

    def test_client_parts_are_bounded_regular_and_exact(self):
        original, staging = self.manifest()
        for attack in ('traversal', 'oversize', 'duplicate', 'wrong-digest', 'symlink'):
            value = copy.deepcopy(original)
            if attack == 'traversal':
                value['files'][0]['name'] = '../outside'
            elif attack == 'oversize':
                value['files'][0]['size'] = client.PART + 1
            elif attack == 'duplicate':
                value['files'].append(copy.deepcopy(value['files'][0]))
            elif attack == 'wrong-digest':
                (staging / original['files'][0]['name']).write_bytes(b'changed')
            else:
                target = staging / original['files'][0]['name']
                target.unlink()
                target.symlink_to('/etc/passwd')
            with self.subTest(attack=attack), self.assertRaises((ValueError, OSError)):
                client.pack(value, staging)

    def test_sequential_bridge_and_provider_exports_preserve_the_actual_gate(self):
        for gate in ('OK', 'ERROR'):
            with self.subTest(gate=gate):
                evidence = self.root / gate / 'evidence'
                sonar_bridge.write_record(evidence / 'bridge.json', {'task_id': 'task-1'})
                task = self.root / ('task-' + gate + '.txt')
                task.write_text('serverUrl=https://sonarcloud.io\nprojectKey=' + capture.PROJECT + '\nceTaskId=task-1\n')
                argv = ['sonar_job_evidence.py', '--report-task', str(task), '--context=' + CONTEXT,
                        '--revision', REVISION, '--output', str(evidence / 'provider'), '--timeout', '1', '--public-project-results']
                code = 0
                with patch.object(capture, 'Sonar', return_value=Provider(gate)), patch.object(sys, 'argv', argv):
                    try:
                        capture.main()
                    except SystemExit as stopped:
                        code = stopped.code
                self.assertEqual(code, 1 if gate == 'ERROR' else 0)
                record = json.loads((evidence / 'provider/capture.json').read_text())
                self.assertEqual(record['status'], 'completed')
                self.assertEqual(record['quality_gate'], gate)
                self.assertTrue((evidence / 'provider/issues.json').is_file())
                self.assertTrue((evidence / 'bridge.json').is_file())

    def test_real_age_encryption_keeps_separate_source_and_failed_report_binding(self):
        if not shutil.which('age') or not shutil.which('age-keygen'):
            raise RuntimeError('real age/age-keygen required; CI installs age')
        source = self.root / 'source'
        source.mkdir()
        (source / 'data.txt').write_text('candidate data only')
        revision = commit_fixture(source)
        evidence = self.root / 'evidence'
        (evidence / 'provider').mkdir(parents=True)
        (evidence / 'bridge.json').write_text('{"task_id":"task-1"}')
        (evidence / 'provider/capture.json').write_text('{"status":"completed","quality_gate":"ERROR"}')
        identity = self.root / 'identity'
        subprocess.run(['age-keygen', '-o', str(identity)], check=True, capture_output=True)
        recipient = subprocess.check_output(['age-keygen', '-y', str(identity)], text=True).strip()
        environment = {'GITHUB_REPOSITORY': 'lorconksu/veyport', 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
                       'GITHUB_SHA': 'b' * 40, 'RUNNER_TEMP': str(self.root), 'PATH': os.environ['PATH']}
        output = self.root / 'encrypted'
        with patch.dict(os.environ, environment, clear=True):
            ci_evidence.encrypt_job(evidence, output, recipient, 'sonar', 'failure', ['**/*'], revision,
                                    '.github/workflows/ci.yml', source_root=source)
        wire = next(output.glob('*.age')).read_bytes()
        self.assertTrue(wire.startswith(b'age-encryption.org/v1\n'))
        decrypted = subprocess.run(['age', '-d', '-i', str(identity)], input=wire, check=True, capture_output=True).stdout
        with zipfile.ZipFile(io.BytesIO(decrypted)) as archive:
            manifest = json.loads(archive.read('manifest.json'))
            self.assertTrue(all(item.compress_type == zipfile.ZIP_STORED for item in archive.infolist()))
        self.assertEqual(manifest['details']['status'], 'failure')
        self.assertEqual(manifest['revision'], revision)
        self.assertFalse(manifest['complete'])
        self.assertEqual({item['name'] for item in manifest['details']['original_files']}, {'bridge.json', 'provider/capture.json'})


if __name__ == '__main__':
    unittest.main()

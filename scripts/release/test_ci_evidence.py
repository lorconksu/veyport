import contextlib
import hashlib
import importlib.util
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

import capture_step
import ci_evidence

ROOT = Path(__file__).resolve().parents[2]
REV = 'a' * 40
spec = importlib.util.spec_from_file_location('test_job_crypto', ROOT / 'infra/evidence-collector/evidence.py')
crypto = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crypto)


class PrivateJobEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('age') or not shutil.which('age-keygen'):
            raise RuntimeError('real age and age-keygen required; CI installs age before helper tests')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.identity = self.root / 'identity'
        subprocess.run(['age-keygen', '-o', str(self.identity)], check=True, capture_output=True)
        self.recipient = subprocess.check_output(['age-keygen', '-y', str(self.identity)]).decode().strip()
        self.environment = {'GITHUB_REPOSITORY': 'lorconksu/veyport', 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'c' * 40, 'RUNNER_TEMP': str(self.root)}

    def encrypt(self, paths, status='success'):
        with patch.dict(os.environ, self.environment), patch.object(ci_evidence.subprocess, 'check_output', return_value=(REV + '\n').encode()):
            ci_evidence.encrypt_job(self.source, self.root / 'encrypted', self.recipient, 'unit', status, paths, REV, '.github/workflows/ci.yml')
        results = []
        for path in sorted((self.root / 'encrypted').glob('*.age')):
            wire = path.read_bytes()
            self.assertNotIn(b'sensitive-test-token-value', wire)
            results.append(crypto.unpack(crypto.age_decrypt(wire, self.identity)))
        return results

    def test_real_crypto_chunk_reconstruction_redaction_and_context_binding(self):
        (self.source / 'report.json').write_text('{"token":"sensitive-test-token-value","count":1}')
        (self.source / 'large.out').write_bytes(b'a' * (ci_evidence.PART + 17))
        chunks = self.encrypt(['*.json', '*.out'])
        self.assertGreaterEqual(len(chunks), 2)
        blobs = {digest: data for _, contents in chunks for digest, data in contents.items()}
        original = chunks[0][0]['details']['original_files']
        for item in original:
            rebuilt = b''.join(blobs[p['sha256']] for p in item['parts'])
            self.assertEqual(hashlib.sha256(rebuilt).hexdigest(), item['sha256'])
            self.assertEqual(len(rebuilt), item['size'])
            if item['name'] == 'report.json':
                self.assertNotIn(b'sensitive-test-token-value', rebuilt)
                self.assertTrue(item['redacted'])
        for manifest, _ in chunks:
            self.assertFalse(manifest['complete'])
            self.assertEqual(manifest['details']['github_sha'], 'c' * 40)
            self.assertEqual(manifest['details']['checkout_revision'], REV)
            self.assertLessEqual(sum(f['size'] for f in manifest['files']), ci_evidence.PART)

    def test_missing_outputs_are_explicit_partial_evidence(self):
        chunks = self.encrypt(['missing.json'], 'failure')
        self.assertEqual(len(chunks), 1)
        manifest = chunks[0][0]
        self.assertEqual(manifest['files'], [])
        self.assertEqual(manifest['details']['missing'], ['missing.json'])
        self.assertEqual(manifest['details']['status'], 'failure')

    def test_symlink_and_wrong_checkout_are_rejected(self):
        (self.source / 'link.json').symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            self.encrypt(['link.json'])
        with patch.dict(os.environ, self.environment), patch.object(ci_evidence.subprocess, 'check_output', return_value=b'b' * 40 + b'\n'):
            with self.assertRaises(ValueError):
                ci_evidence.encrypt_job(self.source, self.root / 'other', self.recipient, 'unit', 'success', [], REV, '.github/workflows/ci.yml')

    def test_trace_auth_headers_body_and_resources_are_redacted(self):
        source = io.BytesIO()
        with zipfile.ZipFile(source, 'w') as archive:
            archive.writestr('test.network', json.dumps({'headers': [{'name': 'Authorization', 'value': 'secret'}], 'postData': 'password', 'status': 200}) + '\n')
            archive.writestr('resources/credential-response', b'sensitive-test-token-value')
        sanitized = ci_evidence.browser_archive(source.getvalue())
        with zipfile.ZipFile(io.BytesIO(sanitized)) as archive:
            self.assertNotIn(b'sensitive-test-token-value', archive.read('resources/credential-response'))
            record = json.loads(archive.read('test.network'))
            self.assertEqual(record['headers'], '[REDACTED]')
            self.assertEqual(record['postData'], '[REDACTED]')
            self.assertEqual(record['status'], 200)

    def test_malicious_trace_paths_rejected(self):
        source = io.BytesIO()
        with zipfile.ZipFile(source, 'w') as archive:
            archive.writestr('../escape', b'unsafe')
        with self.assertRaises(ValueError):
            ci_evidence.browser_archive(source.getvalue())


class PrivateCaptureTests(unittest.TestCase):
    def test_failure_diagnostics_retained_without_console_contents(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'RUNNER_TEMP': directory}):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = capture_step.capture('fixture', ['bash', '-c', 'echo sensitive-diagnostic; exit 7'], 5)
            self.assertEqual(code, 7)
            self.assertNotIn('sensitive-diagnostic', output.getvalue())
            root = Path(directory) / 'ssdf-results'
            self.assertIn('sensitive-diagnostic', (root / 'fixture.stdout').read_text())
            self.assertEqual(json.loads((root / 'fixture.result.json').read_text())['exit_code'], 7)

    def test_cli_preserves_child_umask_while_capture_files_stay_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "public-checkpoint"
            child = "import os,sys; descriptor=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644); os.close(descriptor)"
            result = subprocess.run([sys.executable, str(ROOT / "scripts/release/capture_step.py"), "--name", "permissions", "--", sys.executable, "-c", child, str(public)],
                                    env={**os.environ, "RUNNER_TEMP": directory}, umask=0o022, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(public.stat().st_mode & 0o777, 0o644)
            logs = root / "ssdf-results"
            self.assertEqual(logs.stat().st_mode & 0o777, 0o700)
            for name in ("permissions.stdout", "permissions.stderr", "permissions.result.json"):
                self.assertEqual((logs / name).stat().st_mode & 0o777, 0o600)

    def test_timeout_is_failure(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'RUNNER_TEMP': directory}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(capture_step.capture('timeout', ['sleep', '2'], 1), 124)
            result = json.loads((Path(directory) / 'ssdf-results/timeout.result.json').read_text())
            self.assertTrue(result['timed_out'])

    def test_ci_keeps_coverage_consumers_and_encrypts_scanner_reports(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('name: coverage-units', workflow)
        self.assertIn('name: coverage-integration', workflow)
        for name in ('semgrep-results', 'gitleaks-results', 'playwright-report', 'source-vulnerability-results'):
            self.assertNotIn('name: ' + name + '\n          path:', workflow)
        self.assertEqual(workflow.count('name: Transfer only encrypted job evidence'), 10)
        self.assertIn('if: ${{ !inputs.defer_semgrep_to_delivery }}', workflow)


if __name__ == '__main__':
    unittest.main()

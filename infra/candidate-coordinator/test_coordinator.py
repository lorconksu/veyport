"""Candidate transport, identity, lease and fail-closed qualification regressions."""
import copy
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('coordinator', Path(__file__).with_name('coordinator.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
e = c.e


def hold_lease(config, ready):
    with c.lease(config):
        ready.set()
        time.sleep(2)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.payload = b'exact-candidate-test-binary'
        self.candidate = {'schema_version': 1, 'repository': 'owner/repo', 'workflow': '.github/workflows/staging.yml', 'run_id': 123, 'run_attempt': 1, 'revision': 'a' * 40, 'candidate_id': 'run-123-1', 'version': '0.0.0-prototype', 'audit_profile': 'standard', 'files': [{'name': 'bin/agent', 'size': len(self.payload), 'sha256': e.digest(self.payload)}]}
        self.config = {'repository': 'owner/repo', 'allowed_workflows': ['.github/workflows/staging.yml'], 'allowed_branches': ['main'], 'allowed_events': ['push'], 'state_root': str(self.root), 'minimum_free_bytes': 0, 'audit_profile': 'standard', 'required_cases': ['case-' + str(i) for i in range(6)]}
        self.run = {'id': 123, 'run_attempt': 1, 'repository': {'full_name': 'owner/repo'}, 'head_repository': {'full_name': 'owner/repo'}, 'head_sha': 'a' * 40, 'head_branch': 'main', 'path': '.github/workflows/staging.yml', 'event': 'push', 'status': 'in_progress'}
        self.config['agent_runtime_image'] = 'sha256:' + 'd' * 64
        self.runtime = {'agent_binary_sha256': 'e' * 64, 'hub_image_id': 'sha256:' + 'b' * 64, 'hub_container_id': 'c' * 64}
        self.report = {'schema_version': 1, 'status': 'completed', 'candidate_qualified': True, 'candidate_id': self.candidate['candidate_id'], 'revision': self.candidate['revision'], 'artifact_manifest_sha256': e.digest(e.canonical(self.candidate)), 'audit_profile': 'standard', 'enhanced_receipt_exercised': False, 'required_audit_admission_exercised': True, 'required_scopes': ['native:grpc', 'native:ssh'], 'scopes': [{'id': scope, 'status': 'completed', 'authenticated': True, 'coverage_complete': True, 'findings': []} for scope in ['native:grpc', 'native:ssh']], 'runtime': dict(self.runtime, agent_image_id=self.config['agent_runtime_image']), 'cases': [{'id': name, 'status': 'pass'} for name in self.config['required_cases']]}

    def tar(self, mode='valid'):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as archive:
            manifest = copy.deepcopy(self.candidate)
            if mode == 'path':
                manifest['files'][0]['name'] = '../escape'
            data = e.canonical(manifest)
            info = tarfile.TarInfo('candidate.json')
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
            if mode == 'missing':
                return raw
            info = tarfile.TarInfo('delivery/' + manifest['files'][0]['name'])
            info.size = len(self.payload)
            info.mtime = time.time()  # Exercise genuine PAX metadata produced by sender.
            if mode == 'symlink':
                info.type = tarfile.SYMTYPE
                info.linkname = '/etc/passwd'
                info.size = 0
            archive.addfile(info, io.BytesIO(self.payload if mode != 'corrupt' else b'x' * len(self.payload)))
            if mode == 'extra':
                info = tarfile.TarInfo('extra')
                info.size = 1
                archive.addfile(info, io.BytesIO(b'x'))
        raw.seek(0)
        return raw

    def test_stream_tar_accepts_exact_inventory_and_rejects_traversal_links_extra_missing_corruption(self):
        m = c.extract_stream(self.tar(), self.root / 'valid', time.monotonic() + 10)
        self.assertEqual(m, self.candidate)
        self.assertEqual((self.root / 'valid/bin/agent').read_bytes(), self.payload)
        for mode in ('path', 'symlink', 'extra', 'corrupt', 'missing'):
            with self.subTest(mode=mode), self.assertRaises((e.EvidenceError, tarfile.TarError)):
                raw = self.tar(mode)
                raw.seek(0)
                c.extract_stream(raw, self.root / mode, time.monotonic() + 10)
        self.assertFalse((self.root / 'escape').exists())

    def test_tar_metadata_and_timeout_are_bounded(self):
        reader = c.BoundedReader(io.BytesIO(), time.monotonic() + 10)
        with self.assertRaises(e.EvidenceError):
            reader.read(c.MAX_METADATA + 1)
        expired = c.BoundedReader(io.BytesIO(b'x'), time.monotonic() - 1)
        with self.assertRaises(e.EvidenceError):
            expired.read(1)

    def test_real_recipient_encryption_sender_tar_and_truncated_ciphertext_fail(self):
        if not shutil.which('age') or not shutil.which('age-keygen'):
            self.fail('candidate tests require age and age-keygen installed')
        identity, recipients = self.root / 'identity', self.root / 'recipients'
        subprocess.run(['age-keygen', '-o', str(identity)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        recipients.write_bytes(subprocess.check_output(['age-keygen', '-y', str(identity)]))
        raw = self.tar().getvalue()
        ciphertext = e.age_encrypt(raw, recipients)
        path = self.root / 'candidate.age'
        path.write_bytes(ciphertext)
        self.assertEqual(c.decrypt_candidate(path, identity, self.root / 'decrypted'), self.candidate)
        path.write_bytes(ciphertext[:-1])
        with self.assertRaises(e.EvidenceError):
            c.decrypt_candidate(path, identity, self.root / 'truncated')

    def test_manifest_identity_and_mutated_bytes_rejected(self):
        c.bind_manifest(self.candidate, self.run, self.config)
        for key, value in [('run_id', 124), ('revision', 'b' * 40), ('workflow', '.github/workflows/other.yml')]:
            with self.subTest(key=key), self.assertRaises(e.EvidenceError):
                altered = dict(self.candidate, **{key: value})
                c.bind_manifest(altered, self.run, self.config)
        (self.root / 'bin').mkdir()
        (self.root / 'bin/agent').write_bytes(self.payload)
        c.verify_inventory(self.candidate, self.root)
        (self.root / 'bin/agent').write_bytes(b'changed')
        with self.assertRaises(e.EvidenceError):
            c.verify_inventory(self.candidate, self.root)

    def test_candidate_redirect_never_accepts_insecure_or_untrusted_hosts(self):
        valid = 'https://result.blob.core.windows.net/artifact?signature=fixture'
        self.assertEqual(c.trusted_blob_url(valid), valid)
        for url in ('http://result.blob.core.windows.net/x', 'https://evil.example/x', 'https://user@result.blob.core.windows.net/x', 'https://result.blob.core.windows.net:444/x'):
            with self.subTest(url=url), self.assertRaises(e.EvidenceError):
                c.trusted_blob_url(url)

    def test_native_report_requires_real_complete_cases_exact_runtime_and_selected_audit_profile(self):
        c.validate_report(self.report, self.candidate, self.runtime, self.config)
        changes = [('candidate_qualified', False), ('audit_profile', 'enhanced'), ('required_audit_admission_exercised', False), ('enhanced_receipt_exercised', True), ('runtime', {'hub_image_id': 'wrong'}), ('cases', self.report['cases'][:-1]), ('artifact_manifest_sha256', 'f' * 64)]
        for key, value in changes:
            with self.subTest(key=key), self.assertRaises(e.EvidenceError):
                c.validate_report(dict(self.report, **{key: value}), self.candidate, self.runtime, self.config)
        enhanced_candidate = dict(self.candidate, audit_profile='enhanced')
        enhanced_report = dict(self.report, audit_profile='enhanced', artifact_manifest_sha256=e.digest(e.canonical(enhanced_candidate)))
        with self.assertRaises(e.EvidenceError):
            c.validate_report(enhanced_report, enhanced_candidate, self.runtime, dict(self.config, audit_profile='enhanced'))
        enhanced_report['enhanced_receipt_exercised'] = True
        c.validate_report(enhanced_report, enhanced_candidate, self.runtime, dict(self.config, audit_profile='enhanced'))

    def test_public_summary_cannot_leak_private_diagnostics(self):
        self.report['private_diagnostic'] = 'fixture-secret-not-public'
        self.report['runtime']['endpoint'] = 'private.invalid'
        self.report['cases'][0]['error'] = 'fixture-secret-not-public'
        encoded = e.canonical(c.disclosure_safe_report(self.report))
        self.assertNotIn(b'fixture-secret', encoded)
        self.assertNotIn(b'private.invalid', encoded)
        self.assertNotIn(b'hub_container_id', encoded)
        self.assertIn(b'"audit_profile":"standard"', encoded)

    def test_exclusive_candidate_lease_refuses_overlap(self):
        event = multiprocessing.Event()
        process = multiprocessing.Process(target=hold_lease, args=(self.config, event))
        process.start()
        self.assertTrue(event.wait(5))
        try:
            with self.assertRaises(e.EvidenceError):
                with c.lease(self.config):
                    pass
        finally:
            process.join(5)
        self.assertEqual(process.exitcode, 0)

    def test_durable_completion_deduplicates_without_renewing_or_rerunning(self):
        marker = self.root / 'completed/123-1.json'
        artifact = {'id': 55, 'digest': 'sha256:' + 'd' * 64, 'name': 'ssdf-candidate-v1-123-1'}
        c.save_state(marker, {'artifact_id': 55, 'artifact_digest': artifact['digest'], 'published': True})
        api = mock.Mock()
        api.pages.side_effect = [[self.run], [artifact]]
        with mock.patch.object(c, 'qualify') as qualify:
            c.poll(self.config, api)
            qualify.assert_not_called()
        artifact['id'] = 56
        api.pages.side_effect = [[self.run], [artifact]]
        with self.assertRaises(e.EvidenceError):
            c.poll(self.config, api)

    def test_docker_conversion_allows_only_reserialization_not_rootfs_or_command_changes(self):
        source = {'rootfs': {'diff_ids': ['sha256:' + 'a' * 64]}, 'config': {'Cmd': ['--serve'], 'Labels': {'revision': 'a' * 40}}, 'history': [{'created_by': 'trusted build'}]}
        imported = json.loads(json.dumps(source, indent=4))
        binding = c.config_conversion_binding(source, imported, 'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
        self.assertEqual(binding['runtime_image_id'], 'sha256:' + 'c' * 64)
        for key, value in [('rootfs', {'diff_ids': ['sha256:' + 'd' * 64]}), ('config', {'Cmd': ['--other']}), ('history', [])]:
            with self.subTest(key=key), self.assertRaises(e.EvidenceError):
                c.config_conversion_binding(source, dict(imported, **{key: value}), 'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)

    def test_private_reports_are_verified_then_discarded(self):
        raw = self.tar()
        c.extract_stream(raw, self.root / 'discarded', time.monotonic() + 10, retained=set())
        self.assertFalse((self.root / 'discarded/bin/agent').exists())
        with self.assertRaises(e.EvidenceError):
            c.extract_stream(self.tar('corrupt'), self.root / 'corrupt-discarded', time.monotonic() + 10, retained=set())

    def test_extraction_grants_native_execute_without_inheriting_suid_modes(self):
        payload = b'#!/bin/sh\nexit 0\n'
        candidate = copy.deepcopy(self.candidate)
        candidate['files'] = [{'name': 'bin/veyport-agent-linux-amd64', 'sha256': e.digest(payload), 'size': len(payload)}]
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as archive:
            info = tarfile.TarInfo('candidate.json')
            document = e.canonical(candidate)
            info.size = len(document)
            archive.addfile(info, io.BytesIO(document))
            info = tarfile.TarInfo('delivery/bin/veyport-agent-linux-amd64')
            info.size, info.mode = len(payload), 0o4777
            archive.addfile(info, io.BytesIO(payload))
        raw.seek(0)
        previous = os.umask(0o077)
        try:
            c.extract_stream(raw, self.root / 'executable', time.monotonic() + 10, retained=c.RETAINED)
        finally:
            os.umask(previous)
        path = self.root / 'executable/bin/veyport-agent-linux-amd64'
        self.assertEqual(path.stat().st_mode & 0o7777, 0o700)
        self.assertEqual(subprocess.run([str(path)], check=False).returncode, 0)

    def test_command_stdout_is_bounded_without_breaking_archive_file_writes(self):
        output = self.root / 'archive-fixture'
        c.command(['python3', '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b"x"*8192)', str(output)], limit=64)
        self.assertEqual(output.stat().st_size, 8192)
        with self.assertRaises(e.EvidenceError):
            c.command(['python3', '-c', 'import sys;sys.stdout.buffer.write(b"x"*8192)'], limit=64)

    def test_named_network_cannot_bypass_firewall_on_a_different_bridge_or_subnet(self):
        config = dict(self.config, docker_network='veyport-candidate-internal', docker_network_id='a' * 64, docker_network_subnet='172.29.115.0/28')
        network = {'Id': 'a' * 64, 'Name': config['docker_network'], 'Driver': 'bridge', 'Internal': True, 'Labels': {'io.veyport.ssdf': 'qualification'}, 'Options': {'com.docker.network.bridge.name': 'br-vey-cand'}, 'IPAM': {'Config': [{'Subnet': '172.29.115.0/28'}]}}
        c.validate_network(network, config)
        for field, value in [('Id', 'b' * 64), ('Options', {'com.docker.network.bridge.name': 'br-other'}), ('IPAM', {'Config': [{'Subnet': '10.0.0.0/28'}]}), ('Internal', False)]:
            with self.subTest(field=field), self.assertRaises(e.EvidenceError):
                c.validate_network(dict(network, **{field: value}), config)

    def test_cancelled_run_cannot_deploy_or_qualify(self):
        api = mock.Mock()
        api.verified_sources = set()
        with mock.patch.object(e, 'verify_trust_anchor'), mock.patch.object(c, 'download_candidate') as download:
            with self.assertRaises(e.EvidenceError):
                c.qualify(self.config, api, dict(self.run, status='completed'), {})
            download.assert_not_called()

    def test_no_receipt_on_failed_harness_and_runtime_always_cleaned(self):
        api = mock.Mock()
        artifact = {'id': 55, 'digest': 'sha256:' + 'd' * 64}
        config = dict(self.config, identity_file='fixture')
        with mock.patch.object(c, 'RETAINED', {'bin/agent'}), mock.patch.object(e, 'verify_trust_anchor'), mock.patch.object(c, 'download_candidate'), mock.patch.object(c, 'unwrap_candidate'), mock.patch.object(c, 'decrypt_candidate', return_value=self.candidate), mock.patch.object(c, 'verify_inventory'), mock.patch.object(c, 'DockerRuntime') as runtime, mock.patch.object(c, 'run_harness', side_effect=e.EvidenceError('required audit unavailable')), mock.patch.object(c, 'publish_qualification') as publish:
            runtime.return_value.start.return_value = self.runtime
            with self.assertRaises(e.EvidenceError):
                c.qualify(config, api, self.run, artifact)
            runtime.return_value.stop.assert_called_once()
            publish.assert_not_called()


if __name__ == '__main__':
    unittest.main()

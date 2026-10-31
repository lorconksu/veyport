"""Failure-oriented archive tests with real age/OpenSSL and throwaway fixture keys."""
import copy
import datetime as dt
import importlib.util
import io
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

spec = importlib.util.spec_from_file_location('evidence', Path(__file__).with_name('evidence.py'))
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)


class LocalArchive(e.Archive):
    """Only tests replace the NFS mount check; production has no such config switch."""
    def check_mount(self):
        e.require(not getattr(self, 'lost', False), 'expected NFS mount unavailable')


def concurrent_save(config, manifest, blobs, run, artifact):
    archive = LocalArchive(config)
    archive.save(manifest, blobs, run, artifact, config)
    os.close(archive.root_fd)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ('age', 'age-keygen', 'openssl')):
            raise RuntimeError('collector tests require age, age-keygen and OpenSSL; install the age and openssl packages')
        cls.keys = tempfile.TemporaryDirectory()
        cls.keyroot = Path(cls.keys.name)
        cls.identity = cls.keyroot / 'identity'
        subprocess.run(['age-keygen', '-o', str(cls.identity)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        recipient = subprocess.run(['age-keygen', '-y', str(cls.identity)], check=True, capture_output=True).stdout
        cls.recipients = cls.keyroot / 'recipients'
        cls.recipients.write_bytes(recipient)
        cls.signing = cls.keyroot / 'signing'
        cls.public = cls.keyroot / 'public'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(cls.signing)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['openssl', 'pkey', '-in', str(cls.signing), '-pubout', '-out', str(cls.public)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = {'repository': 'owner/repo', 'archive_root': str(self.root), 'mount_source': 'nas:/archive', 'archive_id': 'test', 'allowed_workflows': ['.github/workflows/release.yml'], 'allowed_branches': ['main'], 'allowed_events': ['push'], 'identity_file': str(self.identity), 'recipient_file': str(self.recipients), 'signing_key_file': str(self.signing), 'signing_public_key_file': str(self.public), 'retention_enabled': True}
        self.run = {'id': 123, 'run_attempt': 1, 'repository': {'full_name': 'owner/repo'}, 'head_repository': {'full_name': 'owner/repo'}, 'head_sha': 'a' * 40, 'head_branch': 'main', 'path': '.github/workflows/release.yml', 'event': 'push', 'status': 'completed', 'conclusion': 'success', 'updated_at': e.iso(e.now())}
        self.payload = b'{"private_findings":["fixture"]}'
        self.sha = e.digest(self.payload)
        self.manifest = {'schema': 1, 'repository': 'owner/repo', 'workflow': '.github/workflows/release.yml', 'run_id': 123, 'run_attempt': 1, 'revision': 'a' * 40, 'candidate_id': 'release-123-1', 'complete': True, 'files': [{'name': 'report.json', 'sha256': self.sha, 'size': len(self.payload)}], 'details': {'dast': 'deferred', 'policy_sha256': 'b' * 64}}
        self.blobs = {self.sha: self.payload}
        self.artifact = {'id': 42, 'name': e.artifact_name(123, 1), 'digest': 'sha256:' + 'b' * 64, 'workflow_run': {'id': 123, 'head_sha': 'a' * 40}}
        self.archive = LocalArchive(self.config)
        self.addCleanup(os.close, self.archive.root_fd)
        self.api = mock.Mock()
        self.api.prefix = '/repos/owner/repo'
        self.api.verified_sources = set()
        self.api.run_cache = {}
        self.api.job_cache = {}
        self.api.get.return_value = copy.deepcopy(self.run)
        self.api.pages.return_value = []

    def save(self, manifest=None, run=None):
        return self.archive.save(manifest or self.manifest, self.blobs, run or self.run, self.artifact, self.config)

    def acknowledge(self, record):
        e.publish_receipt(self.api, self.archive, record, self.config)
        return self.archive.records()[0]

    def cleanup_api(self, artifact=None, jobs=None, latest=None):
        self.api.pages.side_effect = lambda path, key: [] if path == '/releases' else (jobs if jobs is not None else [{'status': 'completed'}])
        self.api.get.side_effect = lambda path: copy.deepcopy(artifact or self.artifact) if path.startswith('/actions/artifacts/') else copy.deepcopy(latest or self.run) if path == '/actions/runs/123' else copy.deepcopy(self.run)

    def test_real_crypto_roundtrip_and_ciphertext_tamper(self):
        ciphertext = e.age_encrypt(self.payload, self.recipients)
        self.assertNotIn(self.payload, ciphertext)
        self.assertEqual(e.age_decrypt(ciphertext, self.identity), self.payload)
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 1
        with self.assertRaises(e.EvidenceError):
            e.age_decrypt(bytes(tampered), self.identity)

    def test_canonical_manifest_hash_binds_entire_details(self):
        altered = copy.deepcopy(self.manifest)
        altered['details']['policy_sha256'] = 'c' * 64
        self.assertNotEqual(e.digest(e.canonical(self.manifest)), e.digest(e.canonical(altered)))
        with self.assertRaises(e.EvidenceError):
            e.parse_json(b'{"schema":1,"schema":2}')

    def test_pack_unpack_validated_and_path_traversal_rejected(self):
        (self.root / 'report.json').write_bytes(self.payload)
        packed = e.pack(self.manifest, self.root)
        m, blobs = e.unpack(packed)
        self.assertEqual(m, self.manifest)
        self.assertEqual(blobs, self.blobs)
        for name in ('../private', '/etc/passwd', 'a/../../b', 'a\\b', 'a//b', './a'):
            with self.subTest(name=name), self.assertRaises(e.EvidenceError):
                bad = copy.deepcopy(self.manifest)
                bad['files'][0]['name'] = name
                e.manifest_valid(bad)

    def test_zip_bomb_extra_file_and_corrupt_digest_rejected(self):
        for mode in ('compressed', 'extra', 'tamper', 'duplicate'):
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED if mode == 'compressed' else zipfile.ZIP_STORED) as z:
                z.writestr('manifest.json', e.canonical(self.manifest))
                z.writestr('blobs/' + self.sha, b'wrong' if mode == 'tamper' else self.payload)
                if mode == 'extra':
                    z.writestr('../../escape', b'bad')
                if mode == 'duplicate':
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        z.writestr('manifest.json', b'{}')
            with self.subTest(mode=mode), self.assertRaises(e.EvidenceError):
                e.unpack(data.getvalue())

    def test_bounds_and_symlink_input_rejected(self):
        bad = copy.deepcopy(self.manifest)
        bad['files'][0]['size'] = e.MAX_FILE + 1
        with self.assertRaises(e.EvidenceError):
            e.manifest_valid(bad)
        secret = self.root / 'secret'
        secret.write_bytes(self.payload)
        (self.root / 'report.json').symlink_to(secret)
        with self.assertRaises(e.EvidenceError):
            e.pack(self.manifest, self.root)

    def test_crypto_output_has_os_enforced_size_limit(self):
        with self.assertRaises(e.EvidenceError):
            e.crypto(['python3', '-c', 'import sys;sys.stdout.buffer.write(b"x"*4096)'], b'', limit=64)

    def test_trusted_source_and_exact_run_binding(self):
        for field, value in [('head_repository', {'full_name': 'fork/repo'}), ('path', '.github/workflows/untrusted.yml'), ('head_branch', 'feature'), ('event', 'pull_request')]:
            with self.subTest(field=field), self.assertRaises(e.EvidenceError):
                run = copy.deepcopy(self.run)
                run[field] = value
                e.bind_manifest(self.manifest, run, self.config)
        bad = copy.deepcopy(self.manifest)
        bad['run_attempt'] = 2
        with self.assertRaises(e.EvidenceError):
            e.bind_manifest(bad, self.run, self.config)

    def test_archive_readback_encrypted_deduplicated_and_idempotent(self):
        record = self.save()
        second = self.save()
        self.assertEqual(record, second)
        self.assertEqual(len(list((self.root / 'blobs').iterdir())), 1)
        encrypted = next((self.root / 'blobs').iterdir()).read_bytes()
        self.assertNotIn(self.payload, encrypted)
        self.assertEqual(e.age_decrypt(encrypted, self.identity), self.payload)
        altered = copy.deepcopy(self.manifest)
        altered['candidate_id'] = 'new-attempt'
        self.save(altered)
        self.assertEqual(len(self.archive.records()), 2)
        self.assertEqual(len(list((self.root / 'blobs').iterdir())), 1)

    def test_signature_binds_manifest_source_complete_and_storage(self):
        record = self.acknowledge(self.save())
        receipt = record['receipt']
        expected = {key: receipt['payload'][key] for key in ('repository', 'run_id', 'run_attempt', 'revision', 'manifest_sha256')}
        self.assertTrue(e.validate_receipt(receipt, expected, self.public)['complete'])
        self.assertEqual(e.receipt_from_url(e.receipt_url(receipt), 'owner/repo', 123), receipt)
        for field, value in [('manifest_sha256', 'f' * 64), ('complete', False), ('run_attempt', 2), ('storage_sha256', 'e' * 64)]:
            altered = copy.deepcopy(receipt)
            altered['payload'][field] = value
            with self.subTest(field=field), self.assertRaises(e.EvidenceError):
                e.validate_receipt(altered, expected, self.public)
        wrong = dict(expected, run_attempt=2)
        with self.assertRaises(e.EvidenceError):
            e.validate_receipt(receipt, wrong, self.public)

    def test_incomplete_signed_receipt_cannot_authorize_publication(self):
        m = copy.deepcopy(self.manifest)
        m['complete'] = False
        record = self.acknowledge(self.save(m))
        with self.assertRaises(e.EvidenceError):
            e.validate_receipt(record['receipt'], {}, self.public)

    def test_local_mount_fallback_is_rejected(self):
        (self.root / '.archive-id').write_text('test')
        with self.assertRaises(e.EvidenceError):
            e.Archive(self.config)
        self.archive.lost = True
        with self.assertRaises(e.EvidenceError):
            self.save()
        self.assertFalse((self.root / 'blobs').exists())

    def test_pinned_directory_does_not_write_into_replacement_mountpoint(self):
        moved = self.root.with_name(self.root.name + '-old')
        self.root.rename(moved)
        self.root.mkdir()
        try:
            self.archive.write('probes/pinned', b'test')
            self.assertFalse((self.root / 'probes').exists())
            self.assertEqual((moved / 'probes/pinned').read_bytes(), b'test')
        finally:
            shutil.rmtree(self.root)
            moved.rename(self.root)

    def test_cleanup_deletes_only_exact_artifact_after_archive_ack(self):
        self.acknowledge(self.save())
        self.cleanup_api()
        self.api.request.reset_mock()
        e.cleanup(self.config, self.api, self.archive)
        self.api.request.assert_called_once_with('/repos/owner/repo/actions/artifacts/42', 'DELETE')
        e.cleanup(self.config, self.api, self.archive)
        self.assertEqual(self.api.request.call_count, 1)

    def test_cleanup_unacknowledged_running_mismatched_or_corrupt_blocks(self):
        record = self.save()
        self.cleanup_api()
        self.api.request.reset_mock()
        e.cleanup(self.config, self.api, self.archive)
        self.api.request.assert_not_called()
        self.acknowledge(record)
        for kind in ('jobs', 'artifact', 'rerun', 'corrupt'):
            with self.subTest(kind=kind):
                self.api.request.reset_mock()
                bad = dict(self.artifact, name='other-artifact') if kind == 'artifact' else None
                jobs = [{'status': 'in_progress'}] if kind == 'jobs' else None
                latest = dict(self.run, status='in_progress') if kind == 'rerun' else None
                self.cleanup_api(artifact=bad, jobs=jobs, latest=latest)
                if kind == 'corrupt':
                    (self.root / 'blobs' / (self.sha + '.age')).write_bytes(b'corrupted')
                with self.assertRaises(e.EvidenceError):
                    e.cleanup(self.config, self.api, self.archive)
                self.api.request.assert_not_called()

    def test_cleanup_retry_after_remote_delete_durable_write_failure(self):
        self.acknowledge(self.save())
        self.cleanup_api()
        original = self.api.get.side_effect
        def get(path):
            if path.startswith('/actions/artifacts/'):
                raise e.GitHubError(404)
            return original(path)
        self.api.get.side_effect = get
        self.api.request.reset_mock()
        e.cleanup(self.config, self.api, self.archive)
        self.api.request.assert_not_called()
        self.assertTrue(self.archive.records()[0]['deleted'])

    def test_release_retention_extends_shared_blob_latest_deadline(self):
        old = e.now() - dt.timedelta(days=200)
        record = self.save()
        record['completed_at'] = e.iso(old)
        record['retain_until'] = e.iso(old + dt.timedelta(days=180))
        self.archive.write('runs/' + record['record_name'], e.canonical(record), replace=True)
        # Another run references identical report bytes and remains live.
        m, run = copy.deepcopy(self.manifest), copy.deepcopy(self.run)
        m['run_id'] = run['id'] = 124
        run['head_sha'] = m['revision'] = 'c' * 40
        self.save(m, run)
        ancient = dict(self.run, updated_at=e.iso(old))
        self.api.get.side_effect = lambda path: ancient if '/123/' in path else run
        self.api.pages.return_value = []
        e.retain(self.config, self.api, self.archive)
        self.assertEqual([x['run_id'] for x in self.archive.records()], [124])
        self.assertTrue((self.root / 'blobs' / (self.sha + '.age')).exists())
        publication = e.now() - dt.timedelta(days=10)
        current = self.archive.records()[0]
        e.reconcile_record(self.api, self.archive, current, self.config, {'c' * 40: [publication]})
        self.assertGreaterEqual(e.timestamp(self.archive.records()[0]['retain_until']), e.year_after(publication))

    def test_retention_provider_outage_and_role_disable_do_not_unlink(self):
        self.save()
        self.api.pages.side_effect = e.EvidenceError('outage')
        with self.assertRaises(e.EvidenceError):
            e.retain(self.config, self.api, self.archive)
        self.assertEqual(len(self.archive.records()), 1)
        self.api.pages.side_effect = None
        with self.assertRaises(e.EvidenceError):
            e.retain(dict(self.config, retention_enabled=False), self.api, self.archive)
        self.assertEqual(len(self.archive.records()), 1)

    def test_cancelled_and_fork_runs_get_explicit_incomplete_metadata(self):
        for fork in (False, True):
            run = copy.deepcopy(self.run)
            run['conclusion'] = 'cancelled'
            if fork:
                run['id'] = 125
                run['head_repository']['full_name'] = 'fork/repo'
            self.api.artifact.return_value = None
            self.api.verified_sources = {(run['head_sha'], run['path'])}
            e.collect_attempt(self.config, self.api, self.archive, run)
        records = self.archive.records()
        self.assertEqual(len(records), 2)
        self.assertTrue(all(not x['complete'] and not x['acknowledged'] for x in records))
        self.api.request.assert_not_called()
        self.assertEqual({x['source_trusted'] for x in records}, {True, False})

    def test_stale_reconciliation_cannot_erase_acknowledgement_or_deadline(self):
        stale = self.save()
        fresh = self.acknowledge(copy.deepcopy(stale))
        fresh['retain_until'] = e.iso(e.now() + dt.timedelta(days=400))
        with self.archive.lock():
            self.archive.update(fresh)
            self.archive.update(stale)
        current = self.archive.records()[0]
        self.assertTrue(current['acknowledged'])
        self.assertGreater(e.timestamp(current['retain_until']), e.now() + dt.timedelta(days=399))
        self.assertIn('receipt', current)

    def test_simultaneous_collection_keeps_one_blob_and_manifest(self):
        processes = [multiprocessing.Process(target=concurrent_save, args=(self.config, self.manifest, self.blobs, self.run, self.artifact)) for _ in range(3)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(20)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(len(self.archive.records()), 1)
        self.assertEqual(len(list((self.root / 'blobs').glob('*.age'))), 1)

    def test_trust_anchor_rejects_unreachable_or_changed_workflow_and_accepts_exact_pin(self):
        self.api.verified_sources = set()
        anchor = 'c' * 40
        def response(path):
            if path.startswith('/git/ref/'):
                return {'object': {'sha': anchor}}
            if path.startswith('/compare/'):
                return {'merge_base_commit': {'sha': self.run['head_sha']}}
            if path.startswith('/git/commits/'):
                commit_sha = path.rsplit('/', 1)[-1]
                return {'sha': commit_sha, 'tree': {'sha': 'e' * 40 if commit_sha == self.run['head_sha'] else 'f' * 40}}
            if path.startswith('/git/trees/'):
                tree_sha = path.rsplit('/', 1)[-1].split('?')[0]
                return {'sha': tree_sha, 'truncated': False, 'tree': [{'path': self.run['path'], 'type': 'blob', 'mode': '100644', 'sha': 'b' * 40}]}
            if path.startswith('/commits/'):
                return {'sha': self.run['head_sha']}
            raise AssertionError(path)
        self.api.get.side_effect = response
        e.verify_trust_anchor(self.api, self.run, self.config)
        self.assertEqual(self.api.get.call_count, 6)
        self.api.verified_sources.clear()
        def unreachable(path):
            return {'merge_base_commit': {'sha': 'd' * 40}} if path.startswith('/compare/') else response(path)
        self.api.get.side_effect = unreachable
        with self.assertRaises(e.EvidenceError):
            e.verify_trust_anchor(self.api, self.run, self.config)
        def changed(path):
            if path.startswith('/git/trees/' + 'e' * 40):
                return {'sha': 'e' * 40, 'truncated': False, 'tree': [{'path': self.run['path'], 'type': 'blob', 'mode': '100644', 'sha': 'd' * 40}]}
            return response(path)
        self.api.tree_cache = {}
        self.api.get.side_effect = changed
        with self.assertRaises(e.EvidenceError):
            e.verify_trust_anchor(self.api, self.run, self.config)
        pinned = dict(self.config, approved_source_revisions=[self.run['head_sha']])
        self.api.get.side_effect = response
        feature_run = dict(self.run, head_branch='feat/exact-rehearsal')
        e.trusted_run(feature_run, pinned)
        e.verify_trust_anchor(self.api, feature_run, pinned)
        feature_run['head_sha'] = 'f' * 40
        with self.assertRaises(e.EvidenceError):
            e.trusted_run(feature_run, pinned)

    def test_discovery_checkpoint_covers_long_outage_and_pending_runs(self):
        old = e.now() - dt.timedelta(days=10)
        with self.archive.lock():
            self.archive.write('state/discovery.json', e.canonical({'last_success': e.iso(old), 'pending': [123]}))
        self.api.pages.return_value = []
        self.api.get.return_value = self.run
        found, _ = e.discover_runs(self.config, self.api, self.archive)
        self.assertEqual([x['id'] for x in found], [123])
        self.assertGreaterEqual(self.api.pages.call_count, 10)
        first_query = self.api.pages.call_args_list[0].args[0]
        import urllib.parse
        self.assertIn(e.iso(old - dt.timedelta(hours=1)), urllib.parse.unquote(first_query))
        self.api.pages.return_value = [self.run] * 1000
        with self.assertRaises(e.EvidenceError):
            e.discover_runs(self.config, self.api, self.archive)

    def test_artifact_transport_exact_archive_digest_and_inventory(self):
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, 'w') as archive:
            archive.writestr('evidence.age', b'opaque-encrypted-fixture')
        raw = outer.getvalue()
        artifact = dict(self.artifact, digest='sha256:' + e.digest(raw), expired=False, size_in_bytes=len(raw))
        self.api.request.return_value = raw
        self.assertEqual(e.encrypted_artifact(self.api, artifact, self.run), b'opaque-encrypted-fixture')
        artifact['digest'] = 'sha256:' + 'f' * 64
        with self.assertRaises(e.EvidenceError):
            e.encrypted_artifact(self.api, artifact, self.run)
        artifact['workflow_run']['id'] = 999
        with self.assertRaises(e.EvidenceError):
            e.encrypted_artifact(self.api, artifact, self.run)

    def job_archive(self, missing=False, tamper=False):
        pieces = [b'first-', b'second']
        retained = b''.join(pieces)
        original = {'name': 'reports/test.json', 'sha256': e.digest(retained), 'size': len(retained), 'original_sha256': e.digest(b'raw-sensitive-fixture'), 'redacted': True, 'parts': [{'name': 'parts/' + e.digest(data), 'sha256': e.digest(data), 'size': len(data), 'offset': sum(len(x) for x in pieces[:index]), 'chunk_index': index} for index, data in enumerate(pieces)]}
        if tamper:
            original['sha256'] = 'f' * 64
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, 'w') as outer:
            for index, data in enumerate(pieces):
                if missing and index == 1:
                    continue
                chunk = copy.deepcopy(self.manifest)
                part = original['parts'][index]
                chunk['files'] = [{key: part[key] for key in ('name', 'sha256', 'size')}]
                chunk['complete'] = False
                chunk['details'] = {'kind': 'job-chunk', 'job': 'unit', 'chunk_index': index, 'chunk_count': 2, 'original_files': [original], 'checkout_revision': chunk['revision'], 'github_sha': chunk['revision'], 'status': 'success'}
                inner = io.BytesIO()
                with zipfile.ZipFile(inner, 'w', compression=zipfile.ZIP_STORED) as bundle:
                    bundle.writestr('manifest.json', e.canonical(chunk))
                    bundle.writestr('blobs/' + part['sha256'], data)
                outer.writestr(f'chunk-{index:04d}.age', e.age_encrypt(inner.getvalue(), self.recipients))
        path = self.root / ('job-missing.zip' if missing else 'job.zip')
        path.write_bytes(raw.getvalue())
        artifact = {'id': 84, 'name': 'ssdf-job-v1-123-1-unit', 'digest': 'sha256:' + e.digest(raw.getvalue())}
        return path, artifact, pieces

    def test_cancel_independent_job_chunks_archive_all_parts_with_one_exact_signed_cleanup_receipt(self):
        path, artifact, pieces = self.job_archive()
        record = e.archive_job_zip(self.config, self.api, self.archive, self.run, artifact, 'unit', path, True)
        self.assertTrue(record['acknowledged'])
        self.assertFalse(record['complete'])
        self.assertTrue({e.digest(x) for x in pieces} <= set(record['blobs']))
        self.assertEqual(len(self.archive.records()), 3)
        self.assertEqual(sum(x['artifact_id'] is not None for x in self.archive.records()), 1)
        self.api.request.assert_not_called()  # CI acknowledgements are private; no public diagnostic transport.
        e.verify_storage(self.archive, record)
        m = e.parse_json(e.age_decrypt((self.root / 'manifests' / (record['manifest_sha256'] + '.age')).read_bytes(), self.identity))
        self.assertEqual(m['details']['missing_original_files'], [])
        self.assertEqual(m['details']['missing_chunk_indices'], [])
        self.assertEqual(len(m['details']['chunks']), 2)
        original = m['details']['original_files'][0]
        self.assertTrue(original['redacted'])
        self.assertNotEqual(original['sha256'], original['original_sha256'])
        self.assertEqual(len(e.archive_job_zip(self.config, self.api, self.archive, self.run, artifact, 'unit', path, True)['blobs']), len(record['blobs']))

    def test_missing_chunk_is_retained_explicitly_incomplete_not_invented_clean(self):
        path, artifact, pieces = self.job_archive(missing=True)
        record = e.archive_job_zip(self.config, self.api, self.archive, self.run, artifact, 'unit', path, False)
        m = e.parse_json(e.age_decrypt((self.root / 'manifests' / (record['manifest_sha256'] + '.age')).read_bytes(), self.identity))
        self.assertEqual(m['details']['missing_original_files'], ['reports/test.json'])
        self.assertEqual(m['details']['missing_chunk_indices'], [1])
        self.assertFalse(record['source_trusted'])
        with self.assertRaises(e.EvidenceError):
            e.validate_receipt(record['receipt'], {}, self.public)

    def test_corrupt_original_reconstruction_never_acknowledges_whole_job(self):
        path, artifact, _ = self.job_archive(tamper=True)
        with self.assertRaises(e.EvidenceError):
            e.archive_job_zip(self.config, self.api, self.archive, self.run, artifact, 'unit', path, True)
        self.assertTrue(all(x['artifact_id'] is None and not x['acknowledged'] for x in self.archive.records()))

    def test_job_chunk_receipt_authorizes_only_allowlisted_exact_job_artifact(self):
        path, artifact, _ = self.job_archive()
        e.archive_job_zip(self.config, self.api, self.archive, self.run, artifact, 'unit', path, True)
        actual = dict(artifact, workflow_run={'id': self.run['id']})
        self.cleanup_api(artifact=actual)
        self.api.request.reset_mock()
        e.cleanup(dict(self.config, allowed_job_chunks=['unit']), self.api, self.archive)
        self.api.request.assert_called_once_with('/repos/owner/repo/actions/artifacts/84', 'DELETE')

    def test_release_receipt_requires_independent_success_and_complete_ci_payload_closure(self):
        m = copy.deepcopy(self.manifest)
        m['details']['expected_ci_jobs'] = ['unit']
        self.api.pages.return_value = [{'id': 99, 'run_id': 123, 'head_sha': self.run['head_sha'], 'name': 'required-ci / unit', 'status': 'completed', 'conclusion': 'success'}]
        with mock.patch.object(e, 'REQUIRED_RELEASE_JOBS', ['unit']):
            with self.assertRaises(e.EvidenceError):
                e.complete_ci_closure(self.config, self.api, self.archive, self.run, m)
            path, artifact, pieces = self.job_archive()
            job = e.archive_job_zip(self.config, self.api, self.archive, self.run, artifact, 'unit', path, True)
            self.api.request.return_value = b'compiler and tests completed successfully\n'
            e.collect_job_logs(self.config, self.api, self.archive, self.run, True)
            identities, additional, references = e.complete_ci_closure(self.config, self.api, self.archive, self.run, m)
            self.assertEqual(identities['unit'], job['manifest_sha256'])
            self.assertIn('unit:logs', identities)
            self.assertTrue({e.digest(x) for x in pieces} <= references)
            blobs = dict(self.blobs, **additional)
            record = self.archive.save(m, blobs, self.run, self.artifact, self.config, extra_refs=references, ci_jobs=identities)
            e.publish_receipt(self.api, self.archive, record, self.config)
            record = next(x for x in self.archive.records() if x['record_name'] == record['record_name'])
            self.assertEqual(record['receipt']['payload']['ci_jobs_sha256'], e.digest(e.canonical(identities)))
            self.assertTrue({e.digest(x) for x in pieces} <= set(record['blobs']))
            e.verify_storage(self.archive, record)
            self.api.job_cache.clear()
            self.api.pages.return_value = [{'id': 99, 'name': 'required-ci / unit', 'status': 'completed', 'conclusion': 'failure'}]
            with self.assertRaises(e.EvidenceError):
                e.complete_ci_closure(self.config, self.api, self.archive, self.run, m)
            with self.assertRaises(e.EvidenceError):
                e.complete_ci_closure(dict(self.config, required_complete_jobs={self.run['path']: []}), self.api, self.archive, self.run, m)

    def test_complete_release_cannot_accept_partial_ci_reports_or_untrusted_archive(self):
        m = copy.deepcopy(self.manifest)
        m['details']['expected_ci_jobs'] = ['unit']
        self.api.pages.return_value = [{'name': 'unit', 'status': 'completed', 'conclusion': 'success'}]
        path, artifact, _ = self.job_archive(missing=True)
        e.archive_job_zip(self.config, self.api, self.archive, self.run, artifact, 'unit', path, True)
        with mock.patch.object(e, 'REQUIRED_RELEASE_JOBS', ['unit']), self.assertRaises(e.EvidenceError):
            e.complete_ci_closure(self.config, self.api, self.archive, self.run, m)

    def test_finalized_records_are_not_requeried_and_first_finalization_shares_run_cache(self):
        self.run['status'] = 'in_progress'
        path, artifact, _ = self.job_archive()
        e.archive_job_zip(self.config, self.api, self.archive, self.run, artifact, 'unit', path, True)
        self.api.get.reset_mock()
        for record in self.archive.records():
            e.reconcile_record(self.api, self.archive, record, self.config, {}, refresh=False)
        self.assertEqual(self.api.get.call_count, 1)  # Three indexes share one authenticated attempt lookup.
        self.api.get.reset_mock()
        self.api.run_cache.clear()
        for _ in range(2):
            for record in self.archive.records():
                e.reconcile_record(self.api, self.archive, record, self.config, {}, refresh=False)
        self.api.get.assert_not_called()

    def test_api_budget_backlog_does_not_advance_discovery_checkpoint(self):
        candidates = [dict(self.run, id=number, status='in_progress') for number in (123, 124, 125)]
        with mock.patch.object(e, 'discover_runs', return_value=(candidates, e.now())), mock.patch.object(e, 'collect_attempt', side_effect=[None, e.APIBudgetExceeded('budget')]):
            with self.assertRaises(e.EvidenceError):
                e.collect(self.config, self.api, self.archive)
        backlog = e.parse_json((self.root / 'state/backlog.json').read_bytes())
        self.assertEqual(backlog['status'], 'backlog')
        self.assertEqual(backlog['run_ids'], [124, 125])
        self.assertFalse(backlog['checkpoint_advanced'])
        self.assertFalse((self.root / 'state/discovery.json').exists())
        client = e.GitHub('owner/repo', 'throwaway-fixture', max_calls=1)
        client.charge()
        with self.assertRaises(e.APIBudgetExceeded):
            client.charge()

    def test_old_completed_run_rerun_is_discovered_by_bounded_historical_audit(self):
        self.save()
        self.api.pages.return_value = []
        self.api.get.return_value = dict(self.run, run_attempt=2)
        found, _ = e.discover_runs(self.config, self.api, self.archive)
        self.assertEqual([(x['id'], x['run_attempt']) for x in found], [(123, 2)])
        self.api.get.assert_called_once_with('/actions/runs/123')
        audit = e.parse_json((self.root / 'state/historical-audit.json').read_bytes())
        self.assertEqual(audit['cursor'], 1)

    def test_terminal_logs_are_redacted_encrypted_bound_to_exact_job_and_idempotent(self):
        source = b'compile error: fixture.c:2\npassword="fixture-password"\nAuthorization: Bearer fixtureBearer123456\ntotp_secret=JBSWY3DPEHPK3PXP\nhttps://example.invalid/?token=fixturequery\n-----BEGIN PRIVATE KEY-----\nfixture-key-material\n-----END PRIVATE KEY-----\n'
        job = {'id': 99, 'run_id': 123, 'head_sha': self.run['head_sha'], 'name': 'required-ci / unit', 'status': 'completed', 'conclusion': 'failure'}
        self.api.pages.return_value = [job]
        self.api.request.return_value = source
        e.collect_job_logs(self.config, self.api, self.archive, self.run, True)
        record = self.archive.records()[0]
        self.assertTrue(record['acknowledged'])
        self.assertEqual(record['collector_kind'], 'job-logs')
        self.assertEqual(record['job_log_id'], 99)
        self.assertIsNone(record['artifact_id'])
        m = e.parse_json(e.age_decrypt((self.root / 'manifests' / (record['manifest_sha256'] + '.age')).read_bytes(), self.identity))
        retained = b''.join(e.age_decrypt((self.root / 'blobs' / (item['sha256'] + '.age')).read_bytes(), self.identity) for item in m['files'])
        for sensitive in (b'fixture-password', b'fixtureBearer', b'JBSWY3', b'fixturequery', b'fixture-key-material'):
            self.assertNotIn(sensitive, retained)
        self.assertIn(b'compile error: fixture.c:2', retained)
        self.assertEqual(m['details']['raw_sha256'], e.digest(source))
        self.assertEqual(m['details']['sanitized_sha256'], e.digest(retained))
        e.verify_storage(self.archive, record)
        e.collect_job_logs(self.config, self.api, self.archive, self.run, True)
        self.api.request.assert_called_once_with('/repos/owner/repo/actions/jobs/99/logs', raw=True)

    def test_terminal_log_provider_failure_or_wrong_source_cannot_be_clean_evidence(self):
        job = {'id': 99, 'run_id': 123, 'head_sha': self.run['head_sha'], 'name': 'unit', 'status': 'completed', 'conclusion': 'success'}
        self.api.pages.return_value = [job]
        self.api.request.side_effect = e.GitHubError(404)
        with mock.patch('sys.stderr', new=io.StringIO()):
            e.collect_job_logs(self.config, self.api, self.archive, self.run, True)
        records = self.archive.records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['collector_kind'], 'job-logs-missing')
        self.assertFalse(records[0]['acknowledged'])
        self.api.job_cache.clear()
        self.api.pages.return_value = [dict(job, run_id=124)]
        self.api.request.reset_mock()
        with self.assertRaises(e.EvidenceError):
            e.collect_job_logs(self.config, self.api, self.archive, self.run, True)
        self.api.request.assert_not_called()

    def test_log_download_redirect_does_not_forward_github_authorization(self):
        import urllib.error
        url = 'https://logs.blob.core.windows.net/result?sig=throwaway'
        redirect = urllib.error.HTTPError('https://api.github.com/fixture', 302, 'Found', {'Location': url}, None)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.headers = {}
        response.read.return_value = b'safe fixture log'
        opener = mock.Mock()
        opener.open.side_effect = [redirect, response]
        with mock.patch.object(e.urllib.request, 'build_opener', return_value=opener):
            result = e.GitHub('owner/repo', 'throwaway-token').request('/repos/owner/repo/actions/jobs/99/logs', raw=True)
        self.assertEqual(result, b'safe fixture log')
        first, second = [item.args[0] for item in opener.open.call_args_list]
        self.assertIn('Authorization', first.headers)
        self.assertNotIn('Authorization', second.headers)
        self.assertEqual(second.full_url, url)

    def test_mutable_index_cannot_redirect_signed_receipt_to_other_transport_artifact(self):
        record = self.acknowledge(self.save())
        record['artifact_id'] = 43
        record['artifact_name'] = 'ssdf-job-v1-123-1-unit'
        record['artifact_digest'] = 'sha256:' + 'f' * 64
        with self.archive.lock():
            self.archive.update(record)
        self.cleanup_api(artifact={'id': 43, 'name': record['artifact_name'], 'digest': record['artifact_digest'], 'workflow_run': {'id': 123}})
        self.api.request.reset_mock()
        with self.assertRaises(e.EvidenceError):
            e.cleanup(dict(self.config, allowed_job_chunks=['unit']), self.api, self.archive)
        self.api.request.assert_not_called()

    def test_production_main_trust_does_not_spend_one_call_per_helper(self):
        api = mock.Mock()
        api.verified_sources = set()
        api.get.return_value = {'object': {'sha': self.run['head_sha']}}
        config = dict(self.config, trusted_helper_paths=['scripts/helper-' + str(x) + '.py' for x in range(40)])
        e.verify_trust_anchor(api, self.run, config)
        api.get.assert_called_once_with('/git/ref/heads/main')
        self.assertIn((self.run['head_sha'], self.run['path']), api.verified_sources)

    def test_leap_day_year_deadline(self):
        self.assertEqual(e.year_after(dt.datetime(2024, 2, 29, tzinfo=e.UTC)), dt.datetime(2025, 2, 28, tzinfo=e.UTC))


if __name__ == '__main__':
    unittest.main()

"""Isolated role fixtures; these do not qualify a deployed token or NFS identity."""
import copy
import datetime as dt
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

import test_evidence as fixtures

e = fixtures.e


class CleanupRuntimeTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.EvidenceTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.EvidenceTests.tearDownClass.__func__)
    setUp = fixtures.EvidenceTests.setUp
    save = fixtures.EvidenceTests.save
    acknowledge = fixtures.EvidenceTests.acknowledge
    cleanup_api = fixtures.EvidenceTests.cleanup_api

    def keyless(self):
        return {k: v for k, v in self.config.items()
                if k not in ('identity_file', 'recipient_file', 'signing_key_file')}

    def test_cleanup_requires_explicit_enable_before_any_side_effect(self):
        for value in (None, False, 'true', 1):
            with self.subTest(value=value):
                config = dict(self.config, cleanup_enabled=value)
                api, archive = mock.Mock(), mock.Mock()
                with self.assertRaisesRegex(e.EvidenceError, 'cleanup role is not enabled'):
                    e.cleanup(config, api, archive)
                self.assertEqual(api.mock_calls, [])
                self.assertEqual(archive.mock_calls, [])

    def test_keyless_cleanup_and_restart_delete_only_one_exact_fixture(self):
        self.acknowledge(self.save())
        self.cleanup_api()
        self.api.request.reset_mock()
        with mock.patch.object(e, 'age_decrypt', side_effect=AssertionError('private key use forbidden')), \
                mock.patch.object(e, 'sign', side_effect=AssertionError('signing forbidden')):
            e.cleanup(self.keyless(), self.api, self.archive)
            restarted = fixtures.LocalArchive(self.keyless())
            self.addCleanup(os.close, restarted.root_fd)
            e.cleanup(self.keyless(), self.api, restarted)
        self.api.request.assert_called_once_with('/repos/owner/repo/actions/artifacts/42', 'DELETE')
        self.assertEqual(restarted.records()[0]['cleanup_outcome'], 'exact-artifact-deleted')

    def test_denied_delete_keeps_acknowledged_fixture_retryable(self):
        self.acknowledge(self.save())
        self.cleanup_api()
        self.api.request.reset_mock()
        self.api.request.side_effect = e.GitHubError(403)
        with self.assertRaises(e.GitHubError):
            e.cleanup(self.keyless(), self.api, self.archive)
        self.assertFalse(self.archive.records()[0]['deleted'])
        self.assertTrue(self.archive.records()[0]['acknowledged'])
        self.api.request.side_effect = None
        e.cleanup(self.keyless(), self.api, self.archive)
        self.assertTrue(self.archive.records()[0]['deleted'])

    def test_mount_loss_before_delete_and_recovery(self):
        self.acknowledge(self.save())
        self.cleanup_api()
        original = self.api.get.side_effect

        def disconnect(path):
            result = original(path)
            if path.startswith('/actions/artifacts/'):
                self.archive.lost = True
            return result

        self.api.get.side_effect = disconnect
        self.api.request.reset_mock()
        with self.assertRaisesRegex(e.EvidenceError, 'NFS mount unavailable'):
            e.cleanup(self.keyless(), self.api, self.archive)
        self.api.request.assert_not_called()
        self.archive.lost = False
        self.assertFalse(self.archive.records()[0]['deleted'])
        self.cleanup_api()
        e.cleanup(self.keyless(), self.api, self.archive)
        self.api.request.assert_called_once_with('/repos/owner/repo/actions/artifacts/42', 'DELETE')

    def test_delete_committed_before_index_failure_recovers_without_second_delete(self):
        self.acknowledge(self.save())
        self.cleanup_api()
        original = self.archive.update

        def crash(record):
            if record['deleted']:
                raise OSError('fixture crash after remote commit')
            return original(record)

        self.api.request.reset_mock()
        with mock.patch.object(self.archive, 'update', side_effect=crash), self.assertRaises(OSError):
            e.cleanup(self.keyless(), self.api, self.archive)
        self.assertFalse(self.archive.records()[0]['deleted'])
        self.api.request.assert_called_once()
        current = self.api.get.side_effect

        def absent(path):
            if path.startswith('/actions/artifacts/'):
                raise e.GitHubError(404)
            return current(path)

        self.api.get.side_effect = absent
        e.cleanup(self.keyless(), self.api, self.archive)
        self.api.request.assert_called_once()
        self.assertEqual(self.archive.records()[0]['cleanup_outcome'], 'upstream-already-absent')

    def test_other_attempt_consumer_blocks_then_terminal_retry_succeeds(self):
        self.acknowledge(self.save())
        self.cleanup_api(jobs=[{'run_attempt': 1, 'status': 'completed'},
                               {'run_attempt': 2, 'status': 'queued'}])
        self.api.request.reset_mock()
        with self.assertRaisesRegex(e.EvidenceError, 'consumers still running'):
            e.cleanup(self.keyless(), self.api, self.archive)
        self.api.request.assert_not_called()
        self.cleanup_api()
        e.cleanup(self.keyless(), self.api, self.archive)
        self.api.request.assert_called_once()

    def test_retention_is_keyless_and_shared_payload_lives_until_last_reference(self):
        instant = e.now()
        old = instant - dt.timedelta(days=400)
        first = self.save()
        manifest, run = copy.deepcopy(self.manifest), copy.deepcopy(self.run)
        manifest['run_id'] = run['id'] = 124
        run['head_sha'] = manifest['revision'] = 'c' * 40
        second = self.save(manifest, run)
        first['completed_at'] = second['completed_at'] = e.iso(old)
        first['retain_until'] = e.iso(instant - dt.timedelta(seconds=1))
        second['retain_until'] = e.iso(instant + dt.timedelta(days=1))
        for record in (first, second):
            # Seed past deadlines directly; production update correctly forbids shortening them.
            with self.archive.lock():
                self.archive.write('runs/' + record['record_name'], e.canonical(record), replace=True)
        for path in (self.root / 'blobs').glob('*.age'):
            os.utime(path, (old.timestamp(), old.timestamp()))
        self.api.pages.return_value = []
        with mock.patch.object(e, 'age_decrypt', side_effect=AssertionError('decryption forbidden')), \
                mock.patch.object(e, 'sign', side_effect=AssertionError('signing forbidden')):
            e.retain(self.keyless(), self.api, self.archive)
            self.assertEqual([r['run_id'] for r in self.archive.records()], [124])
            self.assertTrue((self.root / 'blobs' / (self.sha + '.age')).exists())
            with mock.patch.object(e, 'now', return_value=instant + dt.timedelta(days=2)):
                e.retain(self.keyless(), self.api, self.archive)
        self.assertEqual(self.archive.records(), [])
        self.assertFalse((self.root / 'blobs' / (self.sha + '.age')).exists())

    def test_cli_roles_load_only_their_own_credential(self):
        for command, field in (('cleanup', 'delete_token_file'), ('retain', 'read_token_file')):
            with self.subTest(command=command):
                config = self.keyless()
                credential = self.root / (command + '-fixture-token')
                credential.write_text(command + '-fixture-credential')
                config[field] = str(credential)
                path = self.root / (command + '.json')
                path.write_text(json.dumps(config))
                with mock.patch.object(sys, 'argv', ['evidence.py', command, '--config', str(path)]), \
                        mock.patch.object(e, 'Archive', return_value=self.archive), \
                        mock.patch.object(e, 'GitHub') as github, \
                        mock.patch.object(e, command if command == 'cleanup' else 'retain') as operation:
                    e.main()
                github.assert_called_once_with('owner/repo', command + '-fixture-credential', max_calls=60)
                operation.assert_called_once_with(config, github.return_value, self.archive)


if __name__ == '__main__':
    unittest.main()

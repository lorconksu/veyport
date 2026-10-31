import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import publication
from artifacts import BINARIES
from risk_acceptance import REPOSITORY, canonical, sha

REV = 'a' * 40
STAMP = '2026-10-31T07:00:00Z'


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.fail_upload = False
        self.bad_digest = False
        self.other_id = False

    def request(self, method, path, value=None, asset=None):
        self.calls.append((method, path, value))
        if asset is not None:
            if self.fail_upload:
                raise ValueError('synthetic asset failure')
            return {'name': asset.name, 'state': 'uploaded', 'size': asset.stat().st_size,
                    'digest': 'sha256:' + ('0' * 64 if self.bad_digest else sha(asset.read_bytes()))}
        if method == 'POST':
            return {'id': 41, 'draft': True, 'tag_name': 'v2.0.58'}
        if method == 'PATCH':
            return {'id': 42 if self.other_id else 41, 'draft': False, 'tag_name': 'v2.0.58', 'prerelease': False,
                    'published_at': STAMP, 'target_commitish': 'mutable-main-is-not-source-proof'}
        raise AssertionError((method, path))


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'bin').mkdir()
        for name in BINARIES:
            (self.root / 'bin' / name).write_bytes(b'synthetic exact binary')
            (self.root / 'bin' / (name + '.sha256')).write_bytes(b'synthetic checksum')
        for name in ('SHA256SUMS', 'artifact-manifest.json'):
            (self.root / 'bin' / name).write_bytes(b'synthetic manifest')
        (self.root / 'release-summary.json').write_text('{}')
        (self.root / 'release-notes.md').write_text('Disclosure-safe release notes')
        self.binding = {'repository': REPOSITORY, 'workflow': '.github/workflows/release.yml', 'run_id': 123, 'run_attempt': 1,
                        'revision': REV, 'candidate_id': 'run-123-1', 'version': '2.0.58', 'tag': 'v2.0.58',
                        'archive_manifest_sha256': 'b' * 64, 'candidate_manifest_sha256': 'c' * 64}

    def test_complete_draft_uploads_exact_id_then_publishes_and_captures_response(self):
        api = FakeAPI()
        with patch.object(publication.git_tag, 'verify') as verify:
            result = publication.publish(self.root, self.binding, False, api)
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(api.calls[0][0], 'POST')
        self.assertTrue(api.calls[0][2]['draft'])
        self.assertEqual(len(api.calls), len(publication.assets(self.root)) + 2)
        for method, path, _ in api.calls[1:-1]:
            self.assertEqual(method, 'POST')
            self.assertIn('/releases/41/assets?name=', path)
            self.assertNotIn('/tags/', path)
        self.assertEqual(api.calls[-1][:2], ('PATCH', '/repos/' + REPOSITORY + '/releases/41'))
        self.assertIs(api.calls[-1][2]['draft'], False)
        self.assertEqual(result['release_id'], 41)
        self.assertEqual(result['published_at'], STAMP)
        self.assertEqual(result['revision'], REV)
        self.assertEqual(result['archive_manifest_sha256'], self.binding['archive_manifest_sha256'])

    def test_asset_error_or_digest_mismatch_never_publishes_partial_draft(self):
        for failure in ('fail_upload', 'bad_digest'):
            with self.subTest(failure=failure):
                api = FakeAPI()
                setattr(api, failure, True)
                with patch.object(publication.git_tag, 'verify'), self.assertRaises(ValueError):
                    publication.publish(self.root, self.binding, False, api)
                self.assertFalse(any(method == 'PATCH' for method, _, _ in api.calls))

    def test_tag_change_during_upload_prevents_publication(self):
        api = FakeAPI()
        with patch.object(publication.git_tag, 'verify', side_effect=[None, ValueError('synthetic moved tag')]), self.assertRaises(ValueError):
            publication.publish(self.root, self.binding, False, api)
        self.assertFalse(any(method == 'PATCH' for method, _, _ in api.calls))

    def test_expired_approval_after_uploads_refuses_final_publication_patch(self):
        api = FakeAPI()
        def expired():
            self.assertEqual(len(api.calls), len(publication.assets(self.root)) + 1)
            raise ValueError('synthetic approval expired during private uploads')
        with patch.object(publication.git_tag, 'verify'), self.assertRaises(ValueError):
            publication.publish(self.root, self.binding, False, api, authorize=expired)
        self.assertFalse(any(method == 'PATCH' for method, _, _ in api.calls))

    def test_wrong_response_id_cannot_create_provenance(self):
        api = FakeAPI()
        api.other_id = True
        with patch.object(publication.git_tag, 'verify'), self.assertRaises(ValueError):
            publication.publish(self.root, self.binding, False, api)

    def test_publication_manifest_binds_exact_run_candidate_and_archive(self):
        result = {**self.binding, 'schema': 1, 'release_id': 41, 'published_at': STAMP}
        manifest = publication.manifest(result)
        self.assertFalse(manifest['complete'])
        self.assertEqual(manifest['files'], [])
        self.assertEqual(manifest['revision'], REV)
        self.assertEqual(manifest['details']['kind'], 'publication')
        for key in ('release_id', 'published_at', 'tag', 'archive_manifest_sha256', 'candidate_manifest_sha256'):
            self.assertEqual(manifest['details'][key], result[key])
        for changed in ({**result, 'release_id': True}, {**result, 'archive_manifest_sha256': 'bad'}, {**result, 'published_at': None}):
            with self.assertRaises(ValueError):
                publication.manifest(changed)

    def test_context_rejects_wrong_run_source_or_archive_candidate(self):
        candidate = {**{key: self.binding[key] for key in ('repository', 'workflow', 'run_id', 'run_attempt', 'revision', 'candidate_id', 'version')}, 'files': []}
        candidate_path = self.root / 'candidate.json'
        candidate_path.write_bytes(canonical(candidate))
        archive = {**{key: self.binding[key] for key in ('repository', 'workflow', 'run_id', 'run_attempt', 'revision', 'candidate_id')},
                   'complete': True, 'files': [{'name': 'candidate.json', 'sha256': sha(candidate_path.read_bytes()), 'size': candidate_path.stat().st_size}]}
        archive_path = self.root / 'archive.json'
        env = {'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_SHA': REV, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_REF': 'refs/tags/v2.0.58'}
        archive_path.write_bytes(canonical(archive))
        with patch.dict(os.environ, env):
            binding = publication.context(candidate_path, archive_path, 'v2.0.58', '2.0.58', False)
            self.assertEqual(binding['candidate_manifest_sha256'], sha(canonical(candidate)))
            for key, value in (('revision', 'd' * 40), ('run_attempt', 2), ('candidate_id', 'other'), ('complete', False)):
                wrong = {**archive, key: value}
                archive_path.write_bytes(canonical(wrong))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    publication.context(candidate_path, archive_path, 'v2.0.58', '2.0.58', False)

    def test_workflow_seals_marker_only_after_independent_publish_step(self):
        workflow = (Path(__file__).resolve().parents[2] / '.github/workflows/delivery.yml').read_text()
        self.assertIn('id: publish_release', workflow)
        self.assertIn("if: inputs.publish && steps.publish_release.outcome == 'success'", workflow)
        self.assertIn('ssdf-publication-v1-${{ github.run_id }}-${{ github.run_attempt }}', workflow)
        self.assertLess(workflow.index('publication.py publish'), workflow.index('publication.py manifest'))
        self.assertIn('publication-transport/evidence.age', workflow)


if __name__ == '__main__':
    unittest.main()

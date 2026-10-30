import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import sync


def archive_fixture(overrides=None, extra=None):
    revision = 'a' * 40
    files = {'reports/build-artifact-manifest.json': json.dumps({'version': '1.2.3', 'revision': revision}).encode()}
    published = []
    for target in sync.TARGETS:
        image_digest = 'sha256:' + 'b' * 64
        image = 'veyport' if target == 'veyport' else 'veyport-' + target
        published.append('docker.io/yiucloud/' + image + '@' + image_digest)
        files[f'reports/{target}.spdx.json'] = b'{"packages":[]}'
        files[f'reports/{target}.scan-binding.json'] = json.dumps({'version': '1.2.3', 'revision': revision, 'published_index_digest': image_digest}).encode()
    files['published-images.txt'] = '\n'.join(published).encode()
    files['DELIVERY_SHA256SUMS'] = '\n'.join(hashlib.sha256(v).hexdigest() + '  ' + k for k, v in files.items() if k.startswith('reports/')).encode()
    files.update(overrides or {})
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as tar:
        for name, data in files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
        if extra:
            tar.addfile(extra, io.BytesIO(b'') if extra.isfile() else None)
    return stream.getvalue()


class EvidenceTests(unittest.TestCase):
    def test_verified_release(self):
        data = archive_fixture()
        found, revision, version = sync.evidence(data, sync.digest(data), 'v1.2.3')
        self.assertEqual((revision, version, len(found)), ('a' * 40, '1.2.3', 9))

    def test_outer_digest_required(self):
        data = archive_fixture()
        for checksum in [None, 'sha256:' + '0' * 64]:
            with self.subTest(checksum=checksum), self.assertRaises(sync.IntegrationError):
                sync.evidence(data, checksum, 'v1.2.3')

    def test_inner_checksum_mismatch(self):
        data = archive_fixture({'reports/veyport.spdx.json': b'altered'})
        with self.assertRaisesRegex(sync.IntegrationError, 'Inner evidence'):
            sync.evidence(data, sync.digest(data), 'v1.2.3')

    def test_rejects_wrong_release(self):
        data = archive_fixture()
        with self.assertRaisesRegex(sync.IntegrationError, 'identity'):
            sync.evidence(data, sync.digest(data), 'v1.2.4')

    def test_rejects_wrong_published_binding(self):
        data = archive_fixture({'published-images.txt': b'wrong'})
        with self.assertRaisesRegex(sync.IntegrationError, 'binding'):
            sync.evidence(data, sync.digest(data), 'v1.2.3')

    def test_rejects_traversal_duplicate_and_link(self):
        link = tarfile.TarInfo('link')
        link.type = tarfile.SYMTYPE
        link.linkname = '/etc/passwd'
        for entry in [tarfile.TarInfo('../escape'), tarfile.TarInfo('published-images.txt'), link]:
            data = archive_fixture(extra=entry)
            with self.subTest(entry=entry.name), self.assertRaises(sync.IntegrationError):
                sync.evidence(data, sync.digest(data), 'v1.2.3')

    def test_expansion_bound(self):
        data = archive_fixture()
        with patch.object(sync, 'MAX_EXPANDED', 10), self.assertRaises(sync.IntegrationError):
            sync.evidence(data, sync.digest(data), 'v1.2.3')


class UploadTests(unittest.TestCase):
    config = {'dependency_track_url': 'https://dt.example'}
    token = b'{"token":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","projectUuid":"project"}'

    def test_waits_for_analysis_completion(self):
        responses = [self.token, b'{"status":"RUNNING","processing":true}', b'{"status":"COMPLETED","processing":false}']
        with patch.object(sync, 'read_url', side_effect=responses) as request, patch.object(sync.time, 'sleep') as sleep:
            self.assertEqual(sync.upload(self.config, 'private-key', 'name', '1.2.3', {}), 'project')
            self.assertEqual(request.call_count, 3)
            sleep.assert_called_once_with(5)

    def test_unknown_and_failed_tokens_fail_closed(self):
        for result in [b'{"processing":false}', b'{"status":"FAILED","processing":false}', b'{"status":"COMPLETED","processing":true}']:
            with self.subTest(result=result), patch.object(sync, 'read_url', side_effect=[self.token, result]), self.assertRaises(sync.IntegrationError):
                sync.upload(self.config, 'key', 'name', 'version', {})

    def test_processing_deadline(self):
        with patch.object(sync, 'read_url', return_value=self.token), self.assertRaisesRegex(sync.IntegrationError, 'deadline'):
            sync.upload(self.config, 'key', 'name', 'version', {}, deadline_seconds=0)

    def test_secret_redirect_is_never_followed(self):
        with self.assertRaises(sync.IntegrationError):
            sync.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.example')

    def test_public_redirect_rejects_downgrade_and_unexpected_host(self):
        for url in ['http://github.com/file', 'https://attacker.example/file']:
            with self.subTest(url=url), self.assertRaises(sync.IntegrationError):
                sync.PublicRedirect().redirect_request(None, None, 302, '', {}, url)


class StateTests(unittest.TestCase):
    def release(self):
        return {'id': 1, 'tag_name': 'v1.2.3', 'assets': [{'name': 'release-evidence.tar.gz', 'digest': 'sha256:' + 'a'*64}]}

    def test_completed_release_is_not_reuploaded(self):
        release = self.release()
        state = {'schema': 1, 'release_digests': {'v1.2.3': release['assets'][0]['digest']}, 'imports': {f'v1.2.3:Veyport / {name}': {} for name in [*sync.TARGETS, 'frontend dependencies']}}
        with tempfile.TemporaryDirectory() as directory, patch.object(sync, 'select_releases', return_value=[release]), patch.object(sync, 'upload') as upload:
            path = Path(directory)/'state.json'
            path.write_text(json.dumps(state))
            sync.sync({}, 'key', Path(directory))
            upload.assert_not_called()
            self.assertIn('last_success', json.loads(path.read_text()))

    def test_replaced_completed_release_refused(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(sync, 'select_releases', return_value=[self.release()]):
            (Path(directory)/'state.json').write_text(json.dumps({'schema': 1, 'release_digests': {'v1.2.3': 'sha256:'+'b'*64}, 'imports': {}}))
            with self.assertRaisesRegex(sync.IntegrationError, 'replaced'):
                sync.sync({}, 'key', Path(directory))

    def test_partial_failure_does_not_record_completion(self):
        data = archive_fixture()
        release = self.release()
        release['assets'][0].update(digest=sync.digest(data),size=len(data),browser_download_url='https://github.com/lorconksu/veyport/releases/download/v1.2.3/release-evidence.tar.gz')
        config = {'repository': 'lorconksu/veyport', 'syft': '/fake/syft'}
        with tempfile.TemporaryDirectory() as directory, patch.object(sync, 'select_releases', return_value=[release]), patch.object(sync, 'read_url', return_value=data), patch.object(sync, 'syft_json', return_value={'bomFormat':'CycloneDX','components':[{'name':'sample'}]}), patch.object(sync, 'upload', side_effect=sync.IntegrationError('failed')):
            with self.assertRaises(sync.IntegrationError):
                sync.sync(config, 'key', Path(directory))
            state = json.loads((Path(directory)/'state.json').read_text())
            self.assertEqual(state['imports'], {})
            self.assertNotIn('last_success',state)
            self.assertEqual(state['release_digests']['v1.2.3'],sync.digest(data))

    def test_deleted_and_recreated_release_cannot_replace_tag(self):
        release = self.release()
        release['id'] = 999
        with tempfile.TemporaryDirectory() as directory, patch.object(sync, 'select_releases', return_value=[release]):
            (Path(directory)/'state.json').write_text(json.dumps({'schema': 1, 'release_digests': {'v1.2.3': 'sha256:'+'b'*64}, 'imports': {}}))
            with self.assertRaisesRegex(sync.IntegrationError, 'replaced'):
                sync.sync({}, 'key', Path(directory))

    def test_discovery_excludes_drafts_prereleases_and_old_versions(self):
        base = {'id':1,'tag_name':'v1.2.3','published_at':'2026-10-29T00:00:00Z'}
        batch = [base,dict(base,id=2,prerelease=True),dict(base,id=3,draft=True),dict(base,id=4,published_at='2026-01-01T00:00:00Z')]
        with patch.object(sync, 'read_url',return_value=json.dumps(batch).encode()):
            self.assertEqual(sync.select_releases({'repository':'lorconksu/veyport','not_before':'2026-10-28T00:00:00Z'}),[base])


if __name__ == '__main__':
    unittest.main()

"""Exercise GitHub request construction and urllib handlers without network I/O."""
from email.message import Message
from http import HTTPStatus
import io
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import urllib.response

import risk_acceptance as risk


ROOT = 'https://api.github.com/repos/' + risk.REPOSITORY
TOKEN = 'synthetic-transport-token'


class Transport(urllib.request.HTTPSHandler):
    """Keep real Request/redirect/error handling; replace only HTTPS transport."""

    def __init__(self):
        super().__init__()
        self.routes = {}
        self.requests = []
        self.read_sizes = []

    def https_open(self, request):
        self.requests.append(request)
        status, body, headers = self.routes[request.full_url]
        metadata = Message()
        for name, value in headers.items():
            metadata[name] = value
        read_sizes = self.read_sizes

        class Body(io.BytesIO):
            def read(self, size=-1):
                read_sizes.append(size)
                return super().read(size)

        response = urllib.response.addinfourl(Body(body), metadata, request.full_url, status)
        response.msg = HTTPStatus(status).phrase
        return response


class RejectHTTP(urllib.request.HTTPHandler):
    def http_open(self, request):
        raise AssertionError('HTTP transport disabled in tests')


class GitHubTransportTests(unittest.TestCase):
    def setUp(self):
        self.transport = Transport()
        original = urllib.request.build_opener

        def build(*handlers):
            opener = original(*handlers, self.transport, RejectHTTP())
            original_open = opener.open

            def open_request(*args, **kwargs):
                try:
                    return original_open(*args, **kwargs)
                except urllib.error.HTTPError as error:
                    self.addCleanup(error.close)
                    raise

            opener.open = open_request
            return opener

        self.opener = patch.object(urllib.request, 'build_opener', side_effect=build)
        self.opener.start()
        self.addCleanup(self.opener.stop)
        # urlopen's unauthenticated artifact request also uses the real urllib
        # machinery with our network-free HTTPS transport and rejecting HTTP.
        self.default_opener = patch.object(urllib.request, '_opener', original(self.transport, RejectHTTP()))
        self.default_opener.start()
        self.addCleanup(self.default_opener.stop)
        self.api = risk.GitHub(TOKEN)

    def route(self, path='', body=b'{}', status=200, headers=None):
        url = ROOT + ('/' + path if path else '')
        self.transport.routes[url] = (status, body, headers or {})
        return url

    def assert_http_error(self, path, status):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.api.get(path)
        self.addCleanup(error.exception.close)
        self.assertEqual(error.exception.code, status)

    def test_both_openers_reject_http_before_any_socket_connection(self):
        openers = (urllib.request.build_opener(), urllib.request._opener)
        with patch('socket.create_connection', side_effect=AssertionError('socket connection attempted')) as connect:
            for opener in openers:
                with self.subTest(opener=opener):
                    with self.assertRaisesRegex(AssertionError, '^HTTP transport disabled in tests$'):
                        opener.open('http://synthetic.blob.core.windows.net/artifact')
            connect.assert_not_called()
        self.assertEqual(self.transport.requests, [])

    def test_empty_repository_route_uses_canonical_url_without_trailing_slash(self):
        self.route(body=b'{"full_name":"lorconksu/veyport"}')
        # Model the actual endpoint distinction instead of accepting either URL.
        self.transport.routes[ROOT + '/'] = (404, b'{}', {})
        self.assertEqual(self.api.get(''), {'full_name': risk.REPOSITORY})
        request, = self.transport.requests
        self.assertEqual(request.full_url, ROOT)
        self.assertEqual(request.get_header('Authorization'), 'Bearer ' + TOKEN)
        self.assertEqual(request.get_header('Accept'), 'application/vnd.github+json')
        self.assertEqual(request.get_header('X-github-api-version'), '2022-11-28')

    def test_nonempty_routes_preserve_exact_path_query_and_json(self):
        paths = ('actions/runs/123', 'actions/runs/123/approvals',
                 'actions/runs/123/artifacts?per_page=100',
                 'compare/' + 'a' * 40 + '...main',
                 'environments/ssdf-risk-approval',
                 'environments/ssdf-risk-approval/deployment-branch-policies')
        for path in paths:
            with self.subTest(path=path):
                url = self.route(path, b'{"ok":true}')
                self.assertEqual(self.api.get(path), {'ok': True})
                self.assertEqual(self.transport.requests[-1].full_url, url)
                self.assertEqual(self.transport.requests[-1].get_header('Authorization'), 'Bearer ' + TOKEN)

    def test_invalid_falsey_nonstring_routes_fail_before_any_request(self):
        for path in (None, False, 0, [], {}, b''):
            with self.subTest(path=path):
                with self.assertRaises(TypeError):
                    self.api.get(path)
        self.assertEqual(self.transport.requests, [])

    def test_content_raw_bytes_and_accept_header_remain_unchanged(self):
        for revision in ('main', 'a' * 40):
            with self.subTest(revision=revision):
                path = 'contents/scripts/release/risk_acceptance.py?ref=' + revision
                url = self.route(path, b'\x00exact raw bytes\xff')
                self.assertEqual(self.api.content('scripts/release/risk_acceptance.py', revision),
                                 b'\x00exact raw bytes\xff')
                self.assertEqual(self.transport.requests[-1].full_url, url)
                self.assertEqual(self.transport.requests[-1].get_header('Accept'), 'application/vnd.github.raw+json')
        with self.assertRaises(ValueError):
            self.api.content('file', 'feature')

    def test_repository_and_other_api_redirects_are_not_followed(self):
        for path in ('', 'actions/runs/123'):
            with self.subTest(path=path):
                self.route(path, status=302, headers={'Location': 'https://other.example/redirect'})
                before = len(self.transport.requests)
                self.assert_http_error(path, 302)
                self.assertEqual(len(self.transport.requests), before + 1)

    def test_http_failures_are_not_retried_or_treated_as_metadata(self):
        for status in (403, 404):
            with self.subTest(status=status):
                self.route(status=status)
                before = len(self.transport.requests)
                self.assert_http_error('', status)
                self.assertEqual(len(self.transport.requests), before + 1)

    def test_only_zip_302_uses_allowlisted_unauthenticated_artifact_download(self):
        path = 'actions/artifacts/123/zip'
        target = 'https://synthetic.blob.core.windows.net/artifact'
        self.route(path, status=302, headers={'Location': target})
        self.transport.routes[target] = (200, b'\x00zip bytes\xff', {})
        self.assertEqual(self.api.get(path, raw=True), b'\x00zip bytes\xff')
        first, second = self.transport.requests
        self.assertEqual(first.full_url, ROOT + '/' + path)
        self.assertEqual(first.get_header('Authorization'), 'Bearer ' + TOKEN)
        self.assertEqual(second.full_url, target)
        self.assertIsNone(second.get_header('Authorization'))
        self.assertIsNone(second.get_header('Accept'))

    def test_artifact_redirect_guard_rejects_untrusted_targets_without_a_second_request(self):
        path = 'actions/artifacts/123/zip'
        targets = ('http://synthetic.blob.core.windows.net/object',
                   'https://untrusted.example/object',
                   'https://synthetic.blob.core.windows.net.untrusted.example/object',
                   'https://user:synthetic-secret@synthetic.blob.core.windows.net/object',
                   'https://synthetic.blob.core.windows.net@untrusted.example/object', '')
        for target in targets:
            with self.subTest(target=target):
                self.route(path, status=302, headers={'Location': target})
                before = len(self.transport.requests)
                with self.assertRaisesRegex(ValueError, '^unexpected artifact download host$'):
                    self.api.get(path, raw=True)
                self.assertEqual(len(self.transport.requests), before + 1)
        for status in (301, 307):
            with self.subTest(status=status):
                self.route(path, status=status, headers={'Location': targets[1]})
                self.assert_http_error(path, status)

    def test_bounded_reads_and_strict_json_apply_to_repository_and_raw_responses(self):
        for raw in (False, True):
            with self.subTest(raw=raw):
                self.route(body=b'x' * (risk.MAX_BYTES + 2))
                with self.assertRaisesRegex(ValueError, '^GitHub response exceeds bound$'):
                    self.api.get('', raw=raw)
                self.assertEqual(self.transport.read_sizes[-1], risk.MAX_BYTES + 1)
        self.route(body=b'{"id":1,"id":2}')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            self.api.get('')


if __name__ == '__main__':
    unittest.main()

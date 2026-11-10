"""Real-age CI payload redaction and omission tests, independent of full collector."""
import base64
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

REV = 'a' * 40


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

    def encrypt(self, paths, status='success', job='unit', runner_results=None):
        with patch.dict(os.environ, self.environment), patch.object(ci_evidence.subprocess, 'check_output', return_value=(REV + '\n').encode()):
            ci_evidence.encrypt_job(self.source, self.root / 'encrypted', self.recipient, job, status, paths, REV, '.github/workflows/ci.yml', runner_results)
        results = []
        for path in sorted((self.root / 'encrypted').glob('*.age')):
            wire = path.read_bytes()
            self.assertNotIn(b'sensitive-test-token-value', wire)
            clear = subprocess.run(['age', '--decrypt', '-i', str(self.identity)], input=wire, check=True, capture_output=True).stdout
            with zipfile.ZipFile(io.BytesIO(clear)) as archive:
                manifest = json.loads(archive.read('manifest.json'))
                blobs = {name.removeprefix('blobs/'): archive.read(name) for name in archive.namelist() if name.startswith('blobs/')}
            results.append((manifest, blobs))
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

    def test_nested_credentials_are_removed_before_real_age_chunk_archiving(self):
        payload = {'status': 'failed', 'errors': [{'message': 'request failed'}],
                   'request': {'body': {'sessionId': 'nested-body-canary'},
                               'headers': [{'name': 'Cookie', 'value': 'sid=header-array-canary'},
                                           {'name': 'Authorization', 'values': ['header-list-canary']}],
                               'responseHeaders': [['Authorization', 'Basic pair-auth-canary'],
                                                   ['Cookie', 'sid=pair-cookie-canary'],
                                                   ['Content-Type', 'application/json']]},
                   'token': 314159265, 'storageState': None,
                   'postData': [{'secret': 'post-list-canary'}],
                   'ceTaskId': 'scanner-task-123', 'analysisId': 'analysis-456',
                   'approval_id': 'approval-789', 'key': 'source-issue-key'}
        (self.source / 'report.json').write_text(json.dumps(payload, indent=2))
        (self.source / 'runner.stdout').write_text('Cookie: sid=plain-cookie-canary\n\tfolded-cookie-canary\nAuthorization: Basic plain-auth-canary\n\tcontinued-auth-canary\nOutcome: failed\n')
        malformed = b'prefix\n{"body":{"sessionId":"malformed-pack-canary"}}'
        (self.source / 'malformed.json').write_bytes(malformed)
        chunks = self.encrypt(['*.json', '*.stdout'], 'failure', job='sonar')
        contents = b'\n'.join(value for _, blobs in chunks for value in blobs.values())
        for secret in (b'nested-body-canary', b'header-array-canary', b'plain-cookie-canary', b'folded-cookie-canary', b'header-list-canary',
                       b'post-list-canary', b'plain-auth-canary', b'continued-auth-canary', b'malformed-pack-canary',
                       b'pair-auth-canary', b'pair-cookie-canary'):
            self.assertNotIn(secret, contents)
        for metadata in (b'scanner-task-123', b'analysis-456', b'approval-789', b'source-issue-key', b'request failed', b'Outcome: failed'):
            self.assertIn(metadata, contents)
        manifest = chunks[0][0]
        omitted = manifest['details']['omitted_files']
        self.assertEqual(omitted, [{'name': 'malformed.json', 'original_sha256': hashlib.sha256(malformed).hexdigest(),
                                   'size': len(malformed), 'reason': 'unparseable-sensitive-diagnostic-excluded'}])
        blobs = {digest: value for _, contents in chunks for digest, value in contents.items()}
        report = next(item for item in manifest['details']['original_files'] if item['name'] == 'report.json')
        retained = json.loads(b''.join(blobs[part['sha256']] for part in report['parts']))
        self.assertEqual(retained['token'], '[REDACTED]')
        self.assertEqual(retained['storageState'], '[REDACTED]')
        self.assertEqual(retained['postData'], '[REDACTED]')
        self.assertEqual(retained['request']['responseHeaders'], [['Authorization', '[REDACTED]'],
                          ['Cookie', '[REDACTED]'], ['Content-Type', 'application/json']])
        self.assertTrue(all(m['details']['status'] == 'failure' and not m['complete'] for m, _ in chunks))
        self.assertTrue(all(item['redacted'] for m, _ in chunks for item in m['details']['original_files']))

    def test_assignment_and_private_key_diagnostics_are_sanitized_before_real_age(self):
        key = '-----BEGIN PRIVATE KEY-----\nprivate-key-canary\n-----END PRIVATE KEY-----'
        (self.source / 'runner.stdout').write_text('password=assignment-canary\n' + key + '\nceTaskId=task-kept\n')
        bad = b'-----BEGIN RSA PRIVATE KEY-----\ntruncated-key-canary\n'
        (self.source / 'truncated.stderr').write_bytes(bad)
        chunks = self.encrypt(['*.stdout', '*.stderr'], 'failure', job='sonar')
        blobs = {digest: value for _, contents in chunks for digest, value in contents.items()}
        retained = b'\n'.join(blobs.values())
        for secret in (b'assignment-canary', b'private-key-canary', b'truncated-key-canary'):
            self.assertNotIn(secret, retained)
        self.assertIn(b'ceTaskId=task-kept', retained)
        details = chunks[0][0]['details']
        self.assertEqual(details['omitted_files'], [{'name': 'truncated.stderr',
            'original_sha256': hashlib.sha256(bad).hexdigest(), 'size': len(bad),
            'reason': 'malformed-private-key-diagnostic-excluded'}])
        self.assertEqual([item['name'] for item in details['original_files']], ['runner.stdout'])
        self.assertTrue(details['original_files'][0]['redacted'])
        self.assertFalse(chunks[0][0]['complete'])

    def test_unsupported_xml_and_body_formats_are_omitted_before_real_age(self):
        unsafe = {'document.xml': b'<request><body>XML_BODY_CANARY</body></request>',
                  'empty.XML': b'', 'misnamed.json': b'<?xml version="1.0"?><response><body>XML_BODY_CANARY</body></response>',
                  'prefixed.log': b'provider diagnostic\n<ns:requestBody>XML_BODY_CANARY</ns:requestBody>',
                  'mixed-carrier.log': b'x<' + b' \t\r\n' * (1 << 14) + b'ns:BODY>XML_BODY_CANARY',
                  'junit.xml': b'<testsuite><testcase><failure><body>XML_BODY_CANARY</body></failure></testcase></testsuite>',
                  'yaml.out': b'request:\n  body:\n    sessionId: YAML_BODY_CANARY\n',
                  'properties.txt': b'request_body=PROPERTY_BODY_CANARY\n'}
        for name, raw in unsafe.items():(self.source / name).write_bytes(raw)
        native = {'ceTaskId': 'task-kept', 'analysisId': 'analysis-kept', 'status': 'completed',
                  'signature': {'digest': 'a' * 64}, 'body': {'sessionId': 'JSON_BODY_CANARY'}}
        (self.source / 'native.json').write_text(json.dumps(native))
        chunks = self.encrypt(['*'], 'failure', job='sonar')
        blobs = {digest: raw for _, contents in chunks for digest, raw in contents.items()}
        payloads = b'\n'.join(blobs.values())
        for value in (b'XML_BODY_CANARY', b'YAML_BODY_CANARY', b'PROPERTY_BODY_CANARY', b'JSON_BODY_CANARY'):
            self.assertNotIn(value, payloads)
        details = chunks[0][0]['details']
        omitted = {entry['name']: entry for entry in details['omitted_files']}
        self.assertEqual(set(omitted), set(unsafe))
        for name, raw in unsafe.items():
            self.assertEqual(omitted[name]['original_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(omitted[name]['size'], len(raw))
            self.assertEqual(omitted[name]['reason'], 'unsupported-structured-body-diagnostic-excluded' if name in ('yaml.out', 'properties.txt') else 'xml-diagnostic-excluded')
        self.assertEqual([entry['name'] for entry in details['original_files']], ['native.json'])
        entry = details['original_files'][0]
        retained = json.loads(b''.join(blobs[part['sha256']] for part in entry['parts']))
        self.assertEqual(retained['ceTaskId'], native['ceTaskId'])
        self.assertEqual(retained['signature'], native['signature'])
        self.assertEqual(retained['body'], '[REDACTED]')
        self.assertFalse(chunks[0][0]['complete'])

    def test_escaped_sensitive_key_after_malformed_prefix_is_omitted_before_real_age(self):
        raw = b'provider "unterminated prefix "b\\u006fdy": "BODY_CANARY"'
        (self.source / 'diagnostic.log').write_bytes(raw)
        safe = b'{"ceTaskId":"task-kept","snippet":"<body>source example</body>","token_count":3}'
        (self.source / 'native.json').write_bytes(safe)
        chunks = self.encrypt(['*.log', '*.json'], 'failure', job='sonar')
        details = chunks[0][0]['details']
        self.assertEqual(details['omitted_files'], [{'name': 'diagnostic.log',
            'original_sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw),
            'reason': 'unparseable-sensitive-diagnostic-excluded'}])
        blobs = {digest: data for _, contents in chunks for digest, data in contents.items()}
        self.assertNotIn(b'BODY_CANARY', b'\n'.join(blobs.values()))
        self.assertEqual([item['name'] for item in details['original_files']], ['native.json'])
        original = details['original_files'][0]
        self.assertEqual(b''.join(blobs[part['sha256']] for part in original['parts']), safe)
        self.assertFalse(chunks[0][0]['complete'])
        self.assertEqual(details['status'], 'failure')

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

    def test_browser_media_archives_and_disguised_binary_are_omitted_not_retained(self):
        canary = b'private-browser-media-canary'
        png = b'\x89PNG\r\n\x1a\n' + canary + b'\x00pixels'
        browser = self.source / 'tests/e2e/test-results'
        browser.mkdir(parents=True)
        (browser / 'failure.PNG').write_bytes(png)
        (browser / 'video.WEBM').write_bytes(b'\x1aE\xdf\xa3' + canary)
        (browser / 'misnamed.json').write_bytes(png)
        (browser / 'invalid-utf8.TXT').write_bytes(b'\xff' + canary)
        (browser / 'snapshot.json').write_bytes(b'<svg>' + canary + b'</svg>')
        (browser / 'raw.trace').write_bytes(b'{"body":"' + canary + b'"}')
        (browser / 'raw.network').write_bytes(canary)
        (browser / 'report.HTML').write_bytes(b'<html>' + canary + b'</html>')
        (browser / 'unknown.bin').write_bytes(canary)
        with zipfile.ZipFile(browser / 'trace.ZIP', 'w') as archive:
            archive.writestr('resources/image.png', png)
            archive.writestr('test.trace', b'{"body":"' + canary + b'"}')
        report = browser / 'results.JSON'
        report.write_text(json.dumps({'status': 'failed', 'message': 'expected <html> content', 'token': 'sensitive-test-token-value'}))
        chunks = self.encrypt(['tests/e2e/test-results/'], 'failure', job='e2e')
        manifest = chunks[0][0]
        self.assertFalse(manifest['complete'])
        details = manifest['details']
        self.assertEqual(details['status'], 'failure')
        self.assertEqual(details['diagnostic_policy'], 'redacted-text-only/v1')
        self.assertEqual(details['missing'], [])
        self.assertEqual([item['name'] for item in details['original_files']], ['tests/e2e/test-results/results.JSON'])
        omitted = {item['name']: item for item in details['omitted_files']}
        self.assertEqual(set(omitted), {p.relative_to(self.source).as_posix() for p in browser.iterdir() if p != report})
        for name, entry in omitted.items():
            raw = (self.source / name).read_bytes()
            self.assertEqual(entry['original_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(entry['size'], len(raw))
            self.assertNotIn('parts', entry)
        retained = b''.join(payload for _, blobs in chunks for payload in blobs.values())
        self.assertNotIn(canary, retained)
        self.assertNotIn(b'sensitive-test-token-value', retained)
        self.assertIn(b'expected <html> content', retained)

    def test_only_browser_media_produces_honest_empty_partial_outcome(self):
        raw = b'\x89PNG\r\n\x1a\nprivate-browser-media-canary'
        (self.source / 'capture.png').write_bytes(raw)
        chunks = self.encrypt(['capture.png'], 'failure', job='e2e')
        self.assertEqual(len(chunks), 1)
        manifest, blobs = chunks[0]
        self.assertEqual(blobs, {})
        self.assertEqual(manifest['files'], [])
        self.assertEqual(manifest['details']['original_files'], [])
        self.assertEqual(manifest['details']['missing'], [])
        self.assertEqual(manifest['details']['omitted_files'], [{'name': 'capture.png', 'original_sha256': hashlib.sha256(raw).hexdigest(),
                                                                  'size': len(raw), 'reason': 'browser-capture-excluded'}])
        self.assertFalse(manifest['complete'])

    def test_structured_runner_report_retains_errors_but_no_embedded_capture_payloads(self):
        canary = b'private-browser-media-canary'
        encoded = base64.b64encode(canary).decode()
        runner = self.root / 'ssdf-results'
        runner.mkdir()
        report = {'status': 'failed', 'errors': [{'message': 'expected control visible'}],
                  'attachments': [{'name': 'screenshot', 'contentType': 'image/png', 'body': encoded}],
                  'steps': [{'screenshots': [encoded], 'browser_trace': {'resources': encoded}}]}
        (runner / 'e2e.stdout').write_text(json.dumps(report))
        (runner / 'e2e.stderr').write_text('prefix diagnostic\n{"attachments":[{"body":{"data":"' + encoded + '"}}]}\n')
        (runner / 'capture.JSON').write_bytes(b'\x89PNG' + canary)
        chunks = self.encrypt([], 'failure', job='e2e', runner_results=runner)
        manifest = chunks[0][0]
        self.assertEqual(len(manifest['details']['original_files']), 2)
        self.assertTrue(all(item['redacted'] for item in manifest['details']['original_files']))
        self.assertEqual(manifest['details']['omitted_files'][0]['name'], 'runner-results/capture.JSON')
        contents = b'\n'.join(payload for _, blobs in chunks for payload in blobs.values())
        self.assertNotIn(canary, contents)
        self.assertNotIn(encoded.encode(), contents)
        self.assertIn(b'expected control visible', contents)
        self.assertIn(b'OMITTED unparseable browser report', contents)
        self.assertIn(b'OMITTED browser capture', contents)


class DiagnosticRedactionTests(unittest.TestCase):
    def test_sensitive_fields_are_omitted_recursively_for_every_value_shape(self):
        fields = ('body', 'request_body', 'response-body', 'PostData', 'storageState', 'auth',
                  'credentials', 'password', 'secret', 'client-secret', 'token', 'access_token',
                  'refreshToken', 'totp-secret', 'Authorization', 'Proxy-Authorization',
                  'Cookie', 'Set-Cookie', 'x-api-key')
        for field in fields:
            for value in ('nested-secret-canary', {'sessionId': 'nested-secret-canary'}, [{'value': 'nested-secret-canary'}], 314159265, True, None):
                with self.subTest(field=field, value_type=type(value).__name__):
                    raw = json.dumps({'steps': [{'request': {field: value, 'method': 'POST'}}], 'status': 'failed'}, indent=2).encode()
                    result = ci_evidence.redact(raw)
                    self.assertNotIn(b'nested-secret-canary', result)
                    self.assertEqual(json.loads(result)['steps'][0]['request'][field], '[REDACTED]')
                    self.assertEqual(json.loads(result)['status'], 'failed')
                    self.assertEqual(json.loads(result)['steps'][0]['request']['method'], 'POST')

    def test_header_arrays_and_nested_string_headers_omit_values_without_hiding_results(self):
        payload = {'headers': [{'NaMe': 'sEt-CoOkIe', 'VaLuE': {'value': 'header-secret-canary'}},
                               {'name': 'Authorization', 'values': ['auth-secret-canary']},
                               {'name': 'Content-Type', 'value': 'application/json'}],
                   'errors': [{'message': 'Cookie: sid=string-secret-canary\n  folded-secret-canary\nrequest failed'}]}
        result = ci_evidence.redact(json.dumps(payload).encode())
        for secret in (b'header-secret-canary', b'auth-secret-canary', b'string-secret-canary', b'folded-secret-canary'):
            self.assertNotIn(secret, result)
        decoded = json.loads(result)
        self.assertEqual(decoded['headers'][2]['value'], 'application/json')
        self.assertIn('request failed', decoded['errors'][0]['message'])

    def test_header_pair_arrays_are_redacted_only_inside_known_header_carriers(self):
        for carrier in ('headers', 'requestHeaders', 'response_headers'):
            with self.subTest(carrier=carrier):
                payload = {'nested': [{carrier: [['AUTHORIZATION', 'Basic pair-auth-canary'],
                                                 ['cOoKiE', {'value': 'pair-cookie-canary'}],
                                                 ['Content-Type', 'application/json']]}],
                           'metadata': [['Cookie', 'public-cookie-label'], ['Authorization', 'public-auth-label']]}
                result = ci_evidence.redact(json.dumps(payload).encode())
                self.assertNotIn(b'pair-auth-canary', result)
                self.assertNotIn(b'pair-cookie-canary', result)
                decoded = json.loads(result)
                self.assertEqual(decoded['nested'][0][carrier], [['AUTHORIZATION', '[REDACTED]'],
                                 ['cOoKiE', '[REDACTED]'], ['Content-Type', 'application/json']])
                self.assertEqual(decoded['metadata'], payload['metadata'])

    def test_unstructured_headers_are_case_insensitive_and_remove_folded_lines(self):
        for header in ('Cookie', 'Set-Cookie', 'Authorization', 'Proxy-Authorization', 'X-API-Key', 'X-Auth-Token'):
            for prefix in ('', '> ', '< '):
                with self.subTest(header=header, prefix=prefix):
                    raw = ('before diagnostic\r\n' + prefix + header.swapcase() + ': short-secret-canary\r\n\tcontinued-secret-canary\r\n\tsecond-secret-canary\r\nOutcome: failed\r\n').encode()
                    result = ci_evidence.redact(raw)
                    self.assertNotIn(b'secret-canary', result)
                    self.assertIn(b'before diagnostic', result)
                    self.assertIn(b'Outcome: failed', result)

    def test_malformed_or_mixed_sensitive_json_is_omitted_instead_of_falling_back_raw(self):
        for raw in (b'prefix\n{"body":{"sessionId":"malformed-secret-canary"}}',
                    b'{"request":{"AUTHORIZATION":["malformed-secret-canary"]',
                    b'{"status":"failed"}\n{"storage_state":{"cookies":["malformed-secret-canary"]}}',
                    b'{"safe":{"body":"malformed-secret-canary"},"safe":{"status":"failed"}}'):
            with self.subTest(raw=raw):
                result = ci_evidence.redact(raw)
                self.assertNotIn(b'malformed-secret-canary', result)
                self.assertIn(b'OMITTED', result)

    def test_plaintext_credential_assignments_remove_quoted_unquoted_and_multiline_values(self):
        cases = ('password=assignment-canary', 'PASSWORD = "assignment-canary with spaces"',
                 "export PASSWORD='assignment-canary\nsecond-secret-line'", 'SONAR_TOKEN=assignment-canary',
                 'api_key=assignment-canary; status=failed')
        for value in cases:
            with self.subTest(value=value):
                result = ci_evidence.redact((value + '\nceTaskId=task-kept\nanalysisId=analysis-kept\n').encode())
                self.assertNotIn(b'assignment-canary', result)
                self.assertNotIn(b'second-secret-line', result)
                self.assertIn(b'ceTaskId=task-kept', result)
                self.assertIn(b'analysisId=analysis-kept', result)

    def test_exact_collector_credential_label_catalog_keeps_safe_metadata(self):
        names = ('AWS_SECRET_ACCESS_KEY', 'aws-secret-access-key', 'AWS_ACCESS_KEY_ID', 'AWS_SESSION_TOKEN',
                 'AWS_SECURITY_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'SONAR_TOKEN', 'SNYK_TOKEN', 'DOCKERHUB_TOKEN',
                 'DHI_TOKEN', 'GITLEAKS_LICENSE', 'X-API-Key', 'X_API_KEY', 'x-auth-token', 'X_AUTH_TOKEN',
                 'X_AMZ_SECURITY_TOKEN', 'client-secret', 'api-key', 'registration-token', 'access-token',
                 'refresh-token', 'totp-secret')
        metadata = b'ceTaskId=task-kept\ntoken_count=12\nAWS_REGION=eu-west-1\nAWS_PROFILE=profile-kept\npublic_key_id=key-kept\nsignature_sha256=' + b'a' * 64 + b'\n'
        for name in names:
            value = 'catalog-secret-canary; later=catalog-suffix-canary'
            for raw in ((name + '=' + value + '\n').encode() + metadata,
                        ('[debug] ' + name + ': Basic ' + value + '\n').encode() + metadata,
                        json.dumps({name: value, 'ceTaskId': 'task-kept', 'signature': 'public-signature'}).encode()):
                with self.subTest(name=name, raw=raw):
                    result = ci_evidence.redact(raw)
                    self.assertNotIn(b'catalog-secret-canary', result)
                    self.assertNotIn(b'catalog-suffix-canary', result)
                    self.assertIn(b'task-kept', result)
                    if raw.startswith(b'{'):
                        self.assertEqual(json.loads(result)['signature'], 'public-signature')
                    else:
                        self.assertIn(metadata, result)
        self.assertEqual(ci_evidence.redact(metadata), metadata)

    def test_structured_message_assignments_and_private_keys_keep_valid_metadata(self):
        payload = {'message': 'password="assignment-canary" ceTaskId=task-in-message',
                   'detail': '-----BEGIN EC PRIVATE KEY-----\nprivate-key-canary\n-----END EC PRIVATE KEY-----',
                   'signature': {'digest': 'a' * 64}, 'ceTaskId': 'task-kept', 'quality_gate': 'ERROR'}
        result = ci_evidence.redact(json.dumps(payload).encode())
        self.assertNotIn(b'assignment-canary', result)
        self.assertNotIn(b'private-key-canary', result)
        decoded = json.loads(result)
        self.assertEqual(decoded['ceTaskId'], payload['ceTaskId'])
        self.assertEqual(decoded['signature'], payload['signature'])
        self.assertIn('ceTaskId=task-in-message', decoded['message'])
        self.assertEqual(decoded['quality_gate'], 'ERROR')

    def test_standard_private_pem_blocks_are_omitted_but_public_material_is_unchanged(self):
        for kind in ('PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY',
                     'OPENSSH PRIVATE KEY', 'ENCRYPTED PRIVATE KEY'):
            with self.subTest(kind=kind):
                raw = ('before\n-----BEGIN ' + kind + '-----\nprivate-key-canary\n-----END ' + kind + '-----\nstatus=failed\n').encode()
                result = ci_evidence.redact(raw)
                self.assertNotIn(b'private-key-canary', result)
                self.assertIn(b'before', result)
                self.assertIn(b'status=failed', result)
        for kind in ('CERTIFICATE', 'PUBLIC KEY', 'RSA PUBLIC KEY'):
            raw = ('-----BEGIN ' + kind + '-----\npublic-evidence-value\n-----END ' + kind + '-----').encode()
            self.assertEqual(ci_evidence.redact(raw), raw)

    def test_ambiguous_secret_carriers_are_refused_instead_of_returning_partial_raw(self):
        for raw in (b'password="left"\xc2\xa0PRIVATE_CONCAT_CANARY',
                    b'password="left"\xe2\x80\x8bPRIVATE_CONCAT_CANARY',
                    b'password="left"\xe2\x80\x83PRIVATE_CONCAT_CANARY',
                    b'password="left"PRIVATE_CONCAT_CANARY', b"password='left'PRIVATE_CONCAT_CANARY",
                    b'password="left""PRIVATE_CONCAT_CANARY"', b'password="unterminated-secret-canary', b'password=\\"escaped-secret-canary\\"',
                    b'-----BEGIN PRIVATE KEY-----\nmissing-end-secret-canary',
                    b'-----BEGIN RSA PRIVATE KEY-----\nwrong-label-secret-canary\n-----END EC PRIVATE KEY-----',
                    b'-----BEGIN PRIVATE KEY----\ntruncated-header-secret-canary'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                ci_evidence.redact(raw)

    def test_exact_scanner_and_approval_metadata_survive_redaction(self):
        metadata = {'ceTaskId': 'task-123', 'analysisId': 'analysis-456', 'projectKey': 'lorconksu_veyport',
                    'key': 'issue-key', 'revision': REV, 'status': 'completed', 'authenticated': True,
                    'quality_gate': 'ERROR', 'approval_id': 'approval-789', 'expires_at': '2026-11-11T00:00:00Z',
                    'signature': {'digest': 'a' * 64, 'certificate': 'public-certificate'},
                    'conditions': [{'status': 'ERROR', 'metricKey': 'coverage', 'actualValue': '79.0'}]}
        self.assertEqual(json.loads(ci_evidence.redact(json.dumps(metadata).encode())), metadata)
        properties = b'projectKey=lorconksu_veyport\nceTaskId=task-123\nceTaskUrl=https://sonarcloud.io/api/ce/task?id=task-123\n'
        self.assertEqual(ci_evidence.redact(properties), properties)


class DiagnosticFormatBoundaryTests(unittest.TestCase):
    def test_xml_suffix_and_recognizable_xml_under_native_text_suffixes_are_omitted(self):
        for suffix in ('.xml', '.XML'):
            for raw in (b'', b'plain-text fixture', b'<body>XML_BODY_CANARY</body>'):
                self.assertEqual(ci_evidence.diagnostic_omission(Path('report' + suffix), raw), 'xml-diagnostic-excluded')
        samples = (b'<body>XML_BODY_CANARY</body>', b'<body/>', b'<root/>',
                   b'<?xml version="1.0"?><request><body>XML_BODY_CANARY</body></request>',
                   b'\xef\xbb\xbf<?xml version="1.0"?><response><body>XML_BODY_CANARY</body></response>',
                   b'<!-- diagnostic --><ns:Response><ns:Body>XML_BODY_CANARY</ns:Body></ns:Response>',
                   b'<!DOCTYPE request [<!ENTITY fixture SYSTEM "https://example.invalid/entity">]><request><body>&fixture;</body></request>',
                   b'<response><body><![CDATA[XML_BODY_CANARY]]></body></response>',
                   b' ' * 5000 + b'<root><body>XML_BODY_CANARY</body></root>',
                   b'provider diagnostic\n<ns:requestBody>XML_BODY_CANARY</ns:requestBody>')
        for suffix in ('.json', '.jsonl', '.sarif', '.txt', '.log', '.out', '.info', '.properties', '.stdout', '.stderr'):
            for raw in samples:
                with self.subTest(suffix=suffix, raw=raw[:80]):
                    self.assertEqual(ci_evidence.diagnostic_omission(Path('report' + suffix), raw), 'xml-diagnostic-excluded')
                    with self.assertRaises(ValueError):ci_evidence.redact(raw)

    def test_non_json_body_mapping_carriers_are_omitted_without_a_yaml_parser(self):
        for raw in (b'request:\n  body:\n    sessionId: BODY_CANARY\n', b"'requestBody': |\n  BODY_CANARY\n",
                    b'{response_body: BODY_CANARY}', b'post_data=BODY_CANARY\n',
                    b'storageState:\n  cookies: [BODY_CANARY]\n', b'credentials:\n  session: BODY_CANARY\n'):
            with self.subTest(raw=raw):
                self.assertEqual(ci_evidence.diagnostic_omission(Path('report.txt'), raw), 'unsupported-structured-body-diagnostic-excluded')
                with self.assertRaises(ValueError):ci_evidence.redact(raw)
        self.assertEqual(ci_evidence.diagnostic_omission(Path('report.yaml'), b'body: BODY_CANARY'), 'unsupported-diagnostic-format')

    def test_large_xml_prefixes_finish_in_a_bounded_child(self):
        program = r'''
from pathlib import Path
import json, resource, sys, time
resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
sys.path.insert(0, str(Path(sys.argv[1]).parent))
import ci_evidence
kind, size = sys.argv[2], int(sys.argv[3])
if kind == 'whitespace':raw = b' ' * (size - 20) + b'<body>CANARY</body>'
elif kind == 'comment':raw = b'<!--' + b'x' * (size - 7) + b'-->'
else:raw = b'<' + b'A' * (size - 3) + b'/>'
began = time.monotonic()
assert ci_evidence.diagnostic_omission(Path('report.out'), raw) == 'xml-diagnostic-excluded'
print(json.dumps({'bytes': len(raw), 'seconds': time.monotonic() - began}))
'''
        for kind in ('whitespace', 'comment', 'tag'):
            with self.subTest(kind=kind):
                result = subprocess.run([sys.executable, '-I', '-S', '-c', program,
                    str(Path(ci_evidence.__file__).resolve()), kind, str(8 << 20)], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertGreater(json.loads(result.stdout)['bytes'], 7 << 20)

    def test_mixed_xml_carriers_preserve_exact_ascii_whitespace_and_label_boundaries(self):
        for whitespace in (b'', b' ', b'\t\r\n ', b' ' * 64):
            for slash in (b'', b'/'):
                for label in (b'body', b'REQUEST-body', b'response_body', b'postData',
                              b'storage-state', b'Credentials', b'auth_state'):
                    raw = b'provider x<' + whitespace + slash + whitespace + b'ns:' + label + b'>CANARY'
                    with self.subTest(raw=raw):
                        self.assertEqual(ci_evidence.diagnostic_omission(Path('report.log'), raw), 'xml-diagnostic-excluded')
                        with self.assertRaisesRegex(ci_evidence.UnsafeDiagnostic, '^xml-diagnostic-excluded$'):
                            ci_evidence.redact(raw)
        for raw in (b'x< bodyX>ordinary', b'x< / /body>ordinary', b'x<\vbody>ordinary',
                    b'x<\fbody>ordinary', b'x<\x01body>ordinary', b'x<\xc2\xa0body>ordinary',
                    b'x< ns::body>ordinary', b'x< :body>ordinary', b'x< ns:bodyX>ordinary',
                    b'x< body\v>ordinary', b'x< body\x01>ordinary'):
            with self.subTest(raw=raw):
                self.assertIsNone(ci_evidence.diagnostic_omission(Path('report.log'), raw))
                self.assertEqual(ci_evidence.redact(raw), raw)

    def test_mixed_xml_carrier_search_is_bounded_in_a_child(self):
        # The mixed prefix bypasses XML_PREFIX and reaches the carrier search.
        # Both successful and failing searches must finish without overlapping
        # whitespace backtracking; failures also traverse normal text redaction.
        program = r'''
from pathlib import Path
import json, resource, sys, time
resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
sys.path.insert(0, str(Path(sys.argv[1]).parent))
import ci_evidence
kind, size = sys.argv[2], int(sys.argv[3])
space = (b' \t\r\n' * ((size + 3) // 4))[:size]
endings = {'missing': b'', 'near-label': b'bodyX>', 'slash-missing': b'/ ',
           'slash-near-label': b'/ ' + space + b'ns:requestBodyX>',
           'control': b'\x01body>', 'slashes': b'/' * size + b'body>',
           'body': b'ns:requestBody>CANARY', 'closing-body': b'/ ' + space + b'NS:BODY>CANARY'}
raw = b'x<' + space + endings[kind]
began = time.monotonic()
expected = 'xml-diagnostic-excluded' if kind in {'body', 'closing-body'} else None
assert ci_evidence.diagnostic_omission(Path('report.out'), raw) == expected
if expected:
    try: ci_evidence.redact(raw)
    except ci_evidence.UnsafeDiagnostic as error: assert str(error) == expected
    else: raise AssertionError('recognized XML carrier was retained')
else:
    assert ci_evidence.redact(raw) == raw
print(json.dumps({'bytes': len(raw), 'seconds': time.monotonic() - began}))
'''
        for kind in ('missing', 'near-label', 'slash-missing', 'slash-near-label',
                     'control', 'slashes', 'body', 'closing-body'):
            with self.subTest(kind=kind):
                result = subprocess.run([sys.executable, '-I', '-S', '-c', program,
                    str(Path(ci_evidence.__file__).resolve()), kind, str(1 << 20)],
                    capture_output=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertGreater(json.loads(result.stdout)['bytes'], 1 << 20)

    def test_json_key_hints_preserve_escaped_sensitive_fields_after_malformed_prefixes(self):
        for key, expected in ((b'"b\\u006fdy"', 'body'), (b'"requ\\u0065st_body"', 'requestbody'),
                              (b'"HEADERS"', 'headers'), (b'"\\u0063redentials"', 'credentials')):
            for prefix in (b'{', b'provider: ', b'log "unterminated prefix ', b'\\"quoted\\" log '):
                raw = prefix + key + b' \t\r\n: "BODY_CANARY"'
                with self.subTest(raw=raw):
                    self.assertIn(expected, ci_evidence.report_hints(raw))
                    self.assertEqual(ci_evidence.diagnostic_omission(Path('report.log'), raw),
                                     'unparseable-sensitive-diagnostic-excluded')
                    self.assertEqual(ci_evidence.redact(raw), b'[OMITTED unparseable credential report]\n')
        for raw in (b'"body', b'"body\\"', b'"body\\q": "ordinary"',
                    b'"b\\uZZZZdy": "ordinary"', b'"not\\\"Xbody": "ordinary"',
                    b'"bodyX": "ordinary"', b'"token_count": 4'):
            with self.subTest(raw=raw):
                self.assertFalse(ci_evidence.report_hints(raw) & ci_evidence.SENSITIVE_FIELDS)
                self.assertIsNone(ci_evidence.diagnostic_omission(Path('report.log'), raw))
                self.assertEqual(ci_evidence.redact(raw), raw)
        # Malformed whitespace and escaped-quote prefixes remain conservative.
        for raw in (b'"body"\v\f: "BODY_CANARY"', b'"not\\\"body": "BODY_CANARY"'):
            self.assertIn('body', ci_evidence.report_hints(raw))
            self.assertEqual(ci_evidence.diagnostic_omission(Path('report.log'), raw),
                             'unparseable-sensitive-diagnostic-excluded')
            self.assertEqual(ci_evidence.redact(raw), b'[OMITTED unparseable credential report]\n')
        quoted_name = json.dumps({'not"ordinary': 'ordinary metadata', 'ceTaskId': 'task-kept'}).encode()
        self.assertIsNone(ci_evidence.diagnostic_omission(Path('native.json'), quoted_name))
        self.assertEqual(ci_evidence.redact(quoted_name), quoted_name)
        native = b'{"b\\u006fdy":{"session":"BODY_CANARY"},"ceTaskId":"task-kept"}'
        self.assertIsNone(ci_evidence.diagnostic_omission(Path('report.json'), native))
        self.assertEqual(json.loads(ci_evidence.redact(native)), {'body': '[REDACTED]', 'ceTaskId': 'task-kept'})

    def test_escaped_quote_hint_search_is_bounded_in_a_child(self):
        program = r'''
from pathlib import Path
import json, resource, sys, time
resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
sys.path.insert(0, str(Path(sys.argv[1]).parent))
import ci_evidence
raw = bytes([92, 34]) * (1 << 15) + b'x'
began = time.monotonic()
assert not ci_evidence.report_hints(raw)
assert ci_evidence.diagnostic_omission(Path('diagnostic.log'), raw) is None
assert ci_evidence.redact(raw) == raw
print(json.dumps({'bytes': len(raw), 'seconds': time.monotonic() - began}))
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-c', program,
            str(Path(ci_evidence.__file__).resolve())], capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout)['bytes'], 65537)

    def test_configured_native_scanner_formats_remain_supported_and_metadata_exact(self):
        native = {'ceTaskId': 'task-kept', 'analysisId': 'analysis-kept', 'status': 'completed',
                  'signature': {'digest': 'a' * 64}, 'message': 'ordinary scanner outcome'}
        sarif = {'version': '2.1.0', 'runs': [{'results': [{'ruleId': 'rule-kept', 'message': {'text': 'ordinary finding'}}]}]}
        for name, raw in (('native.json', json.dumps(native).encode()), ('results.sarif', json.dumps(sarif).encode()),
                          ('coverage.out', b'mode: atomic\nhub/main.go:1.1,2.1 1 1\n'),
                          ('lcov.info', b'TN:\nSF:web/src/app.ts\nDA:1,1\nend_of_record\n'),
                          ('report-task.properties', b'projectKey=lorconksu_veyport\nceTaskId=task-kept\n')):
            with self.subTest(name=name):
                self.assertIsNone(ci_evidence.diagnostic_omission(Path(name), raw))
                self.assertEqual(ci_evidence.redact(raw), raw)
        # Source snippets in supported JSON/SARIF are not reinterpreted as XML.
        snippet = json.dumps({'ruleId': 'rule-kept', 'snippet': '<body>source example</body>'}).encode()
        self.assertIsNone(ci_evidence.diagnostic_omission(Path('snippet.sarif'), snippet))
        self.assertEqual(ci_evidence.redact(snippet), snippet)

"""Local-only fixture regression tests. No VM, archive or API connection."""
import contextlib
import base64
import datetime
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import load


class LoadFixture(unittest.TestCase):
    def test_plan_has_no_network_or_private_credential_reads(self):
        with mock.patch.object(sys, 'argv', ['load.py']), mock.patch.object(load.q, 'request', side_effect=AssertionError('network')), mock.patch.object(load.q, 'remote', side_effect=AssertionError('VM')), mock.patch.object(load.q, 'private_bytes', side_effect=AssertionError('credentials')), contextlib.redirect_stdout(io.StringIO()) as output:
            load.main()
        self.assertIn('Plan only', output.getvalue())

    def test_eight_collectors_wait_for_barrier_and_keep_outputs_isolated(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            commands = []
            try:
                submitted = []
                def command(actor, script, output_directory, name):
                    self.assertTrue(all((directory / previous.name).exists() and previous.process.poll() is None for previous in submitted))
                    # Actual local complete scripts, smaller binary output for
                    # this tooling test; no simulated remote admission retry.
                    script = load.output_script(str(directory), name, 64 << 10, len(submitted) + 1, True)
                    current = load.Command(['/bin/sh', '-s'], os.environ, script, output_directory, name, actor)
                    submitted.append(current)
                    return current
                def snapshot(marker):
                    return {'processes': {current.name: {'state': 'S'} for current in submitted if (directory / current.name).exists() and current.process.poll() is None}}
                def wait(description, check, timeout):
                    deadline = time.monotonic() + timeout
                    while not check():
                        if time.monotonic() >= deadline:
                            self.fail('Staged local fixture process did not reach barrier')
                        time.sleep(0.01)
                with mock.patch.object(load, 'lab_command', side_effect=command) as launch, mock.patch.object(load, 'snapshot', side_effect=snapshot), mock.patch.object(load.q, 'wait_for', side_effect=wait):
                    self.assertEqual(load.start_gated_commands(str(directory), directory, commands, timeout=5), commands)
                self.assertEqual(launch.call_count, 8)
                self.assertTrue(all(c.process.poll() is None for c in commands))
                (directory / 'release').touch()
                load.collect(commands, timeout=5)
                for index, command in enumerate(commands):
                    load.assert_output(command, 64 << 10, index + 1)
                    self.assertEqual((directory / (command.name + '.script')).stat().st_mode & 0o777, 0o600)
                    self.assertNotIn('python3', json.dumps(command.evidence()))
                self.assertEqual([c.actor for c in commands].count(load.ACTORS[0]), 4)
                self.assertEqual([c.actor for c in commands].count(load.ACTORS[1]), 4)
                self.assertEqual(len({c.evidence()['stdout_sha256'] for c in commands}), 8)
            finally:
                for command in commands:
                    command.close()

    def test_rejected_staged_admission_is_never_retried_or_followed_by_more_submissions(self):
        rejected = mock.Mock(name='rejected-command')
        rejected.process.poll.return_value = 3
        commands = []
        def wait(description, check, timeout):
            self.assertGreater(timeout, 0)
            check()
        with mock.patch.object(load, 'lab_command', return_value=rejected) as launch, mock.patch.object(load, 'snapshot') as snapshot, mock.patch.object(load.q, 'wait_for', side_effect=wait):
            with self.assertRaisesRegex(RuntimeError, 'no retry'):
                load.start_gated_commands('/tmp/veyport-load-' + 'a' * 24, Path('/unused'), commands)
            self.assertEqual(launch.call_count, 1)
            snapshot.assert_not_called()
            self.assertEqual(commands, [rejected])
        with mock.patch.object(load, 'lab_command') as launch:
            with self.assertRaisesRegex(RuntimeError, 'bounded deadline'):
                load.start_gated_commands('/tmp/veyport-load-' + 'a' * 24, Path('/unused'), [], timeout=0)
            launch.assert_not_called()

    def test_quiet_command_completes_while_large_consumer_is_paused_and_drains_exactly(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            commands = []
            try:
                slow = load.Command(['/bin/sh', '-s'], os.environ, load.output_script(str(directory), 'slow', 1 << 20, 19), directory, 'slow', pause_seconds=0.6)
                commands.append(slow)
                quiet = load.Command(['/bin/sh', '-s'], os.environ, load.output_script(str(directory), 'quiet', 256, 7), directory, 'quiet')
                commands.append(quiet)
                load.collect(commands, timeout=5)
                self.assertLess(quiet.completed, slow.resume_stdout)
                load.assert_output(slow, 1 << 20, 19)
                load.assert_output(quiet, 256, 7)
            finally:
                for command in commands:
                    command.close()

    def test_oversize_and_hung_output_fail_with_bounded_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, code, maximum, message in [
                ('oversize', 'import sys;sys.stdout.buffer.write(b"x"*4096)', 1024, 'output exceeded'),
                ('hung', 'import time;time.sleep(30)', load.MAX_STDOUT, 'bounded deadline'),
            ]:
                command = load.Command([sys.executable, '-c', code], os.environ, b'', directory, name)
                try:
                    with mock.patch.object(load, 'MAX_STDOUT', maximum), self.assertRaisesRegex(RuntimeError, message):
                        load.collect([command], timeout=0.3)
                finally:
                    command.close()
                self.assertIsNotNone(command.process.poll())
                self.assertTrue(command.source.closed)
                self.assertTrue(all(stream.closed for stream in command.streams))

    def test_leader_exit_does_not_leave_descendant_holding_fixture_pipes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            code = 'import subprocess,sys;subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"]);sys.exit(23)'
            command = load.Command([sys.executable, '-c', code], os.environ, b'', directory, 'held-pipe')
            try:
                with self.assertRaisesRegex(RuntimeError, 'bounded deadline'):
                    load.collect([command], timeout=0.3)
                self.assertEqual(command.process.poll(), 23)
            finally:
                command.close()
            self.assertTrue(all(stream.closed for stream in command.streams))

    def test_exit_between_final_pipe_drain_and_loop_condition_retains_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            command = load.Command(['/bin/sh', '-s'], os.environ, b'exit 0\n', directory, 'exit-race')
            command.process.wait(timeout=2)
            try:
                with mock.patch.object(command.process, 'poll', side_effect=[None, 0]):
                    load.collect([command], timeout=2)
                self.assertIsNotNone(command.completed)
                self.assertEqual(command.evidence()['exit_code'], 0)
            finally:
                command.close()

    def test_private_state_and_cleanup_cannot_touch_other_principals(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(load, 'STATE_FILE', Path(temporary) / 'fixture.json'):
            load.persist({'users': {'load-a': {'password': 'private-fixture-canary'}}})
            self.assertEqual(load.STATE_FILE.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(load.STATE_FILE.read_text())['users']['load-a']['password'], 'private-fixture-canary')
        with mock.patch.object(load.q, 'request') as request:
            with self.assertRaisesRegex(RuntimeError, 'unrelated principal'):
                load.disable_actors({'users': {'load-a': {'id': 'a' * 36, 'username': 'protected-approver'}}}, 'token')
            request.assert_not_called()
        with mock.patch.object(load.q, 'remote') as remote:
            for directory in ('/tmp', '/tmp/veyport-load-invalid', '/tmp/veyport-load-' + 'a' * 24 + ';id'):
                with self.assertRaises(RuntimeError):
                    load.marker_operation(directory, 'cleanup')
            remote.assert_not_called()

    def test_protected_roles_never_count_as_ordinary_load_actor(self):
        user = {'role': 'admin', 'roles': ['admin'], 'capabilities': ['terminal.execute']}
        self.assertTrue(load.operational(user))
        self.assertTrue(load.operational({**user, 'id': 'ordinary-id', 'person_id': 'user:ordinary-id'}))
        for changes in ({'roles': ['admin', 'security-approver']}, {'person_id': 'enrolled-person'}, {'role': 'viewer'}, {'capabilities': []}):
            self.assertFalse(load.operational({**user, **changes}))

    def test_existing_provisioner_uses_totp_challenge_response_contract(self):
        calls = []
        def request(path, body=None, token='', expected=200, method=None):
            calls.append((path, expected))
            if path == '/api/auth/login':
                self.assertEqual(expected, 202)
                return {'totp_token': 'synthetic-challenge'}
            self.assertEqual(path, '/api/auth/login/totp')
            self.assertEqual(expected, 200)
            return {'access_token': 'synthetic-session'}
        state = {'last_mfa_at': 1}
        bootstrap = {'users': {'officer': {'username': 'synthetic-officer', 'password': 'private-password'}}}
        with mock.patch.object(load.q, 'request', side_effect=request), mock.patch.object(load.q, 'fresh_code', return_value='synthetic-code'):
            self.assertEqual(load.login_provisioner(bootstrap, state), 'synthetic-session')
        self.assertEqual(calls, [('/api/auth/login', 202), ('/api/auth/login/totp', 200)])

    def test_normal_user_setup_uses_only_password_mfa_and_operational_role(self):
        created = {}
        requests = []
        current = None
        def request(path, body=None, token='', expected=200, method=None):
            nonlocal current
            requests.append((path, body))
            if path == '/api/users':
                self.assertEqual(expected, 201)
                current = ('a' if not created else 'b') * 8 + '-1234-1234-1234-' + '0' * 12
                created[current] = body['username']
                return {'user': {'id': current}, 'temporary_password': 'private-temporary-password'}
            if path.startswith('/api/security/principals?'):
                identity = path.split('search=')[1]
                return {'principals': [{'id': identity, 'username': created[identity], 'roles': ['admin'], 'person_id': 'user:' + identity}]}
            if path == '/api/auth/login':
                self.assertEqual(expected, 200)  # temporary-password setup token.
                return {'setup_token': 'test-setup'}
            if path == '/api/auth/totp/setup':
                return {'secret': 'TESTSEED'}
            if path == '/api/auth/totp/enable':
                return {'access_token': 'test-normal-session'}
            if path == '/api/auth/me':
                return {'id': current, 'role': 'admin', 'roles': ['admin'], 'person_id': 'user:' + current, 'capabilities': ['terminal.execute']}
            if path.endswith('/status'):
                self.assertEqual(method, 'PUT')
                return {'disabled': body['disabled']}
            raise AssertionError('Unexpected fixture API route')
        state = {}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(load, 'STATE_FILE', Path(temporary) / 'fixture.json'), mock.patch.object(load.q, 'request', side_effect=request), mock.patch.object(load.q, 'fresh_code', return_value='test-code'), mock.patch.object(load.q, 'cli_login') as login, mock.patch.object(load.q, 'cli') as cli:
            load.prepare_actors(state, 'test-provisioner')
            self.assertEqual(login.call_count, 2)
            self.assertEqual(cli.call_args_list, [mock.call(actor, ['ssh-cert']) for actor in load.ACTORS])
            load.disable_actors(state, 'test-provisioner')
            self.assertTrue(all(state['users'][actor]['disabled'] for actor in load.ACTORS))
            load.prepare_actors(state, 'test-provisioner')
            self.assertTrue(all(not state['users'][actor]['disabled'] for actor in load.ACTORS))
            self.assertEqual(load.STATE_FILE.stat().st_mode & 0o777, 0o600)
        self.assertEqual([body['role'] for path, body in requests if path == '/api/users'], ['admin', 'admin'])
        self.assertFalse(any('/api/security/changes' in path or 'step-up' in path for path, _ in requests))

    def test_explicit_status_method_reaches_normal_urllib_request(self):
        response = mock.MagicMock(status=200)
        response.__enter__.return_value = response
        response.read.return_value = b'{"disabled":true}'
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(load.q.ssl, 'create_default_context'), mock.patch.object(load.q.urllib.request, 'build_opener', return_value=opener):
            load.q.request('/api/users/synthetic-user/status', {'disabled': True}, 'private-fixture-token', method='PUT')
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), 'PUT')
        self.assertEqual(json.loads(request.data), {'disabled': True})
        self.assertEqual(opener.open.call_args.kwargs['timeout'], 15)

    def test_cleanup_refuses_new_protected_binding_before_status_mutation(self):
        user = {'id': 'a' * 8 + '-1234-1234-1234-' + '0' * 12, 'username': 'lab_synthetic_load_a'}
        page = {'principals': [{'id': user['id'], 'username': user['username'], 'roles': ['admin', 'security-approver'], 'person_id': 'protected-person'}]}
        with mock.patch.object(load.q, 'request', return_value=page) as request:
            with self.assertRaisesRegex(RuntimeError, 'protected authority'):
                load.disable_actors({'users': {'load-a': user}}, 'test-provisioner')
            self.assertEqual(request.call_count, 1)
            self.assertIn('/api/security/principals?', request.call_args.args[0])

    def test_outage_partition_uses_scoped_multiline_rule_and_cleans_up_after_failure(self):
        calls = []
        success = mock.Mock(returncode=42, stdout=b'isolated-verified', stderr=b'isolated-stderr')
        def remote(host, command, raw=b''):
            calls.append((host, command, raw))
            return b'x' if b"operation = 'read'" in raw else b''
        def cli(person, arguments, *args):
            if arguments == ['ssh-cert']:
                return {}
            if any(command == 'sudo -n nft -f -' for _, command, _ in calls):
                raise RuntimeError('synthetic CLI failure during outage')
            return success
        with mock.patch.object(load.q, 'remote', side_effect=remote), mock.patch.object(load.q, 'cli', side_effect=cli), mock.patch.object(load.q, 'wait_for'), mock.patch.object(load.q, 'database', return_value=[{}]), mock.patch.object(load.q, 'verify_stored_receipt', return_value={}):
            with self.assertRaisesRegex(RuntimeError, 'during outage'):
                load.q.execution_matrix({})
        partition = [raw for host, command, raw in calls if command == 'sudo -n nft -f -']
        self.assertEqual(len(partition), 1)
        lines = partition[0].decode().splitlines()
        self.assertEqual(lines[-2:], ['  }', '}'])
        self.assertIn('ip daddr 10.10.1.60 tcp dport 8443 reject', partition[0].decode())
        self.assertEqual([host for host, command, _ in calls if 'nft' in command], ['hub', 'hub'])
        self.assertEqual(calls[-1][:2], ('hub', 'sudo -n nft delete table inet veyport_lab_receipt_fault'))

    def test_execution_markers_keep_private_permissions_and_refuse_other_paths(self):
        with mock.patch.object(load.q, 'remote', return_value=b'x') as remote:
            for path in ('/tmp', '/tmp/veyport-isolated-invalid', '/tmp/veyport-isolated-' + 'a' * 24 + ';id'):
                with self.assertRaises(RuntimeError):
                    load.q.execution_marker(path, 'cleanup')
            remote.assert_not_called()
            marker = '/tmp/veyport-isolated-' + 'a' * 24
            self.assertEqual(load.q.execution_marker(marker, 'read'), b'x')
            self.assertEqual(remote.call_args.args[:2], ('agent', 'sudo -n python3 -'))
            source = remote.call_args.args[2].decode()
            compile(source, '<fixture-marker>', 'exec')
            self.assertIn('os.O_NOFOLLOW', source)
            self.assertIn('info.st_uid != 0', source)
            self.assertIn('os.read(fd, 2)', source)
            self.assertNotIn('chmod', source)

    def test_production_compact_receipt_verifies_signature_exact_binding_and_manifest(self):
        # Representative production storage format. The two digest constants
        # were independently computed by auditrecord.Digest in Go, including
        # the execution/details wrapper and millisecond preparation expiry.
        at = datetime.datetime(2026, 10, 11, tzinfo=datetime.timezone.utc)
        preparation = {'preparation_id': 'preparation.fixture', 'boot_id': 'boot.fixture', 'expires_unix_milli': int(at.timestamp() * 1000) + 120123,
                       'limits': {'max_frame_bytes': 32768, 'max_buffer_bytes': 1048576, 'runtime_seconds': 60, 'term_grace_seconds': 5, 'blocked_consumer_seconds': 60},
                       'identity': {'username': 'root', 'uid': 0, 'gid': 0, 'groups': [0], 'groups_sha256': 'a' * 64, 'identity_sha256': 'b' * 64, 'home': '/root', 'shell': '/bin/sh', 'cwd': '/root'}}
        row = {'id': 'execution.fixture', 'actor_id': 'actor.fixture', 'actor_person_id': 'user:actor.fixture', 'actor_name': 'lab_synthetic_load_a', 'actor_provider': 'local', 'actor_subject': 'lab_synthetic_load_a',
               'node_id': 'node.fixture', 'node_name': 'lab-encrypted-target', 'command_sha256': 'c' * 64, 'command_length': 10, 'script_sha256': 'd' * 64, 'script_length': 124,
               'policy_version': '2', 'policy_sha256': 'e' * 64, 'preparation': json.dumps(preparation), 'admission_event_id': 'execution.fixture.admission', 'admission_record_sha256': 'f' * 64, 'created_at': at.isoformat(), 'retention_hours': 24}
        manifest = {'bucket': 'fixture-originals', 'key': 'manifest/fixture', 'version_id': 'immutable-fixture-version', 'sha256': '0' * 64, 'bytes': 512, 'retain_until': '2026-10-12T00:00:00Z'}
        claims = {'iss': 'https://fixture.invalid', 'aud': ['fixture-hub'], 'iat': int(at.timestamp()), 'nbf': int(at.timestamp()), 'exp': int(at.timestamp()) + 60, 'jti': row['admission_event_id'],
                  'schema_version': 1, 'key_id': 'fixture-key', 'event_id': row['admission_event_id'], 'event_type': 'execution.admission', 'record_sha256': 'f' * 64,
                  'actor_sha256': '8a196e17d5f2aad17f18f18146c792f21cdfa0b1930d51167652f92d7f76aea8', 'binding_sha256': 'ba3d31ab55525f4c3a98f762df4514d782748ae59d1c311f4810f26539435234',
                  'policy_version': 2, 'policy_sha256': 'e' * 64, 'execution_id': row['id'], 'preparation_id': preparation['preparation_id'], 'boot_id': preparation['boot_id'], 'node_id': row['node_id'],
                  'identity_sha256': 'b' * 64, 'manifest': manifest, 'qualification_sha256': '1' * 64}
        encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b'=').decode()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            key, public = directory / 'key.pem', directory / 'public.pem'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(key)], check=True, capture_output=True, timeout=5)
            subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(public)], check=True, capture_output=True, timeout=5)
            def sign(value):
                header = encode(json.dumps({'typ': 'JWT', 'alg': 'ES256', 'kid': 'fixture-key'}).encode())
                payload = encode(json.dumps(value).encode())
                message = (header + '.' + payload).encode()
                der = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key)], input=message, check=True, capture_output=True, timeout=5).stdout
                self.assertEqual(der[0], 0x30)
                self.assertEqual(der[2], 0x02)
                size = der[3]
                r = der[4:4 + size].lstrip(b'\0').rjust(32, b'\0')
                offset = 4 + size
                self.assertEqual(der[offset], 0x02)
                s = der[offset + 2:].lstrip(b'\0').rjust(32, b'\0')
                return message.decode() + '.' + encode(r + s)
            runtime = {'signing_key_id': 'fixture-key', 'signing_public_key_path': str(public), 'issuer': claims['iss'], 'audience': 'fixture-hub', 'qualification_sha256': '1' * 64}
            token = sign(claims)
            with mock.patch.object(load.q, 'PRIVATE', directory), mock.patch.object(load.q, 'private_bytes', return_value=json.dumps(runtime).encode()):
                result = load.q.verify_stored_receipt({**row, 'admission_receipt': token})
                self.assertTrue(result['signature_verified'])
                self.assertEqual(result['manifest_version'], manifest['version_id'])
                self.assertNotIn(token, json.dumps(result))
                self.assertFalse((directory / 'execution-receipt-signature.der').exists())
                for changes in ({'actor_name': 'different-actor'}, {'script_length': 123}, {'command_sha256': '2' * 64}, {'retention_hours': 48}, {'retention_hours': None}):
                    with self.assertRaises(RuntimeError):
                        load.q.verify_stored_receipt({**row, **changes, 'admission_receipt': token})
                for modified in ({**claims, 'manifest': {**manifest, 'version_id': 'null'}}, {**claims, 'manifest': {**manifest, 'retain_until': '2026-10-11T01:00:00Z'}}, {**claims, 'exp': int(at.timestamp()) + 121}):
                    with self.assertRaises(RuntimeError):
                        load.q.verify_stored_receipt({**row, 'admission_receipt': sign(modified)})
                parts = token.split('.')
                signature = bytearray(base64.urlsafe_b64decode(parts[2] + '=='))
                signature[0] ^= 1
                with self.assertRaises(RuntimeError):
                    load.q.verify_stored_receipt({**row, 'admission_receipt': '.'.join(parts[:2] + [encode(signature)])})
                with self.assertRaises(RuntimeError):
                    load.q.verify_stored_receipt({**row, 'admission_receipt': json.dumps({'token': token, 'manifest': manifest})})

    def test_evidence_requires_exact_actor_node_and_finished_enhanced_state(self):
        command = mock.Mock(script_sha256='a' * 64, actor='load-a')
        state = {'users': {'load-a': {'id': 'actor-a'}}, 'target_id': 'node-a'}
        row = {'script_sha256': command.script_sha256, 'actor_id': 'actor-a', 'node_id': 'node-a', 'enhanced': 1, 'state': 'exited', 'evidence_state': 'confirmed'}
        with mock.patch.object(load.q, 'database', return_value=[row]):
            self.assertIsNotNone(load.execution_rows([command], state))
            for changes in ({'actor_id': 'actor-b'}, {'node_id': 'node-b'}, {'enhanced': 0}):
                with mock.patch.object(load.q, 'database', return_value=[{**row, **changes}]), self.assertRaisesRegex(RuntimeError, 'binding'):
                    load.execution_rows([command], state)
            with mock.patch.object(load.q, 'database', return_value=[{**row, 'state': 'running'}]):
                self.assertIsNone(load.execution_rows([command], state))


if __name__ == '__main__':
    unittest.main()

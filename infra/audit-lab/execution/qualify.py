#!/usr/bin/env python3
"""Real built CLI, encrypted spools and receipt checks in the isolated .59/.64 lab."""
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import ssl
import struct
import subprocess
import sys
import termios
import time
import urllib.error
import urllib.request

from deploy import ARTIFACTS, HERE, PRIVATE, private_bytes, remote, write_remote

HUB = 'https://10.10.1.59:8443'
STATE_FILE = PRIVATE / 'execution-fixture.json'
os.umask(0o077)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        raise RuntimeError('Lab REST redirect rejected')


def persist(state):
    temporary = STATE_FILE.with_suffix('.new')
    temporary.write_text(json.dumps(state))
    temporary.chmod(0o600)
    os.replace(temporary, STATE_FILE)


def request(path, body=None, token='', expected=200):
    if not path.startswith('/api/'):
        raise RuntimeError('REST path outside lab API')
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    raw = None if body is None else json.dumps(body).encode()
    context = ssl.create_default_context(cafile=str(PRIVATE / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
    try:
        response = opener.open(urllib.request.Request(HUB + path, raw, headers), timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read((1 << 20) + 1)
        if response.status != expected or len(data) > 1 << 20:
            raise RuntimeError('Lab REST contract failed at ' + path.split('?')[0] + ' status=' + str(response.status))
        return json.loads(data)


def fresh_code(state, person):
    user = state['users'][person]
    while True:
        now = time.time()
        slot = int(now // 30)
        # Login and protected step-up share a three-attempt/minute IP limit.
        # Keep all synthetic people below that real limit without resetting it.
        if slot > user.get('used_slot', 0) and now >= state.get('last_mfa_at', 0) + 23:
            break
        time.sleep(1)
    secret = base64.b32decode(user['totp_secret'] + '=' * (-len(user['totp_secret']) % 8))
    digest = hmac.new(secret, struct.pack('>Q', slot), hashlib.sha1).digest()
    offset = digest[-1] & 15
    code = str((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)
    user['used_slot'], state['last_mfa_at'] = slot, time.time()
    persist(state)
    return code


def cli_environment(person):
    config = PRIVATE / 'execution-cli' / person
    config.mkdir(mode=0o700, parents=True, exist_ok=True)
    config.chmod(0o700)
    environment = dict(os.environ, XDG_CONFIG_HOME=str(config), SSL_CERT_FILE=str(PRIVATE / 'ca.crt'), DBUS_SESSION_BUS_ADDRESS='unix:path=/nonexistent-veyport-lab-keyring')
    environment.pop('VEYPORT_TOKEN', None)
    return environment


def cli(person, arguments, data=None, expected=0, timeout=45):
    try:
        result = subprocess.run([str(ARTIFACTS / 'vey'), '--json', '--hub', HUB, *arguments], input=data, capture_output=True, env=cli_environment(person), timeout=timeout)
    finally:
        transient = PRIVATE / ('execution-' + person + '.totp')
        if '--totp-file' in arguments and transient.exists():
            transient.unlink()
    if expected is None:
        return result
    if result.returncode != expected:
        raise RuntimeError('Real CLI contract failed at ' + arguments[0] + ' exit=' + str(result.returncode))
    return json.loads(result.stdout)


def cli_login(state, person):
    user = state['users'][person]
    master, slave = pty.openpty()
    settings = termios.tcgetattr(slave)
    settings[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, settings)
    process = subprocess.Popen([str(ARTIFACTS / 'vey'), '--json', '--hub', HUB, 'login'], stdin=slave, stdout=subprocess.PIPE, stderr=slave, env=cli_environment(person))
    prompts = [(b'Username: ', lambda: user['username']), (b'Password: ', lambda: user['password']), (b'One-time code (valid for 60 seconds): ', lambda: fresh_code(state, person))]
    transcript = b''  # Private terminal bytes are never emitted or saved.
    try:
        deadline = time.monotonic() + 120
        for prompt, value in prompts:
            while prompt not in transcript:
                if time.monotonic() > deadline or process.poll() is not None:
                    raise RuntimeError('Real CLI login prompt contract failed')
                if select.select([master], [], [], 1)[0]:
                    transcript += os.read(master, 4096)
                    if len(transcript) > 64 << 10:
                        raise RuntimeError('Real CLI login output exceeded bound')
            if termios.tcgetattr(slave)[3] & termios.ECHO:
                raise RuntimeError('Private lab terminal echo unexpectedly enabled')
            os.write(master, value().encode() + b'\n')
            transcript = b''
        output, _ = process.communicate(timeout=30)
        if process.returncode or json.loads(output)['username'] != user['username']:
            raise RuntimeError('Real CLI login did not establish expected interactive session')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        os.close(slave)


def setup_users_and_target(state):
    initialized = request('/api/auth/status')['initialized']
    if initialized and not state.get('users'):
        raise RuntimeError('Existing isolated database has no matching private fixture state; refused reset')
    users = state.setdefault('users', {})
    for person in ['officer', 'approver-a', 'approver-b']:
        user = users.setdefault(person, {'username': 'lab_synthetic_' + person.replace('-', '_'), 'password': 'Isolated-7!' + secrets.token_urlsafe(24)})
        persist(state)
        if 'id' in user and 'totp_secret' in user and user.get('complete'):
            continue
        if person == 'officer':
            response = request('/api/auth/register', {'username': user['username'], 'email': person + '@isolated.invalid', 'password': user['password']})
            user['id'], setup_token = response['user']['id'], response['setup_token']
            temporary_password = ''
        else:
            admin = users['officer']['access_token']
            response = request('/api/users', {'username': user['username'], 'email': person + '@isolated.invalid', 'role': 'viewer'}, admin, 201)
            user['id'], temporary_password = response['user']['id'], response['temporary_password']
            setup_token = request('/api/auth/login', {'username': user['username'], 'password': temporary_password})['setup_token']
        user['totp_secret'] = request('/api/auth/totp/setup', {}, token=setup_token)['secret']
        persist(state)
        payload = {'code': fresh_code(state, person)}
        if temporary_password:
            payload['new_password'] = user['password']
        user['access_token'] = request('/api/auth/totp/enable', payload, setup_token)['access_token']
        user['complete'] = True
        persist(state)
    if not state.get('target_id'):
        created = request('/api/servers', {'name': 'lab-encrypted-target', 'labels': '{"environment":"isolated-synthetic-audit-lab"}'}, users['officer']['access_token'], 201)
        pin = re.search(r"--ca-pin '([0-9a-f]{64})'", created['install_command'])
        if pin is None:
            raise RuntimeError('Normal enrollment CA pin missing')
        state['target_id'] = created['server']['id']
        environment = 'VEYPORT_LAB_REGISTRATION_TOKEN=' + created['registration_token'] + '\nVEYPORT_LAB_CA_PIN=' + pin.group(1) + '\n'
        write_remote('agent', '/srv/veyport/config/execution-agent/enrollment.env', environment.encode())
        persist(state)
    remote('agent', 'sudo -n systemctl restart veyport-lab-agent\nsudo -n systemctl is-active --quiet veyport-lab-agent')
    print('Synthetic principals enrolled through normal password/MFA APIs; target enrollment uses pinned gRPC TLS', flush=True)


def database(query):
    script = "import sqlite3,json\nc=sqlite3.connect('file:/srv/veyport/data/veyport-isolated.db?mode=ro',uri=True)\nc.row_factory=sqlite3.Row\nprint(json.dumps([dict(r) for r in c.execute(" + repr(query) + ")]))\n"
    return json.loads(remote('hub', 'sudo -n python3 -', script.encode()))


def wait_for(description, check, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(2)
    raise RuntimeError('Isolated lab timeout: ' + description)


def mfa_arguments(state, person):
    path = PRIVATE / ('execution-' + person + '.totp')
    path.write_text(fresh_code(state, person))
    path.chmod(0o600)
    return ['--totp-file', str(path)]


def prepare_candidate(state):
    for person in state['users']:
        cli_login(state, person)
    status = cli('officer', ['security', 'status'])
    if status['policy']['version'] != 1 or status['state'] != 'standard':
        raise RuntimeError('Browser bootstrap requires pristine never-enrolled Standard policy')
    runtime = json.loads(private_bytes(PRIVATE / 'receipt-runtime.json'))
    if not state.get('candidate_policy'):
        credential = {'certificate_pem': private_bytes(runtime['clients']['hub-ingest']['certificate_path']).decode(), 'private_key_pem': private_bytes(runtime['clients']['hub-ingest']['key_path']).decode()}
        path = PRIVATE / 'execution-destination.json'
        path.write_text(json.dumps(credential)); path.chmod(0o600)
        reference = cli('officer', ['security', 'secret', '--kind', 'destination', '--value-file', str(path)])['credential_ref']
        state['candidate_policy'] = {'profile': 'enhanced', 'actors': [], 'nodes': [state['target_id']], 'runtime_seconds': 60, 'retention_hours': 24, 'destination': runtime['endpoint'], 'credential_ref': reference, 'trust_key_ids': [runtime['signing_key_id']], 'qualification_sha256': runtime['qualification_sha256']}
        persist(state)
    payload = {'kind': 'bootstrap', 'policy': state['candidate_policy'], 'nominations': [{'user_id': state['users'][person]['id'], 'person_id': 'isolated-synthetic-person-' + person, 'roles': ['security-officer' if person == 'officer' else 'security-approver'], 'verification': 'Isolated .59 synthetic fixture; no human or owner approval represented'} for person in state['users']]}
    change_path = PRIVATE / 'execution-bootstrap.json'
    change_path.write_text(json.dumps(payload)); change_path.chmod(0o600)
    remote('hub', 'sudo -n python3 -', b"import sqlite3,os\np='/srv/veyport/backup/execution/pre-enrollment.db'\nif not os.path.exists(p):\n a=sqlite3.connect('/srv/veyport/data/veyport-isolated.db'); b=sqlite3.connect(p); a.backup(b); b.close(); a.close(); os.chmod(p,0o600)\n")
    wait_for('online enrolled agent', lambda: database("SELECT status FROM servers WHERE name='lab-encrypted-target'")[0]['status'] == 'online')
    return change_path


def activate(state):
    for person in state['users']:
        cli_login(state, person)
    status = cli('officer', ['security', 'status'])
    if status['state'] == 'enhanced':
        # Exercise the real CLI governance contract after browser bootstrap,
        # preserving profile, destination, qualifications and enrolled people.
        policy = dict(status['policy']['policy'])
        policy['runtime_seconds'] = 61 if policy['runtime_seconds'] == 60 else 60
        change_path = PRIVATE / 'execution-policy-change.json'
        change_path.write_text(json.dumps({'kind': 'policy', 'policy': policy})); change_path.chmod(0o600)
        expected_version = status['policy']['version']
    else:
        change_path = prepare_candidate(state)
        expected_version = 1
    change = cli('officer', ['security', 'request', '--change', str(change_path), '--reason', 'Isolated synthetic production-runtime qualification; no human approval represented', '--expected-version', str(expected_version), *mfa_arguments(state, 'officer')])
    for person in ['approver-a', 'approver-b']:
        change = cli(person, ['security', 'approve', change['id'], '--digest', change['digest'], *mfa_arguments(state, person)])
    if change['state'] != 'approved' or len(change['approvals']) != 2 or len({a['person_id'] for a in change['approvals']} | {change['requester_person_id']}) != 3:
        raise RuntimeError('Real CLI did not establish three-person immutable quorum')
    applied = cli('officer', ['security', 'apply', change['id'], '--digest', change['digest'], *mfa_arguments(state, 'officer')])
    if applied['state'] != 'applied' or not all(applied.get(k) for k in ['intent_ref', 'commit_ref', 'result_ref']):
        raise RuntimeError('Real CLI activation lacked confirmed external governance evidence')
    state['change_id'], state['change_digest'] = applied['id'], applied['digest']
    persist(state)
    # Role/person activation intentionally invalidates every nominee's sessions.
    for person in state['users']:
        cli_login(state, person)
    status = cli('officer', ['security', 'status'])
    if status['state'] != 'enhanced' or not all(status['readiness'].values()):
        raise RuntimeError('Activated policy lacks actual archive, transport, marker readiness')
    print('Real vey security request, two approvals and apply confirmed via qualified independent archive and latest anchor', flush=True)


def verify_stored_receipt(row):
    # Production stores the compact signed JWT, not the ingestion response's
    # {token,manifest} wrapper. The manifest is taken only from verified claims.
    token = row['admission_receipt']
    if not isinstance(token, str) or not 0 < len(token) <= 16384 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token):
        raise RuntimeError('Stored admission token rejected')
    header64, claims64, signature64 = token.split('.')
    decode = lambda value: base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    header, claims = json.loads(decode(header64)), json.loads(decode(claims64))
    runtime = json.loads(private_bytes(PRIVATE / 'receipt-runtime.json'))
    signature = decode(signature64)
    if len(signature) != 64 or header.get('typ') != 'JWT' or header.get('alg') != 'ES256' or header.get('kid') != runtime['signing_key_id']:
        raise RuntimeError('Stored receipt signer rejected')
    def integer(raw):
        raw = raw.lstrip(b'\0') or b'\0'
        if raw[0] & 0x80:
            raw = b'\0' + raw
        return b'\x02' + bytes([len(raw)]) + raw
    encoded = integer(signature[:32]) + integer(signature[32:])
    sig_file = PRIVATE / 'execution-receipt-signature.der'
    sig_file.write_bytes(b'\x30' + bytes([len(encoded)]) + encoded)
    sig_file.chmod(0o600)
    try:
        checked = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', runtime['signing_public_key_path'], '-signature', str(sig_file)], input=(header64 + '.' + claims64).encode(), capture_output=True, timeout=15)
    finally:
        sig_file.unlink(missing_ok=True)
    preparation = json.loads(row['preparation'])
    actor = {'user_id': row['actor_id'], 'person_id': row['actor_person_id'], 'name': row['actor_name'], 'provider': row['actor_provider'], 'subject': row['actor_subject']}
    actor_sha = hashlib.sha256(json.dumps(actor, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    expiry_ms = preparation['expires_unix_milli']
    expires = datetime.datetime.fromtimestamp(expiry_ms // 1000, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
    if expiry_ms % 1000:
        expires += '.' + str(expiry_ms % 1000).zfill(3).rstrip('0')
    binding = {'execution_id': row['id'], 'preparation_id': preparation['preparation_id'], 'boot_id': preparation['boot_id'], 'node_id': row['node_id'], 'node_name': row['node_name'], 'identity': preparation['identity'], 'command_sha256': row['command_sha256'], 'command_bytes': row['command_length']}
    if row['script_sha256']:
        binding['script_sha256'] = row['script_sha256']
    if row['script_length']:
        binding['script_bytes'] = row['script_length']
    binding.update({'prepared_until': expires + 'Z', 'limits': preparation['limits']})
    binding_sha = hashlib.sha256(json.dumps({'execution': binding, 'details': None}, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    def timestamp(value):
        parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.timezone.utc)
    retention_hours = row['retention_hours']
    if type(retention_hours) is not int or not 24 <= retention_hours <= 87600:
        raise RuntimeError('Stored immutable policy retention rejected')
    minimum_retention = max(timestamp(row['created_at']), datetime.datetime.fromtimestamp(claims['iat'], datetime.timezone.utc)) + datetime.timedelta(hours=retention_hours)
    audience = claims.get('aud', [])
    if isinstance(audience, str):
        audience = [audience]
    manifest = claims['manifest']
    valid_manifest = all(isinstance(manifest.get(key), str) and manifest[key] for key in ('bucket', 'key', 'version_id')) and manifest['version_id'] != 'null' and re.fullmatch(r'[0-9a-f]{64}', manifest.get('sha256', '')) and type(manifest.get('bytes')) is int and manifest['bytes'] > 0
    # This is historical admission evidence, not permission to replay a receipt:
    # expiry must have fitted the exact preparation when issued, but may be past
    # now after the process completed and lifecycle recovery was confirmed.
    if checked.returncode or claims.get('schema_version') != 1 or claims.get('key_id') != header['kid'] or claims.get('jti') != row['admission_event_id'] or claims['iss'] != runtime['issuer'] or audience != [runtime['audience']] or claims['event_type'] != 'execution.admission' or claims['event_id'] != row['admission_event_id'] or claims['record_sha256'] != row['admission_record_sha256'] or claims['actor_sha256'] != actor_sha or claims['binding_sha256'] != binding_sha or claims['execution_id'] != row['id'] or claims['preparation_id'] != preparation['preparation_id'] or claims['boot_id'] != preparation['boot_id'] or claims['node_id'] != row['node_id'] or claims['identity_sha256'] != preparation['identity']['identity_sha256'] or claims['policy_version'] != int(row['policy_version']) or claims['policy_sha256'] != row['policy_sha256'] or claims['qualification_sha256'] != runtime['qualification_sha256'] or not valid_manifest or timestamp(manifest['retain_until']) < minimum_retention or not 0 < claims['exp'] - claims['iat'] <= 300 or claims['exp'] * 1000 > expiry_ms or not claims['iat'] <= claims['nbf'] < claims['exp']:
        raise RuntimeError('Signed admission did not match exact stored execution/retention trust')
    return {'execution_id': row['id'], 'record_sha256': row['admission_record_sha256'], 'receipt_sha256': hashlib.sha256(token.encode()).hexdigest(), 'manifest_version': manifest['version_id'], 'signature_verified': True}


def execution_matrix(state):
    cli('officer', ['ssh-cert'])
    evidence = []
    for mode in ['confirmed', 'receipt-outage', 'restored']:
        marker = '/tmp/veyport-isolated-' + secrets.token_hex(12)
        script = ("printf x >> '" + marker + "'\nprintf isolated-verified\nprintf isolated-stderr >&2\nexit 42\n").encode()
        if mode == 'receipt-outage':
            remote('hub', 'sudo -n nft -f -', b'table inet veyport_lab_receipt_fault { chain output { type filter hook output priority -5; policy accept; ip daddr 10.10.1.60 tcp dport 8443 reject; } }\n')
        try:
            result = cli('officer', ['ssh', 'lab-encrypted-target', '--', '/bin/sh -s'], script, None)
            present = remote('agent', 'if test -f ' + marker + '; then cat ' + marker + '; fi')
            if mode == 'receipt-outage':
                if result.returncode == 0 or present:
                    raise RuntimeError('Receipt outage launched protected remote side effect')
                evidence.append({'case': mode, 'denied_without_side_effect': True})
            else:
                if result.returncode != 42 or result.stdout != b'isolated-verified' or result.stderr != b'isolated-stderr' or present != b'x':
                    raise RuntimeError('Confirmed protected whole script/output/exit contract failed')
                wait_for('confirmed completion evidence', lambda: database("SELECT evidence_state FROM executions ORDER BY created_at DESC LIMIT 1")[0]['evidence_state'] == 'confirmed')
                row = database("SELECT id,actor_id,actor_person_id,actor_name,actor_provider,actor_subject,node_id,node_name,command_sha256,command_length,script_sha256,script_length,policy_version,policy_sha256,preparation,admission_event_id,admission_record_sha256,admission_receipt,created_at,(SELECT json_extract(payload,'$.retention_hours') FROM audit_policy_versions WHERE version=executions.policy_version) AS retention_hours FROM executions ORDER BY created_at DESC LIMIT 1")[0]
                evidence.append({'case': mode, 'exact_once_marker': True, 'exit_code': 42, **verify_stored_receipt(row)})
            remote('agent', 'rm -f -- ' + marker)
        finally:
            if mode == 'receipt-outage':
                remote('hub', 'sudo -n nft delete table inet veyport_lab_receipt_fault')
    print('Actual encrypted whole-script transport and signed receipts passed; receipt partition launched no process', flush=True)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--prepare-only', action='store_true', help='Prepare normal users, target and immutable candidate; preserve initial policy for browser bootstrap')
    args = parser.parse_args()
    if not args.apply:
        print('Plan: synthetic normal setup/enrollment; real vey login/security quorum; encrypted whole-script execution; .59-only receipt partition; preserve all external originals and anchors')
        return
    state = json.loads(private_bytes(STATE_FILE)) if STATE_FILE.exists() else {}
    setup_users_and_target(state)
    if args.prepare_only:
        prepare_candidate(state)
        state['prepared_for_browser'] = True
        persist(state)
        print('Normal synthetic users, pinned enrolled target and immutable candidate prepared; policy remains never-enrolled Standard for actual browser bootstrap', flush=True)
        return
    activate(state)
    execution = execution_matrix(state)
    report = {'schema': 1, 'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'scope': 'isolated synthetic .59/.64; no human approvals or staging mutation', 'phase': 'API/CLI/native transport qualification; browser evidence tracked separately', 'build': json.loads((ARTIFACTS / 'build.json').read_text()), 'hub_https': HUB, 'target': '10.10.1.64', 'receipt': 'https://10.10.1.60:8443', 'change_id': state.get('change_id'), 'change_sha256': state.get('change_digest'), 'execution': execution, 'limitations': ['Prototype VM/fault qualification only; final Sonar and broader failure matrix remain separate']}
    (HERE / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Public synthetic qualification metadata written; private credentials and receipts withheld', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Isolated execution qualification failed; private process/API output withheld', file=sys.stderr)
        raise SystemExit(1)

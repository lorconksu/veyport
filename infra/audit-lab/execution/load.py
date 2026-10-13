#!/usr/bin/env python3
"""Opt-in real CLI load checks for the isolated Enhanced .59/.64 target."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import subprocess
import sys
import tempfile
import time

import qualify as q

STATE_FILE = q.PRIVATE / 'execution-load-fixture.json'
BOOTSTRAP_FILE = q.STATE_FILE
ACTORS = ('load-a', 'load-b')
TARGET = 'lab-encrypted-target'
MAX_STDOUT = 9 << 20
MAX_STDERR = 1 << 20
os.umask(0o077)


def persist(state):
    raw = json.dumps(state).encode()
    if len(raw) > 1 << 20:
        raise RuntimeError('Private load state exceeds bound')
    with tempfile.NamedTemporaryFile(dir=STATE_FILE.parent, prefix='.execution-load-', delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
            temporary.chmod(0o600)
            os.replace(temporary, STATE_FILE)
        finally:
            temporary.unlink(missing_ok=True)


def login_provisioner(bootstrap, state):
    # Read the existing officer's real password/MFA credentials; never change its
    # role, person binding, fixture state, policy, approval or enrollment marker.
    officer = dict(bootstrap['users']['officer'])
    officer['used_slot'] = max(officer.get('used_slot', 0), int(time.time() // 30))
    private_state = {'users': {'provisioner': officer}, 'last_mfa_at': state.get('last_mfa_at', 0)}
    password = q.request('/api/auth/login', {'username': officer['username'], 'password': officer['password']}, expected=202)
    # Keep the existing helper's pacing and replay protection, but write only
    # rate-limit timing to the separate load fixture, never officer credentials.
    original_persist = q.persist
    def save_timing(value):
        state['last_mfa_at'] = value['last_mfa_at']
        persist(state)
    q.persist = save_timing
    try:
        code = q.fresh_code(private_state, 'provisioner')
    finally:
        q.persist = original_persist
    return q.request('/api/auth/login/totp', {'totp_token': password['totp_token'], 'code': code})['access_token']


def operational(user):
    roles = set(user.get('roles') or [])
    ordinary_person = user.get('person_id', '') in ('', 'user:' + user.get('id', ''))
    return user.get('role') == 'admin' and roles == {'admin'} and ordinary_person and 'terminal.execute' in user.get('capabilities', [])


def assert_created_actor(user, provisioner_token):
    # Normal read-only principal metadata proves this exact extra account has no
    # protected role/person binding before reenable, enrollment or cleanup.
    page = q.request('/api/security/principals?limit=10&search=' + user['id'], token=provisioner_token)
    matches = [person for person in page['principals'] if person['id'] == user['id']]
    if len(matches) != 1 or matches[0]['username'] != user['username'] or set(matches[0]['roles']) != {'admin'} or matches[0]['person_id'] not in ('', 'user:' + user['id']):
        raise RuntimeError('Extra load account acquired unrelated/protected authority')


def prepare_actors(state, provisioner_token):
    users = state.setdefault('users', {})
    for actor in ACTORS:
        user = users.setdefault(actor, {'username': 'lab_synthetic_' + actor.replace('-', '_'), 'password': 'Isolated-load-7!' + secrets.token_urlsafe(24)})
        persist(state)
        if 'id' not in user:
            created = q.request('/api/users', {'username': user['username'], 'email': actor + '@isolated.invalid', 'role': 'admin'}, provisioner_token, 201)
            user['id'], user['temporary_password'] = created['user']['id'], created['temporary_password']
            persist(state)
        if not re.fullmatch(r'[0-9a-f-]{36}', user['id']):
            raise RuntimeError('Synthetic load identity is invalid')
        assert_created_actor(user, provisioner_token)
        if user.get('disabled'):
            q.request('/api/users/' + user['id'] + '/status', {'disabled': False}, provisioner_token, method='PUT')
            user['disabled'] = False
            persist(state)
        if not user.get('complete'):
            setup = q.request('/api/auth/login', {'username': user['username'], 'password': user['temporary_password']})['setup_token']
            if not user.get('totp_secret'):
                user['totp_secret'] = q.request('/api/auth/totp/setup', {}, setup)['secret']
                persist(state)
            enabled = q.request('/api/auth/totp/enable', {'code': q.fresh_code(state, actor), 'new_password': user['password']}, setup)
            if not operational(q.request('/api/auth/me', token=enabled['access_token'])):
                raise RuntimeError('Load actor lacks ordinary operational authority or acquired a protected role')
            user['complete'] = True
            user.pop('temporary_password', None)
            persist(state)
        q.cli_login(state, actor)
        q.cli(actor, ['ssh-cert'])
    if users[ACTORS[0]]['id'] == users[ACTORS[1]]['id']:
        raise RuntimeError('Load requires two distinct ordinary operational actors')


def disable_actors(state, provisioner_token):
    # Only the two exact fixture-created IDs are eligible for cleanup. Keeping
    # disabled records preserves execution/audit attribution and permits reuse.
    for actor in ACTORS:
        user = state.get('users', {}).get(actor, {})
        if 'id' not in user:
            continue
        if user.get('username') != 'lab_synthetic_' + actor.replace('-', '_') or not re.fullmatch(r'[0-9a-f-]{36}', user['id']):
            raise RuntimeError('Refused cleanup of an unrelated principal')
        assert_created_actor(user, provisioner_token)
        q.request('/api/users/' + user['id'] + '/status', {'disabled': True}, provisioner_token, method='PUT')
        user['disabled'] = True
        persist(state)


class Command:
    def __init__(self, argv, environment, script, directory, name, actor='', pause_seconds=0):
        self.name, self.actor = name, actor
        self.script_sha256 = hashlib.sha256(script).hexdigest()
        self.stdout, self.stderr = bytearray(), bytearray()
        self.started = time.monotonic()
        self.resume_stdout = self.started + pause_seconds
        self.completed = None
        self.source = (directory / (name + '.script')).open('xb')
        self.source.write(script)
        self.source.close()
        self.source = (directory / (name + '.script')).open('rb')
        try:
            self.process = subprocess.Popen(argv, stdin=self.source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, start_new_session=True)
        except BaseException:
            self.source.close()
            raise
        self.streams = {self.process.stdout: self.stdout, self.process.stderr: self.stderr}
        for stream in self.streams:
            os.set_blocking(stream.fileno(), False)

    def stop(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)

    def close(self):
        # The fixture owns a separate local process group, including native ssh.
        # A leader that exited can still leave a descendant holding a pipe.
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if self.process.poll() is None:
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.process.wait(timeout=3)
        for stream in self.streams:
            stream.close()
        self.source.close()

    def evidence(self):
        return {'case': self.name, 'actor': self.actor, 'script_sha256': self.script_sha256, 'exit_code': self.process.returncode,
                'stdout_bytes': len(self.stdout), 'stdout_sha256': hashlib.sha256(self.stdout).hexdigest(),
                'stderr_bytes': len(self.stderr), 'stderr_sha256': hashlib.sha256(self.stderr).hexdigest(),
                'seconds': round(self.completed - self.started, 3)}


def collect(commands, timeout=45):
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        paused = []
        for command in commands:
            for stream, destination in command.streams.items():
                if stream is command.process.stdout and time.monotonic() < command.resume_stdout:
                    paused.append((command, stream, destination))
                else:
                    selector.register(stream, selectors.EVENT_READ, (command, destination))
        while selector.get_map() or paused or any(c.process.poll() is None for c in commands):
            if time.monotonic() >= deadline:
                raise RuntimeError('Load command/drain exceeded bounded deadline')
            for item in paused[:]:
                command, stream, destination = item
                if time.monotonic() >= command.resume_stdout:
                    selector.register(stream, selectors.EVENT_READ, (command, destination))
                    paused.remove(item)
            for key, _ in selector.select(0.05):
                command, destination = key.data
                data = os.read(key.fd, 64 << 10)
                if not data:
                    selector.unregister(key.fileobj)
                else:
                    destination.extend(data)
                    maximum = MAX_STDOUT if destination is command.stdout else MAX_STDERR
                    if len(destination) > maximum:
                        raise RuntimeError('Load output exceeded private collector bound')
            open_commands = {key.data[0] for key in selector.get_map().values()}
            open_commands.update(item[0] for item in paused)
            for command in commands:
                if command.completed is None and command.process.poll() is not None and command not in open_commands:
                    command.completed = time.monotonic()
        # A process can exit between the final per-command poll and the loop's
        # next condition. All pipes are drained at this point in either order.
        for command in commands:
            if command.completed is None:
                command.completed = time.monotonic()


def lab_command(actor, script, directory, name, pause_seconds=0):
    argv = [str(q.ARTIFACTS / 'vey'), '--json', '--hub', q.HUB, 'ssh', TARGET, '--', '/bin/sh -s']
    return Command(argv, q.cli_environment(actor), script, directory, name, actor, pause_seconds)


def marker_operation(directory, operation):
    if not re.fullmatch(r'/tmp/veyport-load-[0-9a-f]{24}', directory) or operation not in ('create', 'snapshot', 'release', 'cleanup'):
        raise RuntimeError('Refused marker operation outside unique load fixture')
    source = """import json,os,pathlib,shutil,stat,sys
p=pathlib.Path(sys.argv[1]);op=sys.argv[2]
if op=='create': p.mkdir(mode=0o700)
else:
 s=p.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0: raise SystemExit(1)
 if op=='release': (p/'release').touch(mode=0o600,exist_ok=False)
 elif op=='cleanup':
  if any(x.is_symlink() or not x.is_file() for x in p.iterdir()): raise SystemExit(1)
  shutil.rmtree(p)
 else:
  files=list(p.iterdir())
  if len(files)>16: raise SystemExit(1)
  result={'files':sorted(x.name for x in files),'processes':{}}
  for member in files:
   if member.name.startswith('parallel-') or member.name in ('slow','quiet'):
    pid=int(member.read_text());path=pathlib.Path('/proc')/str(pid)/'stat'
    if pid<=1: raise SystemExit(1)
    if path.exists():
     fields=path.read_text().rsplit(')',1)[1].split()
     result['processes'][member.name]={'state':fields[0],'start':fields[19]}
  child=p/'cancel.child'
  if child.exists():
   pid=int(child.read_text());path=pathlib.Path('/proc')/str(pid)/'stat'
   if pid<=1: raise SystemExit(1)
   if path.exists():
    fields=path.read_text().rsplit(')',1)[1].split()
    result['child']={'pid':pid,'state':fields[0],'start':fields[19]}
  print(json.dumps(result))
"""
    return q.remote('agent', 'sudo -n python3 - ' + directory + ' ' + operation, source.encode(), timeout=15)


def snapshot(directory):
    return json.loads(marker_operation(directory, 'snapshot'))


def output_script(marker, name, size, exit_code, gated=False):
    script = 'umask 077\nprintf \'%s\' "$$" > ' + marker + '/' + name + '\n'
    if gated:
        script += 'i=0; until test -f ' + marker + '/release; do i=$((i+1)); test "$i" -lt 450 || exit 90; sleep 0.1; done\n'
    offset = sum(name.encode()) % 256
    script += "python3 - <<'PY'\nimport sys\nsys.stdout.buffer.write(bytes((i+" + str(offset) + ")%256 for i in range(256))*" + str(size // 256) + ")\nsys.stderr.buffer.write(" + repr((name + '\0stderr').encode()) + ")\nPY\nexit " + str(exit_code) + '\n'
    return script.encode()


def assert_output(command, size, exit_code):
    offset = sum(command.name.encode()) % 256
    expected = bytes((i + offset) % 256 for i in range(256)) * (size // 256)
    if command.process.returncode != exit_code or command.stdout != expected or command.stderr != (command.name + '\0stderr').encode():
        raise RuntimeError('Real CLI output/exit differed from complete finite script')


def execution_rows(commands, state):
    hashes = ','.join("'" + c.script_sha256 + "'" for c in commands)
    columns = "id,actor_id,actor_person_id,actor_name,actor_provider,actor_subject,node_id,node_name,command_sha256,command_length,script_length,policy_version,policy_sha256,preparation,admission_event_id,admission_record_sha256,admission_receipt,created_at,state,evidence_state,enhanced,script_sha256,(SELECT json_extract(payload,'$.retention_hours') FROM audit_policy_versions WHERE version=executions.policy_version) AS retention_hours"
    rows = q.database('SELECT ' + columns + ' FROM executions WHERE script_sha256 IN (' + hashes + ')')
    if len(rows) != len(commands):
        return None
    by_hash = {row['script_sha256']: row for row in rows}
    for command in commands:
        row = by_hash[command.script_sha256]
        if row['actor_id'] != state['users'][command.actor]['id'] or row['node_id'] != state['target_id'] or row['enhanced'] != 1:
            raise RuntimeError('Execution did not retain exact actor/node/Enhanced binding')
        if state.get('policy_version') is not None and int(row['policy_version']) != state['policy_version']:
            raise RuntimeError('Execution policy changed during isolated load fixture')
        if row['state'] in ('submitted', 'prepared', 'admitted', 'dispatching', 'running') or row['evidence_state'] != 'confirmed':
            return None
    return by_hash


def confirmed(commands, state):
    q.wait_for('exact load lifecycle evidence', lambda: execution_rows(commands, state) is not None, timeout=90)
    rows = execution_rows(commands, state)
    evidence = []
    for command in commands:
        row = rows[command.script_sha256]
        evidence.append({**command.evidence(), 'actor_id': row['actor_id'], 'state': row['state'], 'evidence_state': row['evidence_state'], **q.verify_stored_receipt(row)})
    return evidence


def start_gated_commands(marker, directory, commands, timeout=40):
    # The independent receipt service has four nonblocking HTTP slots shared by
    # readiness and preservation. Running-process capacity is eight. Stage each
    # unique admission once while earlier processes remain gated; never retry a
    # rejected command or adjust either service's resource budget.
    deadline = time.monotonic() + timeout
    eight = []
    for index in range(8):
        if time.monotonic() >= deadline:
            raise RuntimeError('Staged load admissions exceeded bounded deadline')
        name = 'parallel-' + str(index)
        command = lab_command(ACTORS[index // 4], output_script(marker, name, 4 << 20, index + 1, True), directory, name)
        eight.append(command)
        commands.append(command)
        def started():
            if any(previous.process.poll() is not None for previous in eight):
                raise RuntimeError('Unique load admission ended before eight processes were ready; no retry')
            current = snapshot(marker)
            return all(current['processes'].get(previous.name, {}).get('state') not in (None, 'Z') for previous in eight)
        q.wait_for('unique staged admission ' + name, started, timeout=min(10, deadline - time.monotonic()))
    return eight


def matrix(state, directory, report):
    marker = '/tmp/veyport-load-' + secrets.token_hex(12)
    marker_operation(marker, 'create')
    state['active_marker'] = marker
    persist(state)
    commands = []
    try:
        report['phase'] = 'eight-simultaneous-commands'
        report['admission_mode'] = 'staged once; eight running processes before release'
        report['receipt_http_request_limit'] = 4
        eight = start_gated_commands(marker, directory, commands)
        def all_started():
            current = snapshot(marker)
            return all(current['processes'].get(c.name, {}).get('state') not in (None, 'Z') and c.process.poll() is None for c in eight)
        q.wait_for('eight simultaneous started processes across two actors', all_started, timeout=25)
        report['simultaneous_started'] = 8
        marker_operation(marker, 'release')
        collect(eight)
        for index, command in enumerate(eight):
            assert_output(command, 4 << 20, index + 1)
        report['eight_across_two_actors'] = confirmed(eight, state)

        report['phase'] = 'slow-consumer-quiet-isolation-and-drain'
        slow = lab_command(ACTORS[0], output_script(marker, 'slow', 8 << 20, 19), directory, 'slow', 60)
        commands.append(slow)
        q.wait_for('slow process started before quiet command', lambda: 'slow' in snapshot(marker)['files'], timeout=15)
        quiet = lab_command(ACTORS[1], output_script(marker, 'quiet', 256, 7), directory, 'quiet')
        commands.append(quiet)
        slow.resume_stdout = time.monotonic() + 8
        collect([slow, quiet], timeout=35)
        assert_output(slow, 8 << 20, 19)
        assert_output(quiet, 256, 7)
        if quiet.completed >= slow.resume_stdout:
            raise RuntimeError('Quiet command did not finish while slow stdout was withheld')
        report['slow_consumer_and_quiet'] = {'quiet_finished_before_slow_stdout_read': True, 'pause_seconds': 8, 'full_output_drained_before_exit': True, 'executions': confirmed([slow, quiet], state)}

        report['phase'] = 'cancellation-and-drain'
        cancel_script = ('umask 077\npython3 -c "import pathlib,time; time.sleep(30); pathlib.Path(\'' + marker + '/forbidden\').write_text(\'late\')" &\nprintf \'%s\' "$!" > ' + marker + '/cancel.child\npython3 -c \'import sys; sys.stdout.buffer.write(bytes(range(256))*1024)\'\nwait\n').encode()
        cancelled = lab_command(ACTORS[0], cancel_script, directory, 'cancel')
        commands.append(cancelled)
        q.wait_for('owned descendant started', lambda: snapshot(marker).get('child', {}).get('state') not in (None, 'Z'), timeout=15)
        before = snapshot(marker)['child']
        cancelled.stop()
        collect([cancelled], timeout=12)
        if cancelled.process.returncode == 0 or cancelled.stdout != (bytes(range(256)) * 1024)[:len(cancelled.stdout)]:
            raise RuntimeError('Cancellation fabricated success or corrupted already delivered bytes')
        q.wait_for('owned descendant terminated', lambda: snapshot(marker).get('child', {}).get('start') != before['start'] or snapshot(marker).get('child', {}).get('state') == 'Z', timeout=12)
        if 'forbidden' in snapshot(marker)['files']:
            raise RuntimeError('Cancelled descendant produced a later process effect')
        cancellation_evidence = confirmed([cancelled], state)
        if cancellation_evidence[0]['state'] not in ('cancelled', 'transport_lost', 'outcome_unknown'):
            raise RuntimeError('Cancelled execution reported a completed successful lifecycle')
        report['cancellation_and_drain'] = {'owned_descendant_terminated': True, 'later_child_effect_absent': True, 'already_delivered_output_not_rolled_back': True, 'executions': cancellation_evidence}
        return report
    finally:
        for command in commands:
            command.close()
        marker_operation(marker, 'cleanup')
        state.pop('active_marker', None)
        persist(state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='Explicit opt-in normal API account creation and lab-only command execution')
    args = parser.parse_args()
    if not args.apply:
        print('Plan only: preserve existing three-person bootstrap; two separate synthetic ordinary operational actors; eight Enhanced finite scripts (four per actor), slow/quiet isolation, cancellation/drain; disable only load actors and remove own markers; root must serialize actual MFA/VM runs')
        return
    bootstrap = json.loads(q.private_bytes(BOOTSTRAP_FILE))
    state = json.loads(q.private_bytes(STATE_FILE)) if STATE_FILE.exists() else {'users': {}}
    state['last_mfa_at'] = max(state.get('last_mfa_at', 0), bootstrap.get('last_mfa_at', 0))
    if state.get('active_marker'):
        raise RuntimeError('Interrupted load marker requires root inspection/cleanup before retry')
    enrolled_ids = {user['id'] for user in bootstrap['users'].values()}
    if any(user.get('id') in enrolled_ids for user in state.get('users', {}).values()):
        raise RuntimeError('Refused load state aliasing an enrolled bootstrap principal')
    if state.get('target_id', bootstrap['target_id']) != bootstrap['target_id']:
        raise RuntimeError('Existing load fixture target differs from enrolled bootstrap target')
    state['target_id'] = bootstrap['target_id']
    q.STATE_FILE = STATE_FILE
    provisioner = login_provisioner(bootstrap, state)
    policy = q.request('/api/audit-policy', token=provisioner)
    if policy['state'] != 'enhanced' or state['target_id'] not in policy['policy']['policy']['nodes'] or not all(policy['readiness'].values()):
        raise RuntimeError('Load requires the existing ready Enhanced node-scoped policy')
    if not re.fullmatch(r'[0-9a-f-]{36}', state['target_id']):
        raise RuntimeError('Fixed enrolled target identity is invalid')
    state['policy_version'] = policy['policy']['version']
    active = q.database("SELECT id FROM executions WHERE node_id='" + state['target_id'] + "' AND state IN ('submitted','prepared','admitted','dispatching','running') LIMIT 1")
    if active:
        raise RuntimeError('Load fixture requires an idle isolated target')
    report = {'schema': 1, 'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'scope': 'isolated synthetic .59/.64 Enhanced load; no human approvals or staging mutation', 'build': json.loads((q.ARTIFACTS / 'build.json').read_text()), 'policy_version': policy['policy']['version'], 'actor_count': 2, 'actor_execution_limit': 4, 'node_execution_limit': 8, 'passed': False, 'phase': 'normal-load-actor-setup'}
    failed = False
    try:
        prepare_actors(state, provisioner)
        with tempfile.TemporaryDirectory(prefix='execution-load-', dir=q.PRIVATE) as temporary:
            matrix(state, Path(temporary), report)
    except Exception as error:
        failed = True
        report['failure_type'] = type(error).__name__
    finally:
        try:
            disable_actors(state, provisioner)
            report['load_accounts_disabled'] = True
        except Exception:
            failed = True
            report['load_accounts_disabled'] = False
    report['passed'] = not failed
    (q.HERE / 'load-qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    if failed:
        raise RuntimeError('Load qualification failed; bounded public progress retained')
    print('Actual CLI load checks and account cleanup passed; public hashes/states only, private script bytes withheld')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Isolated load qualification failed; private API/process/script output withheld', file=sys.stderr)
        raise SystemExit(1)

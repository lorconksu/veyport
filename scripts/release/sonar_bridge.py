#!/usr/bin/env python3
"""Trusted-main Sonar task handoff. Public identities only; no policy authority.

Source jobs never obtain the analysis credential. A reviewed
main workflow validates source/coverage, then scans source files as data. Missing
claims/results and changed attempts stop processing; this is not an exactly-once
service and never retries an uncertain scanner submission automatically.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = 'lorconksu/veyport'
WORKFLOW = '.github/workflows/sonar-bridge.yml'
SOURCE_WORKFLOWS = {'.github/workflows/ci.yml', '.github/workflows/release.yml', '.github/workflows/staging.yml'}
PROFILE = 'e707b1213f1b2c0b1fd0375b175a0f625338d6dd448a9b84a03d817ff9811b5e'
TRUSTED_FILES = (WORKFLOW, 'scripts/release/sonar-approved-workflows.json') + tuple(
    'scripts/release/' + name for name in ('sonar_bridge.py', 'sonar_control.py', 'sonar_job_evidence.py',
    'source_sast.py', 'sonar_context.py', 'risk_acceptance.py', 'scan_contract.py', 'metadata.py',
    'ci_evidence.py', 'ci_evidence_crypto.py'))
ACTION = 'SonarSource/sonarqube-scan-action@c7ee0f9df90b7aa20e8dcf9695dcfe2e7da5b4f2'
COVERAGE = {'unit': {'coverage-hub.out', 'coverage-hub-cmd.out', 'coverage-agent.out', 'coverage-cli.out', 'coverage-proto.out', 'web/coverage/lcov.info'},
            'integration': {'coverage-integration.out', 'coverage-agent-integration.out'}}
MAX_JSON = 16 << 20
MAX_ZIP = 128 << 20
MAX_TOTAL = 512 << 20


def require(ok, message='Sonar bridge identity or input rejected'):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def strict_json(raw):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate bridge JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite bridge JSON')))


def sha(value):
    return hashlib.sha256(value).hexdigest()


def exact_sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}', value)


def positive(value):
    return type(value) is int and 0 < value < 10**20


def mode(value):
    require(value == 'bridge', 'Trusted-main Sonar bridge must be explicitly configured')
    return 'bridge'


# Official verifier pin: release archive and the sole executable extracted from it.
VERIFIER_VERSION = '2.103.3'
VERIFIER_ARCHIVE_SHA256 = '4c806978ffce1cec70853302a56d70ac6da4f19bae7adca4e1a8ab00633dd91d'
VERIFIER_BINARY_SHA256 = 'b768184570b12536be4ac1528893f6340d1c6a7b40b56ad45bca9cd0e87ad34d'
APPROVALS = 'scripts/release/sonar-approved-workflows.json'
# Direct committed orchestration only; candidate test/config/runtime semantics
# remain untrusted. This is not an executable dependency graph or execution proof.
PRODUCER_CONTROLS = ('scripts/release/capture_step.py', 'scripts/release/server_test_shards.py',
                     'hub/internal/integration/main_test.go')
REPOSITORY_ID = '1188082218'
UPLOAD_STEPS = {'unit': 'Upload complete coverage for Sonar', 'integration': 'Upload integration coverage'}


def verifier_path():
    return Path(os.environ['RUNNER_TEMP']) / 'sonar-verifier' / 'gh'


def install_verifier():
    target = verifier_path()
    require(not target.parent.is_symlink() and not target.exists())
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    url = f'https://github.com/cli/cli/releases/download/v{VERIFIER_VERSION}/gh_{VERIFIER_VERSION}_linux_amd64.tar.gz'
    # No API/analysis credential is attached to the fixed public release request.
    with urllib.request.urlopen(url, timeout=90) as response:
        raw = response.read((32 << 20) + 1)
    require(len(raw) <= 32 << 20 and sha(raw) == VERIFIER_ARCHIVE_SHA256, 'Official verifier archive pin differs')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        member = archive.getmember(f'gh_{VERIFIER_VERSION}_linux_amd64/bin/gh')
        require(member.isfile() and 0 < member.size <= 64 << 20)
        with archive.extractfile(member) as stream:
            binary = stream.read((64 << 20) + 1)
    require(sha(binary) == VERIFIER_BINARY_SHA256, 'Official verifier executable pin differs')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(binary)


def remaining_timeout(deadline, maximum=30):
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'Sonar bridge command deadline exceeded')
    return min(maximum, remaining)


def verifier_output(argv, environment, cwd, deadline=None):
    # Bound both output streams while the official verifier processes external
    # bundles. No shell, candidate PATH/config, or candidate executable is used.
    deadline = min(time.monotonic() + 120, deadline) if deadline is not None else time.monotonic() + 120
    remaining_timeout(deadline)
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, cwd=cwd)
    output = {process.stdout: bytearray(), process.stderr: bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for stream in output:
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                require(time.monotonic() < deadline, 'Official verifier deadline exceeded')
                for key, _ in selector.select(timeout=remaining_timeout(deadline, 1)):
                    value = os.read(key.fileobj.fileno(), 65536)
                    if not value:
                        selector.unregister(key.fileobj)
                        continue
                    output[key.fileobj].extend(value)
                    require(sum(len(v) for v in output.values()) <= 4 << 20, 'Official verifier output exceeds bound')
        require(process.wait(timeout=remaining_timeout(deadline, 5)) == 0, 'Official coverage signature verification failed')
        remaining_timeout(deadline)
        return strict_json(bytes(output[process.stdout]))
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()


def official_coverage_verification(raw, record, token, deadline=None):
    executable = verifier_path()
    require(sha(regular(executable, 64 << 20)) == VERIFIER_BINARY_SHA256, 'Installed verifier pin differs')
    home = executable.parent / 'home'
    require(not home.is_symlink())
    home.mkdir(mode=0o700, exist_ok=True)
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'GH_CONFIG_DIR': str(home / 'config'),
                   'XDG_CACHE_HOME': str(home / 'cache'), 'GH_HOST': 'github.com', 'GH_TOKEN': token,
                   'GH_NO_UPDATE_NOTIFIER': '1', 'GH_PROMPT_DISABLED': '1'}
    with tempfile.TemporaryDirectory(prefix='coverage-', dir=home) as directory:
        artifact_path = Path(directory) / 'coverage.zip'
        artifact_path.write_bytes(raw)
        argv = [str(executable), 'attestation', 'verify', str(artifact_path), '--repo', REPOSITORY,
                '--hostname', 'github.com', '--signer-workflow', REPOSITORY + '/.github/workflows/ci.yml',
                '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com', '--deny-self-hosted-runners',
                '--predicate-type', 'https://slsa.dev/provenance/v1', '--format', 'json', '--limit', '10']
        return verifier_output(argv, environment, home, deadline=deadline)


def approved_control_registry(api, tooling=None):
    tooling = tooling if tooling is not None else os.environ.get('SONAR_BRIDGE_TOOLING_REVISION', '')
    require(exact_sha(tooling))
    value = strict_json(control_file(api, APPROVALS, tooling))
    require(isinstance(value, dict) and set(value) == {'schema', 'workflow_sha256', 'producer_sha256', 'authority'}
            and value['schema'] == 2 and value['authority'] == 'approved-workflow-and-producer-source-bytes/v2'
            and isinstance(value['workflow_sha256'], dict) and set(value['workflow_sha256']) == SOURCE_WORKFLOWS
            and isinstance(value['producer_sha256'], dict) and set(value['producer_sha256']) == set(PRODUCER_CONTROLS)
            and all(isinstance(v, str) and re.fullmatch(r'[0-9a-f]{64}', v)
                    for group in ('workflow_sha256', 'producer_sha256') for v in value[group].values()),
            'Reviewed workflow/producer source-byte approval is missing')
    return value


def approved_workflows(api):
    return approved_control_registry(api)['workflow_sha256']


def producer_controls(api, run, tooling=None):
    """Admit committed direct orchestration; never attest actual test execution.

    Fetch the actual checkout head, not the workflow's synthetic merge revision.
    Git tree modes are required: Contents can resolve symlinks to target bytes.
    Call only after the signed executed workflow is independently admitted.
    """
    revision = run['head_sha']
    require(exact_sha(revision))
    registry = approved_control_registry(api, tooling)
    commit = api.get('git/commits/' + revision)
    require(commit.get('sha') == revision and exact_sha(commit.get('tree', {}).get('sha')),
            'Producer source commit/tree identity missing')
    tree_id = commit['tree']['sha']
    tree = api.get('git/trees/' + tree_id + '?recursive=1')
    require(tree.get('sha') == tree_id and tree.get('truncated') is False
            and isinstance(tree.get('tree'), list) and 0 < len(tree['tree']) <= 10000,
            'Complete bounded producer source tree required')
    entries = {}
    for entry in tree['tree']:
        require(isinstance(entry, dict))
        path = entry.get('path')
        require(isinstance(path, str) and 0 < len(path) <= 1024 and '\\' not in path and '\x00' not in path
                and not path.startswith('/') and all(p not in ('', '.', '..') for p in path.split('/'))
                and path not in entries, 'Invalid or duplicate producer tree path')
        entries[path] = entry
    admitted = {}
    for path in PRODUCER_CONTROLS:
        components = path.split('/')
        for index in range(1, len(components)):
            parent = entries.get('/'.join(components[:index]), {})
            require(parent.get('mode') == '040000' and parent.get('type') == 'tree'
                    and exact_sha(parent.get('sha')), 'Producer source parent is not a regular tree')
        entry = entries.get(path, {})
        require(entry.get('mode') in ('100644', '100755') and entry.get('type') == 'blob'
                and exact_sha(entry.get('sha')) and type(entry.get('size')) is int and 0 < entry['size'] <= 1 << 20,
                'Producer source control must be a bounded regular Git blob')
        blob = api.get('git/blobs/' + entry['sha'])
        require(blob.get('sha') == entry['sha'] and blob.get('encoding') == 'base64'
                and type(blob.get('size')) is int and blob['size'] == entry['size']
                and isinstance(blob.get('content'), str) and len(blob['content']) <= 2 << 20,
                'Producer source blob identity differs')
        raw = base64.b64decode(blob['content'].replace('\n', ''), validate=True)
        git_id = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\x00' + raw, usedforsecurity=False).hexdigest()
        require(len(raw) == entry['size'] and git_id == entry['sha']
                and sha(raw) == registry['producer_sha256'][path], 'Committed producer control differs from reviewed source')
        admitted[path] = {'git_blob': entry['sha'], 'mode': entry['mode'], 'sha256': sha(raw)}
    return {'authority': 'reviewed-committed-orchestration-source-only/v1', 'revision': revision,
            'tree': tree_id, 'registry_sha256': sha(canonical(registry)), 'controls': admitted}


def coverage_certificate(api, verified, run, record):
    """Apply policy only to official-verifier authenticated certificate fields.

    Predicate claims never authorize a workflow, revision or source attempt.
    Coverage values/test semantics remain controlled by candidate source.
    """
    require(isinstance(verified, list) and 0 < len(verified) <= 10)
    approved = approved_workflows(api)
    valid = []
    for item in verified:
        try:
            result = item['verificationResult']
            certificate = result['signature']['certificate']
            workflow_revision = certificate['buildConfigDigest']
            signer_revision = certificate['buildSignerDigest']
            ref = certificate['sourceRepositoryRef']
            require(exact_sha(workflow_revision) and exact_sha(signer_revision))
            invocation = f"https://github.com/{REPOSITORY}/actions/runs/{run['id']}/attempts/{run['run_attempt']}"
            require(certificate['issuer'] == 'https://token.actions.githubusercontent.com'
                    and certificate['sourceRepositoryURI'] == 'https://github.com/' + REPOSITORY
                    and certificate['sourceRepositoryIdentifier'] == REPOSITORY_ID
                    and certificate['sourceRepositoryVisibilityAtSigning'] == 'public'
                    and certificate['runnerEnvironment'] == 'github-hosted'
                    and certificate['runInvocationURI'] == invocation and certificate['buildTrigger'] == run['event']
                    and isinstance(result['verifiedTimestamps'], list) and 0 < len(result['verifiedTimestamps']) <= 10)
            require(certificate['buildConfigURI'] == f"https://github.com/{REPOSITORY}/{run['path']}@{ref}")
            if run['event'] == 'pull_request':
                match = re.fullmatch(r'refs/pull/([1-9][0-9]*)/merge', ref)
                require(match is not None and run['path'] == '.github/workflows/ci.yml')
                pr = api.get('pulls/' + match[1])
                require(pr.get('number') == int(match[1]) and pr.get('head', {}).get('sha') == run['head_sha']
                        and pr.get('head', {}).get('ref') == run['head_branch'] and pr.get('state') == 'open'
                        and pr.get('base', {}).get('ref') == 'main' and pr['base'].get('repo', {}).get('full_name') == REPOSITORY)
                commit = api.get('git/commits/' + workflow_revision)
                require(commit.get('sha') == workflow_revision and len(commit.get('parents', [])) == 2
                        and commit['parents'][1].get('sha') == run['head_sha'])
                ancestor(api, commit['parents'][0]['sha'], 'main')
                require(signer_revision == workflow_revision and certificate['sourceRepositoryDigest'] == workflow_revision)
            else:
                expected_ref = 'refs/heads/main' if run['path'] == '.github/workflows/ci.yml' else next(
                    v['ref'] for v in run['referenced_workflows']
                    if v.get('path') == REPOSITORY + '/.github/workflows/ci.yml@' + run['head_sha'] and v.get('sha') == run['head_sha'])
                require(ref == expected_ref and workflow_revision == signer_revision == run['head_sha']
                        and certificate['sourceRepositoryDigest'] == run['head_sha'])
            signer = f'https://github.com/{REPOSITORY}/.github/workflows/ci.yml@'
            require(certificate['buildSignerURI'] in (signer + ref, signer + signer_revision)
                    and certificate['subjectAlternativeName'] == certificate['buildSignerURI'])
            for path, revision in ((run['path'], workflow_revision), ('.github/workflows/ci.yml', signer_revision)):
                require(sha(control_file(api, path, revision)) == approved[path], 'Executed workflow differs from reviewed control')
            statement = result['statement']
            require(statement['predicateType'] == 'https://slsa.dev/provenance/v1'
                    and statement['subject'] == [{'name': record['name'] + '.zip', 'digest': {'sha256': record['digest'][7:]}}])
            valid.append({'workflow_revision': workflow_revision, 'signer_revision': signer_revision,
                          'source_ref': ref, 'run_uri': invocation, 'certificate_sha256': sha(canonical(certificate)),
                          'verified_statement_sha256': sha(canonical(statement)), 'verifier': 'gh/' + VERIFIER_VERSION})
        except (KeyError, TypeError, ValueError, StopIteration):
            continue
    require(len(valid) == 1, 'One current approved-workflow coverage signature required')
    return valid[0]


def coverage_provenance(api, run, record, job, group, raw):
    steps = job.get('steps')
    require(isinstance(steps, list))
    selected = [v for v in steps if v.get('name') == UPLOAD_STEPS[group]]
    require(len(selected) == 1 and selected[0].get('status') == 'completed'
            and selected[0].get('conclusion') == 'success' and positive(selected[0].get('number')),
            'Expected coverage upload step did not succeed')
    step = selected[0]
    log = api.get(f"actions/jobs/{job['id']}/steps/{step['number']}/logs", raw=True, maximum=2 << 20)
    require(len(log) <= 2 << 20)
    lines = [re.sub(r'^\d{4}-\d\d-\d\dT[0-9:.]+Z ', '', v) for v in log.decode('utf-8').splitlines()]
    completion = [re.fullmatch(r'Artifact ' + re.escape(record['name'])
                  + r' has been successfully uploaded! Final size is ([1-9][0-9]*) bytes\. Artifact ID is ([1-9][0-9]*)', v) for v in lines]
    completion = [v for v in completion if v is not None]
    digests = [re.fullmatch(r'SHA256 digest of uploaded artifact(?: zip)? is ([0-9a-f]{64})', v) for v in lines]
    digests = [v for v in digests if v is not None]
    require(len(completion) == len(digests) == 1 and int(completion[0][1]) == record['size_in_bytes']
            and int(completion[0][2]) == record['id'] and digests[0][1] == record['digest'][7:],
            'Artifact identity is not the expected successful upload invocation')
    certificate = coverage_certificate(api, api.verify_coverage(raw, record, run), run, record)
    return {'step_number': step['number'], 'step_log_sha256': sha(log), 'certificate': certificate,
            'producer_controls': producer_controls(api, run)}



class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class BridgeRateLimit(ValueError):
    """A recognized GitHub throttle; contains no request URL or credential."""
    def __init__(self, delay):
        super().__init__('GitHub bridge rate limited')
        self.delay = delay


def rate_limit_delay(status, headers):
    retry = headers.get('Retry-After')
    remaining = headers.get('X-RateLimit-Remaining')
    if status != 429 and not (status == 403 and (retry is not None or remaining == '0')):
        return None
    delay = 60
    if retry is not None:
        require(isinstance(retry, str) and re.fullmatch(r'[0-9]{1,6}', retry), 'Invalid GitHub throttle delay')
        delay = max(delay, int(retry))
    if remaining == '0':
        reset = headers.get('X-RateLimit-Reset')
        require(isinstance(reset, str) and re.fullmatch(r'[0-9]{1,12}', reset), 'Invalid GitHub quota reset')
        delay = max(delay, int(reset) - time.time() + 1)
    require(delay <= 3600, 'GitHub throttle exceeds bounded wait')
    return delay


class API:
    def __init__(self, token=None, deadline=None):
        self.deadline = deadline
        self.token = os.environ.get('GITHUB_TOKEN', '') if token is None else token

    def get(self, path, raw=False, maximum=MAX_JSON):
        require(isinstance(path, str) and not path.startswith('/') and '\\' not in path and not re.search(r'[\x00-\x20]', path))
        headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'veyport-sonar-bridge', 'X-GitHub-Api-Version': '2026-03-10'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + '/' + path, headers=headers)
        opener = urllib.request.build_opener(NoRedirect())
        try:
            response = opener.open(request, timeout=remaining_timeout(self.deadline))
        except urllib.error.HTTPError as error:
            try:
                delay = rate_limit_delay(error.code, error.headers)
                if delay is not None:
                    raise BridgeRateLimit(delay) from None
                require(error.code == 302 and (re.fullmatch(r'actions/artifacts/[1-9][0-9]*/zip', path)
                        or re.fullmatch(r'actions/jobs/[1-9][0-9]*/steps/[1-9][0-9]*/logs', path)), 'GitHub bridge request failed')
                target = error.headers.get('Location', '')
            finally:
                error.close()
            parsed = urllib.parse.urlsplit(target)
            require(parsed.scheme == 'https' and not parsed.username and not parsed.password and parsed.port in (None, 443)
                    and parsed.hostname and parsed.hostname.endswith('.blob.core.windows.net'), 'Unexpected bridge artifact host')
            # A fresh request deliberately omits the API credential. Further
            # redirects are forbidden, including redirects from the signed URL.
            response = opener.open(urllib.request.Request(target), timeout=remaining_timeout(self.deadline))
        with response:
            data = response.read(maximum + 1)
        require(len(data) <= maximum, 'Bridge response exceeds byte bound')
        remaining_timeout(self.deadline)
        return data if raw else strict_json(data)


    def verify_coverage(self, raw, record, run):
        return official_coverage_verification(raw, record, self.token, deadline=self.deadline)


class IntakeReads:
    """Retry only recognized throttled GETs under one intake deadline/budget."""
    def __init__(self, api, deadline):
        if isinstance(api, API) and api.deadline is not None:
            deadline = min(deadline, api.deadline)
        self.api, self.deadline, self.throttles = api, deadline, 0
        if isinstance(api, API):
            api.deadline = min(api.deadline, deadline) if api.deadline is not None else deadline

    def get(self, path, **kwargs):
        while True:
            remaining_timeout(self.deadline)
            try:
                value = self.api.get(path, **kwargs)
                remaining_timeout(self.deadline)
                return value
            except BridgeRateLimit as error:
                self.throttles += 1
                require(self.throttles <= 5, 'GitHub intake throttle retry limit exceeded')
                delay = max(error.delay, 60 * (2 ** (self.throttles - 1)))
                require(self.deadline - time.monotonic() > delay, 'Source coverage wait expired')
                time.sleep(delay)

    def verify_coverage(self, raw, record, run):
        remaining_timeout(self.deadline)
        value = self.api.verify_coverage(raw, record, run)
        remaining_timeout(self.deadline)
        return value


def pages(api, path, field):
    rows = []
    for page in range(1, 11):
        value = api.get(path + ('&' if '?' in path else '?') + 'per_page=100&page=' + str(page))
        batch = value.get(field)
        require(isinstance(batch, list) and len(batch) <= 100 and type(value.get('total_count')) is int)
        rows.extend(batch)
        if len(batch) < 100:
            require(len(rows) == value['total_count'], 'Incomplete bridge API listing')
            require(len({v['id'] for v in rows}) == len(rows), 'Changing bridge API listing')
            return rows
    raise ValueError('Bridge API pagination bound exceeded')


def run_source(api, run_id, attempt, revision=None):
    require(positive(run_id) and positive(attempt))
    current = api.get(f'actions/runs/{run_id}')
    exact = api.get(f'actions/runs/{run_id}/attempts/{attempt}')
    for run in (current, exact):
        require(run.get('id') == run_id and run.get('run_attempt') == attempt and exact_sha(run.get('head_sha'))
                and run.get('path') in SOURCE_WORKFLOWS and run.get('repository', {}).get('full_name') == REPOSITORY
                and run.get('repository', {}).get('private') is False
                and run.get('head_repository', {}).get('full_name') == REPOSITORY
                and run.get('status') in ('in_progress', 'completed')
                and (run.get('status') != 'completed' or run.get('conclusion') == 'success'), 'Source run changed, failed or is not a supported current attempt')
    fields = ('id', 'run_attempt', 'head_sha', 'head_branch', 'path', 'event')
    require(all(current.get(k) == exact.get(k) for k in fields))
    require(revision is None or exact['head_sha'] == revision, 'Source revision differs')
    path, event = exact['path'], exact['event']
    require((path.endswith('/ci.yml') and event in ('pull_request', 'push')) or
            (path.endswith('/release.yml') and event in ('push', 'workflow_dispatch')) or
            (path.endswith('/staging.yml') and event == 'workflow_dispatch'), 'Unsupported source caller event')
    if path != '.github/workflows/ci.yml':
        refs = exact.get('referenced_workflows', [])
        require(isinstance(refs, list) and sum(v.get('path') == REPOSITORY + '/.github/workflows/ci.yml@' + exact['head_sha']
                and v.get('sha') == exact['head_sha'] for v in refs) == 1, 'Reusable CI caller binding missing')
    return exact


def source_identity(run):
    return {key: run[key] for key in ('id', 'run_attempt', 'head_sha', 'head_branch', 'path', 'event')}


def control_file(api, path, revision):
    value = api.get('contents/' + path + '?ref=' + revision)
    require(value.get('type') == 'file' and value.get('path') == path and value.get('encoding') == 'base64'
            and type(value.get('size')) is int and 0 < value['size'] <= 1 << 20)
    raw = base64.b64decode(value['content'].replace('\n', ''), validate=True)
    require(len(raw) == value['size'])
    return raw


def ancestor(api, older, newer):
    comparison = api.get('compare/' + older + '...' + newer)
    require(comparison.get('status') in ('ahead', 'identical') and comparison.get('merge_base_commit', {}).get('sha') == older,
            'Bridge control/tooling is outside default-main history')


def producer(api, run_id, attempt, tooling, completed=False, allow_failure=False):
    require(positive(run_id) and positive(attempt) and exact_sha(tooling), 'Main bridge tooling pin required')
    run = api.get(f'actions/runs/{run_id}')
    exact = api.get(f'actions/runs/{run_id}/attempts/{attempt}')
    control = run.get('head_sha')
    require(exact_sha(control))
    for value in (run, exact):
        require(value.get('id') == run_id and value.get('run_attempt') == attempt and value.get('head_sha') == control
                and value.get('head_branch') == 'main' and value.get('path') == WORKFLOW and value.get('event') == 'workflow_run'
                and value.get('repository', {}).get('full_name') == REPOSITORY and value.get('repository', {}).get('private') is False
                and value.get('head_repository', {}).get('full_name') == REPOSITORY, 'Untrusted bridge producer')
        if completed:
            require(value.get('status') == 'completed' and value.get('conclusion') in (('success', 'failure', 'cancelled', 'timed_out') if allow_failure else ('success',)), 'Bridge producer is not an accepted terminal run')
    ancestor(api, control, 'main')
    ancestor(api, tooling, control)
    for path in TRUSTED_FILES:
        require(control_file(api, path, control) == control_file(api, path, tooling), 'Bridge control bytes differ from approved tooling')
    return {'id': run_id, 'run_attempt': attempt, 'head_sha': control, 'path': WORKFLOW, 'tooling_revision': tooling}


def own_producer(api):
    tooling = os.environ.get('SONAR_BRIDGE_TOOLING_REVISION', '')
    control = os.environ.get('GITHUB_SHA', '')
    require(exact_sha(control) and exact_sha(tooling)
            and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_run' and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_WORKFLOW_REF') == REPOSITORY + '/' + WORKFLOW + '@refs/heads/main'
            and mode(os.environ.get('SONAR_CREDENTIAL_MODE', '')) == 'bridge', 'Bridge requires reviewed main tooling pin and explicit bridge mode')
    binding = producer(api, int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT']), tooling)
    require(binding['head_sha'] == control, 'Actual platform control revision differs')
    return binding


def pr_context(api, revision, branch):
    require(branch is None or isinstance(branch, str) and re.fullmatch(r'[A-Za-z0-9_./+@-]{1,240}', branch) and branch != 'main')
    rows = []
    for page in range(1, 11):
        params = {'state': 'open', 'base': 'main', 'per_page': 100, 'page': page}
        if branch is not None:
            params['head'] = 'lorconksu:' + branch
        result = api.get('pulls?' + urllib.parse.urlencode(params))
        require(isinstance(result, list) and len(result) <= 100)
        rows.extend(result)
        if len(result) < 100:
            break
    else:
        raise ValueError('PR lookup exceeds bridge bound')
    matches = [v for v in rows if v.get('head', {}).get('sha') == revision]
    require(len(matches) == 1 and positive(matches[0].get('number')), 'Exactly one current open source PR required')
    pr = api.get('pulls/' + str(matches[0]['number']))
    require(pr.get('number') == matches[0]['number'] and pr.get('state') == 'open' and pr.get('merged') is False
            and pr.get('merged_at') is None and pr.get('head', {}).get('sha') == revision
            and (branch is None or pr['head'].get('ref') == branch) and pr['head'].get('repo', {}).get('full_name') == REPOSITORY
            and pr.get('base', {}).get('ref') == 'main' and pr['base'].get('repo', {}).get('full_name') == REPOSITORY, 'PR source changed')
    head = pr['head']['ref']
    require(isinstance(head, str) and re.fullmatch(r'[A-Za-z0-9_./+@-]{1,240}', head) and head != 'main')
    return f"-Dsonar.pullrequest.key={pr['number']} -Dsonar.pullrequest.branch={head} -Dsonar.pullrequest.base=main"


def sonar_get(endpoint, params, deadline=None):
    request = urllib.request.Request('https://sonarcloud.io/api/' + endpoint + '?' + urllib.parse.urlencode(params), headers={'Accept': 'application/json'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=remaining_timeout(deadline)) as response:
        raw = response.read(MAX_JSON + 1)
    require(len(raw) <= MAX_JSON)
    remaining_timeout(deadline)
    return strict_json(raw)


def context(api, run, sonar=None):
    sonar = sonar or (lambda endpoint, params: sonar_get(endpoint, params, getattr(api, 'deadline', None)))
    revision, branch, path = run['head_sha'], run['head_branch'], run['path']
    require(isinstance(branch, str) and re.fullmatch(r'[A-Za-z0-9_./+@-]{1,240}', branch))
    if path == '.github/workflows/ci.yml' and run['event'] == 'pull_request':
        args = gate = pr_context(api, revision, branch)
    elif path == '.github/workflows/ci.yml':
        require(run['event'] == 'push' and branch == 'main')
        require(api.get('commits/main').get('sha') == revision, 'Superseded main analysis refused')
        args = gate = '-Dsonar.branch.name=main'
    else:
        if path == '.github/workflows/release.yml':
            require(re.fullmatch(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', branch), 'Stable caller requires exact stable tag')
            require(api.get('commits/' + urllib.parse.quote('refs/tags/' + branch, safe='')).get('sha') == revision)
            comparison = api.get('compare/' + revision + '...main')
            require(comparison.get('status') in ('ahead', 'identical') and comparison.get('merge_base_commit', {}).get('sha') == revision)
            gate = '-Dsonar.branch.name=main'
        else:
            # Staging's supported reusable caller always requests a full exact
            # source branch. It cannot retarget the main Sonar branch.
            refs = [v['ref'] for v in run['referenced_workflows'] if v.get('path') == REPOSITORY + '/.github/workflows/ci.yml@' + revision]
            require(len(refs) == 1)
            ref = refs[0]
            if ref.startswith('refs/tags/'):
                require(re.fullmatch(r'refs/tags/prototype-(?:ssh-passthrough|application-access|ssdf)\.[1-9][0-9]*', ref) and ref == 'refs/tags/' + branch)
                require(api.get('commits/' + urllib.parse.quote(ref, safe='')).get('sha') == revision)
                gate = pr_context(api, revision, None)
            else:
                require(ref == 'refs/heads/' + branch and branch != 'main')
                gate = pr_context(api, revision, branch)
        name = 'release-ssdf-candidate-' + revision
        component = sonar('components/show', {'component': 'lorconksu_veyport'})['component']
        require(component.get('key') == 'lorconksu_veyport' and component.get('visibility') == 'public')
        settings = sonar('settings/values', {'component': 'lorconksu_veyport', 'keys': 'sonar.branch.longLivedBranches.regex'})['settings']
        patterns = [v.get('value') for v in settings if v.get('key') == 'sonar.branch.longLivedBranches.regex']
        require(len(patterns) == 1 and isinstance(patterns[0], str) and len(patterns[0]) <= 1024 and re.fullmatch(patterns[0], name))
        matches = [v for v in sonar('project_branches/list', {'project': 'lorconksu_veyport'})['branches'] if v.get('name') == name]
        require(len(matches) <= 1 and all(v.get('type') == 'LONG' and v.get('isMain') is False for v in matches))
        if matches:
            rows = sonar('project_analyses/search', {'project': 'lorconksu_veyport', 'branch': name, 'ps': 1, 'p': 1})['analyses']
            require(len(rows) == 1 and rows[0].get('revision') == revision)
        args = '-Dsonar.branch.name=' + name
    return {'args': args, 'gate_args': gate, 'quality_gate_wait': 'true' if args == gate else 'false', 'profile_sha256': PROFILE}


def coverage_ready(api, run):
    prefix = '' if run['path'] == '.github/workflows/ci.yml' else 'required-ci / '
    jobs = pages(api, f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", 'jobs')
    selected = []
    for name in ('test', 'integration'):
        rows = [v for v in jobs if v.get('name') == prefix + name]
        require(len(rows) <= 1, 'Duplicate source coverage job')
        if not rows or rows[0].get('status') != 'completed':
            return None
        job = rows[0]
        require(job.get('conclusion') == 'success' and job.get('run_id') == run['id'] and job.get('run_attempt') == run['run_attempt']
                and job.get('head_sha') == run['head_sha'], 'Source coverage job did not succeed for this attempt')
        selected.append(job)
    signing = [v for v in jobs if v.get('name') == prefix + 'sonar-coverage-attestation']
    require(len(signing) <= 1, 'Duplicate coverage signing job')
    if not signing or signing[0].get('status') != 'completed':
        return None
    require(signing[0].get('conclusion') == 'success' and signing[0].get('run_id') == run['id']
            and signing[0].get('run_attempt') == run['run_attempt'] and signing[0].get('head_sha') == run['head_sha'],
            'Coverage signing job did not succeed for the current source attempt')
    return selected


def artifact(api, record, run_id, maximum=MAX_ZIP):
    require(record.get('expired') is False and positive(record.get('id')) and type(record.get('size_in_bytes')) is int
            and 0 < record['size_in_bytes'] <= maximum and record.get('workflow_run', {}).get('id') == run_id
            and isinstance(record.get('digest'), str) and re.fullmatch(r'sha256:[0-9a-f]{64}', record['digest']), 'Invalid bridge artifact metadata')
    fresh = api.get('actions/artifacts/' + str(record['id']))
    require(fresh == record, 'Bridge artifact metadata changed')
    raw = api.get('actions/artifacts/' + str(record['id']) + '/zip', raw=True, maximum=maximum)
    require(sha(raw) == record['digest'][7:], 'Bridge artifact digest differs')
    return raw


def extract(raw, expected, root=None, maximum=MAX_TOTAL):
    require(len(raw) <= MAX_ZIP)
    result, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) == len(expected) and len({entry.filename for entry in entries}) == len(entries))
        # Validate the entire directory before decompressing even the first
        # member. No ZIP-provided path is ever passed to extract/extractall.
        for entry in entries:
            kind = (entry.external_attr >> 16) & 0o170000
            require(entry.filename in expected and not entry.is_dir() and kind in (0, stat.S_IFREG)
                    and not entry.flag_bits & 1 and 0 <= entry.file_size <= 64 << 20)
        require(sum(entry.file_size for entry in entries) <= maximum)
        for entry in entries:
            kind = (entry.external_attr >> 16) & 0o170000
            require(entry.filename in expected and entry.filename not in result and not entry.is_dir()
                    and kind in (0, stat.S_IFREG) and not entry.flag_bits & 1 and 0 <= entry.file_size <= 64 << 20)
            total += entry.file_size
            require(total <= maximum)
            value = archive.read(entry)
            require(len(value) == entry.file_size and b'\x00' not in value)
            value.decode('utf-8')
            result[entry.filename] = value
    require(set(result) == set(expected))
    if root is not None:
        root = Path(root)
        require(not root.exists(), 'Fresh bridge extraction directory required')
        root.mkdir(parents=True, mode=0o700)
        for name, value in result.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
            target.chmod(0o600)
    return result


def small_record(api, record, run_id, filename):
    raw = artifact(api, record, run_id, 64 << 10)
    files = extract(raw, {filename}, maximum=8192)
    require(len(files[filename]) <= 8192)
    return strict_json(files[filename])


def source_key(source):
    return str(source['id']) + '-' + str(source['run_attempt'])


def claims(api, source, tooling, cache=None):
    # GitHub concurrency serializes the main workflow per source attempt. A
    # claim is valid only after API verification of its actual main producer;
    # candidate same-name uploads cannot deny or authorize a scan.
    name = 'sonar-claim-v1-' + source_key(source)
    rows = pages(api, 'actions/artifacts?name=' + name, 'artifacts')
    trusted, admitted_ids = [], set()
    for row in rows:
        rid = row.get('workflow_run', {}).get('id')
        if not positive(rid):
            continue
        run = api.get(f'actions/runs/{rid}')
        if run.get('path') != WORKFLOW or run.get('event') != 'workflow_run' or run.get('head_branch') != 'main':
            continue
        # A main pin rotation must not erase an earlier trusted claim for the
        # same source attempt. Bind its own actual main control revision; a new
        # source CI attempt is the recovery boundary after an orphan claim.
        require(exact_sha(run.get('head_sha')))
        # Never mistake candidate upload content for a trusted claim.
        require(row.get('name') == name)
        cached = cache.get(row.get('id')) if cache is not None else None
        if cached is not None:
            # The immutable claim bytes/control closure were admitted once in
            # this invocation. Keep checking mutable attempt and API identity;
            # final result acceptance performs the complete validation again.
            previous, value = cached
            require(row == previous and api.get('actions/artifacts/' + str(row['id'])) == row,
                    'Trusted claim artifact identity changed')
            binding = value['producer']
            require(run.get('id') == binding['id'] and run.get('run_attempt') == binding['run_attempt']
                    and run.get('head_sha') == binding['head_sha']
                    and run.get('repository', {}).get('full_name') == REPOSITORY
                    and run.get('repository', {}).get('private') is False
                    and run.get('head_repository', {}).get('full_name') == REPOSITORY,
                    'Trusted claim producer attempt changed')
        else:
            value = small_record(api, row, rid, 'claim.json')
            require(set(value) == {'schema', 'source', 'producer'} and value['schema'] == 1 and value['source'] == source)
            binding = value['producer']
            require(binding == producer(api, rid, binding['run_attempt'], binding['tooling_revision']))
            if cache is not None:
                cache[row['id']] = (row, value)
        trusted.append(value)
        admitted_ids.add(row['id'])
    require(cache is None or set(cache).issubset(admitted_ids), 'Previously admitted trusted claim disappeared')
    return trusted



def lifecycle(api, source, tooling, cache):
    # Only immutable main workflow code writes this early event-derived marker.
    # It can explain terminal failure, never authorize a claim, task or scan.
    name = 'sonar-lifecycle-v1-' + source_key(source)
    trusted = []
    for row in pages(api, 'actions/artifacts?name=' + name, 'artifacts'):
        rid = row.get('workflow_run', {}).get('id')
        if not positive(rid):
            continue
        run = api.get(f'actions/runs/{rid}')
        if run.get('path') != WORKFLOW or run.get('event') != 'workflow_run' or run.get('head_branch') != 'main':
            continue
        require(row.get('name') == name and positive(run.get('run_attempt')))
        cached = cache.get(row.get('id'))
        if cached is None:
            # Admit the actual producer closure before consuming its marker.
            binding = producer(api, rid, run['run_attempt'], tooling)
            value = small_record(api, row, rid, 'lifecycle.json')
            require(set(value) == {'schema', 'source', 'producer', 'authority'} and value['schema'] == 1
                    and value['authority'] == 'negative-lifecycle-only'
                    and set(value['source']) == {'id', 'run_attempt', 'head_sha'}
                    and set(value['producer']) == {'id', 'run_attempt', 'head_sha'})
            require(all(positive(value[part][key]) for part in ('source', 'producer') for key in ('id', 'run_attempt'))
                    and all(exact_sha(value[part]['head_sha']) for part in ('source', 'producer')))
            # Artifacts can outlive a producer retry. They do not speak for its
            # current attempt and cannot cause terminal failure for that retry.
            if value['producer']['run_attempt'] != binding['run_attempt']:
                continue
            require(value['source'] == {key: source[key] for key in ('id', 'run_attempt', 'head_sha')}
                    and value['producer'] == {key: binding[key] for key in ('id', 'run_attempt', 'head_sha')},
                    'Trusted lifecycle source or producer binding differs')
            cache[row['id']] = (row, value, binding)
        else:
            previous, value, binding = cached
            if run.get('run_attempt') != binding['run_attempt']:
                continue
            require(row == previous and api.get('actions/artifacts/' + str(row['id'])) == row,
                    'Trusted lifecycle artifact identity changed')
            require(run.get('id') == binding['id'] and run.get('head_sha') == binding['head_sha']
                    and run.get('repository', {}).get('full_name') == REPOSITORY
                    and run.get('repository', {}).get('private') is False
                    and run.get('head_repository', {}).get('full_name') == REPOSITORY,
                    'Trusted lifecycle producer identity changed')
        trusted.append(binding)
    require(len(trusted) <= 1, 'Multiple trusted lifecycle producers')
    return trusted

def intake(api, event, output, timeout=7200):
    deadline = time.monotonic() + timeout
    api = IntakeReads(api, deadline)
    deadline = api.deadline
    binding = own_producer(api)
    require(event.get('action') == 'in_progress' and event.get('repository', {}).get('full_name') == REPOSITORY)
    triggered = event['workflow_run']
    rid, attempt = triggered['id'], triggered['run_attempt']
    require(exact_sha(triggered.get('head_sha')))
    while True:
        run = run_source(api, rid, attempt, triggered['head_sha'])
        require(all(run.get(k) == triggered.get(k) for k in ('id', 'run_attempt', 'head_sha', 'head_branch', 'path', 'event')))
        jobs = coverage_ready(api, run)
        if jobs:
            break
        # A terminal successful attempt cannot create more coverage jobs.
        # A lagging job-list view is conservatively held; do not assume atomic
        # API ordering or spend the active-source deadline polling an old run.
        require(run.get('status') != 'completed', 'Terminal source attempt lacks ready coverage jobs')
        time.sleep(remaining_timeout(deadline, 15))
    source = source_identity(run)
    require(not claims(api, source, binding['tooling_revision']), 'Existing trusted scan claim: reuse its result or start a fresh source CI attempt')
    plan = {'schema': 1, 'source': source, 'producer': binding, 'context': context(api, run), 'coverage': []}
    listing = pages(api, f'actions/runs/{rid}/artifacts', 'artifacts')
    output = Path(output)
    require(not output.exists())
    remaining_timeout(deadline)
    output.mkdir(mode=0o700, parents=True)
    for group, prefix in (('unit', 'coverage-v1-'), ('integration', 'coverage-integration-v1-')):
        rows = [v for v in listing if v.get('name') == prefix + source_key(source)]
        require(len(rows) == 1, 'Exact current-attempt coverage artifact missing')
        record = rows[0]
        job = jobs[0 if group == 'unit' else 1]
        # Timestamps bound freshness only. The actual numbered upload step and
        # a verified platform certificate independently bind provenance.
        require(job.get('started_at') <= record.get('created_at', '') <= record.get('updated_at', '') <= job.get('completed_at')
                and record.get('workflow_run', {}).get('head_sha') == source['head_sha'], 'Coverage artifact does not belong to current coverage job')
        raw = artifact(api, record, rid)
        provenance = coverage_provenance(api, run, record, job, group, raw)
        (output / 'provenance').mkdir(mode=0o700, exist_ok=True)
        (output / 'provenance' / (group + '.zip')).write_bytes(raw)
        files = extract(raw, COVERAGE[group], output / group)
        plan['coverage'].append({'group': group, 'artifact_id': record['id'], 'digest': record['digest'], 'job_id': job['id'], 'provenance': provenance,
                                 'files': {name: {'sha256': sha(value), 'size': len(value)} for name, value in files.items()}})
    require(source_identity(run_source(api, rid, attempt, source['head_sha'])) == source)
    require(context(api, run) == plan['context'], 'Sonar context changed during intake')
    remaining_timeout(deadline)
    (output / 'intake.json').write_bytes(canonical(plan) + b'\n')
    (output / 'claim.json').write_bytes(canonical({'schema': 1, 'source': source, 'producer': binding}) + b'\n')
    return plan


def regular(path, maximum):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum)
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum)
    return raw


def validate_plan(api, plan, coverage_root=None, verified_reports=None):
    require(verified_reports is None or (type(verified_reports) is dict and not verified_reports))
    signed_reports, signed_total = {}, 0
    require(set(plan) == {'schema', 'source', 'producer', 'context', 'coverage'} and plan['schema'] == 1)
    require(plan['producer'] == own_producer(api), 'Intake belongs to another main producer')
    source = plan['source']
    run = run_source(api, source['id'], source['run_attempt'], source['head_sha'])
    require(source_identity(run) == source and coverage_ready(api, run) is not None)
    require(context(api, run) == plan['context'], 'Intake context no longer current')
    require(len(plan['coverage']) == 2 and {v['group'] for v in plan['coverage']} == set(COVERAGE))
    jobs = coverage_ready(api, run)
    for item in plan['coverage']:
        require(set(item) == {'group', 'artifact_id', 'digest', 'job_id', 'provenance', 'files'} and set(item['files']) == COVERAGE[item['group']])
        record = api.get('actions/artifacts/' + str(item['artifact_id']))
        prefix = 'coverage-v1-' if item['group'] == 'unit' else 'coverage-integration-v1-'
        job = jobs[0 if item['group'] == 'unit' else 1]
        require(item['job_id'] == job['id'] and record.get('name') == prefix + source_key(source) and record.get('digest') == item['digest']
                and record.get('expired') is False and record.get('workflow_run', {}).get('id') == source['id']
                and record['workflow_run'].get('head_sha') == source['head_sha']
                and job['started_at'] <= record.get('created_at', '') <= record.get('updated_at', '') <= job['completed_at'])
        raw = (regular(Path(coverage_root) / 'provenance' / (item['group'] + '.zip'), MAX_ZIP)
               if coverage_root is not None else artifact(api, record, source['id']))
        require(sha(raw) == item['digest'][7:])
        require(coverage_provenance(api, run, record, job, item['group'], raw) == item['provenance'],
                'Coverage upload or signed workflow provenance changed before scanner issuance')
        # The separately transferred plan cannot authorize report bytes. Derive
        # exact names, sizes and hashes from this authenticated archive itself.
        files = extract(raw, COVERAGE[item['group']])
        signed_total += sum(len(value) for value in files.values())
        require(signed_total <= MAX_TOTAL)
        require(item['files'] == {name: {'sha256': sha(value), 'size': len(value)}
                                 for name, value in files.items()},
                'Coverage member metadata differs from verified signed archive')
        if verified_reports is not None:
            signed_reports[item['group']] = files
    require(source_identity(run_source(api, source['id'], source['run_attempt'], source['head_sha'])) == source)
    if verified_reports is not None:
        verified_reports.update(signed_reports)
    return run


def prepare(api, intake_path, workspace):
    plan = strict_json(regular(intake_path, 8192))
    signed_reports = {}
    validate_plan(api, plan, Path(intake_path).parent, verified_reports=signed_reports)
    workspace = Path(workspace)
    require(workspace.is_dir() and not workspace.is_symlink())
    # Reject all checkout-owned links/devices and gitmodules before scanning.
    for base, dirs, files in os.walk(workspace, followlinks=False):
        if Path(base) == workspace:
            dirs[:] = [v for v in dirs if v != '.git']
            files = [v for v in files if v != '.git']
        require(all(not (Path(base) / name).is_symlink() for name in dirs + files))
        require(all(stat.S_ISREG((Path(base) / name).lstat().st_mode) for name in files))
        require('.gitmodules' not in files, 'Candidate submodules are not scanner inputs')
    raw = regular(workspace / 'sonar-project.properties', 65536)
    require(sha(raw) == PROFILE, 'Candidate Sonar profile differs from reviewed technical profile')
    # The exact pinned bytes already fix all source/report paths and API hosts.
    total, reports = 0, {}
    for group, names in COVERAGE.items():
        root = Path(intake_path).parent / group
        require(root.is_dir() and not root.is_symlink())
        actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
        require(actual == names and all(not p.is_symlink() and (p.is_dir() or stat.S_ISREG(p.lstat().st_mode)) for p in root.rglob('*')))
        for name in sorted(names):
            raw = regular(root / name, 64 << 20)
            signed = signed_reports[group][name]
            require(raw == signed, 'Coverage transfer bytes differ from verified signed archive')
            total += len(raw)
            require(total <= MAX_TOTAL and b'\x00' not in raw)
            raw.decode('utf-8')
            reports[name] = signed
    # Finish all transfer checks before writing any scanner report. Copy the
    # authenticated member buffers, without reopening mutable transfer paths.
    for name, raw in reports.items():
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
    private = Path(os.environ['RUNNER_TEMP']) / 'sonar-scan-metadata'
    require(not private.exists() and not private.is_symlink())
    private.mkdir(mode=0o700)
    return plan


def descriptor(api, intake_path, task_path):
    plan = strict_json(regular(intake_path, 8192))
    validate_plan(api, plan, Path(intake_path).parent)
    values = {}
    for line in regular(task_path, 65536).decode('utf-8').splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            require(key not in values)
            values[key] = value
    require(values.get('serverUrl', '').rstrip('/') == 'https://sonarcloud.io' and values.get('projectKey') == 'lorconksu_veyport'
            and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', values.get('ceTaskId', '')), 'Scanner task unavailable')
    outcome = os.environ.get('SCAN_OUTCOME', '')
    require(outcome in ('success', 'failure', 'cancelled'), 'Actual scanner outcome required')
    return {'schema': 1, 'source': plan['source'], 'producer': plan['producer'], 'context': plan['context'],
            'coverage_provenance': [{k: v for k, v in item.items() if k != 'files'} for item in plan['coverage']],
            'task_id': values['ceTaskId'], 'scanner_action': ACTION, 'scanner_outcome': outcome, 'authority': 'technical-scan-identity-only'}


def verify_result(api, record, source, tooling):
    rid = record.get('workflow_run', {}).get('id')
    require(positive(rid))
    result = small_record(api, record, rid, 'descriptor.json')
    require(set(result) == {'schema', 'source', 'producer', 'context', 'coverage_provenance', 'task_id', 'scanner_action', 'scanner_outcome', 'authority'} and result['schema'] == 1
            and result['source'] == source and result['scanner_action'] == ACTION and result['authority'] == 'technical-scan-identity-only')
    coverage = result['coverage_provenance']
    require(isinstance(coverage, list) and len(coverage) == 2 and {v.get('group') for v in coverage} == set(COVERAGE))
    for item in coverage:
        require(set(item) == {'group', 'artifact_id', 'digest', 'job_id', 'provenance'}
                and positive(item['artifact_id']) and positive(item['job_id'])
                and re.fullmatch(r'sha256:[0-9a-f]{64}', item['digest'])
                and item['provenance']['certificate']['run_uri'] ==
                f"https://github.com/{REPOSITORY}/actions/runs/{source['id']}/attempts/{source['run_attempt']}")
    binding = result['producer']
    require(binding.get('tooling_revision') == tooling and binding == producer(api, rid, binding['run_attempt'], tooling, completed=True, allow_failure=True))
    control = binding['head_sha']
    jobs = pages(api, f"actions/runs/{rid}/attempts/{binding['run_attempt']}/jobs", 'jobs')
    scan = [v for v in jobs if v.get('name') == 'scan']
    require(len(scan) == 1 and scan[0].get('status') == 'completed' and scan[0].get('conclusion') in ('success', 'failure', 'cancelled', 'timed_out')
            and scan[0].get('head_sha') == control and scan[0].get('run_id') == rid and scan[0].get('run_attempt') == binding['run_attempt'])
    steps = scan[0].get('steps')
    require(isinstance(steps, list))
    scanner = [v for v in steps if v.get('name') == 'Submit isolated Sonar analysis']
    require(len(scanner) == 1 and scanner[0].get('status') == 'completed'
            and scanner[0].get('conclusion') == result.get('scanner_outcome')
            and result['scanner_outcome'] in ('success', 'failure', 'cancelled'), 'Scanner outcome differs from actual producer step')
    final_run = api.get(f'actions/runs/{rid}')
    require(final_run.get('run_attempt') == binding['run_attempt'] and final_run.get('status') == 'completed'
            and final_run.get('head_sha') == control and final_run.get('conclusion') in ('success', 'failure', 'cancelled', 'timed_out'))
    outcomes = (result['scanner_outcome'], scan[0]['conclusion'], final_run['conclusion'])
    effective = 'success' if all(v == 'success' for v in outcomes) else ('cancelled' if 'cancelled' in outcomes else 'failure')
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,128}', result.get('task_id', '')) and result['context']['profile_sha256'] == PROFILE)
    run = run_source(api, source['id'], source['run_attempt'], source['head_sha'])
    require(source_identity(run) == source and result['context'] == context(api, run))
    admitted_controls = producer_controls(api, run, tooling)
    require(all(item['provenance'].get('producer_controls') == admitted_controls for item in coverage),
            'Descriptor committed producer control admission differs')
    require(source_identity(run_source(api, source['id'], source['run_attempt'], source['head_sha'])) == source)
    return {**result, 'scan_status': effective, 'producer_conclusion': final_run['conclusion'], 'scan_job_conclusion': scan[0]['conclusion']}


def wait_result(api, run_id, attempt, revision, tooling, timeout=2400):
    require(exact_sha(tooling) and exact_sha(revision), 'Bridge consumer requires main helper pin and source revision')
    deadline = time.monotonic() + timeout
    if isinstance(api, API):
        api.deadline = min(api.deadline, deadline) if api.deadline is not None else deadline
        deadline = api.deadline
    claim_cache, lifecycle_cache, terminal_empty, throttles, initial_source = {}, {}, {}, 0, None
    while True:
        require(time.monotonic() < deadline, 'Trusted Sonar bridge result wait expired')
        delay = 60
        try:
            source = source_identity(run_source(api, run_id, attempt, revision))
            require(initial_source is None or source == initial_source, 'Source identity changed during bridge wait')
            initial_source = source
            existing = claims(api, source, tooling, claim_cache)
            require(len(existing) <= 1, 'Multiple trusted scan claims')
            bindings = ([value['producer'] for value in existing] if existing
                        else lifecycle(api, source, tooling, lifecycle_cache))
            # Observe status first, then obtain a fresh descriptor listing. A
            # completion between reads is handled on the next poll, not orphaned.
            completed = []
            for binding in bindings:
                observed = api.get('actions/runs/' + str(binding['id']))
                require(all(observed.get(key) == binding[key] for key in ('id', 'run_attempt', 'head_sha', 'path')),
                        'Trusted producer attempt changed during result wait')
                if observed.get('status') == 'completed':
                    completed.append(binding)
            name = 'sonar-bridge-v1-' + source_key(source)
            rows = pages(api, 'actions/artifacts?name=' + name, 'artifacts')
            valid = []
            for row in rows:
                rid = row.get('workflow_run', {}).get('id')
                if not positive(rid):
                    continue
                run = api.get(f'actions/runs/{rid}')
                if run.get('path') != WORKFLOW or run.get('event') != 'workflow_run' or run.get('head_branch') != 'main':
                    continue
                require(row.get('name') == name)
                if run.get('status') != 'completed':
                    continue
                valid.append(verify_result(api, row, source, tooling))
            require(len(valid) <= 1, 'Multiple trusted Sonar producer results')
            if valid:
                final_claims = claims(api, source, tooling)
                require(len(final_claims) <= 1, 'Multiple trusted scan claims')
                require(not final_claims or final_claims[0]['producer'] == valid[0]['producer'], 'Claim/result producer differs')
                # Last independent source readback follows every expensive
                # terminal claim/producer/artifact validation.
                require(source_identity(run_source(api, run_id, attempt, revision)) == source)
                remaining_timeout(deadline)
                return valid[0]
            now = time.monotonic()
            for binding in completed:
                key = (binding['id'], binding['run_attempt'], binding['head_sha'])
                first, observations = terminal_empty.get(key, (now, 0))
                terminal_empty[key] = (first, observations + 1)
                # Bounded API artifact propagation grace, with repeated fresh
                # listings. Ready descriptors never incur an extra fixed sleep.
                if observations >= 1 and now - first >= 120:
                    require(binding == producer(api, binding['id'], binding['run_attempt'], tooling,
                                                completed=True, allow_failure=True))
                    require(source_identity(run_source(api, run_id, attempt, revision)) == source)
                    raise ValueError('Trusted Sonar producer ended without a usable descriptor; start a fresh source CI attempt')

        except BridgeRateLimit as error:
            throttles += 1
            require(throttles <= 5, 'GitHub bridge throttle retry limit exceeded')
            delay = max(error.delay, 60 * (2 ** (throttles - 1)))
        remaining = deadline - time.monotonic()
        require(remaining > delay, 'Trusted Sonar bridge result wait expired')
        time.sleep(delay)


def destination(plan):
    args = plan['args']
    match = re.fullmatch(r'-Dsonar.pullrequest.key=([1-9][0-9]*) -Dsonar.pullrequest.branch=[A-Za-z0-9_./+@-]{1,240} -Dsonar.pullrequest.base=main', args)
    if match:
        return 'pr-' + match[1]
    match = re.fullmatch(r'-Dsonar.branch.name=(main|release-ssdf-candidate-[0-9a-f]{40})', args)
    require(match is not None)
    return 'branch-' + match[1]


def outputs(values):
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
        for key, value in values.items():
            require(isinstance(value, str) and '\n' not in value and '\r' not in value and len(value) <= 2048)
            stream.write(key + '=' + value + '\n')


def write_record(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.parent.is_symlink() and path.parent.is_dir())
    raw = canonical(value) + b'\n'
    require(len(raw) <= 8192)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('mode', 'install-verifier', 'intake', 'prepare', 'descriptor', 'wait'))
    parser.add_argument('--output')
    parser.add_argument('--intake')
    parser.add_argument('--workspace')
    parser.add_argument('--report-task')
    parser.add_argument('--revision')
    parser.add_argument('--timeout', type=int, default=2400)
    args = parser.parse_args()
    require(0 < args.timeout <= (7200 if args.command == 'intake' else 10800 if args.command == 'wait' else 3600))
    if args.command == 'install-verifier':
        install_verifier()
        return
    if args.command == 'mode':
        selected = mode(os.environ.get('SONAR_CREDENTIAL_MODE', ''))
        if selected == 'bridge':
            require(exact_sha(os.environ.get('SONAR_BRIDGE_TOOLING_REVISION')), 'Bridge main pin missing')
        outputs({'mode': selected})
        return
    api = API(deadline=time.monotonic() + args.timeout)
    if args.command == 'intake':
        event = strict_json(regular(os.environ['GITHUB_EVENT_PATH'], MAX_JSON))
        plan = intake(api, event, args.output, args.timeout)
        remaining_timeout(api.deadline)
        outputs({'revision': plan['source']['head_sha'], 'source_key': source_key(plan['source']), 'destination': destination(plan['context']), **plan['context']})
    elif args.command == 'prepare':
        plan = prepare(api, args.intake, args.workspace)
        remaining_timeout(api.deadline)
        outputs(plan['context'])
    elif args.command == 'descriptor':
        value = descriptor(api, args.intake, args.report_task)
        remaining_timeout(api.deadline)
        write_record(args.output, value)
    else:
        require(mode(os.environ.get('SONAR_CREDENTIAL_MODE', '')) == 'bridge')
        value = wait_result(api, int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT']), args.revision,
                            os.environ.get('SONAR_BRIDGE_TOOLING_REVISION', ''), args.timeout)
        expected = os.environ.get('EXPECTED_BRIDGE_TASK', '')
        if expected:
            require(value['task_id'] == expected and value['context']['args'] == os.environ['EXPECTED_BRIDGE_ARGS']
                    and value['context']['gate_args'] == os.environ['EXPECTED_BRIDGE_GATE'], 'Producer descriptor differs across CI consumers')
        remaining_timeout(api.deadline)
        write_record(args.output, value)
        outputs({'task_id': value['task_id'], 'scan_status': value['scan_status'], **value['context']})


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Sonar bridge failed closed; inspect trusted producer status and exact source attempt') from None

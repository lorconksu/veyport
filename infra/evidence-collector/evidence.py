#!/usr/bin/env python3
"""Private evidence transport and archive. No repository code is executed by collection."""
import argparse
import base64
import calendar
import contextlib
import datetime as dt
import fcntl
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

MAX_TOTAL = 64 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_FILES = 256
MAX_WIRE = MAX_TOTAL + MAX_MANIFEST + 2 * 1024 * 1024
MAX_JOB_WIRE = 512 << 20
MAX_JOB_CHUNKS = 64
CODEQL_WORKFLOW = 'dynamic/github-code-scanning/codeql'
PLATFORM_DIAGNOSTIC_KINDS = {'codeql-analysis', 'codeql-summary', 'platform-outcome', 'job-logs', 'job-logs-missing', 'provider-status'}
_PROVIDER_EXPORTS = None
PUBLICATION_WORKFLOWS = ('.github/workflows/release.yml', '.github/workflows/staging.yml')
PUBLICATION_STEP = 'Publish disclosure-safe binary release assets'
REQUIRED_RELEASE_JOBS = ['unit'] + ['server-' + str(x) for x in range(6)] + ['test', 'integration', 'smoke', 'e2e', 'sonar', 'secrets', 'vulnerability']
HEX = re.compile(r'^[a-f0-9]{64}$')
SHA = re.compile(r'^[a-f0-9]{40}$')
UTC = dt.timezone.utc


class EvidenceError(Exception):
    """A safe, disclosure-free operational error."""


class APIBudgetExceeded(EvidenceError):
    pass


class GitHubError(EvidenceError):
    def __init__(self, code):
        self.code = code
        super().__init__('GitHub API request failed: HTTP ' + str(code))


def require(ok, message):
    if not ok:
        raise EvidenceError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, 'invalid JSON number'))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise EvidenceError('invalid JSON') from exc


def timestamp(value):
    require(isinstance(value, str), 'missing timestamp')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(parsed.tzinfo is not None, 'timestamp needs timezone')
        return parsed.astimezone(UTC)
    except ValueError as exc:
        raise EvidenceError('invalid timestamp') from exc


def now():
    return dt.datetime.now(UTC)


def iso(value):
    return value.isoformat().replace('+00:00', 'Z')


def year_after(value):
    return value.replace(year=value.year + 1, day=min(value.day, calendar.monthrange(value.year + 1, value.month)[1]))


def safe_name(name):
    require(isinstance(name, str) and 0 < len(name) <= 240 and '\\' not in name and '\x00' not in name, 'unsafe file name')
    p = PurePosixPath(name)
    require(not p.is_absolute() and all(x not in ('', '.', '..') for x in name.split('/')), 'unsafe file name')
    return name


def manifest_valid(m):
    require(isinstance(m, dict) and m.get('schema') == 1, 'unsupported manifest')
    require(isinstance(m.get('repository'), str) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', m['repository']), 'invalid repository')
    details = m.get('details')
    platform_diagnostic = m.get('workflow') == CODEQL_WORKFLOW and m.get('complete') is False and isinstance(details, dict) and details.get('kind') in PLATFORM_DIAGNOSTIC_KINDS and details.get('source_trusted') is False
    require(isinstance(m.get('workflow'), str) and (re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml', m['workflow']) or platform_diagnostic), 'invalid workflow or platform diagnostic authority')
    require(type(m.get('run_id')) is int and m['run_id'] > 0 and type(m.get('run_attempt')) is int and m['run_attempt'] > 0, 'invalid run identity')
    require(isinstance(m.get('revision'), str) and SHA.fullmatch(m['revision']), 'invalid revision')
    require(isinstance(m.get('candidate_id'), str) and 0 < len(m['candidate_id']) <= 128, 'invalid candidate identity')
    require(type(m.get('complete')) is bool and isinstance(m.get('details'), dict), 'missing completeness/details')
    files = m.get('files')
    require(isinstance(files, list) and len(files) <= MAX_FILES, 'invalid file inventory')
    names, total = set(), 0
    for item in files:
        require(isinstance(item, dict) and set(item) == {'name', 'sha256', 'size'}, 'invalid file entry')
        name = safe_name(item['name'])
        require(name not in names, 'duplicate file name')
        names.add(name)
        require(isinstance(item['sha256'], str) and HEX.fullmatch(item['sha256']), 'invalid file digest')
        require(type(item['size']) is int and 0 <= item['size'] <= MAX_FILE, 'file exceeds bound')
        total += item['size']
    require(total <= MAX_TOTAL and len(canonical(m)) <= MAX_MANIFEST, 'bundle exceeds bound')
    return m


def crypto(args, data, limit=MAX_WIRE, pass_fds=()):
    # File-backed bounded output avoids buffering an untrusted age decompression stream.
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as output:
        source.write(data)
        source.seek(0)
        def restrict_output():
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        proc = subprocess.Popen(args, stdin=source, stdout=output, stderr=subprocess.DEVNULL, preexec_fn=restrict_output, pass_fds=pass_fds)
        end = time.monotonic() + 90
        while proc.poll() is None:
            if time.monotonic() > end or output.tell() > limit:
                proc.kill()
                proc.wait()
                raise EvidenceError('cryptographic operation exceeded bound')
            time.sleep(.02)
        require(proc.returncode == 0 and output.tell() <= limit, 'cryptographic operation failed')
        output.seek(0)
        return output.read(limit + 1)


def age_encrypt(data, recipients):
    return crypto(['age', '-R', str(recipients)], data)


def age_decrypt(data, identity):
    return crypto(['age', '-d', '-i', str(identity)], data)


def sign(data, key):
    # Ed25519 one-shot input needs a seekable regular file; a sealed Linux memfd never touches disk.
    require(callable(getattr(os, 'memfd_create', None)) and len(data) <= MAX_MANIFEST, 'memory-only signature input unavailable or exceeds bound')
    descriptor = os.memfd_create('veyport-evidence-signature', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(descriptor), 'wb') as message:
            message.write(data)
            message.flush()
        os.lseek(descriptor, 0, os.SEEK_SET)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        signature = crypto(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', '/proc/self/fd/' + str(descriptor)], b'', 256, pass_fds=(descriptor,))
        require(len(signature) == 64, 'invalid Ed25519 signature output')
        return base64.b64encode(signature).decode()
    finally:
        os.close(descriptor)


def verify_signature(data, signature, key):
    try:
        sig = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError) as exc:
        raise EvidenceError('invalid receipt signature') from exc
    require(len(sig) == 64, 'invalid receipt signature')
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        (path / 'data').write_bytes(data)
        (path / 'sig').write_bytes(sig)
        result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-rawin', '-inkey', str(key), '-in', str(path / 'data'), '-sigfile', str(path / 'sig')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        require(result.returncode == 0, 'receipt signature verification failed')


def pack(m, source):
    manifest_valid(m)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('manifest.json', canonical(m))
        seen = set()
        for item in m['files']:
            # Resolve and reject links both to directories and final file.
            path = Path(source)
            for part in item['name'].split('/'):
                path = path / part
                require(not path.is_symlink(), 'symlink evidence is forbidden')
            require(path.is_file() and path.stat().st_size == item['size'], 'evidence file size mismatch')
            data = path.read_bytes()
            require(digest(data) == item['sha256'], 'evidence file digest mismatch')
            if item['sha256'] not in seen:
                archive.writestr('blobs/' + item['sha256'], data)
                seen.add(item['sha256'])
    return buffer.getvalue()


def unpack(data):
    require(len(data) <= MAX_WIRE, 'bundle exceeds bound')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            items = archive.infolist()
            require(len(items) <= MAX_FILES + 1 and len({x.filename for x in items}) == len(items), 'invalid bundle entries')
            for item in items:
                require(item.compress_type == zipfile.ZIP_STORED and item.file_size <= MAX_FILE and not item.flag_bits & 1, 'invalid bundle encoding')
                require(stat.S_IFMT(item.external_attr >> 16) not in (stat.S_IFLNK, stat.S_IFDIR), 'invalid bundle entry type')
            require('manifest.json' in archive.namelist(), 'missing manifest')
            require(archive.getinfo('manifest.json').file_size <= MAX_MANIFEST, 'manifest exceeds bound')
            m = manifest_valid(parse_json(archive.read('manifest.json')))
            expected = {'blobs/' + x['sha256'] for x in m['files']}
            require(set(archive.namelist()) == expected | {'manifest.json'}, 'bundle inventory mismatch')
            blobs = {}
            for item in m['files']:
                payload = archive.read('blobs/' + item['sha256'])
                require(len(payload) == item['size'] and digest(payload) == item['sha256'], 'bundle digest mismatch')
                blobs[item['sha256']] = payload
            return m, blobs
    except (zipfile.BadZipFile, KeyError, RuntimeError) as exc:
        raise EvidenceError('invalid bundle') from exc


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, repository, token, max_calls=None):
        require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'invalid repository')
        require(bool(token), 'GitHub token unavailable')
        self.repository, self.token = repository, token
        self.max_calls, self.calls = max_calls, 0
        self.prefix = '/repos/' + repository

    def charge(self):
        if self.max_calls is not None and self.calls >= self.max_calls:
            raise APIBudgetExceeded('per-poll GitHub API budget exhausted; backlog retained')
        self.calls += 1

    def request(self, path, method='GET', value=None, raw=False, accept='application/vnd.github+json', max_bytes=None, allow_storage_redirect=True):
        self.charge()
        require(path.startswith(self.prefix + '/'), 'API path outside repository')
        response_bound = max_bytes if max_bytes is not None else (MAX_WIRE if raw else 8 * 1024 * 1024)
        require(type(response_bound) is int and 0 < response_bound <= MAX_WIRE and accept in ('application/vnd.github+json', 'application/sarif+json'), 'invalid API representation/bound')
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': accept, 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'veyport-evidence-collector'}
        data = None if value is None else canonical(value)
        if data is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request('https://api.github.com' + path, headers=headers, data=data, method=method)
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
                remaining = response.headers.get('X-RateLimit-Remaining')
                if remaining is not None and int(remaining) < 5:
                    raise APIBudgetExceeded('GitHub API reserve reached; backlog retained')
                body = response.read(response_bound + 1)
                require(len(body) <= response_bound, 'API response exceeds bound')
                return body if raw else (parse_json(body) if body else None)
        except urllib.error.HTTPError as exc:
            if raw and allow_storage_redirect and exc.code == 302:
                url = exc.headers.get('Location', '')
                parsed = urllib.parse.urlparse(url)
                require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password and parsed.port in (None, 443) and (parsed.hostname.endswith('.blob.core.windows.net') or parsed.hostname.endswith('.actions.githubusercontent.com')), 'untrusted artifact redirect')
                # Never forward GitHub credentials to signed blob storage URL or redirects.
                try:
                    with urllib.request.build_opener(NoRedirect()).open(urllib.request.Request(url), timeout=60) as response:
                        body = response.read(response_bound + 1)
                        require(len(body) <= response_bound, 'artifact exceeds bound')
                        return body
                except urllib.error.URLError as error:
                    raise EvidenceError('artifact download failed') from error
            raise GitHubError(exc.code) from exc
        except urllib.error.URLError as exc:
            raise EvidenceError('GitHub API unavailable') from exc

    def get(self, suffix):
        return self.request(self.prefix + suffix)

    def pages(self, suffix, key):
        result = []
        for page in range(1, 101):
            value = self.get(suffix + ('&' if '?' in suffix else '?') + 'per_page=100&page=' + str(page))
            batch = value if key is None else value[key]
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise EvidenceError('API pagination bound reached')

    def artifact(self, run_id, attempt, kind="evidence"):
        artifacts = self.pages('/actions/runs/' + str(run_id) + '/artifacts', 'artifacts')
        require(kind in ('evidence', 'publication'), 'unknown evidence artifact kind')
        expected = artifact_name(run_id, attempt) if kind == 'evidence' else f'ssdf-publication-v1-{run_id}-{attempt}'
        selected = [x for x in artifacts if x['name'] == expected]
        require(len(selected) <= 1, 'ambiguous evidence artifacts')
        return selected[0] if selected else None


def download_encrypted_job(api, artifact, destination):
    require(type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= MAX_JOB_WIRE and not artifact.get('expired'), 'job artifact unavailable or exceeds bound')
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', artifact.get('digest', '')), 'job artifact digest unavailable')
    route = 'https://api.github.com' + api.prefix + '/actions/artifacts/' + str(artifact['id']) + '/zip'
    request = urllib.request.Request(route, headers={'Authorization': 'Bearer ' + api.token, 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'veyport-evidence-collector'})
    api.charge()
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30):
            raise EvidenceError('job artifact redirect unavailable')
    except urllib.error.HTTPError as exc:
        require(exc.code == 302, 'job artifact download unavailable')
        url = exc.headers.get('Location', '')
        parsed = urllib.parse.urlparse(url)
        require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password and parsed.port in (None, 443) and (parsed.hostname.endswith('.blob.core.windows.net') or parsed.hostname.endswith('.actions.githubusercontent.com')), 'untrusted job artifact redirect')
    with urllib.request.build_opener(NoRedirect()).open(urllib.request.Request(url), timeout=60) as response, Path(destination).open('xb') as output:
        h, total, deadline = hashlib.sha256(), 0, time.monotonic() + 300
        while True:
            require(time.monotonic() < deadline, 'job artifact download deadline exceeded')
            data = response.read(1 << 20)
            if not data:
                break
            total += len(data)
            require(total <= MAX_JOB_WIRE, 'job artifact exceeds bound')
            h.update(data)
            output.write(data)
        require('sha256:' + h.hexdigest() == artifact['digest'], 'job artifact archive digest mismatch')


def artifact_name(run, attempt):
    return f'ssdf-evidence-v1-{run}-{attempt}'


def trusted_run(run, config):
    require(run.get('path') != CODEQL_WORKFLOW and run.get('event') != 'dynamic', 'platform diagnostics cannot grant repository workflow authority')
    require(run.get('repository', {}).get('full_name') == config['repository'], 'run repository mismatch')
    require(run.get('head_repository', {}).get('full_name') == config['repository'], 'fork run forbidden')
    require(run.get('event') in config['allowed_events'], 'untrusted run event')
    require(run.get('path') in config['allowed_workflows'], 'untrusted workflow')
    require(run.get('head_sha') in config.get('approved_source_revisions', []) or run.get('head_branch') in config['allowed_branches'] or (run.get('event') == 'push' and any(re.fullmatch(x, run.get('head_branch', '')) for x in config.get('allowed_tag_patterns', []))), 'untrusted ref')
    require(type(run.get('id')) is int and type(run.get('run_attempt')) is int and SHA.fullmatch(run.get('head_sha', '')), 'invalid run')
    return run


def verify_trust_anchor(api, run, config):
    revision = run['head_sha']
    key = (revision, run['path'])
    cache = getattr(api, 'verified_sources', set())
    if key in cache:
        return
    approved = config.get('approved_source_revisions', [])
    require(isinstance(approved, list) and all(isinstance(x, str) and SHA.fullmatch(x) for x in approved), 'invalid approved revision pins')
    if revision in approved:
        # A private operator pin covers the complete immutable tree during an unmerged rehearsal.
        require(api.get('/commits/' + revision).get('sha') == revision, 'approved revision unavailable')
    else:
        branch = config.get('trusted_branch', 'main')
        ref = api.get('/git/ref/heads/' + urllib.parse.quote(branch, safe=''))
        anchor = ref.get('object', {}).get('sha', '')
        require(SHA.fullmatch(anchor), 'trusted branch unavailable')
        if revision != anchor:
            comparison = api.get('/compare/' + revision + '...' + anchor)
            require(comparison.get('merge_base_commit', {}).get('sha') == revision, 'source is not on trusted branch history')
            wanted = {run['path']} | set(config.get('trusted_helper_paths', []))
            for path in wanted:
                safe_name(path)
            trees = getattr(api, 'tree_cache', {})
            if not isinstance(trees, dict):
                trees = {}
            snapshots = []
            for commit_sha in (revision, anchor):
                tree_key = (commit_sha, tuple(sorted(wanted)))
                if tree_key not in trees:
                    commit = api.get('/git/commits/' + commit_sha)
                    tree_sha = commit.get('tree', {}).get('sha', '')
                    require(commit.get('sha') == commit_sha and SHA.fullmatch(tree_sha), 'trusted commit tree identity unavailable')
                    tree = api.get('/git/trees/' + tree_sha + '?recursive=1')
                    require(tree.get('sha') == tree_sha and tree.get('truncated') is False and isinstance(tree.get('tree'), list) and len(tree['tree']) <= 100000, 'trusted tree is truncated or exceeds bound')
                    entries = {}
                    for item in tree['tree']:
                        path = item.get('path')
                        if path in wanted:
                            require(path not in entries and item.get('type') == 'blob' and item.get('mode') in ('100644', '100755') and SHA.fullmatch(item.get('sha', '')), 'invalid trusted helper tree entry')
                            entries[path] = item['sha']
                    trees[tree_key] = entries
                snapshots.append(trees[tree_key])
            require(all(path in snapshots[0] and snapshots[0].get(path) == snapshots[1].get(path) for path in wanted), 'workflow/helper trust mismatch')
            api.tree_cache = trees
        # Identical source/anchor SHA already binds the entire immutable tree without per-file requests.
    cache.add(key)
    api.verified_sources = cache


def bind_manifest(m, run, config):
    trusted_run(run, config)
    require((m['repository'], m['workflow'], m['run_id'], m['run_attempt'], m['revision']) == (config['repository'], run['path'], run['id'], run['run_attempt'], run['head_sha']), 'manifest source identity mismatch')


class Archive:
    def __init__(self, config):
        self.config = config
        self.mount_root = Path(config['archive_root'])
        self.root = self.mount_root
        self.check_mount()
        self.root_fd = os.open(self.mount_root, os.O_DIRECTORY | os.O_NOFOLLOW)
        # Pin every operation to this mount, even if a concurrent unmount reveals a local directory.
        self.root = Path('/proc/self/fd') / str(self.root_fd)
        self.check_mount()

    def check_mount(self):
        require(self.mount_root.is_absolute() and not self.mount_root.is_symlink(), 'invalid archive root')
        # Require an exact mount point. LXC host bind mounts still expose their NFS backing source.
        mount = str(self.mount_root)
        found = False
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            left, right = line.split(' - ', 1)
            fields, fs = left.split(), right.split()
            point = fields[4].replace('\\040', ' ')
            if point == mount and fs[0] in ('nfs', 'nfs4') and fs[1] == self.config['mount_source']:
                found = True
        require(found, 'expected NFS mount unavailable')
        marker = self.root / '.archive-id'
        require(not marker.is_symlink() and marker.read_text().strip() == self.config['archive_id'], 'archive identity mismatch')
        require(self.root.stat().st_dev == self.mount_root.stat().st_dev, 'archive mount changed')

    @contextlib.contextmanager
    def lock(self):
        self.check_mount()
        # This lock is on NFS, shared by collection, cleanup and retention services.
        lock_fd = os.open(self.root / '.archive-lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock_fd, 'a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.check_mount()
            yield
            self.check_mount()

    def write(self, relative, data, replace=False):
        self.check_mount()
        path = self.root / relative
        require(not path.is_symlink() and not path.parent.is_symlink(), 'archive symlink forbidden')
        created_directory = not path.parent.exists()
        path.parent.mkdir(mode=0o700, exist_ok=True)
        if created_directory:
            root_fd = os.open(self.root, os.O_DIRECTORY)
            try:
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
        if path.exists() and not replace:
            require(path.read_bytes() == data, 'immutable archive record conflict')
            return
        fd, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            self.check_mount()
            os.replace(temporary, path)
            with open(path, 'rb') as stored:
                require(stored.read() == data, 'archive readback mismatch')
            directory = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            self.check_mount()
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def records(self):
        self.check_mount()
        directory = self.root / 'runs'
        if not directory.exists():
            return []
        require(not directory.is_symlink(), 'archive directory symlink forbidden')
        records = []
        for path in directory.glob('*.json'):
            require(len(records) < 100000, 'archive record count exceeds bound')
            require(not path.is_symlink(), 'archive symlink forbidden')
            record = parse_json(path.read_bytes())
            require(record.get('record_name') == path.name and re.fullmatch(r'[0-9]+-[0-9]+-[a-f0-9]{64}\.json', path.name), 'archive record identity mismatch')
            require(type(record.get('run_id')) is int and type(record.get('run_attempt')) is int and isinstance(record.get('manifest_sha256'), str) and HEX.fullmatch(record['manifest_sha256']), 'archive record invalid')
            require(isinstance(record.get('blobs'), list) and all(isinstance(sha, str) and HEX.fullmatch(sha) for sha in record['blobs']), 'archive blob reference invalid')
            require(record.get('artifact_id') is None or (type(record['artifact_id']) is int and record['artifact_id'] > 0), 'archive artifact identity invalid')
            records.append(record)
        return records

    def save(self, m, blobs, run, artifact, crypto_config, source_trusted=True, extra_refs=(), ci_jobs=None, collector_kind=None):
        manifest_hash = digest(canonical(m))
        record_name = f"{run['id']}-{run['run_attempt']}-{manifest_hash}.json"
        with self.lock():
            for sha, payload in blobs.items():
                path = self.root / 'blobs' / (sha + '.age')
                if path.exists():
                    require(not path.is_symlink() and digest(age_decrypt(path.read_bytes(), crypto_config['identity_file'])) == sha, 'stored blob integrity failure')
                else:
                    encrypted = age_encrypt(payload, crypto_config['recipient_file'])
                    require(digest(age_decrypt(encrypted, crypto_config['identity_file'])) == sha, 'archive recipient/identity mismatch')
                    self.write('blobs/' + sha + '.age', encrypted)
            all_refs = set(blobs) | set(extra_refs)
            require(len(all_refs) <= 4096 and all(isinstance(sha, str) and HEX.fullmatch(sha) for sha in all_refs), 'invalid archive reference closure')
            for sha in set(extra_refs):
                payload_path = self.root / 'blobs' / (sha + '.age')
                require(not payload_path.is_symlink() and payload_path.is_file() and digest(age_decrypt(payload_path.read_bytes(), crypto_config['identity_file'])) == sha, 'referenced archive payload unavailable')
            path = self.root / 'manifests' / (manifest_hash + '.age')
            if path.exists():
                require(digest(age_decrypt(path.read_bytes(), crypto_config['identity_file'])) == manifest_hash, 'stored manifest integrity failure')
            else:
                encrypted = age_encrypt(canonical(m), crypto_config['recipient_file'])
                require(digest(age_decrypt(encrypted, crypto_config['identity_file'])) == manifest_hash, 'archive recipient/identity mismatch')
                self.write('manifests/' + manifest_hash + '.age', encrypted)
            existing = next((x for x in self.records() if x['record_name'] == record_name), None)
            if existing:
                require(set(existing['blobs']) == all_refs, 'archive reference closure conflict')
                return existing
            completed = timestamp(run['updated_at']) if run.get('status') == 'completed' else None
            initial_deadline = (completed or now()) + dt.timedelta(days=180)
            record = {'record_name': record_name, 'collector_kind': collector_kind, 'job_log_id': m['details'].get('job_id') if collector_kind == 'job-logs' else None, 'ci_jobs': ci_jobs or {}, 'source_trusted': source_trusted, 'workflow': run['path'], 'repository': m['repository'], 'run_id': m['run_id'], 'run_attempt': m['run_attempt'], 'revision': m['revision'], 'manifest_sha256': manifest_hash, 'complete': m['complete'], 'blobs': sorted(all_refs), 'archived_at': iso(now()), 'completed_at': iso(completed) if completed else None, 'conclusion': run.get('conclusion') if completed else None, 'retain_until': iso(initial_deadline), 'artifact_id': artifact['id'], 'artifact_name': artifact.get('name'), 'artifact_digest': artifact['digest'], 'acknowledged': False, 'deleted': False}
            record['storage_digests'] = {'manifest': digest(path.read_bytes()), 'blobs': {sha: digest((self.root / 'blobs' / (sha + '.age')).read_bytes()) for sha in all_refs}}
            self.write('runs/' + record_name, canonical(record))
            return record

    def update(self, record):
        # Callers hold archive.lock; never roll back another service's durable state.
        path = self.root / 'runs' / record['record_name']
        current = parse_json(path.read_bytes())
        for field in ('acknowledged', 'deleted'):
            record[field] = bool(record[field] or current[field])
        if current.get('receipt'):
            record['receipt'] = current['receipt']
        record['retain_until'] = iso(max(timestamp(current['retain_until']), timestamp(record['retain_until'])))
        if current.get('completed_at') and not record.get('completed_at'):
            record['completed_at'] = current['completed_at']
            record['conclusion'] = current.get('conclusion')
        self.write('runs/' + record['record_name'], canonical(record), replace=True)


def receipt_payload(record):
    return {'schema': 1, 'status': 'archived', 'repository': record['repository'], 'run_id': record['run_id'], 'run_attempt': record['run_attempt'], 'revision': record['revision'], 'manifest_sha256': record['manifest_sha256'], 'complete': record['complete'], 'archived_at': record['archived_at'], 'storage_sha256': digest(canonical(record['storage_digests'])), 'ci_jobs_sha256': digest(canonical(record.get('ci_jobs', {}))), 'archive_kind': record.get('collector_kind'), 'source_artifact_sha256': digest(canonical({'id': record.get('artifact_id'), 'name': record.get('artifact_name'), 'digest': record.get('artifact_digest')})), 'source_trusted': record.get('source_trusted')}


def receipt_url(receipt):
    payload = receipt['payload']
    encoded = base64.urlsafe_b64encode(canonical(receipt)).decode().rstrip('=')
    return f"https://github.com/{payload['repository']}/actions/runs/{payload['run_id']}#ssdf-receipt={encoded}"


def receipt_from_url(url, repository, run_id):
    prefix = f'https://github.com/{repository}/actions/runs/{run_id}#ssdf-receipt='
    require(isinstance(url, str) and url.startswith(prefix) and len(url) <= 2048, 'invalid receipt URL')
    encoded = url[len(prefix):]
    require(re.fullmatch(r'[A-Za-z0-9_-]+', encoded), 'invalid receipt encoding')
    try:
        return parse_json(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
    except ValueError as exc:
        raise EvidenceError('invalid receipt encoding') from exc


def publish_receipt(api, archive, record, config, public=True):
    payload = receipt_payload(record)
    receipt = {'payload': payload, 'signature': sign(canonical(payload), config['signing_key_file'])}
    body = {'state': 'success', 'context': f"ssdf-archive/{record['run_id']}/{record['run_attempt']}", 'description': 'Archived sha256:' + record['manifest_sha256'], 'target_url': receipt_url(receipt)}
    if public:
        api.request(api.prefix + '/statuses/' + record['revision'], 'POST', body)
    with archive.lock():
        record['acknowledged'] = True
        record['receipt'] = receipt
        archive.update(record)


def validate_receipt(receipt, expected, public_key):
    require(isinstance(receipt, dict) and set(receipt) == {'payload', 'signature'}, 'invalid receipt')
    payload = receipt['payload']
    require(isinstance(payload, dict), 'invalid receipt payload')
    verify_signature(canonical(payload), receipt['signature'], public_key)
    for key, value in expected.items():
        require(payload.get(key) == value, 'receipt binding mismatch')
    require(payload.get('schema') == 1 and payload.get('status') == 'archived' and payload.get('complete') is True and payload.get('source_trusted') is True, 'receipt is incomplete or untrusted')
    archived = timestamp(payload.get('archived_at'))
    require(archived <= now() + dt.timedelta(minutes=5), 'receipt timestamp is in future')
    return payload


def encrypted_artifact(api, artifact, run):
    require(not artifact.get('expired') and artifact.get('size_in_bytes', MAX_TOTAL + 1) <= MAX_WIRE, 'artifact unavailable or exceeds bound')
    ref = artifact.get('workflow_run', {})
    require(ref.get('id') == run['id'] and ref.get('head_sha') == run['head_sha'], 'artifact run mismatch')
    raw = api.request(api.prefix + '/actions/artifacts/' + str(artifact['id']) + '/zip', raw=True)
    require(artifact.get('digest') == 'sha256:' + digest(raw), 'artifact archive digest mismatch')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            require(archive.namelist() == ['evidence.age'], 'unexpected artifact contents')
            item = archive.getinfo('evidence.age')
            require(item.file_size <= MAX_WIRE and stat.S_IFMT(item.external_attr >> 16) != stat.S_IFLNK, 'invalid encrypted artifact')
            return archive.read('evidence.age')
    except zipfile.BadZipFile as exc:
        raise EvidenceError('invalid artifact ZIP') from exc


def reconcile_record(api, archive, record, config, releases, refresh=True):
    if not refresh and record.get('completed_at'):
        deadline = timestamp(record['retain_until'])
        for published in releases.get(record['revision'], []):
            deadline = max(deadline, year_after(published))
        if deadline != timestamp(record['retain_until']):
            with archive.lock():
                record['retain_until'] = iso(deadline)
                archive.update(record)
        return None
    key = (record['run_id'], record['run_attempt'])
    cache = getattr(api, 'run_cache', {})
    run = cache.get(key)
    if run is None:
        run = api.get('/actions/runs/' + str(record['run_id']) + '/attempts/' + str(record['run_attempt']))
        cache[key] = run
        api.run_cache = cache
    require(run.get('repository', {}).get('full_name') == config['repository'] and run.get('id') == record['run_id'] and run.get('run_attempt') == record['run_attempt'], 'reconciled run identity mismatch')
    if record.get('source_trusted', True):
        trusted_run(run, config)
    require(run['head_sha'] == record['revision'], 'reconciled revision mismatch')
    if run['status'] == 'completed':
        # GitHub updated_at is the last run change and conservatively extends completion retention.
        completed = timestamp(run['updated_at'])
        record['completed_at'] = iso(completed)
        record['conclusion'] = run.get('conclusion')
        deadline = completed + dt.timedelta(days=180)
        for published in releases.get(record['revision'], []):
            deadline = max(deadline, year_after(published))
        record['retain_until'] = iso(max(timestamp(record['retain_until']), deadline))
    else:
        record['retain_until'] = iso(max(timestamp(record['retain_until']), now() + dt.timedelta(days=180)))
    with archive.lock():
        archive.update(record)
    return run


class PublicationDeadlines(dict):
    """Verified publication deadlines plus a repository-wide deletion hold."""
    def __init__(self, values, unresolved):
        super().__init__(values)
        self.unresolved = tuple(unresolved)


def publication_key(release_id, published_at):
    require(type(release_id) is int and release_id > 0, 'invalid publication identity')
    timestamp(published_at)
    return str(release_id) + ':' + published_at


def audited_publications(config):
    rows = config.get('audited_release_publications', [])
    require(isinstance(rows, list) and len(rows) <= 10000, 'invalid audited publication inventory')
    audited = {}
    for row in rows:
        required = {'release_id', 'published_at', 'revision', 'provenance', 'audit_reference', 'audited_at'}
        require(isinstance(row, dict) and required <= set(row) <= required | {'run_id', 'run_attempt'} and ('run_id' in row) == ('run_attempt' in row), 'invalid audited publication record')
        if 'run_id' in row:
            require(type(row['run_id']) is int and row['run_id'] > 0 and type(row['run_attempt']) is int and row['run_attempt'] > 0, 'invalid audited publication run binding')
        key = publication_key(row['release_id'], row['published_at'])
        require(key not in audited and isinstance(row['revision'], str) and SHA.fullmatch(row['revision']), 'conflicting or invalid audited publication revision')
        require(row['provenance'] == 'operator-audit', 'unknown publication provenance')
        reference = row['audit_reference']
        require(isinstance(reference, str) and 0 < len(reference) <= 200 and all(ord(x) >= 32 for x in reference), 'missing publication audit reference')
        audited_at = timestamp(row['audited_at'])
        require(timestamp(row['published_at']) <= audited_at <= now() + dt.timedelta(minutes=5), 'invalid publication audit time')
        audited[key] = row
    return audited


def read_publication_catalog(cache_path, repository):
    cached = parse_json(cache_path.read_bytes()) if cache_path and cache_path.exists() else {}
    catalog = {}
    require(isinstance(cached, dict), 'invalid publication catalog')
    if cached.get('schema') == 2:
        require(set(cached) == {'schema', 'repository', 'publications'} and cached['repository'] == repository, 'invalid publication catalog provenance')
        require(isinstance(cached['publications'], dict), 'invalid publication catalog')
        catalog = cached['publications']
    else:
        # Legacy mappings were first observed through mutable tags and are not historical proof.
        require(isinstance(cached, dict), 'invalid legacy publication catalog')
        for key, item in cached.items():
            require(isinstance(item, dict) and set(item) == {'revision', 'published_at'} and isinstance(item['revision'], str) and SHA.fullmatch(item['revision']), 'invalid legacy publication binding')
            prefix, separator, published_at = key.partition(':')
            require(separator and prefix.isdecimal() and item['published_at'] == published_at, 'invalid legacy publication identity')
            release_id = int(prefix)
            require(publication_key(release_id, published_at) == key, 'invalid legacy publication key')
            catalog[key] = {'release_id': release_id, 'published_at': published_at, 'tag_name': None, 'legacy_tag_revision': item['revision']}
    for key, item in catalog.items():
        require(isinstance(item, dict) and set(item) <= {'release_id', 'published_at', 'tag_name', 'legacy_tag_revision'} and {'release_id', 'published_at', 'tag_name'} <= set(item), 'invalid publication catalog record')
        require(publication_key(item['release_id'], item['published_at']) == key, 'publication catalog identity mismatch')
        require(item['tag_name'] is None or isinstance(item['tag_name'], str) and len(item['tag_name']) <= 200, 'invalid observed publication tag')
        require('legacy_tag_revision' not in item or isinstance(item['legacy_tag_revision'], str) and SHA.fullmatch(item['legacy_tag_revision']), 'invalid legacy tag observation')
    return catalog


def verified_publication_proofs(archive, config):
    proofs = {}
    directory = archive.root / 'publications'
    if not directory.exists():
        return proofs
    require(not directory.is_symlink(), 'publication proof directory symlink forbidden')
    for path in directory.glob('*.json'):
        require(len(proofs) < 10000 and not path.is_symlink() and path.stat().st_size <= 16384, 'publication proof inventory exceeds bound')
        envelope = parse_json(path.read_bytes())
        require(isinstance(envelope, dict) and set(envelope) == {'payload', 'signature'}, 'invalid publication proof')
        payload = envelope['payload']
        required = {'schema', 'kind', 'repository', 'workflow', 'run_id', 'run_attempt', 'revision', 'release_id', 'published_at', 'tag', 'archive_manifest_sha256', 'publication_manifest_sha256', 'source_artifact_sha256'}
        require(isinstance(payload, dict) and set(payload) == required and payload['schema'] == 1 and payload['kind'] == 'publication' and payload['repository'] == config['repository'] and payload['workflow'] in PUBLICATION_WORKFLOWS, 'invalid publication proof identity')
        require(type(payload['run_id']) is int and payload['run_id'] > 0 and type(payload['run_attempt']) is int and payload['run_attempt'] > 0 and SHA.fullmatch(payload['revision']) and all(HEX.fullmatch(payload[x]) for x in ('archive_manifest_sha256', 'publication_manifest_sha256', 'source_artifact_sha256')), 'invalid publication proof source')
        key = publication_key(payload['release_id'], payload['published_at'])
        require(path.name == str(payload['release_id']) + '-' + digest(payload['published_at'].encode()) + '.json' and key not in proofs, 'conflicting publication proof identity')
        verify_signature(canonical(payload), envelope['signature'], config['signing_public_key_file'])
        proofs[key] = payload
    return proofs


def publication_run_ledger(api, archive, config):
    path = archive.root / 'state/publication-runs.json'
    ledger = parse_json(path.read_bytes()) if path.exists() else {}
    require(isinstance(ledger, dict) and len(ledger) <= 100000, 'invalid publication run ledger')
    grouped = {}
    for record in archive.records():
        if record.get('source_trusted') and record.get('completed_at'):
            grouped.setdefault((record['run_id'], record['run_attempt']), record)
    for (run_id, attempt), record in grouped.items():
        key = str(run_id) + ':' + str(attempt)
        if key in ledger:
            prior = ledger[key]
            require(isinstance(prior, dict) and prior.get('run_id') == run_id and prior.get('run_attempt') == attempt and prior.get('revision') == record['revision'], 'publication run ledger identity mismatch')
            continue
        workflow = record.get('workflow')
        if workflow is None:
            # Old indexes lack workflow identity; resolve once through authenticated immutable-attempt metadata.
            cache = getattr(api, 'run_cache', {})
            run = cache.get((run_id, attempt)) if isinstance(cache, dict) else None
            if run is None:
                run = api.get(f'/actions/runs/{run_id}/attempts/{attempt}')
            require(run.get('id') == run_id and run.get('run_attempt') == attempt and run.get('head_sha') == record['revision'] and run.get('repository', {}).get('full_name') == config['repository'], 'historical publication run source unavailable')
            workflow = run['path']
        if workflow not in PUBLICATION_WORKFLOWS:
            continue
        possible = workflow == '.github/workflows/release.yml' and record.get('conclusion') == 'success'
        if not possible:
            jobs = attempt_jobs(api, {'id': run_id, 'run_attempt': attempt})
            possible = any(step.get('name') == PUBLICATION_STEP and step.get('conclusion') != 'skipped' and (step.get('started_at') or step.get('conclusion') == 'success') for job in jobs for step in job.get('steps', []))
        ledger[key] = {'run_id': run_id, 'run_attempt': attempt, 'revision': record['revision'], 'workflow': workflow, 'possible_publication': bool(possible)}
    archive.write('state/publication-runs.json', canonical(ledger), replace=True)
    return ledger


def unresolved_publication_runs(ledger, proofs, audited):
    bindings = list(proofs.values()) + list(audited.values())
    unresolved = []
    for key, run in ledger.items():
        require(key == str(run.get('run_id')) + ':' + str(run.get('run_attempt')) and type(run.get('possible_publication')) is bool and isinstance(run.get('revision'), str) and SHA.fullmatch(run['revision']), 'invalid durable publication run identity')
        if run['possible_publication'] and not any(item.get('run_id') == run['run_id'] and item.get('run_attempt') == run['run_attempt'] and item['revision'] == run['revision'] for item in bindings):
            unresolved.append({'run_id': run['run_id'], 'run_attempt': run['run_attempt'], 'revision': run['revision'], 'workflow': run['workflow']})
    return unresolved


def release_deadlines_locked(api, archive=None, config=None):
    # Current tag targets and target_commitish are mutable: neither proves publication identity.
    config = config if config is not None else archive.config if archive else {}
    cache_path = archive.root / 'state/releases.json' if archive else None
    catalog = read_publication_catalog(cache_path, config.get('repository') or api.repository)
    for release in api.pages('/releases', None):
        if release.get('draft') or not release.get('published_at'):
            continue
        key = publication_key(release['id'], release['published_at'])
        tag = release.get('tag_name')
        require(isinstance(tag, str) and 0 < len(tag) <= 200, 'invalid observed publication metadata')
        item = catalog.setdefault(key, {'release_id': release['id'], 'published_at': release['published_at'], 'tag_name': tag})
        item['tag_name'] = tag  # Display metadata only; never used to derive a revision.
    require(len(catalog) <= 10000, 'publication catalog exceeds bound')
    audited = audited_publications(config)
    proofs = verified_publication_proofs(archive, config) if archive else {}
    ledger = publication_run_ledger(api, archive, config) if archive else {}
    for key, proof in proofs.items():
        catalog.setdefault(key, {'release_id': proof['release_id'], 'published_at': proof['published_at'], 'tag_name': proof['tag']})
        if key in audited:
            require(audited[key]['revision'] == proof['revision'] and ('run_id' not in audited[key] or (audited[key]['run_id'], audited[key]['run_attempt']) == (proof['run_id'], proof['run_attempt'])), 'publication audit conflicts with signed workflow proof')
    # Explicit operator audit can also preserve historical publications already removed upstream.
    for key, row in audited.items():
        catalog.setdefault(key, {'release_id': row['release_id'], 'published_at': row['published_at'], 'tag_name': None})
    by_revision, unresolved, resolved = {}, [], []
    for key, item in sorted(catalog.items()):
        row = proofs.get(key) or audited.get(key)
        if row is None:
            unresolved.append({'release_id': item['release_id'], 'published_at': item['published_at']})
            continue
        by_revision.setdefault(row['revision'], []).append(timestamp(row['published_at']))
        resolved.append({'release_id': row['release_id'], 'published_at': row['published_at'], 'revision': row['revision'], 'provenance': 'trusted-run-attestation' if key in proofs else 'operator-audit'})
    unresolved.extend(unresolved_publication_runs(ledger, proofs, audited))
    if archive:
        archive.write('state/releases.json', canonical({'schema': 2, 'repository': config['repository'], 'publications': catalog}), replace=True)
        archive.write('state/publication-hold.json', canonical({'schema': 1, 'scope': 'repository-deletion', 'status': 'hold' if unresolved else 'resolved', 'checked_at': iso(now()), 'unresolved': unresolved, 'audited': resolved}), replace=True)
    return PublicationDeadlines(by_revision, unresolved)


def release_deadlines(api, archive=None, config=None):
    if archive:
        # Serialize reads as well as writes: a stale snapshot must never erase a newly observed release.
        with archive.lock():
            return release_deadlines_locked(api, archive, config)
    return release_deadlines_locked(api, None, config)


def require_durable_publication_identity_resolved(archive, config, api):
    # Caller holds archive.lock, including all subsequent DELETE/unlink operations.
    path = archive.root / 'state/releases.json'
    require(path.is_file() and not path.is_symlink(), 'durable publication inventory unavailable; deletion held')
    catalog = read_publication_catalog(path, config['repository'])
    audited = audited_publications(config)
    proofs = verified_publication_proofs(archive, config)
    require(all(key in audited or key in proofs for key in catalog), 'new unresolved publication identity detected; deletion held')
    run_path = archive.root / 'state/publication-runs.json'
    require(run_path.is_file() and not run_path.is_symlink(), 'durable publication run inventory unavailable; deletion held')
    ledger = publication_run_ledger(api, archive, config)
    require(not unresolved_publication_runs(ledger, proofs, audited), 'new unresolved publication run detected; deletion held')
    current = {}
    for key, proof in proofs.items():
        if key in audited:
            row = audited[key]
            require(row['revision'] == proof['revision'] and ('run_id' not in row or (row['run_id'], row['run_attempt']) == (proof['run_id'], proof['run_attempt'])), 'publication audit conflicts with signed workflow proof')
    for row in list(proofs.values()) + list(audited.values()):
        current.setdefault(row['revision'], []).append(timestamp(row['published_at']))
    return current


def require_publication_identity_resolved(deadlines):
    require(not getattr(deadlines, 'unresolved', ()), 'published release identity is unresolved; deletion remains on hold')


def bind_source_metadata(m, run, config):
    require((m['repository'], m['workflow'], m['run_id'], m['run_attempt'], m['revision']) == (config['repository'], run['path'], run['id'], run['run_attempt'], run['head_sha']), 'job chunk source identity mismatch')


def validate_chunk(m, job, index):
    require(m['complete'] is False, 'job chunks cannot authorize release')
    details = m['details']
    require(details.get('kind') == 'job-chunk' and details.get('job') == job and type(details.get('chunk_index')) is int and details['chunk_index'] == index, 'job chunk identity mismatch')
    require(sum(item['size'] for item in m['files']) <= 8 << 20, 'job chunk payload exceeds bound')
    count = details.get('chunk_count')
    require(type(count) is int and 1 <= count <= MAX_JOB_CHUNKS and 0 <= index < count and details.get('checkout_revision') == m['revision'] and isinstance(details.get('github_sha'), str) and SHA.fullmatch(details['github_sha']), 'invalid job chunk coverage/source metadata')
    originals = details.get('original_files')
    require(isinstance(originals, list) and len(originals) <= 4096, 'invalid original report inventory')
    mapped = set()
    for original in originals:
        require(isinstance(original, dict) and set(original) == {'name', 'sha256', 'size', 'parts', 'original_sha256', 'redacted'}, 'invalid original report entry')
        safe_name(original['name'])
        require(isinstance(original['sha256'], str) and HEX.fullmatch(original['sha256']) and type(original['size']) is int and 0 <= original['size'] <= MAX_JOB_WIRE, 'invalid original report identity')
        parts = original['parts']
        require(isinstance(parts, list) and 1 <= len(parts) <= MAX_JOB_CHUNKS, 'invalid original report parts')
        offset = 0
        for part in parts:
            require(isinstance(part, dict) and set(part) == {'name', 'offset', 'size', 'sha256', 'chunk_index'}, 'invalid report part')
            require(isinstance(part['sha256'], str) and HEX.fullmatch(part['sha256']) and part['name'] == 'parts/' + part['sha256'], 'report part identity mismatch')
            require(type(part['offset']) is int and part['offset'] == offset and type(part['size']) is int and 0 <= part['size'] <= 8 << 20, 'report part bounds mismatch')
            offset += part['size']
            require(type(part['chunk_index']) is int and 0 <= part['chunk_index'] < count, 'invalid report part chunk binding')
            if part['chunk_index'] == index:
                mapped.add((part['name'], part['size'], part['sha256']))
        require(offset == original['size'], 'original report part coverage mismatch')
    require(sum(item['size'] for item in originals) <= MAX_JOB_WIRE and sum(len(item['parts']) for item in originals) <= 4096, 'original report reconstruction exceeds bound')
    require(all((item['name'], item['size'], item['sha256']) in mapped for item in m['files']), 'chunk contains undeclared report part')
    require(bool(m['files']) or not originals, 'empty outcome chunk cannot declare missing payloads')
    return originals


def archive_job_zip(config, api, archive, run, artifact, job, zip_path, source_trusted):
    require(Path(zip_path).stat().st_size <= MAX_JOB_WIRE, 'job artifact archive exceeds bound')
    with Path(zip_path).open('rb') as source:
        require('sha256:' + hashlib.file_digest(source, 'sha256').hexdigest() == artifact['digest'], 'job artifact spool readback mismatch')
    child_blobs, child_files, refs, originals, chunk_inventory = {}, [], set(), {}, []
    chunk_count, statuses = None, set()
    with zipfile.ZipFile(zip_path) as outer:
        items = outer.infolist()
        require(1 <= len(items) <= MAX_JOB_CHUNKS and len({x.filename for x in items}) == len(items), 'invalid encrypted job chunk inventory')
        for item in sorted(items, key=lambda x: x.filename):
            match = re.fullmatch(r'chunk-([0-9]{4})\.age', item.filename)
            require(match and item.file_size <= MAX_FILE and stat.S_IFMT(item.external_attr >> 16) != stat.S_IFLNK, 'unsafe encrypted job chunk')
            index = int(match.group(1))
            require(index < MAX_JOB_CHUNKS, 'job chunk index exceeds bound')
            ciphertext = outer.read(item)
            m, blobs = unpack(age_decrypt(ciphertext, config['identity_file']))
            bind_source_metadata(m, run, config)
            original_entries = validate_chunk(m, job, index)
            require(m['details'].get('status') in ('success', 'failure', 'cancelled', 'skipped'), 'invalid job outcome')
            statuses.add(m['details']['status'])
            require(chunk_count is None or chunk_count == m['details']['chunk_count'], 'conflicting declared chunk counts')
            chunk_count = m['details']['chunk_count']
            for original in original_entries:
                prior = originals.get(original['name'])
                require(prior is None or prior == original, 'conflicting original report inventories')
                originals[original['name']] = original
            require(sum(x['size'] for x in originals.values()) <= MAX_JOB_WIRE and sum(len(x['parts']) for x in originals.values()) <= 4096, 'aggregate report reconstruction exceeds bound')
            archive.save(m, blobs, run, {'id': None, 'digest': None}, config, source_trusted=source_trusted)
            raw = canonical(m)
            manifest_hash = digest(raw)
            child_blobs[manifest_hash] = raw
            child_files.append({'name': 'chunks/' + item.filename + '.manifest.json', 'sha256': manifest_hash, 'size': len(raw)})
            refs.update(blobs)
            chunk_inventory.append({'name': item.filename, 'sha256': digest(ciphertext), 'size': len(ciphertext), 'manifest_sha256': manifest_hash})
    missing = []
    for original in originals.values():
        if any(part['sha256'] not in refs for part in original['parts']):
            missing.append(original['name'])
            continue
        h = hashlib.sha256()
        for part in original['parts']:
            data = age_decrypt((archive.root / 'blobs' / (part['sha256'] + '.age')).read_bytes(), config['identity_file'])
            require(len(data) == part['size'] and digest(data) == part['sha256'], 'archived report part integrity failure')
            h.update(data)
        require(h.hexdigest() == original['sha256'], 'reconstructed original report digest mismatch')
    indices = {int(x['name'][6:10]) for x in chunk_inventory}
    missing_indices = sorted(set(range(chunk_count)) - indices)
    summary = {'schema': 1, 'repository': config['repository'], 'workflow': run['path'], 'run_id': run['id'], 'run_attempt': run['run_attempt'], 'revision': run['head_sha'], 'candidate_id': f"job-{job}-{run['id']}-{run['run_attempt']}", 'complete': False, 'files': child_files, 'details': {'kind': 'job-archive', 'job': job, 'artifact_id': artifact['id'], 'artifact_digest': artifact['digest'], 'chunks': chunk_inventory, 'original_files': sorted(originals.values(), key=lambda x: x['name']), 'missing_original_files': sorted(missing), 'missing_chunk_indices': missing_indices, 'job_status': next(iter(statuses)) if len(statuses) == 1 else 'inconsistent', 'source_trusted': source_trusted, 'dast': 'deferred'}}
    manifest_valid(summary)
    record = archive.save(summary, child_blobs, run, artifact, config, source_trusted=source_trusted, extra_refs=refs)
    if not record['acknowledged']:
        # Private signed receipt covers all original parts and exact chunk/ciphertext inventory.
        publish_receipt(api, archive, record, config, public=False)
    return record


def collect_job_artifacts(config, api, archive, run, source_trusted):
    artifacts = api.pages('/actions/runs/' + str(run['id']) + '/artifacts', 'artifacts')
    allowlisted = {f"ssdf-job-v1-{run['id']}-{run['run_attempt']}-{job}": job for job in config.get('allowed_job_chunks', [])}
    selected = [x for x in artifacts if x['name'] in allowlisted]
    require(len({x['name'] for x in selected}) == len(selected), 'ambiguous job artifacts')
    for artifact in selected:
        ref = artifact.get('workflow_run', {})
        require(ref.get('id') == run['id'] and ref.get('head_sha') == run['head_sha'], 'job artifact source mismatch')
        already = next((x for x in archive.records() if x.get('artifact_id') == artifact['id'] and x.get('artifact_digest') == artifact['digest'] and x.get('acknowledged')), None)
        if already:
            continue
        spool = Path(config['transport_spool'])
        require(spool.is_absolute() and spool.is_dir() and not spool.is_symlink() and spool.stat().st_mode & 0o077 == 0, 'private encrypted transport spool unavailable')
        require(shutil.disk_usage(spool).free > MAX_JOB_WIRE + (64 << 20), 'encrypted transport spool lacks headroom')
        with tempfile.TemporaryDirectory(prefix='job-', dir=spool) as directory:
            target = Path(directory) / 'encrypted.zip'
            download_encrypted_job(api, artifact, target)
            archive_job_zip(config, api, archive, run, artifact, allowlisted[artifact['name']], target, source_trusted)


def sanitize_job_log(data):
    require(len(data) <= MAX_TOTAL, 'job log exceeds raw collection bound')
    text = data.decode('utf-8', errors='replace')
    text = re.sub(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----', '[REDACTED PRIVATE KEY]', text)
    text = re.sub(r'(?i)(bearer\s+)[A-Za-z0-9._~+/-]{8,}', r'\1[REDACTED]', text)
    text = re.sub(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b', '[REDACTED JWT]', text)
    text = re.sub(r'\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16})\b', '[REDACTED PROVIDER CREDENTIAL]', text)
    text = re.sub(r'(?i)([?&](?:access_token|token|api_key|key|sig|signature|password)=)[^&\s"<>]+', r'\1[REDACTED]', text)
    # Both key=value diagnostic lines and quoted JSON properties are sanitized.
    pattern = r"""(?i)(\b(?:password|passwd|secret|token|access_token|refresh_token|totp_secret|authorization|cookie|set-cookie|client_secret|api_key|registration_token)["']?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;]+)"""
    text = re.sub(pattern, r'\1[REDACTED]', text)
    sanitized = text.encode()
    require(len(sanitized) <= MAX_TOTAL, 'sanitized job log exceeds bound')
    return sanitized


def attempt_jobs(api, run):
    key = (run['id'], run['run_attempt'])
    cache = getattr(api, 'job_cache', {})
    if not isinstance(cache, dict):
        cache = {}
    if key not in cache:
        cache[key] = api.pages(f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", 'jobs')
        api.job_cache = cache
    return cache[key]


def logical_job(name):
    tail = name.split(' / ')[-1]
    for logical, display in [('sonar', 'sonarcloud'), ('secrets', 'secret-scan'), ('vulnerability', 'vulnerability-scan')]:
        if tail == display:
            return logical
    match = re.fullmatch(r'server-tests \(([0-5])\)', tail)
    return 'server-' + match.group(1) if match else tail


def collect_job_logs(config, api, archive, run, source_trusted):
    records = archive.records()
    for job in attempt_jobs(api, run):
        if job.get('status') != 'completed':
            continue
        require(type(job.get('id')) is int and job['id'] > 0 and job.get('run_id') == run['id'] and job.get('run_attempt', run['run_attempt']) == run['run_attempt'] and job.get('head_sha') == run['head_sha'], 'terminal job log source identity mismatch')
        found = [x for x in records if x.get('collector_kind') == 'job-logs' and x.get('job_log_id') == job['id'] and x.get('acknowledged')]
        require(len(found) <= 1, 'ambiguous terminal job log archives')
        if found:
            continue
        try:
            raw = api.request(api.prefix + '/actions/jobs/' + str(job['id']) + '/logs', raw=True)
            require(raw and len(raw) <= MAX_TOTAL, 'terminal job log unavailable or exceeds bound')
            sanitized = sanitize_job_log(raw)
        except APIBudgetExceeded:
            raise
        except EvidenceError:
            missing = {'schema': 1, 'repository': config['repository'], 'workflow': run['path'], 'run_id': run['id'], 'run_attempt': run['run_attempt'], 'revision': run['head_sha'], 'candidate_id': f"job-log-{job['id']}", 'complete': False, 'files': [], 'details': {'kind': 'job-logs-missing', 'job': logical_job(job['name']), 'job_id': job['id'], 'conclusion': job.get('conclusion'), 'missing': ['terminal-log-provider-unavailable-or-bound-exceeded'], 'source_trusted': source_trusted}}
            archive.save(missing, {}, run, {'id': None, 'digest': None}, config, source_trusted=source_trusted, collector_kind='job-logs-missing')
            print('terminal job log unavailable for job ' + str(job['id']), file=sys.stderr)
            continue
        blobs, files = {}, []
        for offset in range(0, max(1, len(sanitized)), 8 << 20):
            part = sanitized[offset:offset + (8 << 20)]
            sha = digest(part)
            blobs[sha] = part
            files.append({'name': 'logs/part-' + str(offset // (8 << 20)).zfill(4), 'sha256': sha, 'size': len(part)})
        m = {'schema': 1, 'repository': config['repository'], 'workflow': run['path'], 'run_id': run['id'], 'run_attempt': run['run_attempt'], 'revision': run['head_sha'], 'candidate_id': f"job-log-{job['id']}", 'complete': False, 'files': files, 'details': {'kind': 'job-logs', 'job': logical_job(job['name']), 'job_id': job['id'], 'conclusion': job.get('conclusion'), 'raw_sha256': digest(raw), 'raw_size': len(raw), 'sanitized_sha256': digest(sanitized), 'sanitized_size': len(sanitized), 'redacted': raw != sanitized, 'credential_redaction_applied': True, 'source_trusted': source_trusted}}
        manifest_valid(m)
        record = archive.save(m, blobs, run, {'id': None, 'digest': None}, config, source_trusted=source_trusted, collector_kind='job-logs')
        if not record['acknowledged']:
            publish_receipt(api, archive, record, config, public=False)
        records.append(record)


def complete_ci_closure(config, api, archive, run, manifest):
    if not manifest['complete']:
        return {}, {}, set()
    required = REQUIRED_RELEASE_JOBS if run['path'] in ('.github/workflows/release.yml', '.github/workflows/staging.yml') else []
    configured = config.get('required_complete_jobs', {}).get(run['path'], required)
    require(isinstance(configured, list) and set(required) <= set(configured) and len(set(configured)) == len(configured), 'required CI archive policy cannot be weakened')
    declared = manifest['details'].get('expected_ci_jobs', [])
    require(isinstance(declared, list) and len(set(declared)) == len(declared) and set(declared) == set(configured), 'complete manifest CI job inventory mismatch')
    if not configured:
        return {}, {}, set()
    jobs = attempt_jobs(api, run)
    records = archive.records()
    extra_blobs, references, identities = {}, set(), {}
    for job in configured:
        api_name = {'sonar': 'sonarcloud', 'secrets': 'secret-scan', 'vulnerability': 'vulnerability-scan'}.get(job, job)
        if job.startswith('server-'):
            api_name = 'server-tests (' + job[7:] + ')'
        matches = [x for x in jobs if x.get('name', '').split(' / ')[-1] == api_name]
        require(len(matches) == 1 and matches[0].get('status') == 'completed' and matches[0].get('conclusion') == 'success', 'required CI job is not independently successful')
        name = f"ssdf-job-v1-{run['id']}-{run['run_attempt']}-{job}"
        found = [x for x in records if x['run_id'] == run['id'] and x['run_attempt'] == run['run_attempt'] and x['revision'] == run['head_sha'] and x.get('artifact_name') == name and x.get('acknowledged') and x.get('source_trusted')]
        require(len(found) == 1, 'required CI job archive acknowledgement unavailable')
        record = found[0]
        verify_signature(canonical(record['receipt']['payload']), record['receipt']['signature'], config['signing_public_key_file'])
        require(record['receipt']['payload'] == receipt_payload(record), 'required CI acknowledgement binding mismatch')
        verify_storage(archive, record)
        raw = age_decrypt((archive.root / 'manifests' / (record['manifest_sha256'] + '.age')).read_bytes(), config['identity_file'])
        require(digest(raw) == record['manifest_sha256'], 'required CI manifest integrity failure')
        details = manifest_valid(parse_json(raw))['details']
        require(details.get('kind') == 'job-archive' and details.get('job') == job and details.get('job_status') == 'success' and details.get('original_files') and not details.get('missing_original_files') and not details.get('missing_chunk_indices'), 'required CI archived reports incomplete')
        log_records = [x for x in records if x.get('collector_kind') == 'job-logs' and x.get('job_log_id') == matches[0]['id'] and x['run_id'] == run['id'] and x['run_attempt'] == run['run_attempt'] and x['revision'] == run['head_sha'] and x.get('acknowledged') and x.get('source_trusted')]
        require(len(log_records) == 1, 'required CI sanitized terminal log archive unavailable')
        log_record = log_records[0]
        verify_signature(canonical(log_record['receipt']['payload']), log_record['receipt']['signature'], config['signing_public_key_file'])
        require(log_record['receipt']['payload'] == receipt_payload(log_record), 'required CI log acknowledgement mismatch')
        verify_storage(archive, log_record)
        log_raw = age_decrypt((archive.root / 'manifests' / (log_record['manifest_sha256'] + '.age')).read_bytes(), config['identity_file'])
        require(digest(log_raw) == log_record['manifest_sha256'], 'required CI log manifest integrity failure')
        log_details = manifest_valid(parse_json(log_raw))['details']
        require(log_details.get('kind') == 'job-logs' and log_details.get('job_id') == matches[0]['id'] and log_details.get('job') == job and log_details.get('conclusion') == 'success' and log_details.get('credential_redaction_applied') is True, 'required CI log evidence mismatch')
        identities[job + ':logs'] = log_record['manifest_sha256']
        extra_blobs[log_record['manifest_sha256']] = log_raw
        references.update(log_record['blobs'])
        identities[job] = record['manifest_sha256']
        extra_blobs[record['manifest_sha256']] = raw
        references.update(record['blobs'])
    return identities, extra_blobs, references


def outcome_manifest(run, config, trusted):
    result = {'schema': 1, 'repository': config['repository'], 'workflow': run['path'], 'run_id': run['id'], 'run_attempt': run['run_attempt'], 'revision': run['head_sha'], 'candidate_id': f"run-{run['id']}-{run['run_attempt']}", 'complete': False, 'files': [], 'details': {'conclusion': run.get('conclusion'), 'missing': ['encrypted-evidence-artifact'] if trusted else ['trusted-source'], 'source_trusted': trusted, 'dast': 'deferred'}}
    if run['path'] == CODEQL_WORKFLOW:
        result['details'].update({'kind': 'platform-outcome', 'platform_diagnostic': True, 'release_authority': False})
    return result


def accept_publication_manifest(config, api, archive, run, artifact, manifest):
    bind_manifest(manifest, run, config)
    verify_trust_anchor(api, run, config)
    require(run['path'] in PUBLICATION_WORKFLOWS and manifest['complete'] is False and not manifest['files'], 'invalid publication attestation manifest')
    require(artifact['name'] == f"ssdf-publication-v1-{run['id']}-{run['run_attempt']}" and type(artifact.get('id')) is int and artifact['id'] > 0 and re.fullmatch(r'sha256:[a-f0-9]{64}', artifact.get('digest', '')) and artifact.get('workflow_run', {}).get('id') == run['id'] and artifact.get('workflow_run', {}).get('head_sha') == run['head_sha'], 'publication artifact source/name mismatch')
    details = manifest['details']
    fields = {'kind', 'release_id', 'published_at', 'tag', 'archive_manifest_sha256'}
    require(fields <= set(details) <= fields | {'candidate_id', 'candidate_manifest_sha256'} and details['kind'] == 'publication', 'invalid publication attestation details')
    key = publication_key(details['release_id'], details['published_at'])
    require(timestamp(details['published_at']) <= now() + dt.timedelta(minutes=5) and isinstance(details['tag'], str) and 0 < len(details['tag']) <= 200 and HEX.fullmatch(details['archive_manifest_sha256']), 'invalid publication attestation metadata')
    found = [x for x in archive.records() if x['manifest_sha256'] == details['archive_manifest_sha256'] and x['run_id'] == run['id'] and x['run_attempt'] == run['run_attempt'] and x['revision'] == run['head_sha'] and x.get('source_trusted') and x.get('complete') and x.get('acknowledged')]
    require(len(found) == 1, 'publication lacks exact complete archived qualification')
    before = found[0]
    verify_signature(canonical(before['receipt']['payload']), before['receipt']['signature'], config['signing_public_key_file'])
    require(before['receipt']['payload'] == receipt_payload(before), 'prepublication archive acknowledgement mismatch')
    verify_storage(archive, before)
    require(timestamp(details['published_at']) + dt.timedelta(minutes=5) >= timestamp(before['archived_at']), 'publication predates its complete archive qualification')
    raw = age_decrypt((archive.root / 'manifests' / (before['manifest_sha256'] + '.age')).read_bytes(), config['identity_file'])
    require(digest(raw) == before['manifest_sha256'], 'prepublication manifest integrity mismatch')
    original = manifest_valid(parse_json(raw))
    bind_manifest(original, run, config)
    require(original['candidate_id'] == manifest['candidate_id'], 'publication candidate identity mismatch')
    if 'candidate_id' in details:
        require(details['candidate_id'] == manifest['candidate_id'], 'publication candidate reference mismatch')
    if 'candidate_manifest_sha256' in details:
        require(HEX.fullmatch(details['candidate_manifest_sha256']) and any(x['name'] == 'candidate.json' and x['sha256'] == details['candidate_manifest_sha256'] for x in original['files']), 'publication candidate inventory reference mismatch')
    record = archive.save(manifest, {before['manifest_sha256']: raw}, run, artifact, config, extra_refs=before['blobs'], collector_kind='publication')
    if not record['acknowledged']:
        publish_receipt(api, archive, record, config, public=False)
    payload = {'schema': 1, 'kind': 'publication', 'repository': config['repository'], 'workflow': run['path'], 'run_id': run['id'], 'run_attempt': run['run_attempt'], 'revision': run['head_sha'], 'release_id': details['release_id'], 'published_at': details['published_at'], 'tag': details['tag'], 'archive_manifest_sha256': before['manifest_sha256'], 'publication_manifest_sha256': record['manifest_sha256'], 'source_artifact_sha256': record['receipt']['payload']['source_artifact_sha256']}
    envelope = {'payload': payload, 'signature': sign(canonical(payload), config['signing_key_file'])}
    with archive.lock():
        name = str(details['release_id']) + '-' + digest(details['published_at'].encode()) + '.json'
        archive.write('publications/' + name, canonical(envelope))
    return record


def provider_exports():
    global _PROVIDER_EXPORTS
    if _PROVIDER_EXPORTS is None:
        path = Path(__file__).with_name('providers.py')
        require(path.is_file() and not path.is_symlink(), 'trusted provider exporter unavailable')
        spec = importlib.util.spec_from_file_location('veyport_provider_exports', path)
        _PROVIDER_EXPORTS = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_PROVIDER_EXPORTS)
    return _PROVIDER_EXPORTS


def collect_platform_codeql(config, api, archive, run):
    module = provider_exports()
    ref = module.diagnostic_run(module.engine(globals()), config, run)
    path = module.state_path(archive, run)
    state = parse_json(path.read_bytes()) if path.exists() else {}
    expected = {'repository': config['repository'], 'run_id': run['id'], 'run_attempt': run['run_attempt'], 'revision': run['head_sha'], 'ref': ref}
    require(not state or state.get('identity') == expected, 'CodeQL diagnostic checkpoint source mismatch')
    if not state.get('done') and state.get('next_retry_at') and timestamp(state['next_retry_at']) > now():
        return False
    if run['status'] == 'completed':
        archive.save(outcome_manifest(run, config, False), {}, run, {'id': None, 'digest': None}, config, source_trusted=False)
    if config.get('collect_terminal_logs', True):
        collect_job_logs(config, api, archive, run, False)
    if config.get('collect_snyk_statuses', False):
        module.collect_snyk_statuses(globals(), config, api, archive, run)
    if not config.get('collect_codeql_provider', True):
        module.save(module.engine(globals()), config, api, archive, run, 'codeql-summary', {}, {'provider': 'CodeQL', 'status': 'disabled', 'missing': ['provider-export-disabled'], 'provider_asserts_run_id': False}, 'summary')
        return True
    return module.collect_codeql(globals(), config, api, archive, run)


def collect_attempt(config, api, archive, run):
    require(run.get('repository', {}).get('full_name') == config['repository'], 'run repository mismatch')
    if run.get('path') == CODEQL_WORKFLOW:
        return collect_platform_codeql(config, api, archive, run)
    if config.get('collect_snyk_statuses', False):
        require(isinstance(run.get('head_sha'), str) and SHA.fullmatch(run['head_sha']), 'invalid commit status source')
        provider_exports().collect_snyk_statuses(globals(), config, api, archive, run)
    try:
        trusted_run(run, config)
        trusted = True
    except EvidenceError:
        trusted = False
    if trusted:
        verify_trust_anchor(api, run, config)
    if config.get('allowed_job_chunks'):
        collect_job_artifacts(config, api, archive, run, trusted)
    if config.get('collect_terminal_logs', True):
        collect_job_logs(config, api, archive, run, trusted)
    if not trusted:
        # Fork and other untrusted runs get authenticated outcome metadata only. Never decrypt their artifacts.
        if run['status'] == 'completed':
            m = manifest_valid(outcome_manifest(run, config, False))
            archive.save(m, {}, run, {'id': None, 'digest': None}, config, source_trusted=False)
        return
    artifact = api.artifact(run['id'], run['run_attempt'])
    if artifact:
        m, blobs = unpack(age_decrypt(encrypted_artifact(api, artifact, run), config['identity_file']))
        bind_manifest(m, run, config)
        ci_jobs, additional, references = complete_ci_closure(config, api, archive, run, m)
        blobs.update(additional)
        record = archive.save(m, blobs, run, artifact, config, extra_refs=references, ci_jobs=ci_jobs)
        if not record['acknowledged']:
            publish_receipt(api, archive, record, config)
    elif run['status'] == 'completed':
        archive.save(outcome_manifest(run, config, True), {}, run, {'id': None, 'digest': None}, config)
    if run['path'] in PUBLICATION_WORKFLOWS:
        publication = api.artifact(run['id'], run['run_attempt'], kind='publication')
        if publication:
            manifest, _ = unpack(age_decrypt(encrypted_artifact(api, publication, run), config['identity_file']))
            accept_publication_manifest(config, api, archive, run, publication, manifest)


def discover_runs(config, api, archive):
    api.deferred_provider_pending = []
    state_path = archive.root / 'state' / 'discovery.json'
    state = parse_json(state_path.read_bytes()) if state_path.exists() else {}
    end = now()
    default = end - dt.timedelta(days=config.get('reconcile_days', 7))
    start = timestamp(state['last_success']) - dt.timedelta(hours=1) if state.get('last_success') else timestamp(config['initial_since']) if config.get('initial_since') else default
    require(start <= end, 'discovery checkpoint is in future')
    runs = {}
    cursor = start
    # Partition by day: GitHub caps filtered workflow searches at 1000 results.
    while cursor < end:
        boundary = min(cursor + dt.timedelta(days=1), end)
        query = urllib.parse.quote(iso(cursor) + '..' + iso(boundary))
        found = api.pages('/actions/runs?created=' + query, 'workflow_runs')
        require(len(found) < 1000, 'discovery day exceeds provider search cap; operator backfill required')
        for run in found:
            runs[run['id']] = run
        cursor = boundary
    for status in ('in_progress', 'queued'):
        for run in api.pages('/actions/runs?status=' + status, 'workflow_runs'):
            runs[run['id']] = run
    historical = sorted({x['run_id'] for x in archive.records()})
    audit_path = archive.root / 'state/historical-audit.json'
    audit = parse_json(audit_path.read_bytes()) if audit_path.exists() else {'cursor': 0}
    audit_budget = config.get('historical_audit_per_poll', 5)
    require(type(audit_budget) is int and 1 <= audit_budget <= 10, 'invalid historical audit budget')
    require(len(historical) <= audit_budget * 60 * 24 * 6, 'historical rerun audit cannot meet temporary retention; increase monitored reconciliation capacity')
    cursor = audit.get('cursor', 0)
    for _ in range(min(audit_budget, len(historical))):
        run_id = historical[cursor % len(historical)]
        if run_id not in runs:
            runs[run_id] = api.get('/actions/runs/' + str(run_id))
        cursor += 1
    with archive.lock():
        archive.write('state/historical-audit.json', canonical({'cursor': cursor, 'checked_at': iso(end)}), replace=True)
    for run_id in state.get('pending', []):
        require(type(run_id) is int and run_id > 0, 'invalid pending run identity')
        if run_id not in runs:
            checkpoints = list((archive.root / 'state').glob('codeql-' + str(run_id) + '-*.json'))
            require(len(checkpoints) <= 100, 'CodeQL pending attempt inventory exceeds bound')
            outstanding = [parse_json(checkpoint.read_bytes()) for checkpoint in checkpoints]
            outstanding = [item for item in outstanding if not item.get('done')]
            deferred = bool(outstanding) and all(item.get('next_retry_at') and timestamp(item['next_retry_at']) > now() for item in outstanding)
            if deferred:
                api.deferred_provider_pending.append(run_id)
                continue
            runs[run_id] = api.get('/actions/runs/' + str(run_id))
    backlog_path = archive.root / 'state/backlog.json'
    backlog = parse_json(backlog_path.read_bytes()).get('run_ids', []) if backlog_path.exists() else []
    for run_id in backlog:
        require(type(run_id) is int and run_id > 0, 'invalid backlog run identity')
        if run_id not in runs:
            runs[run_id] = api.get('/actions/runs/' + str(run_id))
    order = {value: index for index, value in enumerate(backlog)}
    return sorted(runs.values(), key=lambda x: order.get(x['id'], len(order))), end


def collect(config, api, archive):
    # Checkpoints only advance when all discovered work is reconciled. Completed results are cached.
    api.verified_sources, api.run_cache, api.job_cache, api.deferred_provider_pending = set(), {}, {}, []
    runs, discovered_at = discover_runs(config, api, archive)
    processed_path = archive.root / 'state/completed-polls.json'
    processed = parse_json(processed_path.read_bytes()) if processed_path.exists() else {}
    errors, pending, backlog = 0, list(api.deferred_provider_pending), []
    for index, candidate in enumerate(runs):
        try:
            latest = candidate  # Authenticated list/get response already contains the complete run identity.
            require(1 <= latest['run_attempt'] <= 100, 'run attempt bound exceeded')
            api.run_cache[(latest['id'], latest['run_attempt'])] = latest
            key = str(latest['id'])
            previous = processed.get(key, {})
            fingerprint = [latest['run_attempt'], latest.get('updated_at'), latest['status']]
            if latest['status'] == 'completed' and previous.get('fingerprint') == fingerprint and timestamp(previous['checked_at']) + dt.timedelta(minutes=15) > now():
                continue
            provider_pending = False
            for attempt in range(1, latest['run_attempt'] + 1):
                run = latest if attempt == latest['run_attempt'] else api.get('/actions/runs/' + str(latest['id']) + '/attempts/' + str(attempt))
                api.run_cache[(run['id'], attempt)] = run
                if collect_attempt(config, api, archive, run) is False:
                    provider_pending = True
            if latest['status'] != 'completed' or provider_pending:
                pending.append(latest['id'])
            else:
                processed[key] = {'fingerprint': fingerprint, 'checked_at': iso(now())}
        except APIBudgetExceeded:
            backlog.extend(x['id'] for x in runs[index:])
            errors += 1
            break
        except (EvidenceError, OSError, subprocess.SubprocessError):
            errors += 1
            backlog.append(candidate['id'])
            print('evidence collection failed for run ' + str(candidate.get('id')), file=sys.stderr)
    with archive.lock():
        archive.write('state/completed-polls.json', canonical(processed), replace=True)
        archive.write('state/backlog.json', canonical({'status': 'backlog' if errors else 'processing', 'run_ids': sorted(set(backlog)), 'checked_at': iso(now()), 'checkpoint_advanced': False}), replace=True)
    require(errors == 0, 'one or more runs require reconciliation; checkpoint retained')
    try:
        deadlines = release_deadlines(api, archive, config)
        if deadlines.unresolved:
            print('published release identity unresolved; archival continues and deletion is held', file=sys.stderr)
        for record in archive.records():
            reconcile_record(api, archive, record, config, deadlines, refresh=False)
    except EvidenceError:
        with archive.lock():
            archive.write('state/backlog.json', canonical({'status': 'backlog', 'run_ids': [], 'checked_at': iso(now()), 'checkpoint_advanced': False, 'reason': 'final-outcome-reconciliation-unavailable'}), replace=True)
        raise
    with archive.lock():
        archive.write('state/discovery.json', canonical({'last_success': iso(discovered_at), 'pending': pending}), replace=True)
        archive.write('state/backlog.json', canonical({'status': 'complete', 'run_ids': [], 'checked_at': iso(now()), 'checkpoint_advanced': True}), replace=True)


def verify_storage(archive, record):
    expected = record['storage_digests']
    require(digest(canonical(expected)) == record['receipt']['payload']['storage_sha256'], 'archive storage binding mismatch')
    manifest = archive.root / 'manifests' / (record['manifest_sha256'] + '.age')
    require(not manifest.is_symlink() and manifest.is_file() and digest(manifest.read_bytes()) == expected['manifest'], 'archived manifest integrity failure')
    require(set(expected['blobs']) == set(record['blobs']), 'archive blob inventory mismatch')
    for sha in record['blobs']:
        path = archive.root / 'blobs' / (sha + '.age')
        require(not path.is_symlink() and path.is_file() and digest(path.read_bytes()) == expected['blobs'][sha], 'archived blob integrity failure')


def cleanup(config, api, archive):
    # The independent deletion token is never loaded by collection.
    deadlines = release_deadlines(api, archive, config)
    require_publication_identity_resolved(deadlines)
    for record in archive.records():
        # Provider/log/child records have no upstream artifact; they consume no deletion-role API budget.
        if not record['artifact_id'] or record['deleted'] or not record['acknowledged']:
            continue
        run = reconcile_record(api, archive, record, config, deadlines)
        if run['status'] != 'completed':
            continue
        verify_signature(canonical(record['receipt']['payload']), record['receipt']['signature'], config['signing_public_key_file'])
        require(record['receipt']['payload'] == receipt_payload(record), 'stored acknowledgement binding mismatch')
        # Do not touch any artifact until all run jobs are terminal, across every attempt.
        jobs = api.pages('/actions/runs/' + str(run['id']) + '/jobs?filter=all', 'jobs')
        require(all(job['status'] == 'completed' for job in jobs), 'artifact consumers still running')
        latest = api.get('/actions/runs/' + str(run['id']))
        require(latest['status'] == 'completed', 'a rerun still consumes artifacts')
        try:
            current = api.get('/actions/artifacts/' + str(record['artifact_id']))
        except GitHubError as exc:
            if exc.code != 404:
                raise
            # A previous DELETE may have committed before the durable index update, or upstream expired.
            with archive.lock():
                require_durable_publication_identity_resolved(archive, config, api)
                verify_storage(archive, record)
                record['deleted'] = True
                record['cleanup_outcome'] = 'upstream-already-absent'
                archive.update(record)
            continue
        expected_name = record.get('artifact_name') or artifact_name(record['run_id'], record['run_attempt'])
        allowed = {artifact_name(record['run_id'], record['run_attempt']), f"ssdf-ci-v1-{record['run_id']}-{record['run_attempt']}", f"ssdf-publication-v1-{record['run_id']}-{record['run_attempt']}"} | {f"ssdf-job-v1-{record['run_id']}-{record['run_attempt']}-{job}" for job in config.get('allowed_job_chunks', [])}
        require(expected_name in allowed and current['name'] == expected_name and current.get('digest') == record['artifact_digest'] and current.get('workflow_run', {}).get('id') == record['run_id'], 'cleanup artifact identity mismatch')
        # Check archive contents again before deleting the upstream recovery source.
        with archive.lock():
            require_durable_publication_identity_resolved(archive, config, api)
            verify_storage(archive, record)
            api.request(api.prefix + '/actions/artifacts/' + str(record['artifact_id']), 'DELETE')
            record['deleted'] = True
            record['cleanup_outcome'] = 'exact-artifact-deleted'
            archive.update(record)


def retain(config, api, archive):
    # Retention role deliberately has no age identity or receipt signing key requirement.
    require(config.get('retention_enabled') is True, 'retention role is not enabled')
    deadlines = release_deadlines(api, archive, config)  # outage fails closed before any unlink
    require_publication_identity_resolved(deadlines)
    for record in archive.records():
        reconcile_record(api, archive, record, config, deadlines, refresh=False)
    with archive.lock():
        current = require_durable_publication_identity_resolved(archive, config, api)
        records = archive.records()
        for record in records:
            deadline = timestamp(record['retain_until'])
            for published in current.get(record['revision'], []):
                deadline = max(deadline, year_after(published))
            if deadline != timestamp(record['retain_until']):
                record['retain_until'] = iso(deadline)
                archive.update(record)
        live = [x for x in records if not x['completed_at'] or timestamp(x['retain_until']) > now()]
        protected_blobs = {sha for record in live for sha in record['blobs']}
        protected_manifests = {record['manifest_sha256'] for record in live}
        for record in records:
            if record in live:
                continue
            archive.check_mount()
            (archive.root / 'runs' / record['record_name']).unlink()
        # Orphans may result from a failed transaction. Hold them at least 180d, too.
        for directory, protected in [('blobs', protected_blobs), ('manifests', protected_manifests)]:
            path = archive.root / directory
            if not path.exists():
                continue
            require(not path.is_symlink(), 'archive directory symlink forbidden')
            for item in path.glob('*.age'):
                require(not item.is_symlink() and HEX.fullmatch(item.stem), 'unexpected archive entry')
                if item.stem not in protected and dt.datetime.fromtimestamp(item.stat().st_mtime, UTC) + dt.timedelta(days=180) < now():
                    archive.check_mount()
                    item.unlink()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    seal = sub.add_parser('seal')
    for flag in ('manifest', 'source', 'recipient', 'output'):
        seal.add_argument('--' + flag, required=True)
    seal.add_argument('--hash-output')
    wait = sub.add_parser('wait-receipt')
    for flag in ('repository', 'revision', 'manifest-sha256', 'public-key'):
        wait.add_argument('--' + flag, required=True)
    wait.add_argument('--run-id', required=True, type=int)
    wait.add_argument('--attempt', required=True, type=int)
    wait.add_argument('--timeout', default=600, type=int)
    for command in ('collect', 'cleanup', 'retain', 'preflight'):
        p = sub.add_parser(command)
        p.add_argument('--config', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'seal':
            manifest = manifest_valid(parse_json(Path(args.manifest).read_bytes()))
            raw = pack(manifest, args.source)
            Path(args.output).write_bytes(age_encrypt(raw, args.recipient))
            value = digest(canonical(manifest))
            if args.hash_output:
                Path(args.hash_output).write_text(value + '\n')
            print(value)
        elif args.command == 'wait-receipt':
            require(1 <= args.timeout <= 1800 and HEX.fullmatch(args.manifest_sha256) and SHA.fullmatch(args.revision), 'invalid receipt request')
            api = GitHub(args.repository, os.environ.get('GITHUB_TOKEN', ''))
            expected = {'repository': args.repository, 'run_id': args.run_id, 'run_attempt': args.attempt, 'revision': args.revision, 'manifest_sha256': args.manifest_sha256}
            end = time.monotonic() + args.timeout
            while True:
                statuses = api.pages('/commits/' + args.revision + '/statuses', None)
                for status in statuses:
                    if status.get('context') == f'ssdf-archive/{args.run_id}/{args.attempt}' and status.get('state') == 'success' and status.get('description') == 'Archived sha256:' + args.manifest_sha256:
                        receipt = receipt_from_url(status.get('target_url'), args.repository, args.run_id)
                        validate_receipt(receipt, expected, args.public_key)
                        print(canonical(receipt['payload']).decode())
                        return
                require(time.monotonic() < end, 'archive acknowledgement deadline exceeded')
                time.sleep(min(10, max(0, end - time.monotonic())))
        else:
            config = parse_json(Path(args.config).read_bytes())
            archive = Archive(config)
            if args.command == 'preflight':
                with archive.lock():
                    # Deliberately retained probe: collector does not need unlink privileges.
                    archive.write('probes/durable-readback-v1', b'archive-durable-readback-v1\n', replace=True)
                print('archive mount identity and durable write/readback verified')
                return
            token_file = config['delete_token_file'] if args.command == 'cleanup' else config['read_token_file']
            budget = config.get('api_calls_per_poll', 60)
            require(type(budget) is int and 10 <= budget <= 80, 'invalid GitHub per-poll API budget')
            api = GitHub(config['repository'], Path(token_file).read_text().strip(), max_calls=budget)
            {'collect': collect, 'cleanup': cleanup, 'retain': retain}[args.command](config, api, archive)
    except (EvidenceError, OSError, subprocess.SubprocessError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        # Never include report content, URLs, provider responses or subprocess stderr.
        print('evidence operation failed: ' + (str(exc) if isinstance(exc, EvidenceError) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

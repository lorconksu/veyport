"""Narrow CI job-chunk client adapter for the existing collector wire format.

This has no collection, publication, signature or complete-archive authority.
Encryption remains the existing bounded age CLI operation, not a new primitive.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import tempfile
import time
import zipfile

PART = 8 << 20
MAX_MANIFEST = 1 << 20
MAX_FILES = 256
MAX_WIRE = (64 << 20) + MAX_MANIFEST + (2 << 20)
JOBS = {'unit', 'test', 'integration', 'smoke', 'e2e', 'sonar', 'sast', 'secrets', 'vulnerability'} | {'server-' + str(i) for i in range(6)}
WORKFLOWS = {'.github/workflows/ci.yml', '.github/workflows/release.yml', '.github/workflows/staging.yml'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def pack(manifest, source):
    require(isinstance(manifest, dict) and set(manifest) == {'schema', 'repository', 'workflow', 'run_id', 'run_attempt',
            'revision', 'candidate_id', 'complete', 'files', 'details'}, 'incomplete CI job envelope required')
    require(type(manifest['schema']) is int and manifest['schema'] == 1 and manifest['repository'] == 'lorconksu/veyport'
            and manifest['workflow'] in WORKFLOWS and manifest['complete'] is False,
            'client cannot package complete archives or other workflow authorities')
    require(type(manifest['run_id']) is int and manifest['run_id'] > 0 and type(manifest['run_attempt']) is int
            and manifest['run_attempt'] > 0 and re.fullmatch(r'[0-9a-f]{40}', manifest['revision'])
            and manifest['candidate_id'] == f"run-{manifest['run_id']}-{manifest['run_attempt']}", 'invalid CI source identity')
    details = manifest['details']
    require(isinstance(details, dict) and set(details) == {'kind', 'job', 'chunk_index', 'chunk_count', 'github_sha',
            'checkout_revision', 'status', 'missing', 'original_files', 'omitted_files', 'diagnostic_policy', 'dast'},
            'CI job-chunk details required')
    require(details['kind'] == 'job-chunk' and details['job'] in JOBS and details['checkout_revision'] == manifest['revision']
            and (details['github_sha'] is None or isinstance(details['github_sha'], str) and re.fullmatch(r'[0-9a-f]{40}', details['github_sha']))
            and details['status'] in {'success', 'failure', 'cancelled', 'skipped'}
            and type(details['chunk_index']) is int and type(details['chunk_count']) is int
            and 0 <= details['chunk_index'] < details['chunk_count'] <= 64
            and details['diagnostic_policy'] == 'redacted-text-only/v1' and details['dast'] == 'deferred-owner-decision'
            and all(isinstance(details[name], list) for name in ('missing', 'original_files', 'omitted_files')),
            'invalid CI chunk binding')
    encoded = canonical(manifest)
    require(len(encoded) <= MAX_MANIFEST and isinstance(manifest['files'], list) and len(manifest['files']) <= MAX_FILES,
            'CI chunk manifest exceeds bound')
    seen, total = set(), 0
    for item in manifest['files']:
        require(isinstance(item, dict) and set(item) == {'name', 'sha256', 'size'}
                and isinstance(item['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', item['sha256'])
                and item['name'] == 'parts/' + item['sha256'] and item['name'] not in seen
                and type(item['size']) is int and 0 <= item['size'] <= PART, 'invalid CI part')
        seen.add(item['name'])
        total += item['size']
    require(total <= PART, 'CI chunk exceeds existing eight-MiB part bound')
    source = Path(source)
    require(source.is_dir() and not source.is_symlink(), 'regular CI staging root required')
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('manifest.json', encoded)
        for item in manifest['files']:
            require(not (source / 'parts').is_symlink(), 'CI part directory link forbidden')
            descriptor = os.open(source / item['name'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == item['size'], 'CI part size/type differs')
                raw = stream.read(PART + 1)
            require(len(raw) == item['size'] and hashlib.sha256(raw).hexdigest() == item['sha256'], 'CI part digest differs')
            archive.writestr('blobs/' + item['sha256'], raw)
    result = buffer.getvalue()
    require(len(result) <= MAX_WIRE, 'CI wire payload exceeds bound')
    return result


def age_encrypt(data, recipients, limit=MAX_WIRE):
    # Same file-backed age invocation, size limit and deadline as the collector.
    require(isinstance(data, (bytes, bytearray)) and len(data) <= MAX_WIRE and 0 < limit <= MAX_WIRE,
            'cryptographic input/output capacity exceeded')
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as output:
        source.write(data)
        source.seek(0)
        def restrict_output():
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        process = subprocess.Popen(['age', '-R', str(recipients)], stdin=source, stdout=output,
                                   stderr=subprocess.DEVNULL, preexec_fn=restrict_output)
        deadline = time.monotonic() + 90
        try:
            while process.poll() is None:
                require(time.monotonic() <= deadline and output.tell() <= limit, 'cryptographic operation exceeded bound')
                time.sleep(.02)
            require(process.returncode == 0 and output.tell() <= limit, 'cryptographic operation failed')
            output.seek(0)
            return output.read(limit + 1)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()

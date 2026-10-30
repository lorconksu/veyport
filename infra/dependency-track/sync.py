#!/usr/bin/env python3
"""Pull published Veyport release evidence into a private Dependency-Track 5.x.

No downloaded repository code is executed. GitHub and raw source requests are
anonymous; the dedicated upload credential is sent only to the configured API.
"""
import argparse
import base64
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

TARGETS = ('veyport', 'audit-ingest', 'audit-export')
MAX_JSON = 8 << 20
MAX_ARCHIVE = 16 << 20
MAX_EXPANDED = 128 << 20


class IntegrationError(Exception):
    pass


class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if url.scheme != 'https' or url.hostname not in {
            'github.com', 'release-assets.githubusercontent.com', 'api.github.com',
            'raw.githubusercontent.com', 'objects.githubusercontent.com',
        }:
            raise IntegrationError('Rejected unexpected public download redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise IntegrationError('Dependency-Track redirects are not permitted')


def read_url(url, limit=MAX_JSON, payload=None, key=None):
    headers = {'User-Agent': 'veyport-dependency-track-sync/1', 'Accept': 'application/json'}
    if key:
        headers['X-Api-Key'] = key
    if payload is not None:
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(url, data=payload, headers=headers,
                                     method='PUT' if payload is not None else 'GET')
    opener = urllib.request.build_opener(NoRedirect() if key else PublicRedirect())
    try:
        with opener.open(request, timeout=60) as response:
            data = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        raise IntegrationError(f'HTTP {exc.code} from {urllib.parse.urlsplit(url).hostname}') from None
    except (urllib.error.URLError, TimeoutError):
        raise IntegrationError(f'Unable to reach {urllib.parse.urlsplit(url).hostname}') from None
    if len(data) > limit:
        raise IntegrationError('Response exceeded configured size bound')
    return data


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def evidence(data, expected_digest, tag):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_digest or '') or digest(data) != expected_digest:
        raise IntegrationError('Release evidence SHA256 mismatch or missing GitHub digest')
    wanted = {'DELIVERY_SHA256SUMS', 'published-images.txt', 'reports/build-artifact-manifest.json'}
    wanted.update(f'reports/{target}.{suffix}' for target in TARGETS for suffix in ('spdx.json', 'scan-binding.json'))
    found, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r|gz') as archive:
        for entry in archive:
            total += entry.size
            parts = entry.name.split('/')
            if (len(seen) >= 2048 or entry.name in seen or entry.name.startswith('/')
                    or '..' in parts or total > MAX_EXPANDED or entry.size > MAX_JSON
                    or not (entry.isfile() or entry.isdir())):
                raise IntegrationError('Unsafe or oversized evidence archive')
            seen.add(entry.name)
            if entry.name in wanted:
                if not entry.isfile():
                    raise IntegrationError('Evidence entry is not a regular file')
                found[entry.name] = archive.extractfile(entry).read(MAX_JSON + 1)
    if set(found) != wanted:
        raise IntegrationError('Required release evidence is missing')
    checksums = {}
    for line in found['DELIVERY_SHA256SUMS'].decode().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match or match[2] in checksums:
            raise IntegrationError('Malformed or duplicate evidence checksum')
        checksums[match[2]] = match[1]
    for name, content in found.items():
        if name.startswith('reports/') and checksums.get(name) != hashlib.sha256(content).hexdigest():
            raise IntegrationError('Inner evidence checksum mismatch: ' + name)
    manifest = json.loads(found['reports/build-artifact-manifest.json'])
    revision, version = manifest['revision'], manifest['version']
    if not re.fullmatch(r'[0-9a-f]{40}', revision) or tag != 'v' + version:
        raise IntegrationError('Release tag and evidence identity disagree')
    published = found['published-images.txt'].decode().splitlines()
    for target in TARGETS:
        binding = json.loads(found[f'reports/{target}.scan-binding.json'])
        image = 'veyport' if target == 'veyport' else 'veyport-' + target
        image_digest = binding['published_index_digest']
        if (binding['version'] != version or binding['revision'] != revision
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', image_digest)
                or 'docker.io/yiucloud/' + image + '@' + image_digest not in published):
            raise IntegrationError('Published image binding mismatch: ' + target)
    return found, revision, version


def select_releases(config):
    """Discover every stable release since the configured integration baseline."""
    releases = []
    for page in range(1, 11):
        batch = json.loads(read_url(f'https://api.github.com/repos/{config["repository"]}/releases?per_page=100&page={page}'))
        if not isinstance(batch, list):
            raise IntegrationError('Invalid release listing')
        for release in batch:
            if release.get('draft') or release.get('prerelease'):
                continue
            if (release.get('published_at') or '') < config['not_before']:
                continue
            if not re.fullmatch(r'v\d+\.\d+\.\d+', release['tag_name']):
                continue
            releases.append(release)
        # Fetch all pages: creation order need not equal publication order.
        if len(batch) < 100:
            return sorted(releases, key=lambda r: (r['published_at'], r['id']))
    raise IntegrationError('Release pagination bound exceeded; narrow discovery before continuing')


def syft_json(binary, args, directory):
    env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE='false', SYFT_LOG_LEVEL='error')
    output = directory / 'generated.json'
    with output.open('wb') as stream:
        try:
            subprocess.run([binary, *args, '-o', 'cyclonedx-json'], stdout=stream,
                           stderr=subprocess.DEVNULL, env=env, check=True, timeout=180)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise IntegrationError('Pinned Syft inventory generation failed') from None
    if output.stat().st_size > MAX_JSON:
        raise IntegrationError('Generated SBOM exceeds size bound')
    return json.loads(output.read_bytes())


def decorate(bom, name, version, revision, provenance):
    if bom.get('bomFormat') != 'CycloneDX' or not bom.get('components'):
        raise IntegrationError('Inventory must be a nonempty CycloneDX BOM')
    metadata = bom.setdefault('metadata', {})
    component = metadata.setdefault('component', {})
    component.update(type='application', name=name, version=version)
    component['externalReferences'] = [
        {'type': 'vcs', 'url': 'https://github.com/lorconksu/veyport/commit/' + revision},
        {'type': 'distribution', 'url': provenance},
    ]
    metadata.setdefault('properties', []).append({'name': 'veyport:revision', 'value': revision})
    return bom


def upload(config, key, name, version, bom, deadline_seconds=900):
    api = config['dependency_track_url'].rstrip('/') + '/api/v1'
    body = {'projectName': name, 'projectVersion': version, 'autoCreate': True,
            'bom': base64.b64encode(json.dumps(bom).encode()).decode()}
    result = json.loads(read_url(api + '/bom', payload=json.dumps(body).encode(), key=key))
    try:
        token = str(uuid.UUID(result['token']))
    except (KeyError, ValueError, TypeError):
        raise IntegrationError('Upload did not return a valid processing token') from None
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        status = json.loads(read_url(api + '/event/token/' + token, key=key))
        if status.get('status') == 'COMPLETED' and status.get('processing') is False:
            print(f'Imported and analyzed {name} {version}', flush=True)
            return result.get('projectUuid')
        if status.get('status') not in ('PENDING', 'RUNNING'):
            raise IntegrationError('BOM processing failed or returned an unknown token status')
        time.sleep(5)
    raise IntegrationError('BOM processing deadline exceeded; retry will not mark it complete')


def write_state(path, state):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(state, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def sync(config, key, directory):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / 'state.json'
    state = json.loads(path.read_text()) if path.exists() else {'schema': 1, 'imports': {}, 'release_digests': {}}
    for release in select_releases(config):
        tag = release['tag_name']
        assets = [a for a in release['assets'] if a['name'] == 'release-evidence.tar.gz']
        if len(assets) != 1:
            raise IntegrationError('Release lacks exactly one evidence asset: ' + tag)
        asset = assets[0]
        # A GitHub release can be deleted/recreated with a new numeric ID.
        # Bind history to its immutable tag so that cannot replace an inventory.
        identity = tag
        asset_digest = asset.get('digest')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', asset_digest or ''):
            raise IntegrationError('GitHub asset digest is required')
        previous = state['release_digests'].get(identity)
        if previous and previous != asset_digest:
            raise IntegrationError('Previously imported release evidence was replaced: ' + tag)
        names = [f'Veyport / {target}' for target in TARGETS] + ['Veyport / frontend dependencies']
        keys = [identity + ':' + name for name in names]
        if all(k in state['imports'] for k in keys):
            continue
        expected_url = f'https://github.com/{config["repository"]}/releases/download/{tag}/release-evidence.tar.gz'
        if asset['browser_download_url'] != expected_url or not 0 < asset['size'] <= MAX_ARCHIVE:
            raise IntegrationError('Unexpected release asset URL or size')
        data = read_url(expected_url, MAX_ARCHIVE)
        if len(data) != asset['size']:
            raise IntegrationError('Release asset length mismatch')
        files, revision, version = evidence(data, asset_digest, tag)
        # Persist identity before the first upload so partial retries detect replacement.
        state['release_digests'][identity] = asset_digest
        write_state(path, state)
        with tempfile.TemporaryDirectory(prefix='sbom-', dir=directory) as temporary:
            work = Path(temporary)
            for index, name in enumerate(names):
                state_key = keys[index]
                if state_key in state['imports']:
                    continue
                if index < len(TARGETS):
                    target = TARGETS[index]
                    source = work / 'image.spdx.json'
                    source.write_bytes(files[f'reports/{target}.spdx.json'])
                    bom = syft_json(config['syft'], ['convert', str(source)], work)
                    binding = json.loads(files[f'reports/{target}.scan-binding.json'])
                    image = 'veyport' if target == 'veyport' else 'veyport-' + target
                    provenance = 'https://hub.docker.com/r/yiucloud/' + image
                    bom.setdefault('metadata', {}).setdefault('properties', []).append(
                        {'name': 'veyport:published-image-digest', 'value': binding['published_index_digest']})
                else:
                    source = work / 'frontend'
                    source.mkdir()
                    for filename in ('package.json', 'package-lock.json'):
                        url = f'https://raw.githubusercontent.com/{config["repository"]}/{revision}/web/{filename}'
                        raw = read_url(url)
                        json.loads(raw)  # Treat lockfiles as data; never npm install or execute scripts.
                        (source / filename).write_bytes(raw)
                    bom = syft_json(config['syft'], ['scan', 'dir:' + str(source)], work)
                    provenance = f'https://github.com/{config["repository"]}/tree/{revision}/web'
                    bom.setdefault('metadata', {}).setdefault('properties', []).append(
                        {'name': 'veyport:inventory-scope', 'value': 'frontend lockfile; includes development dependencies; not proof of bundled runtime contents'})
                bom = decorate(bom, name, version, revision, provenance)
                project_uuid = upload(config, key, name, version, bom)
                state['imports'][state_key] = {'project_uuid': project_uuid, 'revision': revision,
                                               'evidence_digest': asset_digest, 'version': version}
                write_state(path, state)
    state['last_success'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    write_state(path, state)
    print('Release synchronization complete', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--state-directory', required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if config['repository'] != 'lorconksu/veyport':
        raise IntegrationError('This integration is scoped to lorconksu/veyport')
    url = urllib.parse.urlsplit(config['dependency_track_url'])
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        raise IntegrationError('Dependency-Track requires an HTTPS origin without credentials')
    datetime.datetime.strptime(config['not_before'], '%Y-%m-%dT%H:%M:%SZ')
    if not Path(config['syft']).is_absolute():
        raise IntegrationError('Syft path must be absolute')
    key = (Path(os.environ['CREDENTIALS_DIRECTORY']) / 'api-key').read_text().strip()
    if not key:
        raise IntegrationError('Missing API key')
    args.state_directory.mkdir(parents=True, exist_ok=True)
    with (args.state_directory / '.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise IntegrationError('Another synchronization is already running') from None
        sync(config, key, args.state_directory)


if __name__ == '__main__':
    try:
        main()
    except (IntegrationError, KeyError, ValueError, OSError, tarfile.TarError) as error:
        # Do not print API response bodies, request headers, or credentials.
        if isinstance(error, IntegrationError):
            print('Synchronization failed: ' + str(error), flush=True)
        else:
            print('Synchronization failed: invalid configuration, evidence, or local state (' + type(error).__name__ + ')', flush=True)
        raise SystemExit(1)

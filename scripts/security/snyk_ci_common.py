#!/usr/bin/env python3
"""Bounded evidence parsing and fixed GitHub transport for trusted Snyk controllers.

Load this module by its trusted sibling path, including under Python -I. Policy
comes only from the adjacent qualified local engine; callers supply no policy or
endpoint configuration. Admission, currentness, and publication authority remain
in the automatic controller.
"""
import hashlib
import importlib.util
import io
import json
import math
from pathlib import Path
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

_SPEC = importlib.util.spec_from_file_location('snyk_policy_trusted', Path(__file__).with_name('snyk_policy.py'))
policy = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(policy)
REPOSITORY = 'lorconksu/veyport'
MAX_JSON = 1 << 20
MAX_CIPHER = 128 << 20
MAX_ZIP = 130 << 20
MAX_PAGES = 10
MEMBERS = {'summary.json', 'evidence.tar.gz.age', 'publication.json'}


def require(ok):
    if not ok:
        raise ValueError('Snyk PR policy validation failed')


def positive(value):
    return type(value) is int and 0 < value < 2**63


def exact_sha(value, size=40):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    require(type(raw) is bytes and len(raw) <= MAX_JSON)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    def floating(value):
        result = float(value)
        require(math.isfinite(result))
        return result
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_float=floating,
                          parse_constant=lambda _: require(False))
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError('Snyk PR policy validation failed') from error


def regular(path, maximum):
    path = Path(path)
    info = path.lstat()
    require(path.is_absolute() and path.resolve() == path and stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1 and 0 < info.st_size <= maximum)
    with path.open('rb') as stream:
        value = stream.read(maximum + 1)
    require(len(value) <= maximum)
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Transport:
    def __init__(self, token, checks=False):
        require(type(token) is str and 0 < len(token) <= 16384 and not re.search(r'\s', token))
        self.token, self.checks = token, checks
        self.deadline = time.monotonic() + 120
        self.requests = 0
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, path, body=None, raw=False):
        # No caller-supplied host, arbitrary repo, traversal, or writable endpoint.
        reads = (r'', r'actions/workflows/snyk-pr-policy\.yml',
                 r'actions/workflows/protected-merge\.yml', r'git/ref/heads/main', r'commits/[0-9a-f]{40}',
                 r'actions/workflows/protected-merge-qualification\.yml',
                 r'git/ref/heads/qualification/protected-merge-20261116',
                 r'actions/runs/[1-9][0-9]*',
                 r'actions/workflows/[1-9][0-9]*/runs',
                 r'actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*/jobs',
                 r'actions/runs/[1-9][0-9]*/artifacts', r'actions/artifacts/[1-9][0-9]*/zip',
                 r'commits/[0-9a-f]{40}/pulls', r'pulls/[1-9][0-9]*', r'pulls/[1-9][0-9]*/files',
                 r'commits/[0-9a-f]{40}/check-runs')
        require(type(path) is str and not re.search(r'[\x00-\x20\\#]', path))
        parsed = urllib.parse.urlsplit(path)
        require(not parsed.scheme and not parsed.netloc and not parsed.fragment)
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        require(all(len(v) == 1 for v in query.values()))
        require(set(query) <= {'per_page', 'page', 'event', 'head_sha', 'filter'})
        for key, values in query.items():
            value = values[0]
            require((key == 'per_page' and value == '100') or
                    (key == 'page' and re.fullmatch('[1-9][0-9]?', value)) or
                    (key == 'event' and value == 'pull_request') or
                    (key == 'head_sha' and exact_sha(value)) or
                    (key == 'filter' and value == 'all'))
        if self.checks:
            require(not query and ((method == 'POST' and path == 'check-runs') or
                    (method in ('GET', 'PATCH') and re.fullmatch(r'check-runs/[1-9][0-9]*', path))))
        else:
            require(method == 'GET' and any(re.fullmatch(pattern, parsed.path) for pattern in reads))
        require(raw == bool(re.fullmatch(r'actions/artifacts/[1-9][0-9]*/zip', parsed.path)))
        self.requests += 1
        require(self.requests <= 160 and self.deadline > time.monotonic())
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                   'User-Agent': 'veyport-snyk-pr-policy', 'X-GitHub-Api-Version': '2022-11-28'}
        payload = canonical(body) if body is not None else None
        if payload is not None: headers['Content-Type'] = 'application/json'
        request = urllib.request.Request('https://api.github.com/repos/'+REPOSITORY+'/'+path,
                                         data=payload, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=min(30, self.deadline-time.monotonic()))
        except urllib.error.HTTPError as error:
            try:
                require(raw and error.code == 302)
                target = error.headers.get('Location', '')
            finally:
                error.close()
            redirect = urllib.parse.urlsplit(target)
            require(redirect.scheme == 'https' and not redirect.username and not redirect.password
                    and redirect.port in (None, 443) and not redirect.fragment
                    and redirect.hostname and redirect.hostname.endswith('.blob.core.windows.net'))
            # Fresh unauthenticated request; this opener refuses further redirects.
            response = self.opener.open(urllib.request.Request(target), timeout=min(30, self.deadline-time.monotonic()))
        with response:
            require(response.status == (201 if method == 'POST' else 200))
            data = response.read((MAX_ZIP if raw else MAX_JSON) + 1)
        require(len(data) <= (MAX_ZIP if raw else MAX_JSON) and time.monotonic() < self.deadline)
        return data if raw else strict_json(data)


class MetadataClient:
    def __init__(self, token): self.transport = Transport(token)
    def get(self, path, raw=False): return self.transport.request('GET', path, raw=raw)


def pages(api, path, field=None):
    rows, total = [], None
    for page in range(1, MAX_PAGES + 1):
        value = api.get(path+('&' if '?' in path else '?')+'per_page=100&page='+str(page))
        if field:
            require(type(value) is dict and type(value.get('total_count')) is int and value['total_count'] >= 0)
            if total is None: total = value['total_count']
            require(total == value['total_count'])
            batch = value.get(field)
        else:
            batch = value
        require(type(batch) is list and len(batch) <= 100 and all(type(row) is dict and positive(row.get('id')) for row in batch))
        rows.extend(batch)
        require(len({row['id'] for row in rows}) == len(rows))
        if len(batch) < 100:
            require(total is None or len(rows) == total)
            return rows
    raise ValueError('Snyk PR policy pagination limit')


def validate_summary(raw, source_sha, control_sha):
    """Validate allowlisted aggregate evidence against explicit source/control bindings."""
    summary = strict_json(raw)
    require(type(summary) is dict and set(summary) == {'source_sha', 'control_sha', 'versions', 'projects',
            'policy', 'license_controls', 'processing_status'} and summary['source_sha'] == source_sha
            and summary['control_sha'] == control_sha)
    versions = summary['versions']
    require(type(versions) is dict and set(versions) == set(policy.trial.VERSION_PATTERNS))
    for key, pattern in policy.trial.VERSION_PATTERNS.items():
        require(type(versions[key]) is str and (versions[key] == 'unavailable' or re.fullmatch(pattern, versions[key])))
    require(versions['go'] in ('go'+policy.GO_VERSION, 'unavailable'))
    controls = summary['license_controls']
    require(controls == policy.control_status(True) or controls == policy.control_status(False))
    rows = summary['projects']
    require(type(rows) is list and len(rows) == len(policy.PROJECTS))
    require([row.get('path') for row in rows if type(row) is dict] == list(policy.PROJECTS))
    for row in rows:
        require(set(row) == {'path', *policy.COUNTS, 'status', 'technically_complete', 'policy_status'})
        require(all(type(row[k]) is int and 0 <= row[k] <= 10**12 for k in policy.COUNTS)
                and type(row['technically_complete']) is bool)
        require(row['status'] in (*policy.trial.COMPLETE, 'scan_incomplete')
                and row['policy_status'] == ('assessed' if row['technically_complete'] else 'incomplete'))
        if row['technically_complete']:
            require(row['status'] in policy.trial.COMPLETE and row['dependency_count'] > 0
                    and row['vulnerability_path_records'] == row['blocking_vulnerability_records'] + row['nonblocking_vulnerability_records']
                    and row['license_path_records'] == row['blocking_license_records'] + row['nonblocking_license_records']
                    and (row['status'] == 'scan_complete_clean') == (row['vulnerability_path_records'] + row['license_path_records'] == 0))
    expected = policy.policy_result(rows, controls_verified=controls['status'] == 'verified')
    require(canonical(summary['policy']) == canonical(expected) and summary['processing_status'] in ('complete', 'incomplete'))
    if summary['processing_status'] == 'complete':
        require(expected['technically_complete'] and all(v != 'unavailable' for v in versions.values()))
    return summary


def archive_files(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_ZIP)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            require(len(entries) == 3 and {row.filename for row in entries} == MEMBERS)
            result = {}
            for row in entries:
                maximum = MAX_CIPHER if row.filename == 'evidence.tar.gz.age' else MAX_JSON
                mode = row.external_attr >> 16
                require(not row.is_dir() and (stat.S_IFMT(mode) in (0, stat.S_IFREG)) and not row.flag_bits & 1
                        and 0 < row.file_size <= maximum and row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
                with archive.open(row) as stream: data = stream.read(maximum + 1)
                require(len(data) == row.file_size)
                result[row.filename] = data
            return result
    except (zipfile.BadZipFile, RuntimeError, EOFError, NotImplementedError) as error:
        raise ValueError('Snyk PR policy archive rejected') from error

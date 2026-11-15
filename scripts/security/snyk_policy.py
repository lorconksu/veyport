#!/usr/bin/env python3
"""Trusted-controller manual Snyk candidate. Explicit evidence uses private paths.

Owner-reviewed configuration is smoke-verified using immutable Unknown/GPL
positive controls. This does not export or retest the entire provider policy.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import traceback
from urllib.parse import urlsplit

_SPEC = importlib.util.spec_from_file_location(
    'snyk_trial_shared', Path(__file__).resolve().parents[1] / 'diagnostics/snyk_runner_trial.py')
trial = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(trial)
PROJECTS = (*trial.PROJECTS[:-1], 'tests/e2e/package.json', trial.PROJECTS[-1])
MANIFESTS = (*PROJECTS, *(p.replace('go.mod', 'go.sum') for p in PROJECTS if p.endswith('go.mod')),
             'web/package-lock.json', 'tests/e2e/package-lock.json')
GO_VERSION = '1.26.11'
HIGH_LICENSES = frozenset({'AGPL-1.0', 'AGPL-3.0', 'CPOL-1.02', 'GPL-2.0', 'GPL-3.0', 'SimPL-2.0'})
SEVERITIES = ('low', 'medium', 'high', 'critical')
COUNTS = ('dependency_count', 'vulnerability_path_records', 'license_path_records',
          'blocking_vulnerability_records', 'blocking_license_records',
          'nonblocking_vulnerability_records', 'nonblocking_license_records')
CONFIG_NAMES = {'.npmrc', '.yarnrc', '.yarnrc.yml', '.pnp.cjs', '.pnp.js', '.snyk',
                'go.work', 'go.work.sum', 'pip.conf', 'setup.py', 'setup.cfg', '.gitmodules',
                '.nvmrc', '.node-version', '.python-version'}
MANIFEST_NAMES = {'go.mod', 'go.sum', 'package.json', 'package-lock.json', 'npm-shrinkwrap.json',
                  'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb', 'pyproject.toml',
                  'Pipfile', 'Pipfile.lock', 'poetry.lock', 'uv.lock', 'setup.py', 'setup.cfg',
                  'Cargo.toml', 'Cargo.lock', 'pom.xml', 'build.gradle', 'build.gradle.kts',
                  'Gemfile', 'Gemfile.lock', 'composer.json', 'composer.lock',
                  'deno.json', 'deno.jsonc', 'deno.lock', 'pubspec.yaml', 'pubspec.lock',
                  'mix.exs', 'mix.lock', 'rebar.config', 'rebar.lock',
                  'Package.swift', 'Package.resolved', 'Podfile', 'Podfile.lock',
                  'Cartfile', 'Cartfile.resolved', 'packages.config', 'packages.lock.json',
                  'Directory.Packages.props', 'conanfile.py', 'conanfile.txt', 'conan.lock',
                  'vcpkg.json', 'vcpkg-configuration.json', 'build.sbt', 'build.sc',
                  'project.clj', 'deps.edn', 'bb.edn', 'gradle.lockfile', 'ivy.xml',
                  'libs.versions.toml', 'Gopkg.toml', 'Gopkg.lock', 'glide.yaml', 'glide.lock',
                  'renv.lock', 'Project.toml', 'Manifest.toml',
                  'cabal.project', 'cabal.project.freeze', 'stack.yaml', 'stack.yaml.lock'}

CANARY_FIXTURE = Path(__file__).with_name('snyk_license_canary.json')
CANARY_FIXTURE_SHA256 = 'cd07dad78124e8eb99fdff875b931d583b104ba9c2c0acf13ea2e0cc6cbd4f55'
CONTROL_FILES_SHA256 = {
    'package.json': '97eababafed88aae9e0aa6140c0964204041df19bfb20be51b971647d8e84cc7',
    'package-lock.json': 'e2360d52edb86a988ce8661838fac787606a8293a51d1af907c162f34daf83b6',
}
EXPECTED_CONTROLS = frozenset({
    ('meld-spec', '0.4.2', 'Unknown', 'snyk:lic:npm:meld-spec:Unknown'),
    ('languages', '0.1.3', 'GPL-3.0', 'snyk:lic:npm:languages:GPL-3.0'),
})
EXPECTED_POLICY = {
    'organization_id': trial.ORG, 'high_license_ids': sorted(HIGH_LICENSES),
    'unknown_severity': 'high',
    'owner_capture_sha256': '72076e06f397e3d7d0871827004413886b74cba5b6f17e144344d165d0d7bbe5',
    'verification_scope': 'owner_configured_unknown_and_gpl_positive_controls_v1',
}
POLICY_SHA256 = hashlib.sha256(json.dumps(EXPECTED_POLICY, sort_keys=True,
                                        separators=(',', ':')).encode()).hexdigest()
MAX_CONTROL_AGE_NS = 180 * 60 * 1_000_000_000


def incomplete():
    return {**trial.incomplete(), **{key: 0 for key in COUNTS},
            'technically_complete': False, 'license_controls_verified': False,
            'policy_status': 'incomplete', 'finding_verdict': 'undetermined'}


def finding_type(finding):
    """Legacy vulnerability records omit type; license markers must agree.

    The verified CLI AnnotatedIssue contract has type?: 'license'. Only the
    SNYK vulnerability namespace without a license field supports that omission.
    Null/unknown types or conflicting license fields/IDs are incomplete evidence.
    """
    identity = finding['id']
    if finding.get('type') == 'license':
        license_name = finding.get('license')
        parts = identity.split(':')
        if (len(parts) != 5 or parts[:2] != ['snyk', 'lic']
                or any(not part or not part.isprintable() or any(character.isspace() for character in part)
                       for part in parts)
                or type(license_name) is not str or not license_name
                or license_name.strip() != license_name or parts[-1] != license_name):
            return None
        return 'license'
    if ('type' in finding and finding['type'] != 'vuln') or 'license' in finding:
        return None
    if not re.fullmatch(r'SNYK-[A-Z0-9][A-Z0-9-]*-[0-9]+', identity):
        return None
    return 'vuln'


def assess(value, exit_code, project):
    """Assess application findings independently of the live license controls.

    Policy maps and pass flags in application JSON are never verification evidence.
    """
    result = incomplete()
    if project not in PROJECTS or type(exit_code) is not int:
        return result
    base = trial.assess(value, exit_code, project)
    if base['status'] not in trial.COMPLETE:
        return result
    targets = {'package.json', 'package-lock.json'} if project.endswith('package.json') else {Path(project).name}
    if any(value.get(field) and value[field] not in targets for field in ('targetFile', 'displayTargetFile')):
        return result
    if ('exceptions' in value or value.get('hasUnknownVersions') is not False
            or type(value.get('filtered')) is not dict
            or set(value['filtered']) != {'ignore', 'patch'}
            or any(type(value['filtered'][key]) is not list or value['filtered'][key]
                   for key in ('ignore', 'patch'))):
        return result
    counts = {key: 0 for key in COUNTS}
    counts.update({key: base[key] for key in ('dependency_count', 'vulnerability_path_records', 'license_path_records')})
    for finding in value['vulnerabilities']:
        classified = finding_type(finding)
        if classified is None:
            return result
        severity = finding.get('severity')
        if type(severity) is not str or severity not in SEVERITIES:
            return result
        if 'severityWithCritical' in finding:
            alternate = finding['severityWithCritical']
            if type(alternate) is not str or alternate not in SEVERITIES:
                return result
            severity = SEVERITIES[max(SEVERITIES.index(severity), SEVERITIES.index(alternate))]
        is_license = classified == 'license'
        # Legacy findings identify the license in license; name is the package. Unknown
        # is blocking even if a provider labels it medium; controls are separate.
        license_name = finding.get('license')
        if is_license and (type(license_name) is not str or not license_name):
            return result
        blocked = severity in ('high', 'critical') or (is_license and (
            license_name.lower() == 'unknown' or license_name in HIGH_LICENSES))
        key = ('blocking_' if blocked else 'nonblocking_') + ('license_records' if is_license else 'vulnerability_records')
        counts[key] += 1
    return {**base, **counts, 'technically_complete': True,
            'license_controls_verified': False, 'policy_status': 'incomplete',
            'finding_verdict': 'blocked' if counts['blocking_vulnerability_records'] + counts['blocking_license_records'] else 'nonblocking'}


def policy_result(rows, *, controls_verified=False):
    """Missing, extra, duplicate, or malformed projects never disappear in totals."""
    complete = (type(rows) is list and len(rows) == len(PROJECTS)
                and all(type(row) is dict for row in rows)
                and sorted(row.get('path', '') for row in rows) == sorted(PROJECTS))
    safe_rows = rows if type(rows) is list else []
    totals = {key: sum(row.get(key, 0) for row in safe_rows if type(row) is dict
                       and row.get('path') in PROJECTS and type(row.get(key)) is int and row[key] >= 0)
              for key in COUNTS}
    technical = complete and all(row.get('technically_complete') is True for row in rows)
    verified = technical and controls_verified is True
    blocked = totals['blocking_vulnerability_records'] + totals['blocking_license_records'] > 0
    code = 2 if not verified else 1 if blocked else 0
    return {'exit_code': code, 'policy_status': 'incomplete' if code == 2 else 'blocked' if code == 1 else 'clean',
            'technically_complete': technical, 'license_controls_verified': controls_verified is True,
            'finding_verdict': 'blocked' if totals['blocking_vulnerability_records'] + totals['blocking_license_records'] else 'nonblocking' if technical else 'undetermined',
            **totals}


def public_summary(state, evaluated=None):
    """Only fixed statuses, validated revisions/versions, paths and numeric counts."""
    recorded_versions = state.get('versions', {})
    if type(recorded_versions) is not dict:
        recorded_versions = {}
    versions = {key: value if type(value := recorded_versions.get(key)) is str
                and re.fullmatch(pattern, value) else 'unavailable'
                for key, pattern in trial.VERSION_PATTERNS.items()}
    sha = lambda key: value if type(value := state.get(key)) is str and re.fullmatch('[0-9a-f]{40}', value) else 'unavailable'
    candidates = evaluated.get('projects', []) if type(evaluated) is dict else state.get('projects', [])
    if type(candidates) is not list:
        candidates = []
    rows = []
    for project in PROJECTS:
        found = [row for row in candidates if type(row) is dict and row.get('path') == project]
        row = found[0] if len(found) == 1 else incomplete()
        rows.append({'path': project,
                     **{key: value if type(value := row.get(key)) is int and value >= 0 else 0 for key in COUNTS},
                     'status': row.get('status') if row.get('status') in trial.COMPLETE else 'scan_incomplete',
                     'technically_complete': row.get('technically_complete') is True,
                     'policy_status': 'incomplete' if row.get('technically_complete') is not True else 'assessed'})
    controls = control_status(type(evaluated) is dict and evaluated.get('license_controls', {}).get('status') == 'verified')
    result = policy_result(candidates, controls_verified=controls['status'] == 'verified')
    technical = (result['technically_complete'] and state.get('preparation_complete') is True
                 and state.get('manifests_unchanged') is True and all(v != 'unavailable' for v in versions.values()))
    return {'source_sha': sha('source_sha'), 'control_sha': sha('control_sha'), 'versions': versions,
            'projects': rows, 'policy': result, 'license_controls': controls,
            'processing_status': 'complete' if technical else 'incomplete'}


def git(directory, *arguments):
    return subprocess.check_output(['git', '-C', str(directory), *arguments], stderr=subprocess.DEVNULL, timeout=30)


def regular(path):
    try:
        info = path.lstat()
    except OSError as error:
        raise ValueError('Missing source file') from error
    if path.resolve() != path or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Noncanonical source file')
    return path.read_bytes()


def file_digest(path):
    return hashlib.sha256(regular(path)).hexdigest()


def load_control_fixture():
    """Controller-pinned metadata bytes, never source-owned package code."""
    if file_digest(CANARY_FIXTURE) != CANARY_FIXTURE_SHA256:
        raise ValueError('Control fixture digest mismatch')
    value = trial.load_report(CANARY_FIXTURE)
    if (type(value) is not dict or set(value) != {'schema_version', 'files'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or type(value['files']) is not dict or set(value['files']) != set(CONTROL_FILES_SHA256)):
        raise ValueError('Invalid control fixture schema')
    for name, content in value['files'].items():
        if type(content) is not str or hashlib.sha256(content.encode()).hexdigest() != CONTROL_FILES_SHA256[name]:
            raise ValueError('Control manifest digest mismatch')
    return value['files']


def verify_control_workspace(args):
    load_control_fixture()
    workspace = args.root / 'license-control'
    if (args.root.resolve() != args.root or workspace.resolve() != workspace or not workspace.is_dir()
            or {child.name for child in workspace.iterdir()} != set(CONTROL_FILES_SHA256)):
        raise ValueError('Control workspace scope mismatch')
    if {name: file_digest(workspace / name) for name in CONTROL_FILES_SHA256} != CONTROL_FILES_SHA256:
        raise ValueError('Materialized control fixture mismatch')
    return workspace


def run_provenance(args):
    """Only runner-provided nonsecret identity fields; no caller pass flag."""
    patterns = {'GITHUB_RUN_ID': r'[1-9][0-9]*', 'GITHUB_RUN_ATTEMPT': r'[1-9][0-9]*',
                'GITHUB_JOB': r'[A-Za-z_][A-Za-z0-9_-]{0,99}'}
    result = {}
    for key, pattern in patterns.items():
        if key in os.environ:
            value = os.environ[key]
            if not re.fullmatch(pattern, value):
                raise ValueError('Invalid runner provenance')
            result[key] = value
    if 'GITHUB_REPOSITORY' in os.environ:
        if os.environ['GITHUB_REPOSITORY'] != 'lorconksu/veyport':
            raise ValueError('Wrong runner repository')
        result['GITHUB_REPOSITORY'] = 'lorconksu/veyport'
    if 'GITHUB_SHA' in os.environ:
        if os.environ['GITHUB_SHA'] != args.control_sha:
            raise ValueError('Wrong runner controller revision')
        result['GITHUB_SHA'] = args.control_sha
    if os.environ.get('GITHUB_ACTIONS') == 'true' and set(result) != {*patterns, 'GITHUB_REPOSITORY', 'GITHUB_SHA'}:
        raise ValueError('Missing hosted runner provenance')
    return result


def expected_control_binding(args, raw, state):
    version = trial.verify_snyk_resolution(raw, args.scanner)
    if (state.get('source_sha') != args.sha or state.get('control_sha') != args.control_sha
            or state.get('versions', {}).get('snyk') != version):
        raise ValueError('Control scanner/revision mismatch')
    verify_control_workspace(args)
    return {'schema_version': 1, 'source_sha': args.sha, 'control_sha': args.control_sha,
            'scanner_version': version, 'scanner_sha256': file_digest(args.scanner),
            'policy_sha256': POLICY_SHA256, 'fixture_sha256': CANARY_FIXTURE_SHA256,
            'fixture_files_sha256': CONTROL_FILES_SHA256, 'runner': run_provenance(args)}


def initialize_controls(args, raw, state):
    if args.root.resolve() != args.root or raw != args.root / 'raw' or raw.resolve() != raw:
        raise ValueError('Noncanonical private control root')
    files = load_control_fixture()
    workspace = args.root / 'license-control'
    workspace.mkdir(mode=0o700)
    for name, content in files.items():
        path = workspace / name
        path.write_bytes(content.encode())
        path.chmod(0o400)
    identity = {**expected_control_binding(args, raw, state),
                'nonce': os.urandom(32).hex(), 'created_at_ns': time.time_ns()}
    trial.write_json(args.root / 'run-identity.json', identity)
    state['run_identity_sha256'] = file_digest(args.root / 'run-identity.json')


def verified_control_identity(args, raw, state):
    path = args.root / 'run-identity.json'
    if file_digest(path) != state.get('run_identity_sha256'):
        raise ValueError('Control preparation identity mismatch')
    identity = trial.load_report(path)
    expected = expected_control_binding(args, raw, state)
    if (type(identity) is not dict or set(identity) != {*expected, 'nonce', 'created_at_ns'}
            or any(identity.get(key) != value for key, value in expected.items())
            or type(identity.get('nonce')) is not str or not re.fullmatch('[0-9a-f]{64}', identity['nonce'])
            or type(identity.get('created_at_ns')) is not int
            or not 0 <= time.time_ns() - identity['created_at_ns'] <= MAX_CONTROL_AGE_NS):
        raise ValueError('Stale or mismatched control identity')
    return identity


def assess_controls(value, exit_code):
    """Exact independently identified positive controls; null maps prove nothing."""
    result = assess(value, exit_code, 'web/package.json')
    if (not result['technically_complete'] or exit_code != 1 or value['ok'] is not False
            or value['dependencyCount'] != 3 or value.get('packageManager') != 'npm'
            or (value.get('targetFile') or value.get('displayTargetFile')) != 'package-lock.json'
            or any(value.get(field) and value[field] != 'package-lock.json'
                   for field in ('targetFile', 'displayTargetFile'))
            or len(value['vulnerabilities']) != 2):
        return False
    identities = []
    for finding in value['vulnerabilities']:
        if (finding.get('type') != 'license' or finding.get('severity') not in ('high', 'critical')
                or ('severityWithCritical' in finding and finding['severityWithCritical'] not in ('high', 'critical'))):
            return False
        identity = tuple(finding.get(key) for key in ('name', 'version', 'license', 'id'))
        if any(type(part) is not str for part in identity):
            return False
        identities.append(identity)
    return len(set(identities)) == 2 and set(identities) == EXPECTED_CONTROLS


def run_controls(args, raw, state):
    if not os.environ.get('SNYK_TOKEN', '').strip():
        raise ValueError('Missing scan credentials')
    identity = verified_control_identity(args, raw, state)
    record_path = raw / 'license-controls.json'
    record_path.unlink(missing_ok=True)
    state.pop('license_control_record_sha256', None)
    attempts = []
    for attempt in (1, 2):
        verified_control_identity(args, raw, state)
        prefix = raw / f'license-control-attempt-{attempt}'
        output = prefix.with_suffix('.json')
        output.unlink(missing_ok=True)
        temporary = raw / 'snyk-control-tmp'
        temporary.mkdir(mode=0o700, exist_ok=True)
        command = [args.scanner, 'test', f'--org={trial.ORG}', '--file=package-lock.json',
                   '--ignore-policy', '--json', f'--json-file-output={output}']
        started = time.time_ns()
        code = trial.capture(command, args.root / 'license-control', prefix, timeout=300,
                             env={'SNYK_TMP_PATH': str(temporary)})
        report_hash = file_digest(output) if output.exists() else None
        value = trial.load_report(output) if report_hash else None
        attempts.append({'attempt': attempt, 'exit_code': code, 'report_sha256': report_hash,
                         'started_at_ns': started, 'finished_at_ns': time.time_ns()})
        trial.write_json(record_path, {'schema_version': 1, 'binding': identity, 'attempts': attempts})
        state['license_control_record_sha256'] = file_digest(record_path)
        trial.write_json(raw / 'state.json', state)
        if assess_controls(value, code):
            return True
        # Only processing failures retry. Complete contradictory or policy-negative
        # JSON cannot become verified by trying the same control again.
        if code in (0, 1) and type(value) is dict:
            break
    return False


def control_status(verified=False):
    return {'status': 'verified' if verified else 'incomplete',
            'scope': EXPECTED_POLICY['verification_scope'],
            'policy_sha256': POLICY_SHA256, 'fixture_sha256': CANARY_FIXTURE_SHA256,
            'dependency_count': 3 if verified else 0, 'license_control_records': 2 if verified else 0}


def verify_controls(args, raw, state):
    """Re-read controller-bound raw evidence; a cached boolean has no authority."""
    try:
        identity = verified_control_identity(args, raw, state)
        path = raw / 'license-controls.json'
        if file_digest(path) != state.get('license_control_record_sha256'):
            raise ValueError('Control attempt metadata changed')
        record = trial.load_report(path)
        if (type(record) is not dict or set(record) != {'schema_version', 'binding', 'attempts'}
                or type(record['schema_version']) is not int or record['schema_version'] != 1
                or record['binding'] != identity or type(record['attempts']) is not list
                or not 1 <= len(record['attempts']) <= 2):
            raise ValueError('Control evidence binding mismatch')
        final = None
        for index, attempt in enumerate(record['attempts'], 1):
            if (type(attempt) is not dict or set(attempt) != {'attempt', 'exit_code', 'report_sha256', 'started_at_ns', 'finished_at_ns'}
                    or type(attempt['attempt']) is not int or attempt['attempt'] != index
                    or type(attempt['exit_code']) is not int
                    or type(attempt['started_at_ns']) is not int or type(attempt['finished_at_ns']) is not int
                    or not identity['created_at_ns'] <= attempt['started_at_ns'] <= attempt['finished_at_ns'] <= time.time_ns()
                    or time.time_ns() - attempt['finished_at_ns'] > MAX_CONTROL_AGE_NS):
                raise ValueError('Invalid control attempt metadata')
            output = raw / f'license-control-attempt-{index}.json'
            if attempt['report_sha256'] is None:
                if output.exists():
                    raise ValueError('Unexpected control report')
                value = None
            else:
                if file_digest(output) != attempt['report_sha256']:
                    raise ValueError('Control report changed')
                value = trial.load_report(output)
            if index != len(record['attempts']) and attempt['exit_code'] in (0, 1) and type(value) is dict:
                raise ValueError('Contradictory control was retried')
            final = (value, attempt['exit_code'])
        if final is None or not assess_controls(*final):
            raise ValueError('Positive controls not verified')
        return control_status(True)
    except Exception:
        return control_status()


def relevant(name):
    base = PurePosixPath(name).name
    return (base in MANIFEST_NAMES or (base.startswith('requirements'))
            or base.endswith(('.csproj', '.fsproj', '.vbproj', '.vcxproj', '.sln', '.nuspec',
                              '.gemspec', '.cabal')))


def validate_npm(source, project):
    manifest = trial.load_report(source / project)
    lock = trial.load_report((source / project).with_name('package-lock.json'))
    if type(manifest) is not dict or type(lock) is not dict or lock.get('lockfileVersion') not in (2, 3):
        raise ValueError('Unsupported npm schema')
    if (any(field in manifest for field in ('workspaces', 'engines', 'devEngines', 'packageManager', 'volta', 'os', 'cpu'))
            or type(lock.get('packages')) is not dict):
        raise ValueError('Unsupported npm workspace')
    for field in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
        dependencies = manifest.get(field, {})
        if type(dependencies) is not dict or any(type(value) is not str or
                not re.fullmatch(r'[0-9A-Za-z.*^~<>=| +_-]+', value) for value in dependencies.values()):
            raise ValueError('Unsupported npm dependency source')
    for name, package in lock['packages'].items():
        if type(package) is not dict or package.get('link') or not isinstance(name, str):
            raise ValueError('Unsupported npm package')
        resolved = package.get('resolved')
        if resolved is not None:
            if type(resolved) is not str:
                raise ValueError('Unsupported npm resolution')
            url = urlsplit(resolved)
            if (url.scheme != 'https' or url.hostname != 'registry.npmjs.org' or url.username
                    or url.password or url.port not in (None, 443) or url.fragment):
                raise ValueError('Unsupported npm registry')


def validate_source(source, sha):
    """Bind all tracked regular bytes to a full revision before dependency execution.

    Empty caches and fixed tool versions do not make executable source config safe;
    reject resolver config and unsupported manifests rather than interpret them.
    """
    if (not source.is_absolute() or source.resolve() != source or not re.fullmatch('[0-9a-f]{40}', sha)
            or trial.revision(source) != sha):
        raise ValueError('Source revision mismatch')
    entries = git(source, 'ls-tree', '-rz', '--full-tree', sha).split(b'\0')
    tracked = set()
    for entry in entries:
        if not entry:
            continue
        metadata, raw_name = entry.split(b'\t', 1)
        mode, kind, digest = metadata.split(b' ')
        name = raw_name.decode('utf-8', errors='strict')
        if (mode not in (b'100644', b'100755') or kind != b'blob' or name.startswith('/')
                or any(part in ('.', '..', '.git') for part in PurePosixPath(name).parts)):
            raise ValueError('Unsupported source tree entry')
        content = regular(source / name)
        actual = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest().encode()
        if actual != digest:
            raise ValueError('Tracked source byte drift')
        tracked.add(name)
    # Detect untracked/ignored resolver inputs as well; only runner-generated paths
    # are pruned. They cannot supply configuration to the credential-bearing CLI.
    discovered = set(tracked)
    for directory, directories, files in os.walk(source, followlinks=False):
        relative = Path(directory).relative_to(source)
        for name in list(directories):
            child = relative / name
            if (Path(directory) / name).is_symlink():
                raise ValueError('Source directory symlink')
            if child.as_posix() in ('.git', 'web/node_modules', 'tests/e2e/node_modules', 'hub/web/dist'):
                directories.remove(name)
        for name in files:
            discovered.add((relative / name).as_posix())
    if any(PurePosixPath(name).name in CONFIG_NAMES for name in discovered):
        raise ValueError('Unsupported resolver configuration or exception policy')
    if {name for name in discovered if relevant(name)} != set(MANIFESTS):
        raise ValueError('Missing or unsupported dependency manifest')
    if not set(MANIFESTS) <= tracked:
        raise ValueError('Manifest not tracked')
    for project in PROJECTS:
        if project.endswith('go.mod'):
            content = regular(source / project).decode()
            if re.findall(r'^go\s+(\S+)\s*$', content, re.MULTILINE) != [GO_VERSION]:
                raise ValueError('Unsupported Go version')
            if re.search(r'^\s*(toolchain|tool|godebug)\b', content, re.MULTILINE):
                raise ValueError('Unsupported Go directive')
            # Support bare replacement tokens only. Go decodes quoted/escaped
            # paths before resolution, so testing their literal prefix is unsafe.
            # Process each line to cover both single and block replacement forms.
            for line in content.splitlines():
                line = line.split('//', 1)[0]
                if '=>' not in line:
                    continue
                if '"' in line or '`' in line:
                    raise ValueError('Quoted Go replacements unsupported')
                match = re.search(r'=>\s*(\S+)', line)
                if not match:
                    raise ValueError('Unsupported Go replacement syntax')
                target = match[1]
                # Local module replacements must resolve to a supported module.
                if target.startswith(('.', '/')):
                    resolved = ((source / project).parent / target).resolve()
                    if resolved / 'go.mod' not in {source / p for p in PROJECTS if p.endswith('go.mod')}:
                        raise ValueError('External local Go replacement')
        elif project.endswith('package.json'):
            validate_npm(source, project)
    hashes = trial.manifest_hashes(source, PROJECTS)
    if hashes[PROJECTS[-1]] != trial.PYTHON_REQUIREMENTS_SHA256:
        raise ValueError('Python wheel closure unqualified')
    return hashes


def verify_revisions(args):
    if (not re.fullmatch('[0-9a-f]{40}', args.control_sha) or args.control.resolve() != args.control
            or trial.revision(args.control) != args.control_sha or args.control == args.source
            or args.control in args.source.parents or args.source in args.control.parents):
        raise ValueError('Controller provenance mismatch')
    return validate_source(args.source, args.sha)


def prepare(args, raw):
    if os.environ.get('SNYK_TOKEN'):
        raise ValueError('Credentials present during preparation')
    started = time.monotonic()
    trial.public_workspace_scope(args.public_root, empty=True)
    hashes = verify_revisions(args)
    resolution = trial.verify_snyk_resolution(raw, args.scanner)
    lock_name = 'scripts/diagnostics/snyk_runner_trial_requirements.lock'
    state = {'source_sha': args.sha, 'control_sha': args.control_sha, 'versions': {}, 'projects': [],
             'preparation_complete': False, 'manifests_unchanged': False, 'manifest_hashes': hashes,
             'python_lock': {'path': lock_name, 'sha256': hashlib.sha256(regular(args.control / lock_name)).hexdigest()}}
    trial.write_json(raw / 'state.json', state)
    state['python_mirror'] = trial.create_python_mirror(args.public_root, args.source, args.sha,
                                                       sources={args.sha: GO_VERSION})
    trial.write_json(raw / 'state.json', state)
    # Source Go embed support: only this generated stub, with canonical parents.
    stub = args.source / 'hub/web/dist/index.html'
    stub.parent.mkdir(parents=True, exist_ok=True)
    if stub.resolve() != stub or stub.is_symlink():
        raise ValueError('Noncanonical embed stub')
    stub.touch()
    commands = trial.dependency_commands(args, projects=PROJECTS)
    codes = [trial.capture(cmd, cwd, raw / f'prepare-{index}', timeout=600)
             for index, (cmd, cwd) in enumerate(commands)]
    trial.resolver_permissions(args.root, args.source, args.public_root)
    codes.append(trial.capture(['/usr/bin/sudo', '-n', '/usr/bin/setpriv', '--reuid=65534', '--regid=65534',
                                '--clear-groups', '--no-new-privs', '/usr/bin/test', '-r',
                                args.public_root / 'mirror' / PROJECTS[-1]], args.source,
                               raw / 'resolver-access', timeout=30))
    wrapper = trial.python_resolver_command(raw, args.public_root / 'venv/bin/python', args.public_root)
    (raw / 'snyk-tmp').mkdir(mode=0o700, exist_ok=True)
    versions = {'snyk': [args.scanner, '--version'], 'go': ['go', 'version'], 'node': ['node', '--version'],
                'npm': ['npm', '--version'], 'python': [wrapper, '--version'], 'age': ['age', '--version']}
    for name, command in versions.items():
        prefix = raw / f'version-{name}'
        code = trial.capture(command, args.source, prefix, timeout=30, env={'SNYK_TMP_PATH': str(raw / 'snyk-tmp')})
        value = prefix.with_suffix('.stdout').read_text(errors='replace').strip()
        if name == 'go':
            match = re.fullmatch(r'go version (go[\d.]+) linux/amd64', value)
            value = match[1] if match else 'unavailable'
        state['versions'][name] = value if code == 0 and re.fullmatch(trial.VERSION_PATTERNS[name], value) else 'unavailable'
    unchanged = verify_revisions(args) == hashes
    state.update(preparation_exit_codes=codes, manifests_unchanged=unchanged,
                 preparation_complete=all(code == 0 for code in codes) and unchanged
                 and all(v != 'unavailable' for v in state['versions'].values())
                 and state['versions']['snyk'] == resolution and state['versions']['go'] == 'go' + GO_VERSION,
                 preparation_elapsed_seconds=round(time.monotonic() - started, 3))
    if state['preparation_complete']:
        initialize_controls(args, raw, state)
    trial.write_json(raw / 'state.json', state)
    return state['preparation_complete']


def scan(args, raw):
    if not os.environ.get('SNYK_TOKEN', '').strip():
        raise ValueError('Missing scan credentials')
    state = trial.load_report(raw / 'state.json')
    hashes = verify_revisions(args)
    if (type(state) is not dict or state.get('source_sha') != args.sha or state.get('control_sha') != args.control_sha
            or state.get('preparation_complete') is not True or hashes != state.get('manifest_hashes')):
        raise ValueError('Scan preparation binding mismatch')
    trial.verify_python_mirror(args.public_root, args.source, args.sha, state.get('python_mirror'),
                               sources={args.sha: GO_VERSION})
    if trial.verify_snyk_resolution(raw, args.scanner) != state.get('versions', {}).get('snyk'):
        raise ValueError('Scanner bootstrap binding mismatch')
    def recheck():
        if verify_revisions(args) != hashes:
            raise ValueError('Scan source drift')
        trial.verify_snyk_resolution(raw, args.scanner)
    state['projects'] = []
    state['manifests_unchanged'] = False
    trial.write_json(raw / 'state.json', state)
    if not run_controls(args, raw, state):
        return False
    started = time.monotonic()
    state['projects'] = trial.scan_projects(args.source, args.scanner, raw, args.public_root / 'venv/bin/python',
                                            args.public_root, projects=PROJECTS, assessor=assess,
                                            ignore_policy=True, verify_source=recheck,
                                            attempt_binding=state['run_identity_sha256'])
    state['manifests_unchanged'] = verify_revisions(args) == hashes
    state['scan_elapsed_seconds'] = round(time.monotonic() - started, 3)
    trial.write_json(raw / 'state.json', state)
    return state['manifests_unchanged'] and policy_result(state['projects'])['technically_complete']


def application_report(raw, index, project, attempts, run_identity_sha256):
    """Re-read every exact attempt binding; cached statuses never authorize pass."""
    if (type(run_identity_sha256) is not str or not re.fullmatch('[0-9a-f]{64}', run_identity_sha256)
            or type(attempts) is not list or not 1 <= len(attempts) <= 2):
        raise ValueError('Missing application attempt binding')
    assessed = incomplete()
    fields = {'attempt', 'project', 'exit_code', 'status', 'run_identity_sha256', 'report_sha256'}
    for number, attempt in enumerate(attempts, 1):
        if (type(attempt) is not dict or set(attempt) != fields
                or type(attempt['attempt']) is not int or attempt['attempt'] != number
                or attempt['project'] != project or type(attempt['exit_code']) is not int
                or attempt['run_identity_sha256'] != run_identity_sha256):
            raise ValueError('Invalid application attempt metadata')
        path = raw / f'project-{index}-attempt-{number}.json'
        if attempt['report_sha256'] is None:
            if path.exists() or path.is_symlink():
                raise ValueError('Unexpected application report')
            value = None
        else:
            if (type(attempt['report_sha256']) is not str
                    or not re.fullmatch('[0-9a-f]{64}', attempt['report_sha256'])
                    or file_digest(path) != attempt['report_sha256']):
                raise ValueError('Application report changed after attempt')
            value = trial.load_report(path)
        assessed = assess(value, attempt['exit_code'], project)
        if attempt['status'] != assessed['status']:
            raise ValueError('Application attempt status mismatch')
        if number != len(attempts) and assessed['technically_complete']:
            raise ValueError('Complete application scan was retried')
    return assessed


def evaluate_result(args, raw):
    """Fresh raw reports plus trusted per-run binding, never cached pass fields."""
    state = trial.load_report(raw / 'state.json')
    rows = []
    controls = control_status()
    prerequisites = False
    if type(state) is dict:
        try:
            prerequisites = (state.get('preparation_complete') is True and state.get('manifests_unchanged') is True
                and state.get('source_sha') == args.sha and state.get('control_sha') == args.control_sha
                and type(state.get('versions')) is dict
                and all(type(state['versions'].get(key)) is str and re.fullmatch(pattern, state['versions'][key])
                        for key, pattern in trial.VERSION_PATTERNS.items())
                and state['versions']['go'] == 'go' + GO_VERSION
                and verify_revisions(args) == state.get('manifest_hashes')
                and type(state.get('projects')) is list and len(state['projects']) == len(PROJECTS)
                and all(type(row) is dict and type(row.get('path')) is str for row in state['projects'])
                and sorted(row['path'] for row in state['projects']) == sorted(PROJECTS))
        except Exception:
            prerequisites = False
        candidates = state.get('projects', [])
        if type(candidates) is not list:
            candidates = []
        for index, project in enumerate(PROJECTS):
            matches = [row for row in candidates if type(row) is dict and row.get('path') == project]
            attempts = matches[0].get('attempts', []) if len(matches) == 1 else []
            assessed = incomplete()
            try:
                assessed = application_report(raw, index, project, attempts, state.get('run_identity_sha256'))
            except Exception:
                pass
            rows.append({'path': project, **assessed})
        if prerequisites:
            controls = verify_controls(args, raw, state)
    result = policy_result(rows, controls_verified=controls['status'] == 'verified')
    return {'policy': result, 'projects': rows, 'license_controls': controls}


def evaluate(args, raw):
    result = evaluate_result(args, raw)
    trial.write_json(raw / 'policy.json', result)
    return result['policy']['exit_code']


def seal(args, raw):
    state = trial.load_report(raw / 'state.json')
    if type(state) is not dict:
        state = {'source_sha': args.sha, 'control_sha': args.control_sha}
    summary = public_summary(state, evaluate_result(args, raw))
    public = args.root / 'public'
    public.mkdir(mode=0o700, exist_ok=True)
    archive, ciphertext = args.root / 'evidence.tar.gz', public / 'evidence.tar.gz.age'
    ciphertext.unlink(missing_ok=True)
    (public / 'summary.json').unlink(missing_ok=True)
    with tarfile.open(archive, 'w:gz') as bundle:
        bundle.add(raw, arcname='raw')
    code = trial.capture(['age', '-r', trial.RECIPIENT, '-o', ciphertext, archive], args.root,
                          args.root / 'encryption', timeout=120)
    if code != 0 or not ciphertext.is_file() or ciphertext.stat().st_size == 0:
        ciphertext.unlink(missing_ok=True)
        raise ValueError('Evidence encryption failed')
    trial.write_json(public / 'summary.json', summary)
    archive.unlink()
    shutil.rmtree(raw)
    # GitHub scopes this file to the current encrypt step. Export only the
    # freshly evaluated, successfully sealed verdict; policy failure must not
    # suppress ciphertext upload or the unconditional cleanup step.
    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with Path(output).open('a', encoding='utf-8') as stream:
            stream.write(f"sealed_policy_exit={summary['policy']['exit_code']}\n")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'scan', 'evaluate', 'seal', 'cleanup'))
    for key in ('source', 'control', 'root', 'scanner', 'public-root'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--control-sha', required=True)
    args = parser.parse_args()
    raw = args.root / 'raw'
    try:
        if args.mode == 'cleanup':
            failed = False
            try:
                if args.public_root.exists():
                    trial.cleanup_public_workspace(args.public_root)
            except Exception:
                failed = True
            for path in (raw, args.root / 'home', args.root / 'config', args.root / 'cache',
                         args.root / 'license-control', args.root / 'run-identity.json',
                         args.root / 'evidence.tar.gz', args.root / 'encryption.stdout', args.root / 'encryption.stderr'):
                try:
                    if path.is_dir(): shutil.rmtree(path)
                    else: path.unlink(missing_ok=True)
                except Exception:
                    failed = True
            return 2 if failed else 0
        raw.mkdir(mode=0o700, parents=True, exist_ok=True)
        if args.mode == 'prepare': return 0 if prepare(args, raw) else 2
        if args.mode == 'scan': return 0 if scan(args, raw) else 2
        if args.mode == 'evaluate': return evaluate(args, raw)
        seal(args, raw)
        return 0
    except Exception:
        if raw.is_dir(): (raw / 'policy-helper-error.txt').write_text(traceback.format_exc())
        print('Snyk policy candidate incomplete; inspect encrypted evidence if available.', file=sys.stderr)
        return 2


if __name__ == '__main__': sys.exit(main())

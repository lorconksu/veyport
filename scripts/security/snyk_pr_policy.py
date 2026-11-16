#!/usr/bin/env python3
"""Trusted, standard-library admission and publication for same-repository PRs.

Never execute source code or decrypt evidence. All API paths are controller built;
Native checks are informational only. Separate clients constrain metadata reads
and check writes while using the job-scoped GITHUB_TOKEN.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

_SPEC = importlib.util.spec_from_file_location('snyk_ci_common_trusted', Path(__file__).with_name('snyk_ci_common.py'))
common = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(common)
# Retain the automatic helper's existing public aliases and policy identity.
policy = common.policy
REPOSITORY = common.REPOSITORY
MAX_JSON = common.MAX_JSON
MAX_CIPHER = common.MAX_CIPHER
MAX_ZIP = common.MAX_ZIP
MAX_PAGES = common.MAX_PAGES
MEMBERS = common.MEMBERS
require = common.require
positive = common.positive
exact_sha = common.exact_sha
canonical = common.canonical
digest = common.digest
strict_json = common.strict_json
regular = common.regular
NoRedirect = common.NoRedirect
Transport = common.Transport
MetadataClient = common.MetadataClient
pages = common.pages
archive_files = common.archive_files
REPOSITORY_ID = 1188082218
OWNER_ID = 13374789
UPSTREAM_ID = 251054731
UPSTREAM_PATH = '.github/workflows/ci.yml'
DRIVER_PATH = '.github/workflows/snyk-pr-policy.yml'
CHECK_NAME = 'Snyk PR scan'
INFORMATIONAL_APP_ID = 15368
# Exact names are the workflow/API contract. Extra platform pre/post steps are
# allowed, but each required step must appear once and succeed.
REQUIRED_STEPS = {
    'admission': ('Checkout trusted main controller', 'Validate trusted controller and activation',
                  'Admit current PR and create informational check'),
    'scan': ('Initialize private evidence', 'Checkout trusted main controller',
             'Checkout exact admitted source', 'Verify source and inventory before tool setup',
             'Setup Go', 'Setup Node',
             'Bootstrap authenticated packages and checksummed latest stable CLI',
             'Test trusted helper boundaries before credentials',
             'Prepare eight dependency targets without credentials',
             'Scan current source and bound license controls',
             'Evaluate all findings and bound license controls',
             'Seal private evidence and generate allowlisted summary',
             'Bind publication envelope', 'Upload only encrypted evidence and allowlisted aggregates',
             'Remove public resolver workspace and private plaintext', 'Final policy and evidence gate'),
}
IDENTITY_KEYS = {'purpose', 'schema_version', 'repository_id', 'owner_id', 'pr_number', 'head_repository_id',
                 'source_sha', 'source_ref_sha256', 'base_repository_id', 'base_ref', 'base_sha',
                 'upstream_workflow_id', 'upstream_workflow_path', 'upstream_run_id',
                 'upstream_run_number', 'upstream_attempt', 'driver_workflow_id', 'driver_workflow_path',
                 'control_sha', 'driver_run_id', 'driver_run_number', 'driver_attempt', 'app_id'}
ADMISSION_KEYS = IDENTITY_KEYS | {'check_id', 'external_id'}


class ChecksClient:
    def __init__(self, token): self.transport = Transport(token, checks=True)
    def create(self, body): return self.transport.request('POST', 'check-runs', body)
    def get(self, identity):
        require(positive(identity))
        return self.transport.request('GET', 'check-runs/'+str(identity))
    def update(self, identity, body):
        require(positive(identity))
        return self.transport.request('PATCH', 'check-runs/'+str(identity), body)


def trusted_repo(repo):
    require(type(repo) is dict and positive(repo.get('id')) and repo.get('id') == REPOSITORY_ID
            and repo.get('full_name') == REPOSITORY and type(repo.get('owner')) is dict
            and positive(repo['owner'].get('id')) and repo['owner']['id'] == OWNER_ID)


def run_fields(run):
    require(type(run) is dict and all(positive(run.get(k)) for k in ('id', 'run_number', 'run_attempt', 'workflow_id'))
            and exact_sha(run.get('head_sha')) and type(run.get('head_branch')) is str
            and 0 < len(run['head_branch']) <= 1024)
    trusted_repo(run.get('repository'))


def driver_run(api, run_id, control_sha=None, workflow_id=None):
    run = api.get('actions/runs/'+str(run_id))
    run_fields(run)
    trusted_repo(run.get('head_repository'))
    require(run['id'] == run_id and run.get('path') == DRIVER_PATH and run.get('event') == 'workflow_run'
            and run['head_branch'] == 'main')
    if control_sha is not None: require(run['head_sha'] == control_sha)
    if workflow_id is not None: require(run['workflow_id'] == workflow_id)
    return run


def external_identity(identity):
    return 'snyk-pr-v1:'+':'.join(str(identity[k]) for k in (
        'pr_number', 'source_sha', 'upstream_run_id', 'upstream_attempt', 'driver_run_id', 'driver_attempt'))+':'+digest(canonical(identity))


def parse_external(value):
    require(type(value) is str and len(value) <= 255)
    match = re.fullmatch(r'snyk-pr-v1:([1-9][0-9]*):([0-9a-f]{40}):([1-9][0-9]*):([1-9][0-9]*):([1-9][0-9]*):([1-9][0-9]*):([0-9a-f]{64})', value)
    require(match is not None)
    pr, sha, upstream, upstream_attempt, driver, driver_attempt, binding = match.groups()
    result = {'pr_number': int(pr), 'source_sha': sha, 'upstream_run_id': int(upstream),
              'upstream_attempt': int(upstream_attempt), 'driver_run_id': int(driver),
              'driver_attempt': int(driver_attempt), 'binding': binding}
    require(all(positive(result[k]) for k in result if k not in ('source_sha', 'binding')))
    return result


def validate_admission(admission):
    require(type(admission) is dict and set(admission) == ADMISSION_KEYS)
    identity = {k: admission[k] for k in IDENTITY_KEYS}
    require(identity['purpose'] == 'automatic-pr' and identity['schema_version'] == 1 and type(identity['schema_version']) is int
            and identity['repository_id'] == REPOSITORY_ID and identity['owner_id'] == OWNER_ID
            and identity['base_repository_id'] == REPOSITORY_ID and identity['base_ref'] == 'main'
            and identity['upstream_workflow_id'] == UPSTREAM_ID and identity['upstream_workflow_path'] == UPSTREAM_PATH
            and identity['driver_workflow_path'] == DRIVER_PATH)
    for key in ('source_sha', 'base_sha', 'control_sha'): require(exact_sha(identity[key]))
    require(exact_sha(identity['source_ref_sha256'], 64))
    numeric = IDENTITY_KEYS - {'source_sha', 'base_sha', 'control_sha', 'source_ref_sha256',
                              'purpose', 'base_ref', 'upstream_workflow_path', 'driver_workflow_path'}
    require(all(positive(identity[k]) for k in numeric) and identity['app_id'] == INFORMATIONAL_APP_ID
            and positive(admission['check_id']) and admission['external_id'] == external_identity(identity))
    parse_external(admission['external_id'])
    return identity


def validate_check(check, admission, pending=False):
    validate_admission(admission)
    require(type(check) is dict and positive(check.get('id')) and check.get('id') == admission['check_id']
            and check.get('name') == CHECK_NAME and check.get('head_sha') == admission['source_sha']
            and type(check.get('app')) is dict and positive(check['app'].get('id')) and check['app'].get('id') == admission['app_id']
            and check.get('external_id') == admission['external_id'])
    if pending: require(check.get('status') == 'in_progress' and check.get('conclusion') is None)


def current_heads(api, source_sha):
    # Checks are commit-wide: count distinct current main-target PRs across
    # branch refs and repositories, including forks. Associated old heads do
    # not count; every candidate is reread through authenticated PR metadata.
    associated = pages(api, 'commits/'+source_sha+'/pulls')
    require(len({item.get('number') for item in associated}) == len(associated))
    matches = []
    for item in associated:
        require(positive(item.get('number')))
        pr = api.get('pulls/'+str(item['number']))
        require(type(pr) is dict and positive(pr.get('id')) and pr['id'] == item['id']
                and pr.get('number') == item['number'])
        head, base = pr.get('head', {}), pr.get('base', {})
        if (pr.get('state') == 'open' and head.get('sha') == source_sha
                and base.get('repo', {}).get('id') == REPOSITORY_ID and base.get('ref') == 'main'):
            trusted_repo(base['repo'])
            require(exact_sha(base.get('sha')) and type(head.get('ref')) is str
                    and 0 < len(head['ref']) <= 1024 and positive(head.get('repo', {}).get('id')))
            matches.append(pr)
    return matches


def context(api, event, env):
    require(env.get('SNYK_PR_POLICY_ENABLED') == 'true' and env.get('GITHUB_EVENT_NAME') == 'workflow_run'
            and env.get('GITHUB_REPOSITORY') == REPOSITORY and env.get('GITHUB_REF') == 'refs/heads/main'
            and exact_sha(env.get('GITHUB_SHA')) and env.get('GITHUB_JOB') in ('admission', 'scan', 'publish'))
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        require(type(env.get(key)) is str and re.fullmatch('[1-9][0-9]{0,18}', env[key]))
    require(type(event) is dict and event.get('action') == 'in_progress')
    trusted_repo(event.get('repository'))
    repo = api.get('')
    trusted_repo(repo)
    require(repo.get('default_branch') == 'main')
    workflow = api.get('actions/workflows/snyk-pr-policy.yml')
    require(type(workflow) is dict and positive(workflow.get('id')) and workflow.get('path') == DRIVER_PATH and workflow.get('state') == 'active')
    driver = driver_run(api, int(env['GITHUB_RUN_ID']), env['GITHUB_SHA'], workflow['id'])
    require(driver['run_attempt'] == int(env['GITHUB_RUN_ATTEMPT']))
    source = event.get('workflow_run')
    run_fields(source)
    require(source.get('event') == 'pull_request' and source.get('path') == UPSTREAM_PATH and source['workflow_id'] == UPSTREAM_ID)
    upstream = api.get('actions/runs/'+str(source['id']))
    run_fields(upstream)
    for key in ('id', 'run_number', 'run_attempt', 'workflow_id', 'path', 'event', 'head_sha', 'head_branch'):
        require(upstream.get(key) == source.get(key))
    require(type(upstream.get('head_repository')) is dict and positive(upstream['head_repository'].get('id'))
            and upstream['head_repository'].get('id') == source.get('head_repository', {}).get('id'))
    heads = current_heads(api, upstream['head_sha'])
    matches = [pr for pr in heads if pr['head']['ref'] == upstream['head_branch']
               and pr['head']['repo']['id'] == upstream['head_repository']['id']]
    require(len(matches) == 1)
    pr = matches[0]
    identity = {'purpose': 'automatic-pr', 'schema_version': 1, 'repository_id': REPOSITORY_ID, 'owner_id': OWNER_ID,
                'pr_number': pr['number'], 'head_repository_id': upstream['head_repository']['id'],
                'source_sha': upstream['head_sha'], 'source_ref_sha256': digest(upstream['head_branch'].encode()),
                'base_repository_id': REPOSITORY_ID, 'base_ref': 'main', 'base_sha': pr['base']['sha'],
                'upstream_workflow_id': UPSTREAM_ID, 'upstream_workflow_path': UPSTREAM_PATH,
                'upstream_run_id': upstream['id'], 'upstream_run_number': upstream['run_number'],
                'upstream_attempt': upstream['run_attempt'], 'driver_workflow_id': driver['workflow_id'],
                'driver_workflow_path': DRIVER_PATH, 'control_sha': driver['head_sha'],
                'driver_run_id': driver['id'], 'driver_run_number': driver['run_number'],
                'driver_attempt': driver['run_attempt'], 'app_id': INFORMATIONAL_APP_ID}
    return identity, len(heads) > 1


def currentness(api, identity, *, collision_rejection=False, admitting=False):
    # Called again immediately before the success PATCH, after artifact/job reads.
    upstream = api.get('actions/runs/'+str(identity['upstream_run_id']))
    run_fields(upstream)
    require(upstream['id'] == identity['upstream_run_id'] and upstream['workflow_id'] == UPSTREAM_ID
            and upstream.get('path') == UPSTREAM_PATH and upstream.get('event') == 'pull_request'
            and upstream['run_number'] == identity['upstream_run_number']
            and upstream['run_attempt'] == identity['upstream_attempt'] and upstream['head_sha'] == identity['source_sha']
            and digest(upstream['head_branch'].encode()) == identity['source_ref_sha256']
            and upstream.get('head_repository', {}).get('id') == identity['head_repository_id'])
    pr = api.get('pulls/'+str(identity['pr_number']))
    require(type(pr) is dict and pr.get('number') == identity['pr_number'] and pr.get('state') == 'open')
    head, base = pr.get('head', {}), pr.get('base', {})
    trusted_repo(base.get('repo'))
    require(head.get('sha') == identity['source_sha'] and type(head.get('ref')) is str
            and digest(head['ref'].encode()) == identity['source_ref_sha256']
            and head.get('repo', {}).get('id') == identity['head_repository_id']
            and base.get('ref') == 'main' and base.get('sha') == identity['base_sha'])
    if identity['head_repository_id'] == REPOSITORY_ID: trusted_repo(head.get('repo'))
    driver = driver_run(api, identity['driver_run_id'], identity['control_sha'], identity['driver_workflow_id'])
    require(driver['run_number'] == identity['driver_run_number'] and driver['run_attempt'] == identity['driver_attempt'])
    # A safely identified collision must still produce its own failure check
    # even when another PR has newer CI. This path can only reject admission.
    if collision_rejection:
        require(admitting)
        return True
    if admitting:
        heads = current_heads(api, identity['source_sha'])
        require(any(pr['number'] == identity['pr_number'] for pr in heads))
        if len(heads) > 1: return True
    runs = pages(api, 'actions/workflows/'+str(UPSTREAM_ID)+'/runs?event=pull_request&head_sha='+identity['source_sha'], 'workflow_runs')
    require(any(row['id'] == identity['upstream_run_id'] for row in runs))
    for row in runs:
        run_fields(row)
        require(row.get('path') == UPSTREAM_PATH and row['workflow_id'] == UPSTREAM_ID and row.get('event') == 'pull_request')
        if row['head_sha'] == identity['source_sha']:
            require(row['id'] <= identity['upstream_run_id'] and row['run_number'] <= identity['upstream_run_number'])
            if row['id'] == identity['upstream_run_id']: require(row['run_attempt'] == identity['upstream_attempt'])
    markers = pages(api, 'commits/'+identity['source_sha']+'/check-runs?filter=all', 'check_runs')
    for check in markers:
        if check.get('name') != CHECK_NAME or check.get('app', {}).get('id') != identity['app_id']: continue
        require(check.get('head_sha') == identity['source_sha'])
        marker = parse_external(check.get('external_id'))
        require(marker['source_sha'] == identity['source_sha'])
        other = driver_run(api, marker['driver_run_id'], workflow_id=identity['driver_workflow_id'])
        require(marker['driver_attempt'] <= other['run_attempt'])
        # Admission order also governs collision rejections triggered by an
        # older upstream run. Such a newer blocker must not be overwritten.
        require(other['id'] <= identity['driver_run_id'] and other['run_number'] <= identity['driver_run_number'])
        if other['id'] == identity['driver_run_id']: require(marker['driver_attempt'] <= identity['driver_attempt'])
        require(marker['upstream_run_id'] <= identity['upstream_run_id'])
        if marker['upstream_run_id'] == identity['upstream_run_id']:
            require(marker['upstream_attempt'] <= identity['upstream_attempt'])

    # Last metadata reads before publication: a second PR may have appeared
    # while jobs/artifacts or chronology were being checked.
    heads = current_heads(api, identity['source_sha'])
    if admitting and len(heads) > 1:
        require(any(pr['number'] == identity['pr_number'] for pr in heads))
        return True
    require(len(heads) == 1 and heads[0]['number'] == identity['pr_number'])
    return False


def check_body(identity, conclusion=None):
    return {'name': CHECK_NAME, 'head_sha': identity['source_sha'], 'external_id': external_identity(identity),
            'status': 'completed' if conclusion else 'in_progress',
            **({'conclusion': conclusion} if conclusion else {}),
            'output': {'title': CHECK_NAME, 'summary': 'Informational only; protected merge independently rescans. Scan '+('passed.' if conclusion == 'success' else 'did not pass.' if conclusion else 'in progress.')}}


def admit(api, checks, event, env):
    if env.get('SNYK_PR_POLICY_ENABLED') != 'true':
        return {'decision': 'ignore', 'source_sha': '', 'admission_json': ''}
    identity, shared = context(api, event, env)
    shared = currentness(api, identity, collision_rejection=shared, admitting=True)
    existing = pages(api, 'commits/'+identity['source_sha']+'/check-runs?filter=all', 'check_runs')
    for row in existing:
        if row.get('name') != CHECK_NAME or row.get('app', {}).get('id') != identity['app_id']:
            continue
        marker = parse_external(row.get('external_id'))
        require(not all(marker[k] == identity[k] for k in ('pr_number', 'source_sha', 'upstream_run_id',
                        'upstream_attempt', 'driver_run_id', 'driver_attempt')))
    supported = identity['head_repository_id'] == REPOSITORY_ID and not shared
    check = checks.create(check_body(identity))
    admission = {**identity, 'check_id': check.get('id'), 'external_id': external_identity(identity)}
    validate_check(check, admission, pending=True)
    if not supported:
        # Known forks and shared heads get their own informational failure.
        # Never update another attempt or allow source checkout on rejection.
        validate_check(checks.get(admission['check_id']), admission, pending=True)
        body = check_body(identity, 'failure')
        body.pop('head_sha')
        result = checks.update(admission['check_id'], body)
        validate_check(result, admission)
        require(result.get('status') == 'completed' and result.get('conclusion') == 'failure')
    return {'decision': 'scan' if supported else 'rejected', 'source_sha': identity['source_sha'],
            'admission_json': canonical(admission).decode()}


def validate_summary(raw, admission):
    """Compatibility wrapper for automatic admission-bound evidence."""
    return common.validate_summary(raw, admission['source_sha'], admission['control_sha'])


def make_envelope(admission, summary_raw, cipher, scanner):
    validate_admission(admission)
    require(admission['head_repository_id'] == REPOSITORY_ID)
    summary = validate_summary(summary_raw, admission)
    require(type(cipher) is bytes and 0 < len(cipher) <= MAX_CIPHER
            and cipher.startswith(b'age-encryption.org/v1\n') and type(scanner) is bytes and scanner)
    return {'schema_version': 1, 'admission': admission, 'inventory': list(policy.PROJECTS),
            'policy_sha256': policy.POLICY_SHA256, 'fixture_sha256': policy.CANARY_FIXTURE_SHA256,
            'scanner': {'version': summary['versions']['snyk'], 'sha256': digest(scanner), 'size': len(scanner)},
            'summary': {'sha256': digest(summary_raw), 'size': len(summary_raw)},
            'ciphertext': {'sha256': digest(cipher), 'size': len(cipher)}}


def validate_envelope(admission, files):
    validate_admission(admission)
    require(admission['head_repository_id'] == REPOSITORY_ID and type(files) is dict and set(files) == MEMBERS)
    envelope = strict_json(files['publication.json'])
    require(type(envelope) is dict and set(envelope) == {'schema_version', 'admission', 'inventory',
            'policy_sha256', 'fixture_sha256', 'scanner', 'summary', 'ciphertext'}
            and type(envelope['schema_version']) is int and envelope['schema_version'] == 1
            and envelope['admission'] == admission and envelope['inventory'] == list(policy.PROJECTS)
            and envelope['policy_sha256'] == policy.POLICY_SHA256 and envelope['fixture_sha256'] == policy.CANARY_FIXTURE_SHA256)
    validate_admission(envelope['admission'])
    for key, name, maximum in [('summary', 'summary.json', MAX_JSON), ('ciphertext', 'evidence.tar.gz.age', MAX_CIPHER)]:
        raw = files[name]
        require(type(raw) is bytes and 0 < len(raw) <= maximum and envelope[key] == {'sha256': digest(raw), 'size': len(raw)})
    require(files['evidence.tar.gz.age'].startswith(b'age-encryption.org/v1\n'))
    summary = validate_summary(files['summary.json'], admission)
    scanner = envelope['scanner']
    require(type(scanner) is dict and set(scanner) == {'version', 'sha256', 'size'}
            and scanner['version'] == summary['versions']['snyk'] and exact_sha(scanner['sha256'], 64)
            and type(scanner['size']) is int and 0 < scanner['size'] <= MAX_CIPHER)
    return summary


def execution_complete(admission, jobs):
    require(type(jobs) is list)
    for name, names in REQUIRED_STEPS.items():
        matches = [job for job in jobs if type(job) is dict and job.get('name') == name]
        require(len(matches) == 1)
        job = matches[0]
        require(positive(job.get('id')) and positive(job.get('run_id')) and positive(job.get('run_attempt'))
                and job.get('run_id') == admission['driver_run_id']
                and job.get('run_attempt') == admission['driver_attempt'] and job.get('head_sha') == admission['control_sha']
                and job.get('status') == 'completed' and job.get('conclusion') == 'success'
                and type(job.get('steps')) is list)
        for name in names:
            steps = [step for step in job['steps'] if type(step) is dict and step.get('name') == name]
            require(len(steps) == 1 and positive(steps[0].get('number')) and steps[0].get('status') == 'completed'
                    and steps[0].get('conclusion') == 'success')
        # Also reject failed/skipped extra work: continue-on-error can turn the
        # job green while the API retains the step failure conclusion.
        require(all(type(step) is dict and step.get('status') == 'completed' and step.get('conclusion') == 'success'
                    for step in job['steps']))


def final_verdict(admission, files, jobs, scan_result):
    try:
        require(scan_result == 'success')
        summary = validate_envelope(admission, files)
        execution_complete(admission, jobs)
        require(summary['processing_status'] == 'complete' and summary['policy']['exit_code'] == 0
                and summary['license_controls']['status'] == 'verified')
        return 'success'
    except (ValueError, KeyError, TypeError):
        return 'failure'


def download_evidence(api, admission):
    artifacts = pages(api, 'actions/runs/'+str(admission['driver_run_id'])+'/artifacts', 'artifacts')
    expected_name = 'snyk-pr-policy-'+str(admission['driver_run_id'])+'-'+str(admission['driver_attempt'])
    matches = [row for row in artifacts if row.get('name') == expected_name]
    require(len(matches) == 1)
    artifact = matches[0]
    provenance = artifact.get('workflow_run')
    require(artifact.get('expired') is False and type(artifact.get('size_in_bytes')) is int
            and 0 < artifact['size_in_bytes'] <= MAX_ZIP and type(provenance) is dict
            and provenance.get('id') == admission['driver_run_id'] and provenance.get('repository_id') == REPOSITORY_ID
            and provenance.get('head_repository_id') == REPOSITORY_ID and provenance.get('head_branch') == 'main'
            and provenance.get('head_sha') == admission['control_sha'])
    raw = api.get('actions/artifacts/'+str(artifact['id'])+'/zip', raw=True)
    require(len(raw) == artifact['size_in_bytes'])
    # GitHub exposes SHA-256 on current v4+ uploads. If supplied, it is mandatory
    # authority rather than an optional best-effort comparison.
    if artifact.get('digest') is not None:
        require(artifact['digest'] == 'sha256:'+digest(raw))
    return archive_files(raw)


def publish(api, checks, admission, event, env):
    validate_admission(admission)
    require(env.get('GITHUB_JOB') == 'publish')
    # Context must rederive exactly the original identity; admission is data,
    # never an authority supplied solely through needs outputs or artifacts.
    identity, shared = context(api, event, env)
    require(not shared)
    currentness(api, identity)
    require(identity == {k: admission[k] for k in IDENTITY_KEYS})
    validate_check(checks.get(admission['check_id']), admission, pending=True)
    conclusion = 'failure'
    try:
        jobs = pages(api, 'actions/runs/'+str(admission['driver_run_id'])+'/attempts/'+str(admission['driver_attempt'])+'/jobs', 'jobs')
        files = download_evidence(api, admission)
        conclusion = final_verdict(admission, files, jobs, env.get('SCAN_RESULT'))
    except (ValueError, OSError, KeyError, TypeError, urllib.error.URLError):
        pass
    # A previous green is never re-used or rewritten. Re-read the exact check,
    # then currentness is the last API read before the check update.
    validate_check(checks.get(admission['check_id']), admission, pending=True)
    currentness(api, identity)
    body = check_body(identity, conclusion)
    body.pop('head_sha')
    result = checks.update(admission['check_id'], body)
    validate_check(result, admission)
    require(result.get('status') == 'completed' and result.get('conclusion') == conclusion)
    return conclusion


def outputs(values, env):
    path = env.get('GITHUB_OUTPUT')
    require(type(path) is str and path)
    with open(path, 'a', encoding='utf-8') as stream:
        for name, value in values.items():
            require('\n' not in value and '\r' not in value)
            stream.write(name+'='+value+'\n')


def main(argv=None):
    os.umask(0o077)
    class SanitizedParser(argparse.ArgumentParser):
        def error(self, message):
            self.exit(2, 'Snyk PR policy invalid command.\n')
    parser = SanitizedParser(description=__doc__)
    parser.add_argument('mode', choices=('admit', 'envelope', 'publish'))
    args = parser.parse_args(argv)
    env = os.environ
    try:
        if args.mode == 'admit' and env.get('SNYK_PR_POLICY_ENABLED') != 'true':
            outputs({'decision': 'ignore', 'source_sha': '', 'admission_json': ''}, env)
            return 0
        if args.mode == 'envelope':
            require(env.get('GITHUB_JOB') == 'scan' and not env.get('SNYK_TOKEN') and not env.get('GITHUB_TOKEN'))
            admission = strict_json(env.get('ADMISSION_JSON', '').encode())
            validate_admission(admission)
            require(env.get('GITHUB_REPOSITORY') == REPOSITORY and env.get('GITHUB_SHA') == admission['control_sha']
                    and env.get('GITHUB_RUN_ID') == str(admission['driver_run_id'])
                    and env.get('GITHUB_RUN_ATTEMPT') == str(admission['driver_attempt']))
            root = Path(env.get('TRIAL_ROOT', ''))
            public = root/'public'
            require(root.is_absolute() and root.resolve() == root and public.resolve() == public
                    and {p.name for p in public.iterdir()} == {'summary.json', 'evidence.tar.gz.age'})
            envelope = make_envelope(admission, regular(public/'summary.json', MAX_JSON),
                                     regular(public/'evidence.tar.gz.age', MAX_CIPHER), regular(root/'tools/snyk', MAX_CIPHER))
            target = public/'publication.json'
            with target.open('xb') as stream: stream.write(canonical(envelope)+b'\n')
            return 0
        require(not env.get('SNYK_TOKEN'))
        event = strict_json(regular(Path(env.get('GITHUB_EVENT_PATH', '')), MAX_JSON))
        api = MetadataClient(env.get('GITHUB_TOKEN', ''))
        checks = ChecksClient(env.get('GITHUB_TOKEN', ''))
        if args.mode == 'admit':
            require(env.get('GITHUB_JOB') == 'admission')
            outputs(admit(api, checks, event, env), env)
        else:
            admission = strict_json(env.get('ADMISSION_JSON', '').encode())
            conclusion = publish(api, checks, admission, event, env)
            print('Snyk PR scan '+('passed.' if conclusion == 'success' else 'did not pass.'))
            return 0 if conclusion == 'success' else 1
        return 0
    except Exception:
        print('Snyk PR policy failed; check trusted workflow configuration and rerun the entire workflow.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

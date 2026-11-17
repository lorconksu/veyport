#!/usr/bin/env python3
"""Exact owner-requested, fresh-run protected merge authority for one repository.

No source execution, automatic-check authority, credential fallback, arbitrary
target or uncertain-write retry. Load only the trusted main controller with -I.
"""
import argparse
import http.client
import importlib.util
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

_SPEC = importlib.util.spec_from_file_location('snyk_ci_common_trusted', Path(__file__).with_name('snyk_ci_common.py'))
common = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(common)
require, positive, exact_sha = common.require, common.positive, common.exact_sha
canonical, digest, strict_json = common.canonical, common.digest, common.strict_json
MetadataClient = common.MetadataClient
REPOSITORY, REPOSITORY_ID, OWNER_ID = 'lorconksu/veyport', 1188082218, 13374789
OWNER = 'lorconksu'
WORKFLOW = '.github/workflows/protected-merge.yml'
PURPOSES = {'verify': 'protected-merge-preview', 'merge': 'protected-merge'}
ADMISSION_KEYS = {'schema_version', 'purpose', 'operation', 'repository_id', 'owner_id',
                  'actor_id', 'triggering_actor_id', 'pr_number', 'pr_id', 'pr_node_id',
                  'head_repository_id', 'source_sha', 'source_ref_sha256', 'base_repository_id',
                  'base_ref', 'base_sha', 'control_sha', 'workflow_id', 'workflow_path',
                  'run_id', 'run_number', 'run_attempt'}
REQUIRED_STEPS = {
    'admission': ('Checkout trusted main controller', 'Admit exact owner request'),
    'scan': ('Initialize private evidence', 'Checkout trusted main controller',
             'Checkout exact admitted source', 'Verify source and inventory before tool setup',
             'Setup Go', 'Setup Node',
             'Bootstrap authenticated packages and checksummed latest stable CLI',
             'Test trusted helper boundaries before credentials',
             'Prepare eight dependency targets without credentials',
             'Scan current source and bound license controls',
             'Evaluate all findings and bound license controls',
             'Seal private evidence and generate allowlisted summary',
             'Bind protected merge evidence', 'Upload only encrypted evidence and allowlisted aggregates',
             'Remove public resolver workspace and private plaintext', 'Final policy and evidence gate'),
    'verify': ('Checkout trusted main controller', 'Verify fresh protected merge evidence'),
}
MERGE_PRIOR_STEPS = ('Checkout trusted main controller', 'Preflight fresh protected merge evidence',
                     'Mint protected merge token')
MERGE_STEP = 'Merge exact owner request once'
APP_PERMISSIONS = {'contents': 'write', 'administration': 'read', 'metadata': 'read'}
CHECK_CONTEXTS = ('test', 'integration', 'smoke', 'e2e', 'vulnerability-scan', 'sonarcloud',
                  'CodeQL', 'Analyze (actions)', 'Analyze (go)', 'Analyze (javascript-typescript)',
                  'Analyze (python)', 'Analyze (ruby)')


def integer_env(env, name):
    value = env.get(name)
    require(type(value) is str and re.fullmatch('[1-9][0-9]{0,18}', value))
    result = int(value)
    require(positive(result))
    return result


def trusted_owner(value):
    require(type(value) is dict and positive(value.get('id')) and value['id'] == OWNER_ID
            and value.get('login') == OWNER)


def trusted_repo(value):
    require(type(value) is dict and positive(value.get('id')) and value['id'] == REPOSITORY_ID
            and value.get('full_name') == REPOSITORY)
    trusted_owner(value.get('owner'))


def validate_admission(value):
    require(type(value) is dict and set(value) == ADMISSION_KEYS)
    numeric = {'schema_version', 'repository_id', 'owner_id', 'actor_id', 'triggering_actor_id',
               'pr_number', 'pr_id', 'head_repository_id', 'base_repository_id', 'workflow_id',
               'run_id', 'run_number', 'run_attempt'}
    require(all(positive(value[k]) for k in numeric) and value['schema_version'] == 1
            and value['run_attempt'] == 1)
    require(all(value[k] == REPOSITORY_ID for k in ('repository_id', 'head_repository_id', 'base_repository_id'))
            and all(value[k] == OWNER_ID for k in ('owner_id', 'actor_id', 'triggering_actor_id')))
    require(type(value['operation']) is str and value['operation'] in PURPOSES
            and value['purpose'] == PURPOSES[value['operation']] and value['workflow_path'] == WORKFLOW
            and value['base_ref'] == 'main' and value['base_sha'] == value['control_sha'])
    for key in ('source_sha', 'base_sha', 'control_sha'): require(exact_sha(value[key]))
    require(exact_sha(value['source_ref_sha256'], 64) and type(value['pr_node_id']) is str
            and re.fullmatch('[A-Za-z0-9_=-]{1,256}', value['pr_node_id']))
    return value


def context(api, event, env):
    """Re-derive authority from request, authenticated run, PR and current main."""
    require(env.get('PROTECTED_MERGE_ENABLED') == 'true' and not env.get('SNYK_TOKEN')
            and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('GITHUB_REF') == 'refs/heads/main' and env.get('GITHUB_REPOSITORY') == REPOSITORY
            and env.get('GITHUB_JOB') in ('admission', 'scan', 'verify', 'merge')
            and env.get('GITHUB_ACTOR') == OWNER and env.get('GITHUB_TRIGGERING_ACTOR') == OWNER
            and integer_env(env, 'GITHUB_ACTOR_ID') == OWNER_ID
            and integer_env(env, 'GITHUB_REPOSITORY_ID') == REPOSITORY_ID
            and integer_env(env, 'GITHUB_REPOSITORY_OWNER_ID') == OWNER_ID
            and env.get('GITHUB_RUN_ATTEMPT') == '1'
            and exact_sha(env.get('GITHUB_SHA')) and env.get('GITHUB_WORKFLOW_SHA') == env['GITHUB_SHA']
            and env.get('GITHUB_WORKFLOW_REF') == REPOSITORY+'/'+WORKFLOW+'@refs/heads/main')
    run_id = integer_env(env, 'GITHUB_RUN_ID')
    require(type(event) is dict and event.get('ref') == 'refs/heads/main')
    trusted_repo(event.get('repository')); trusted_owner(event.get('sender'))
    inputs = event.get('inputs')
    require(type(inputs) is dict and set(inputs) == {'operation', 'pr_number', 'head_sha'}
            and type(inputs['operation']) is str and inputs['operation'] in PURPOSES
            and exact_sha(inputs['head_sha']))
    number = integer_env(inputs, 'pr_number')
    repo = api.get(''); trusted_repo(repo)
    require(repo.get('default_branch') == 'main')
    workflow = api.get('actions/workflows/protected-merge.yml')
    require(type(workflow) is dict and positive(workflow.get('id')) and workflow.get('path') == WORKFLOW
            and workflow.get('state') == 'active')
    run = api.get('actions/runs/'+str(run_id))
    require(type(run) is dict and all(positive(run.get(k)) for k in ('id', 'run_number', 'run_attempt', 'workflow_id'))
            and run['id'] == run_id and run['run_attempt'] == 1 and run['workflow_id'] == workflow['id']
            and run.get('path') == WORKFLOW and run.get('event') == 'workflow_dispatch'
            and run.get('head_sha') == env['GITHUB_SHA'] and run.get('head_branch') == 'main'
            and run.get('status') == 'in_progress' and run.get('conclusion') is None)
    trusted_repo(run.get('repository')); trusted_repo(run.get('head_repository'))
    trusted_owner(run.get('actor')); trusted_owner(run.get('triggering_actor'))
    pr = api.get('pulls/'+str(number))
    require(type(pr) is dict and positive(pr.get('id')) and positive(pr.get('number'))
            and pr['number'] == number and pr.get('state') == 'open' and pr.get('draft') is False
            and pr.get('merged') is False)
    head, base = pr.get('head'), pr.get('base')
    require(type(head) is dict and type(base) is dict)
    trusted_repo(head.get('repo')); trusted_repo(base.get('repo'))
    require(head.get('sha') == inputs['head_sha'] and type(head.get('ref')) is str
            and 0 < len(head['ref']) <= 1024 and not re.search(r'[\x00-\x20\x7f]', head['ref'])
            and base.get('ref') == 'main' and base.get('sha') == env['GITHUB_SHA'])
    main = api.get('git/ref/heads/main')
    require(type(main) is dict and main.get('ref') == 'refs/heads/main' and type(main.get('object')) is dict
            and main['object'].get('type') == 'commit' and main['object'].get('sha') == env['GITHUB_SHA'])
    result = {'schema_version': 1, 'purpose': PURPOSES[inputs['operation']], 'operation': inputs['operation'],
              'repository_id': REPOSITORY_ID, 'owner_id': OWNER_ID, 'actor_id': OWNER_ID, 'triggering_actor_id': OWNER_ID,
              'pr_number': number, 'pr_id': pr['id'], 'pr_node_id': pr.get('node_id'),
              'head_repository_id': REPOSITORY_ID, 'source_sha': head['sha'],
              'source_ref_sha256': digest(head['ref'].encode()), 'base_repository_id': REPOSITORY_ID,
              'base_ref': 'main', 'base_sha': base['sha'], 'control_sha': run['head_sha'],
              'workflow_id': workflow['id'], 'workflow_path': WORKFLOW,
              'run_id': run_id, 'run_number': run['run_number'], 'run_attempt': 1}
    return validate_admission(result)


def admit(api, event, env):
    require(env.get('GITHUB_JOB') == 'admission' and not env.get('PROTECTED_MERGE_TOKEN'))
    admission = context(api, event, env)
    return {'admission_json': canonical(admission).decode(), 'source_sha': admission['source_sha']}


def make_evidence(admission, summary_raw, cipher, scanner):
    validate_admission(admission)
    summary = common.validate_summary(summary_raw, admission['source_sha'], admission['control_sha'])
    require(type(cipher) is bytes and 0 < len(cipher) <= common.MAX_CIPHER
            and cipher.startswith(b'age-encryption.org/v1\n') and type(scanner) is bytes
            and 0 < len(scanner) <= common.MAX_CIPHER)
    return {'schema_version': 1, 'purpose': admission['purpose'], 'admission': admission,
            'inventory': list(common.policy.PROJECTS), 'policy_sha256': common.policy.POLICY_SHA256,
            'fixture_sha256': common.policy.CANARY_FIXTURE_SHA256,
            'scanner': {'version': summary['versions']['snyk'], 'sha256': digest(scanner), 'size': len(scanner)},
            'summary': {'sha256': digest(summary_raw), 'size': len(summary_raw)},
            'ciphertext': {'sha256': digest(cipher), 'size': len(cipher)}}


def validate_evidence(admission, files):
    validate_admission(admission)
    require(type(files) is dict and set(files) == common.MEMBERS)
    envelope = strict_json(files['publication.json'])
    require(type(envelope) is dict and set(envelope) == {'schema_version', 'purpose', 'admission', 'inventory',
            'policy_sha256', 'fixture_sha256', 'scanner', 'summary', 'ciphertext'}
            and type(envelope['schema_version']) is int and envelope['schema_version'] == 1
            and envelope['purpose'] == admission['purpose'] and envelope['admission'] == admission
            and envelope['inventory'] == list(common.policy.PROJECTS)
            and envelope['policy_sha256'] == common.policy.POLICY_SHA256
            and envelope['fixture_sha256'] == common.policy.CANARY_FIXTURE_SHA256)
    validate_admission(envelope['admission'])
    for key, filename, maximum in [('summary', 'summary.json', common.MAX_JSON),
                                  ('ciphertext', 'evidence.tar.gz.age', common.MAX_CIPHER)]:
        raw, binding = files[filename], envelope[key]
        require(type(raw) is bytes and 0 < len(raw) <= maximum and type(binding) is dict
                and set(binding) == {'sha256', 'size'} and type(binding['size']) is int
                and binding == {'sha256': digest(raw), 'size': len(raw)})
    require(files['evidence.tar.gz.age'].startswith(b'age-encryption.org/v1\n'))
    summary = common.validate_summary(files['summary.json'], admission['source_sha'], admission['control_sha'])
    scanner = envelope['scanner']
    require(type(scanner) is dict and set(scanner) == {'version', 'sha256', 'size'}
            and scanner['version'] == summary['versions']['snyk'] and exact_sha(scanner['sha256'], 64)
            and type(scanner['size']) is int and 0 < scanner['size'] <= common.MAX_CIPHER)
    require(summary['processing_status'] == 'complete' and summary['policy']['exit_code'] == 0
            and summary['license_controls']['status'] == 'verified')
    return summary


def job_record(admission, jobs, name):
    matches = [job for job in jobs if job.get('name') == name]
    require(len(matches) == 1)
    job = matches[0]
    require(all(positive(job.get(k)) for k in ('id', 'run_id', 'run_attempt'))
            and job['run_id'] == admission['run_id'] and job['run_attempt'] == 1
            and job.get('head_sha') == admission['control_sha'] and type(job.get('steps')) is list
            and all(type(step) is dict and positive(step.get('number')) for step in job['steps'])
            and len({step['number'] for step in job['steps']}) == len(job['steps']))
    return job


def successful_steps(job, names):
    for name in names:
        matches = [step for step in job['steps'] if step.get('name') == name]
        require(len(matches) == 1 and matches[0].get('status') == 'completed'
                and matches[0].get('conclusion') == 'success')


def execution_complete(admission, jobs, final=False, writing=False):
    require(type(jobs) is list and all(type(job) is dict for job in jobs))
    for name, steps in REQUIRED_STEPS.items():
        if name == 'verify' and not final: continue
        job = job_record(admission, jobs, name)
        require(job.get('status') == 'completed' and job.get('conclusion') == 'success')
        successful_steps(job, steps)
        require(all(step.get('status') == 'completed' and step.get('conclusion') == 'success'
                    for step in job['steps']))
    if writing:
        job = job_record(admission, jobs, 'merge')
        require(job.get('status') == 'in_progress' and job.get('conclusion') is None)
        successful_steps(job, MERGE_PRIOR_STEPS)
        active = [step for step in job['steps'] if step.get('name') == MERGE_STEP]
        require(len(active) == 1 and active[0].get('status') == 'in_progress' and active[0].get('conclusion') is None)
        require(all(step.get('conclusion') in (None, 'success') for step in job['steps']))


def download_evidence(api, admission):
    rows = common.pages(api, 'actions/runs/'+str(admission['run_id'])+'/artifacts', 'artifacts')
    matches = [row for row in rows if row.get('name') == 'protected-merge-'+str(admission['run_id'])+'-1']
    require(len(matches) == 1)
    artifact = matches[0]
    run = artifact.get('workflow_run')
    require(artifact.get('expired') is False and type(artifact.get('size_in_bytes')) is int
            and 0 < artifact['size_in_bytes'] <= common.MAX_ZIP and type(run) is dict
            and positive(run.get('id')) and run['id'] == admission['run_id']
            and run.get('repository_id') == REPOSITORY_ID and run.get('head_repository_id') == REPOSITORY_ID
            and run.get('head_branch') == 'main' and run.get('head_sha') == admission['control_sha'])
    raw = api.get('actions/artifacts/'+str(artifact['id'])+'/zip', raw=True)
    require(type(raw) is bytes and len(raw) == artifact['size_in_bytes']
            and artifact.get('digest') == 'sha256:'+digest(raw))
    return common.archive_files(raw)


def verify(api, event, env, admission, writing=False):
    require(env.get('GITHUB_JOB') in ('verify', 'merge'))
    validate_admission(admission)
    require(context(api, event, env) == admission)
    jobs = common.pages(api, 'actions/runs/'+str(admission['run_id'])+'/attempts/1/jobs', 'jobs')
    execution_complete(admission, jobs, final=env['GITHUB_JOB'] == 'merge', writing=writing)
    validate_evidence(admission, download_evidence(api, admission))
    require(context(api, event, env) == admission)
    return {'verified': 'true', 'purpose': admission['purpose'], 'source_sha': admission['source_sha']}


def token_valid(token):
    require(type(token) is str and 0 < len(token) <= 16384 and not re.search(r'\s', token))


class AppReadClient:
    """Final-job-only privileged GETs; no writable endpoint or redirect."""
    def __init__(self, token):
        token_valid(token)
        self.token, self.requests, self.deadline = token, 0, time.monotonic() + 120
        self.opener = urllib.request.build_opener(common.NoRedirect())

    def get(self, path):
        require(type(path) is str and not re.search(r'[\x00-\x20\\#]', path))
        parsed = urllib.parse.urlsplit(path)
        require(not parsed.scheme and not parsed.netloc and not parsed.fragment)
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        require(all(len(v) == 1 for v in query.values()) and set(query) <= {'page', 'per_page'})
        for key, values in query.items():
            require((key == 'per_page' and values == ['100']) or
                    (key == 'page' and re.fullmatch('[1-9][0-9]?', values[0])))
        global_path = bool(re.fullmatch(r'apps/[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?', parsed.path)
                           or parsed.path == 'installation/repositories')
        require(global_path or any(re.fullmatch(pattern, parsed.path) for pattern in
                (r'branches/main/protection', r'rulesets', r'rulesets/[1-9][0-9]*', r'rules/branches/main')))
        require(not query or parsed.path in ('installation/repositories', 'rulesets', 'rules/branches/main'))
        self.requests += 1
        require(self.requests <= 80 and time.monotonic() < self.deadline)
        url = 'https://api.github.com/'+('' if global_path else 'repos/'+REPOSITORY+'/')+path
        request = urllib.request.Request(url, headers={'Authorization': 'Bearer '+self.token,
            'Accept': 'application/vnd.github+json', 'User-Agent': 'veyport-protected-merge',
            'X-GitHub-Api-Version': '2022-11-28'}, method='GET')
        with self.opener.open(request, timeout=min(30, self.deadline-time.monotonic())) as response:
            require(response.status == 200)
            raw = response.read(common.MAX_JSON+1)
        require(time.monotonic() < self.deadline)
        return strict_json(raw)


def protection_config(env):
    app = integer_env(env, 'PROTECTED_MERGE_APP_ID')
    installation = integer_env(env, 'PROTECTED_MERGE_INSTALLATION_ID')
    ruleset = integer_env(env, 'PROTECTED_MERGE_RULESET_ID')
    require(app not in (15368, 57789)
            and integer_env(env, 'PROTECTED_MERGE_MINTED_INSTALLATION_ID') == installation)
    slug, client = env.get('PROTECTED_MERGE_APP_SLUG'), env.get('PROTECTED_MERGE_APP_CLIENT_ID')
    require(type(slug) is str and re.fullmatch('[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?', slug)
            and type(client) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}', client))
    return app, ruleset, slug, client


def validate_classic(value):
    """Exact 2026-11-16 baseline, ignoring API navigation URLs only."""
    require(type(value) is dict)
    expected = {'required_status_checks', 'enforce_admins', 'required_pull_request_reviews', 'required_signatures',
                'required_linear_history', 'allow_force_pushes', 'allow_deletions', 'block_creations',
                'required_conversation_resolution', 'lock_branch', 'allow_fork_syncing'}
    # GitHub omits restrictions when none exist for this personal repository;
    # explicit null is the only equivalent representation. No required control defaults.
    require(set(value) - {'url', 'restrictions'} == expected
            and ('restrictions' not in value or value['restrictions'] is None))
    for key in expected - {'required_status_checks', 'required_pull_request_reviews'}:
        item = value[key]
        require(type(item) is dict and set(item)-{'url'} == {'enabled'}
                and item['enabled'] is (key in ('enforce_admins', 'required_conversation_resolution')))
    reviews = value['required_pull_request_reviews']
    require(type(reviews) is dict and set(reviews)-{'url'} == {'dismiss_stale_reviews', 'require_code_owner_reviews',
            'require_last_push_approval', 'required_approving_review_count'}
            and all(reviews[k] is False for k in ('dismiss_stale_reviews', 'require_code_owner_reviews', 'require_last_push_approval'))
            and type(reviews['required_approving_review_count']) is int and reviews['required_approving_review_count'] == 0)
    status = value['required_status_checks']
    require(type(status) is dict and set(status)-{'url', 'contexts_url'} == {'strict', 'contexts', 'checks'}
            and status['strict'] is True and type(status['contexts']) is list
            and len(status['contexts']) == 12 and set(status['contexts']) == set(CHECK_CONTEXTS)
            and type(status['checks']) is list and len(status['checks']) == 12)
    pairs = set()
    for check in status['checks']:
        require(type(check) is dict and set(check) == {'context', 'app_id'}
                and type(check['context']) is str and positive(check['app_id']))
        pairs.add((check['context'], check['app_id']))
    require(pairs == {(name, 57789 if name == 'CodeQL' else 15368) for name in CHECK_CONTEXTS})


def exact_update_rules(rules, metadata=None):
    """One restrictive update rule, with only the two observed parameter forms."""
    metadata = {} if metadata is None else metadata
    if type(rules) is not list or len(rules) != 1 or type(rules[0]) is not dict:
        return False
    rule = rules[0]
    # Validate complete keys and effective-rule provenance independently of the
    # optional parameters. Never discard fields or normalize a malformed value.
    if set(rule)-{'parameters'} != {'type'} | set(metadata) or rule.get('type') != 'update':
        return False
    if canonical({key: rule[key] for key in metadata}) != canonical(metadata):
        return False
    if 'parameters' not in rule:
        return True
    parameters = rule['parameters']
    return (type(parameters) is dict and set(parameters) == {'update_allows_fetch_and_merge'}
            and parameters['update_allows_fetch_and_merge'] is False)


def validate_protections(api, env):
    app_id, ruleset_id, slug, client = protection_config(env)
    app = api.get('apps/'+slug)
    require(type(app) is dict and positive(app.get('id')) and app['id'] == app_id
            and app.get('slug') == slug and app.get('client_id') == client
            and app.get('permissions') == APP_PERMISSIONS)
    trusted_owner(app.get('owner'))
    repos = common.pages(api, 'installation/repositories', 'repositories')
    require(len(repos) == 1); trusted_repo(repos[0])
    validate_classic(api.get('branches/main/protection'))
    rulesets = common.pages(api, 'rulesets')  # includes_parents defaults to true.
    selected = [rule for rule in rulesets if rule['id'] == ruleset_id]
    require(len(selected) == 1)
    # Extra active rules are conservatively rejected, never bypassed or guessed
    # from wildcard applicability. Hosted setup currently has one active rule.
    for row in rulesets:
        require(row.get('enforcement') in ('active', 'disabled', 'evaluate'))
        if row['enforcement'] == 'active': require(row['id'] == ruleset_id)
    rule = api.get('rulesets/'+str(ruleset_id))
    require(type(rule) is dict and positive(rule.get('id')) and rule['id'] == ruleset_id
            and rule.get('source_type') == 'Repository' and rule.get('source') == REPOSITORY
            and rule.get('target') == 'branch' and rule.get('enforcement') == 'active'
            and selected[0].get('enforcement') == 'active'
            and rule.get('conditions') == {'ref_name': {'include': ['refs/heads/main'], 'exclude': []}}
            and exact_update_rules(rule.get('rules'))
            and canonical(rule.get('bypass_actors')) == canonical([{'actor_id': app_id, 'actor_type': 'Integration', 'bypass_mode': 'pull_request'}]))
    # Branch rule records lack IDs. Bound pagination independently and compare
    # the complete list, including inherited rules and all their parameters.
    active = []
    for page in range(1, common.MAX_PAGES+1):
        batch = api.get('rules/branches/main?per_page=100&page='+str(page))
        require(type(batch) is list and len(batch) <= 100 and all(type(row) is dict for row in batch))
        active.extend(batch)
        if len(batch) < 100: break
    else: require(False)
    require(exact_update_rules(active, {'ruleset_id': ruleset_id,
            'ruleset_source_type': 'Repository', 'ruleset_source': REPOSITORY}))


class MergeClient:
    """One conditional-head PUT, one repository, no caller path/method/body."""
    def __init__(self, token):
        token_valid(token)
        self.token, self.used = token, False
        self.opener = urllib.request.build_opener(common.NoRedirect())

    def merge(self, number, sha):
        require(not self.used and positive(number) and exact_sha(sha))
        self.used = True  # Consume before network I/O, including uncertain errors.
        request = urllib.request.Request('https://api.github.com/repos/'+REPOSITORY+'/pulls/'+str(number)+'/merge',
            data=canonical({'sha': sha, 'merge_method': 'merge'}), method='PUT',
            headers={'Authorization': 'Bearer '+self.token, 'Accept': 'application/vnd.github+json',
                     'Content-Type': 'application/json', 'User-Agent': 'veyport-protected-merge',
                     'X-GitHub-Api-Version': '2022-11-28'})
        with self.opener.open(request, timeout=30) as response:
            require(response.status == 200)
            raw = response.read(common.MAX_JSON+1)
        result = strict_json(raw)
        require(type(result) is dict)
        return result


def merged_outcome(api, admission, expected_sha=None):
    pr = api.get('pulls/'+str(admission['pr_number']))
    require(type(pr) is dict and positive(pr.get('id')) and pr['id'] == admission['pr_id']
            and pr.get('node_id') == admission['pr_node_id'] and pr.get('number') == admission['pr_number']
            and pr.get('merged') is True and pr.get('state') == 'closed' and pr.get('draft') is False)
    head, base = pr.get('head'), pr.get('base')
    require(type(head) is dict and type(base) is dict)
    trusted_repo(head.get('repo')); trusted_repo(base.get('repo'))
    require(head.get('sha') == admission['source_sha'] and type(head.get('ref')) is str
            and digest(head['ref'].encode()) == admission['source_ref_sha256'] and base.get('ref') == 'main')
    sha = pr.get('merge_commit_sha')
    require(exact_sha(sha) and (expected_sha is None or sha == expected_sha))
    commit = api.get('commits/'+sha)
    require(type(commit) is dict and commit.get('sha') == sha and type(commit.get('parents')) is list
            and len(commit['parents']) == 2
            and all(type(parent) is dict and exact_sha(parent.get('sha')) for parent in commit['parents'])
            and [parent['sha'] for parent in commit['parents']] == [admission['base_sha'], admission['source_sha']])
    return {'result': 'merged', 'merge_commit_sha': sha}


def merge_once(api, app_reads, merger, event, env, admission):
    require(env.get('GITHUB_JOB') == 'merge')
    validate_admission(admission)
    require(admission['operation'] == 'merge' and admission['purpose'] == 'protected-merge')
    verify(api, event, env, admission, writing=True)
    validate_protections(app_reads, env)
    jobs = common.pages(api, 'actions/runs/'+str(admission['run_id'])+'/attempts/1/jobs', 'jobs')
    execution_complete(admission, jobs, final=True, writing=True)
    # Last reads before the PUT re-derive owner/run/source/current-main authority.
    # GitHub has no atomic expected-base predicate. Trusted repository writers
    # and administrators remain a boundary; the expected-head predicate is atomic.
    require(context(api, event, env) == admission)
    try:
        result = merger.merge(admission['pr_number'], admission['source_sha'])
    except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
        result = None
    # Reconcile every write response through actual read-only PR/commit state,
    # including malformed success objects. Preserve any valid returned SHA as
    # an additional binding. Never retry a write, even for a definite 409.
    expected_sha = result.get('sha') if type(result) is dict and exact_sha(result.get('sha')) else None
    try:
        # Preflight may spend its entire read budget. Start confirmation only
        # after the one write, with a fresh bounded reader and the same read token.
        return merged_outcome(api.fresh_readonly(), admission, expected_sha)
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError, http.client.HTTPException):
        return {'result': 'unconfirmed', 'merge_commit_sha': ''}


def outputs(values, env):
    path = env.get('GITHUB_OUTPUT')
    require(type(path) is str and path)
    with open(path, 'a', encoding='utf-8') as stream:
        for key, value in values.items():
            require(type(value) is str and '\n' not in value and '\r' not in value)
            stream.write(key+'='+value+'\n')


def main(argv=None):
    os.umask(0o077)
    class SanitizedParser(argparse.ArgumentParser):
        def error(self, message): self.exit(2, 'Protected merge invalid command.\n')
    parser = SanitizedParser(description=__doc__)
    parser.add_argument('mode', choices=('admit', 'make-evidence', 'verify', 'merge-once'))
    args = parser.parse_args(argv)
    env = os.environ
    try:
        require(not env.get('SNYK_TOKEN') and not env.get('PROTECTED_MERGE_APP_PRIVATE_KEY'))
        event = strict_json(common.regular(Path(env.get('GITHUB_EVENT_PATH', '')), common.MAX_JSON))
        api = MetadataClient(env.get('GITHUB_TOKEN', ''))
        if args.mode == 'admit':
            outputs(admit(api, event, env), env)
            return 0
        admission = strict_json(env.get('ADMISSION_JSON', '').encode())
        validate_admission(admission)
        if args.mode == 'make-evidence':
            require(env.get('GITHUB_JOB') == 'scan' and not env.get('PROTECTED_MERGE_TOKEN'))
            require(context(api, event, env) == admission)
            root = Path(env.get('TRIAL_ROOT', '')); public = root/'public'
            require(root.is_absolute() and root.resolve() == root and public.resolve() == public
                    and {p.name for p in public.iterdir()} == {'summary.json', 'evidence.tar.gz.age'})
            envelope = make_evidence(admission, common.regular(public/'summary.json', common.MAX_JSON),
                common.regular(public/'evidence.tar.gz.age', common.MAX_CIPHER), common.regular(root/'tools/snyk', common.MAX_CIPHER))
            with (public/'publication.json').open('xb') as stream: stream.write(canonical(envelope)+b'\n')
            return 0
        if args.mode == 'verify':
            require(not env.get('PROTECTED_MERGE_TOKEN'))
            outputs(verify(api, event, env, admission), env)
            return 0
        # Perform credential-free preflight before even constructing privileged
        # clients. Pinned action outputs are trusted job wiring, never artifacts.
        require(env.get('GITHUB_JOB') == 'merge' and admission['operation'] == 'merge')
        verify(api, event, env, admission, writing=True)
        token = env.get('PROTECTED_MERGE_TOKEN', '')
        token_valid(token); require(token != env.get('GITHUB_TOKEN'))
        protection_config(env)
        result = merge_once(api, AppReadClient(token), MergeClient(token), event, env, admission)
        outputs(result, env)
        print('Protected merge '+result['result']+'.')
        return 0 if result['result'] == 'merged' else 1
    except Exception:
        print('Protected merge failed; inspect trusted configuration and dispatch a fresh exact request.', file=sys.stderr)
        return 1


if __name__ == '__main__': sys.exit(main())

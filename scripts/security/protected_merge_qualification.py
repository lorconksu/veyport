#!/usr/bin/env python3
"""Disabled-by-default, owner-dispatched platform probes for one literal fixture.

This is not production merge authority or scanner proof. No rule editing, ref
creation, arbitrary targets, write retries, or private-key handling exists here.
"""
import argparse
from contextlib import contextmanager
import http.client
import importlib.util
import os
from pathlib import Path
import re
import signal
import sys
import time
import urllib.error
import urllib.request

_SPEC = importlib.util.spec_from_file_location('qualification_merge_trusted', Path(__file__).with_name('protected_merge.py'))
merge = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(merge)
_DIAGNOSTIC_SPEC = importlib.util.spec_from_file_location(
    'qualification_diagnostic_trusted', Path(__file__).with_name('protected_merge_diagnostic.py'))
diagnostic = importlib.util.module_from_spec(_DIAGNOSTIC_SPEC)
_DIAGNOSTIC_SPEC.loader.exec_module(diagnostic)
common = merge.common
require, canonical, strict_json = common.require, common.canonical, common.strict_json
TARGET = 'qualification/protected-merge-20261116'
WORKFLOW = '.github/workflows/protected-merge-qualification.yml'
BRANCH_PATH = 'qualification%2Fprotected-merge-20261116'
SETTINGS_DIAGNOSTIC = 'settings-diagnostic'
WRITE_CASES = ('wrong-head', 'direct-push', 'native-merge', 'missing-canary',
               'pending-canary', 'failed-canary', 'workflow-file-merge')
CASES = ('main-settings', SETTINGS_DIAGNOSTIC, *WRITE_CASES)
CANARY = 'Protected merge qualification canary'
ERRORS = (OSError, ValueError, KeyError, TypeError, urllib.error.URLError, http.client.HTTPException)
EFFECTIVE_RULES_PATH = 'rules/branches/'+BRANCH_PATH+'?per_page=100&page=1'
FIXTURE_CLASSIC_PATH = 'branches/'+BRANCH_PATH+'/protection'
INSTALLATION_SCOPE_PATH = 'installation/repositories?per_page=100&page=1'
DIAGNOSTIC_REQUEST_SECONDS = 30


def fixed_target(target):
    # Independent mutation-layer guard, even if admission was bypassed/damaged.
    require(target != 'main' and target != 'refs/heads/main' and target == TARGET)


def local_guard(event, env):
    require(env.get('PROTECTED_MERGE_QUALIFICATION_ENABLED') == 'true'
            and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('GITHUB_REF') == 'refs/heads/main'
            and env.get('GITHUB_REPOSITORY') == merge.REPOSITORY
            and env.get('GITHUB_REPOSITORY_ID') == str(merge.REPOSITORY_ID)
            and env.get('GITHUB_REPOSITORY_OWNER_ID') == str(merge.OWNER_ID)
            and env.get('GITHUB_ACTOR') == merge.OWNER
            and env.get('GITHUB_ACTOR_ID') == str(merge.OWNER_ID)
            and env.get('GITHUB_TRIGGERING_ACTOR') == merge.OWNER
            and env.get('GITHUB_RUN_ATTEMPT') == '1'
            and env.get('GITHUB_JOB') in ('admission', 'probe')
            and common.exact_sha(env.get('GITHUB_SHA'))
            and env.get('GITHUB_WORKFLOW_SHA') == env['GITHUB_SHA']
            and env.get('GITHUB_WORKFLOW_REF') == merge.REPOSITORY+'/'+WORKFLOW+'@refs/heads/main'
            and not env.get('SNYK_TOKEN') and not env.get('PROTECTED_MERGE_APP_PRIVATE_KEY'))
    merge.integer_env(env, 'GITHUB_RUN_ID')
    require(type(event) is dict and event.get('ref') == 'refs/heads/main')
    merge.trusted_repo(event.get('repository')); merge.trusted_owner(event.get('sender'))
    inputs = event.get('inputs')
    require(type(inputs) is dict and set(inputs) == {'case', 'pr_number', 'head_sha'}
            and type(inputs['case']) is str and inputs['case'] in CASES
            and common.exact_sha(inputs['head_sha']))
    merge.integer_env(inputs, 'pr_number')
    return inputs


def ref_sha(api):
    value = api.get('git/ref/heads/'+TARGET)
    require(type(value) is dict and value.get('ref') == 'refs/heads/'+TARGET
            and type(value.get('object')) is dict and value['object'].get('type') == 'commit'
            and common.exact_sha(value['object'].get('sha')))
    return value['object']['sha']


def context(api, event, env):
    inputs = local_guard(event, env)
    merge.trusted_repo(api.get(''))
    workflow = api.get('actions/workflows/protected-merge-qualification.yml')
    require(type(workflow) is dict and common.positive(workflow.get('id'))
            and workflow.get('path') == WORKFLOW and workflow.get('state') == 'active')
    run_id = merge.integer_env(env, 'GITHUB_RUN_ID')
    run = api.get('actions/runs/'+str(run_id))
    require(type(run) is dict and run.get('id') == run_id and type(run.get('id')) is int
            and type(run.get('run_attempt')) is int and run['run_attempt'] == 1
            and common.positive(run.get('run_number')) and run.get('workflow_id') == workflow['id']
            and run.get('path') == WORKFLOW and run.get('event') == 'workflow_dispatch'
            and run.get('head_sha') == env['GITHUB_SHA'] and run.get('head_branch') == 'main'
            and run.get('status') == 'in_progress' and run.get('conclusion') is None)
    for key in ('repository', 'head_repository'): merge.trusted_repo(run.get(key))
    for key in ('actor', 'triggering_actor'): merge.trusted_owner(run.get(key))
    main = api.get('git/ref/heads/main')
    require(type(main) is dict and main.get('ref') == 'refs/heads/main' and type(main.get('object')) is dict
            and main['object'].get('type') == 'commit' and main['object'].get('sha') == env['GITHUB_SHA'])
    number = merge.integer_env(inputs, 'pr_number')
    pr = api.get('pulls/'+str(number))
    require(type(pr) is dict and common.positive(pr.get('id')) and type(pr.get('number')) is int
            and pr['number'] == number and type(pr.get('node_id')) is str
            and re.fullmatch('[A-Za-z0-9_=-]{1,256}', pr['node_id'])
            and pr.get('state') == 'open' and pr.get('draft') is False and pr.get('merged') is False
            and pr.get('mergeable') is True)
    head, base = pr.get('head'), pr.get('base')
    require(type(head) is dict and type(base) is dict)
    merge.trusted_repo(head.get('repo')); merge.trusted_repo(base.get('repo'))
    fixed_target(base.get('ref'))
    require(head.get('sha') == inputs['head_sha'] and type(head.get('ref')) is str
            and 0 < len(head['ref']) <= 1024 and not re.search(r'[\x00-\x20\x7f]', head['ref'])
            and common.exact_sha(base.get('sha')) and base['sha'] == ref_sha(api)
            and head['sha'] != base['sha'])
    return {'case': inputs['case'], 'target': TARGET, 'pr_number': number, 'pr_id': pr['id'],
            'pr_node_id': pr['node_id'], 'head_sha': head['sha'], 'head_ref_sha256': common.digest(head['ref'].encode()),
            'base_sha': base['sha'], 'control_sha': env['GITHUB_SHA'], 'run_id': run_id}


class NativeCanaryClient:
    """One native Checks POST, fixed name/state from the two fixture cases only."""
    def __init__(self, token):
        merge.token_valid(token)
        self.token, self.used = token, False
        self.opener = urllib.request.build_opener(common.NoRedirect())

    def create(self, admitted):
        fixed_target(admitted.get('target'))
        case = admitted.get('case')
        require(not self.used and case in ('pending-canary', 'failed-canary')
                and common.exact_sha(admitted.get('head_sha')))
        body = {'name': CANARY, 'head_sha': admitted['head_sha'],
                'status': 'in_progress' if case == 'pending-canary' else 'completed'}
        if case == 'failed-canary': body['conclusion'] = 'failure'
        self.used = True  # Uncertain POSTs are never retried.
        request = urllib.request.Request('https://api.github.com/repos/'+merge.REPOSITORY+'/check-runs',
            data=canonical(body), method='POST', headers={'Authorization': 'Bearer '+self.token,
            'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
            'User-Agent': 'veyport-protected-merge-qualification', 'X-GitHub-Api-Version': '2022-11-28'})
        with self.opener.open(request, timeout=30) as response:
            require(response.status == 201)
            value = strict_json(response.read(common.MAX_JSON+1))
        require(type(value) is dict and common.positive(value.get('id')) and value.get('name') == CANARY
                and value.get('head_sha') == admitted['head_sha'] and value.get('status') == body['status']
                and value.get('conclusion') == body.get('conclusion') and type(value.get('app')) is dict
                and type(value['app'].get('id')) is int and value['app']['id'] == 15368)
        return value['id']


def produce_canary(api, event, env):
    require(env.get('GITHUB_JOB') == 'admission' and not env.get('PROTECTED_MERGE_TOKEN'))
    admitted = context(api, event, env)
    require(admitted['case'] != SETTINGS_DIAGNOSTIC)
    result = {'schema_version': 1, 'case': admitted['case'], 'target': TARGET,
              'head_sha': admitted['head_sha'], 'mutation_attempted': False, 'outcome': 'canary-not-requested'}
    if admitted['case'] not in ('pending-canary', 'failed-canary'): return result
    rows = common.pages(api, 'commits/'+admitted['head_sha']+'/check-runs?filter=all', 'check_runs')
    require(not any(row.get('name') == CANARY for row in rows))
    native_checks(rows, admitted['head_sha'])
    require(context(api, event, env) == admitted)
    writer = NativeCanaryClient(env.get('GITHUB_TOKEN'))
    result.update(mutation_attempted=True, outcome='canary-unconfirmed')
    try:
        check_id = writer.create(admitted)
    except ERRORS:
        return result
    return {**result, 'outcome': 'canary-created', 'check_run_id': check_id}


class FixtureReadClient(merge.AppReadClient):
    """Two literal fixture settings reads; all other reads use reviewed allowlist."""
    def get(self, path):
        allowed = ('branches/'+BRANCH_PATH+'/protection', 'rules/branches/'+BRANCH_PATH)
        if path not in allowed and not re.fullmatch(re.escape(allowed[1])+r'\?per_page=100&page=[1-9][0-9]?', path):
            return super().get(path)
        self.requests += 1
        require(self.requests <= 80 and time.monotonic() < self.deadline)
        request = urllib.request.Request('https://api.github.com/repos/'+merge.REPOSITORY+'/'+path,
            headers={'Authorization': 'Bearer '+self.token, 'Accept': 'application/vnd.github+json',
                     'User-Agent': 'veyport-protected-merge-qualification', 'X-GitHub-Api-Version': '2022-11-28'}, method='GET')
        with self.opener.open(request, timeout=min(30, self.deadline-time.monotonic())) as response:
            require(response.status == 200)
            raw = response.read(common.MAX_JSON+1)
        require(time.monotonic() < self.deadline)
        return strict_json(raw)


def _diagnostic_timeout(_signal, _frame):
    raise TimeoutError


@contextmanager
def diagnostic_read_deadline(seconds):
    """Bound the POSIX CLI's network I/O even if bytes keep arriving slowly."""
    previous = signal.signal(signal.SIGALRM, _diagnostic_timeout)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        finally:
            signal.signal(signal.SIGALRM, previous)


class DiagnosticReadClient:
    """Only the fixed settings GETs and one read-only GraphQL operation."""
    def __init__(self, token):
        merge.token_valid(token)
        self.token = token
        self.opener = urllib.request.build_opener(DiagnosticNoRedirect())
        self.deadline = time.monotonic() + 120
        self.requests = 0

    def get(self, path):
        return self._read(path=path)

    def graphql_fixture_ruleset(self, rule_id):
        return self._read(graphql_rule_id=rule_id)

    def _read(self, *, path=None, graphql_rule_id=None):
        if path is None:
            require(type(graphql_rule_id) is int and 0 < graphql_rule_id <= diagnostic.GRAPHQL_INT_MAX)
            route = 'graphql'
            body = canonical({'query': diagnostic.GRAPHQL_QUERY, 'variables': {'id': graphql_rule_id}})
        else:
            require(type(path) is str and graphql_rule_id is None)
            route, body = self._rest_route(path), None
        remaining = self.deadline - time.monotonic()
        if self.requests >= 7 or remaining <= 0:
            return {'result': 'budget-exhausted'}, None
        self.requests += 1
        request = urllib.request.Request('https://api.github.com/'+route, data=body,
            method='POST' if body is not None else 'GET', headers={'Authorization': 'Bearer '+self.token,
            'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
            'User-Agent': 'veyport-protected-merge-qualification', 'X-GitHub-Api-Version': '2022-11-28'})
        stage = {}
        timeout = min(DIAGNOSTIC_REQUEST_SECONDS, remaining)
        try:
            with diagnostic_read_deadline(timeout):
                try:
                    response = self.opener.open(request, timeout=timeout)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    status = response.code if isinstance(response, urllib.error.HTTPError) else response.status
                    if type(status) is int and 100 <= status <= 599:
                        stage['http_status'] = status
                    if type(status) is not int or status != 200:
                        return {**stage, 'result': 'http-error'}, None
                    # A bounded HTTPResponse.read can silently return fewer bytes than declared.
                    declared_length = getattr(response, 'length', None)
                    if declared_length is not None and declared_length > common.MAX_JSON:
                        return {**stage, 'result': 'validation-failed'}, None
                    raw = response.read(common.MAX_JSON+1)
                    if declared_length is not None and len(raw) != declared_length:
                        return {**stage, 'result': 'transport-error'}, None
            if time.monotonic() >= self.deadline:
                return {**stage, 'result': 'budget-exhausted'}, None
        except ERRORS:
            return {**stage, 'result': 'transport-error'}, None
        try:
            return {**stage, 'result': 'observed'}, strict_json(raw)
        except ValueError:
            return {**stage, 'result': 'validation-failed'}, None

    @staticmethod
    def _rest_route(path):
        if path == INSTALLATION_SCOPE_PATH or re.fullmatch(r'apps/[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?', path):
            return path
        rule = re.fullmatch(r'rulesets/([1-9][0-9]{0,9})', path)
        require(path in ('branches/main/protection', FIXTURE_CLASSIC_PATH, EFFECTIVE_RULES_PATH)
                or (rule and int(rule[1]) <= diagnostic.GRAPHQL_INT_MAX))
        return 'repos/'+merge.REPOSITORY+'/'+path


class DiagnosticNoRedirect(common.NoRedirect):
    def http_error_302(self, request, response, status, message, headers):
        # Let urllib's default handler report the original status without parsing Location.
        return None

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def validate_app_identity(app, app_id, slug, client):
    require(type(app) is dict and type(app.get('id')) is int and app['id'] == app_id
            and app.get('slug') == slug and app.get('client_id') == client
            and app.get('permissions') == merge.APP_PERMISSIONS)
    merge.trusted_owner(app.get('owner'))


def fixture_rule_identity(rule, rule_id):
    return (type(rule) is dict and type(rule.get('id')) is int and rule['id'] == rule_id
            and rule.get('source_type') == 'Repository' and rule.get('source') == merge.REPOSITORY)


def fixture_rule_conditions(rule):
    return rule.get('conditions') == {'ref_name': {'include': ['refs/heads/'+TARGET], 'exclude': []}}


def settings(reads, env, case):
    # Reuse exact identity validation without relaxing production protections.
    app_id, production_rule_id, slug, client = merge.protection_config(env)
    validate_app_identity(reads.get('apps/'+slug), app_id, slug, client)
    repos = common.pages(reads, 'installation/repositories', 'repositories')
    require(len(repos) == 1); merge.trusted_repo(repos[0])
    merge.validate_classic(reads.get('branches/main/protection'))
    if case == 'main-settings': return
    rule_id = merge.integer_env(env, 'PROTECTED_MERGE_QUALIFICATION_RULESET_ID')
    require(rule_id != production_rule_id)
    rule = reads.get('rulesets/'+str(rule_id))
    require(fixture_rule_identity(rule, rule_id)
            and rule.get('target') == 'branch' and rule.get('enforcement') == 'active'
            and fixture_rule_conditions(rule)
            and merge.exact_update_rules(rule.get('rules'))
            and canonical(rule.get('bypass_actors')) == canonical([{'actor_id': app_id, 'actor_type': 'Integration', 'bypass_mode': 'pull_request'}]))
    require(effective_update_matches(reads.get(EFFECTIVE_RULES_PATH), rule_id))
    classic = reads.get(FIXTURE_CLASSIC_PATH)
    if case in ('missing-canary', 'pending-canary', 'failed-canary'):
        # A single extra Actions canary; all original baseline fields retained.
        require(type(classic) is dict and type(classic.get('required_status_checks')) is dict)
        status = classic['required_status_checks']
        require(type(status.get('contexts')) is list and status['contexts'].count(CANARY) == 1
                and type(status.get('checks')) is list
                and status['checks'].count({'context': CANARY, 'app_id': 15368}) == 1)
        status['contexts'] = [name for name in status['contexts'] if name != CANARY]
        status['checks'] = [row for row in status['checks'] if row != {'context': CANARY, 'app_id': 15368}]
    merge.validate_classic(classic)


def effective_update_matches(value, rule_id):
    return merge.exact_update_rules(value, {'ruleset_id': rule_id,
            'ruleset_source_type': 'Repository', 'ruleset_source': merge.REPOSITORY})


def observe(response, inspect):
    stage, value = response
    if stage['result'] != 'observed':
        return stage
    try:
        predicates = inspect(value)
    except (KeyError, TypeError, ValueError):
        return {**stage, 'result': 'validation-failed'}
    if predicates is None:  # Successful exact validator.
        return {**stage, 'result': 'verified'}
    return {**stage, **predicates}


def validate_diagnostic_scope(value):
    # Exactly one installed repository must fit in the first page.
    require(type(value) is dict and type(value.get('total_count')) is int and value['total_count'] == 1
            and type(value.get('repositories')) is list and len(value['repositories']) == 1)
    merge.trusted_repo(value['repositories'][0])


def describe_fixture_rule(rule, rule_id, app_id):
    if not fixture_rule_identity(rule, rule_id):
        return {'result': 'validation-failed', 'identity_matches': False}
    enforcement = rule.get('enforcement')
    return {'identity_matches': True, 'branch_target_matches': rule.get('target') == 'branch',
            'conditions_match': fixture_rule_conditions(rule), 'restrictive_update_matches': merge.exact_update_rules(rule.get('rules')),
            'enforcement': enforcement if enforcement in ('active', 'disabled', 'evaluate') else 'unrecognized',
            **diagnostic.rest_bypass(rule, app_id)}


def describe_effective_rules(value, rule_id):
    require(type(value) is list and len(value) <= 100)
    return {'restrictive_update_matches': effective_update_matches(value, rule_id), 'empty': not value}


def settings_diagnostic(reads, env, admitted):
    """Collect settings observations after admission and exact App checks."""
    stages = {'admission': {'result': 'verified'}}
    result = {'schema_version': 1, 'outcome': 'diagnostic-refused', 'mutation_attempted': False,
              'evidence_scope': 'settings-visibility-only', 'stages': stages,
              **{key: admitted[key] for key in ('case', 'target', 'run_id', 'pr_number', 'head_sha', 'base_sha')}}
    try:
        app_id, production_rule_id, slug, client = merge.protection_config(env)
    except ValueError:
        stages['app_configuration'] = {'result': 'validation-failed'}
        return result
    stages['app_configuration'] = {'result': 'verified'}
    stages['app_identity'] = observe(reads.get('apps/'+slug),
        lambda value: validate_app_identity(value, app_id, slug, client))
    if stages['app_identity']['result'] != 'verified':
        return result
    stages['installation_scope'] = observe(reads.get(INSTALLATION_SCOPE_PATH), validate_diagnostic_scope)
    if stages['installation_scope']['result'] != 'verified':
        return result
    try:
        rule_id = merge.integer_env(env, 'PROTECTED_MERGE_QUALIFICATION_RULESET_ID')
        require(rule_id != production_rule_id and rule_id <= diagnostic.GRAPHQL_INT_MAX)
    except ValueError:
        stages['fixture_configuration'] = {'result': 'validation-failed'}
        return result
    stages['fixture_configuration'] = {'result': 'verified'}
    stages['main_classic'] = observe(reads.get('branches/main/protection'), merge.validate_classic)
    stages['fixture_ruleset'] = observe(reads.get('rulesets/'+str(rule_id)),
        lambda value: describe_fixture_rule(value, rule_id, app_id))
    stages['fixture_effective'] = observe(reads.get(EFFECTIVE_RULES_PATH),
        lambda value: describe_effective_rules(value, rule_id))
    stages['fixture_classic'] = observe(reads.get(FIXTURE_CLASSIC_PATH), merge.validate_classic)
    stages['graphql_bypass'] = {'sole_app_pr_only': False, **observe(reads.graphql_fixture_ruleset(rule_id),
        lambda value: diagnostic.graphql_bypass(value, merge.REPOSITORY, merge.REPOSITORY_ID, rule_id, app_id))}
    return {**result, 'outcome': 'diagnostic-collected'}


def native_checks(rows, sha):
    require(type(rows) is list and all(type(row) is dict for row in rows))
    for name in merge.CHECK_CONTEXTS:
        matches = [row for row in rows if row.get('name') == name]
        require(len(matches) == 1)
        row = matches[0]
        require(row.get('head_sha') == sha and row.get('status') == 'completed' and row.get('conclusion') == 'success'
                and type(row.get('app')) is dict and type(row['app'].get('id')) is int
                and row['app']['id'] == (57789 if name == 'CodeQL' else 15368))


def fixture_preflight(api, admitted):
    case, sha = admitted['case'], admitted['head_sha']
    if case == 'direct-push':
        commit = api.get('commits/'+sha)
        # Real fast-forward, non-no-op update. Divergence would test a different denial.
        require(type(commit) is dict and commit.get('sha') == sha
                and type(commit.get('parents')) is list and len(commit['parents']) == 1
                and type(commit['parents'][0]) is dict and commit['parents'][0].get('sha') == admitted['base_sha'])
    if case in ('native-merge', 'workflow-file-merge', 'missing-canary', 'pending-canary', 'failed-canary'):
        checks = common.pages(api, 'commits/'+sha+'/check-runs?filter=all', 'check_runs')
        native_checks(checks, sha)
        if case.endswith('canary'):
            found = [row for row in checks if row.get('name') == CANARY]
            if case == 'missing-canary': require(not found)
            else:
                require(len(found) == 1 and found[0].get('head_sha') == sha
                        and type(found[0].get('app')) is dict and found[0]['app'].get('id') == 15368)
                require((case == 'pending-canary' and found[0].get('status') in ('queued', 'in_progress') and found[0].get('conclusion') is None)
                        or (case == 'failed-canary' and found[0].get('status') == 'completed' and found[0].get('conclusion') == 'failure'))
    if case == 'workflow-file-merge':
        # Actual authenticated PR diff, bounded to 100 entries; no input claims.
        pr = api.get('pulls/'+str(admitted['pr_number']))
        require(type(pr) is dict and type(pr.get('changed_files')) is int and 0 < pr['changed_files'] < 100)
        files = api.get('pulls/'+str(admitted['pr_number'])+'/files?per_page=100&page=1')
        require(type(files) is list and len(files) == pr['changed_files']
                and all(type(row) is dict and type(row.get('filename')) is str for row in files)
                and any(row['filename'].startswith('.github/workflows/') for row in files))


class FixtureMutationClient:
    """Exactly one PATCH to the literal existing fixture, or exact PR merge PUT."""
    def __init__(self, token):
        merge.token_valid(token)
        self.token, self.used = token, False
        self.opener = urllib.request.build_opener(common.NoRedirect())

    def probe(self, admitted):
        fixed_target(admitted.get('target'))
        case = admitted.get('case')
        require(not self.used and case in WRITE_CASES
                and common.positive(admitted.get('pr_number'))
                and common.exact_sha(admitted.get('head_sha')) and common.exact_sha(admitted.get('base_sha'))
                and admitted['head_sha'] != admitted['base_sha'])
        if case == 'direct-push':
            method, path, body = 'PATCH', 'git/refs/heads/'+TARGET, {'sha': admitted['head_sha'], 'force': False}
        else:
            method, path = 'PUT', 'pulls/'+str(admitted['pr_number'])+'/merge'
            body = {'sha': admitted['base_sha'] if case == 'wrong-head' else admitted['head_sha'], 'merge_method': 'merge'}
        self.used = True
        request = urllib.request.Request('https://api.github.com/repos/'+merge.REPOSITORY+'/'+path,
            data=canonical(body), method=method, headers={'Authorization': 'Bearer '+self.token,
            'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
            'User-Agent': 'veyport-protected-merge-qualification', 'X-GitHub-Api-Version': '2022-11-28'})
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status, raw = response.code if isinstance(response, urllib.error.HTTPError) else response.status, response.read(common.MAX_JSON+1)
        value = strict_json(raw)
        require(type(value) is dict)
        return status, value


def classify(admitted, status, response, unchanged):
    case = admitted['case']; message = response.get('message', '') if type(response) is dict else ''
    outcome = 'unproven'
    if not unchanged: outcome = 'unexpected-update'
    elif case == 'wrong-head' and status == 409: outcome = 'head-mismatch-denied'
    elif case == 'direct-push' and status in (403, 422) and type(message) is str and 'GH013' in message and 'Cannot update this protected ref' in message:
        outcome = 'restriction-denied'
    elif case in ('missing-canary', 'pending-canary', 'failed-canary') and status == 405 and type(message) is str and re.search(r'required status checks?', message, re.I):
        outcome = 'canary-check-denied'
    return {'schema_version': 1, 'case': case, 'target': TARGET, 'run_id': admitted['run_id'],
            'pr_number': admitted['pr_number'], 'head_sha': admitted['head_sha'], 'base_sha': admitted['base_sha'],
            'http_status': status, 'outcome': outcome, 'merge_commit_sha': '',
            'mutation_attempted': True,
            'evidence_scope': 'general-check-blocking-only' if case.endswith('canary') else 'isolated-platform-primitive'}


def probe(api, reads, event, env):
    admitted = context(api, event, env)
    if admitted['case'] == SETTINGS_DIAGNOSTIC:
        return settings_diagnostic(reads, env, admitted)
    settings(reads, env, admitted['case'])
    if admitted['case'] == 'main-settings':
        result = classify(admitted, None, {}, True)
        return {**result, 'outcome': 'main-baseline-visible', 'mutation_attempted': False, 'evidence_scope': 'main-classic-and-app-identity-only'}
    fixture_preflight(api, admitted)
    require(context(api, event, env) == admitted)  # last request/head/base/owner reads
    token = env.get('PROTECTED_MERGE_TOKEN')
    merge.token_valid(token); require(token != env.get('GITHUB_TOKEN'))
    writer = FixtureMutationClient(token)
    status, response = None, {}
    try:
        status, response = writer.probe(admitted)
    except ERRORS:
        pass  # Only read-only reconciliation follows uncertain write; never retry.
    try:
        return reconcile(api.fresh_readonly(), admitted, status, response)
    except ERRORS:
        result = classify(admitted, status, response, True)
        return {**result, 'outcome': 'unconfirmed'}


def reconcile(api, admitted, status, response):
    current = api.get('pulls/'+str(admitted['pr_number']))
    require(type(current) is dict and current.get('id') == admitted['pr_id']
            and current.get('node_id') == admitted['pr_node_id'] and current.get('number') == admitted['pr_number']
            and type(current.get('base')) is dict and type(current.get('head')) is dict)
    merge.trusted_repo(current['base'].get('repo')); merge.trusted_repo(current['head'].get('repo'))
    fixed_target(current['base'].get('ref'))
    require(current['head'].get('sha') == admitted['head_sha']
            and type(current['head'].get('ref')) is str
            and common.digest(current['head']['ref'].encode()) == admitted['head_ref_sha256'])
    target = ref_sha(api)
    unchanged = (target == admitted['base_sha'] and current.get('merged') is False and current.get('state') == 'open')
    result = classify(admitted, status, response, unchanged)
    if admitted['case'] in ('native-merge', 'workflow-file-merge') and current.get('merged') is True and current.get('state') == 'closed':
        sha = current.get('merge_commit_sha'); require(common.exact_sha(sha) and target == sha)
        if common.exact_sha(response.get('sha')): require(response['sha'] == sha)
        commit = api.get('commits/'+sha)
        require(type(commit) is dict and commit.get('sha') == sha and type(commit.get('parents')) is list
                and len(commit['parents']) == 2
                and all(type(parent) is dict and common.exact_sha(parent.get('sha')) for parent in commit['parents'])
                and [parent['sha'] for parent in commit['parents']] == [admitted['base_sha'], admitted['head_sha']])
        result.update(outcome='native-merge-confirmed', merge_commit_sha=sha, evidence_scope='actual-twelve-native-producers-and-merge')
    return result


def main(argv=None):
    os.umask(0o077)
    class Parser(argparse.ArgumentParser):
        def error(self, message): self.exit(2, 'Qualification invalid command.\n')
    parser = Parser(description=__doc__); parser.add_argument('mode', choices=('admit', 'produce-canary', 'probe'))
    args = parser.parse_args(argv)
    try:
        env = os.environ
        event = strict_json(common.regular(Path(env.get('GITHUB_EVENT_PATH', '')), common.MAX_JSON))
        inputs = local_guard(event, env)  # refuses before constructing token clients or networking
        api = common.MetadataClient(env.get('GITHUB_TOKEN', ''))
        if args.mode == 'admit':
            require(not env.get('PROTECTED_MERGE_TOKEN'))
            admitted = context(api, event, env)
            merge.outputs({'admitted': 'true', 'case': admitted['case']}, env)
            return 0
        if args.mode == 'produce-canary':
            result = produce_canary(api, event, env)
            print(canonical(result).decode())
            return 0 if result['outcome'] in ('canary-created', 'canary-not-requested') else 1
        require(env.get('GITHUB_JOB') == 'probe')
        token = env.get('PROTECTED_MERGE_TOKEN'); merge.token_valid(token)
        require(token != env.get('GITHUB_TOKEN'))
        reader = DiagnosticReadClient if inputs['case'] == SETTINGS_DIAGNOSTIC else FixtureReadClient
        result = probe(api, reader(token), event, env)
        print(canonical(result).decode())
        if inputs['case'] == SETTINGS_DIAGNOSTIC:
            return 0 if result['outcome'] == 'diagnostic-collected' else 1
        return 0 if result['outcome'] in ('main-baseline-visible', 'head-mismatch-denied', 'restriction-denied', 'canary-check-denied', 'native-merge-confirmed') else 1
    except ERRORS:
        print(canonical({'schema_version': 1, 'outcome': 'refused', 'target': TARGET, 'mutation_attempted': False}).decode())
        return 1


if __name__ == '__main__':
    sys.exit(main())

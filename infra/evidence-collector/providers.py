"""Read-only provider diagnostics. These exports never authorize release or claim a new scan."""
import datetime as dt
from pathlib import Path
import re
from types import SimpleNamespace
import urllib.parse

CODEQL_PATH = 'dynamic/github-code-scanning/codeql'
CODEQL_KEY = CODEQL_PATH + ':analyze'
LANGUAGES = ('actions', 'go', 'javascript-typescript', 'python', 'ruby')


def engine(namespace):
    return SimpleNamespace(**namespace)


def diagnostic_run(e, config, run):
    e.require(isinstance(run, dict) and isinstance(run.get('repository'), dict) and run['repository'].get('full_name') == config['repository'] and run.get('path') == CODEQL_PATH and run.get('event') == 'dynamic', 'unexpected platform diagnostic workflow')
    e.require(type(run.get('id')) is int and run['id'] > 0 and type(run.get('run_attempt')) is int and run['run_attempt'] > 0 and isinstance(run.get('head_sha'), str) and e.SHA.fullmatch(run['head_sha']), 'invalid platform diagnostic identity')
    branch = run.get('head_branch', '')
    e.require(isinstance(branch, str) and 0 < len(branch) <= 240 and not any(x in branch for x in ('\x00', '\n', '\r', '?', '#')), 'invalid platform diagnostic ref')
    ref = branch if branch.startswith('refs/') else 'refs/heads/' + branch
    e.require(re.fullmatch(r'refs/(heads/[^\s]+|pull/[1-9][0-9]*/(head|merge)|tags/[^\s]+)', ref), 'unsupported platform diagnostic ref')
    return ref


def manifest(e, config, run, kind, files, details, suffix):
    value = {'schema': 1, 'repository': config['repository'], 'workflow': run['path'], 'run_id': run['id'], 'run_attempt': run['run_attempt'], 'revision': run['head_sha'], 'candidate_id': f"provider-{run['id']}-{run['run_attempt']}-{suffix}", 'complete': False, 'files': files,
             'details': {'kind': kind, 'source_trusted': False, 'platform_diagnostic': run['path'] == CODEQL_PATH, 'release_authority': False, **details}}
    return e.manifest_valid(value)


def save(e, config, api, archive, run, kind, payloads, details, suffix, extra_refs=()):
    blobs, files = {}, []
    for name, payload in sorted(payloads.items()):
        sha = e.digest(payload)
        blobs[sha] = payload
        files.append({'name': name, 'sha256': sha, 'size': len(payload)})
    m = manifest(e, config, run, kind, files, details, suffix)
    record = archive.save(m, blobs, run, {'id': None, 'digest': None}, config, source_trusted=False, collector_kind=kind, extra_refs=extra_refs)
    if not record['acknowledged']:
        e.publish_receipt(api, archive, record, config, public=False)
    return record


def job_contexts(e, api, run):
    contexts = {}
    for job in e.attempt_jobs(api, run):
        e.require(isinstance(job, dict) and isinstance(job.get('name'), str), 'invalid CodeQL attempt job metadata')
        match = re.fullmatch(r'Analyze \(([a-z][a-z0-9-]{0,63})\)', job.get('name', ''))
        if not match:
            continue
        e.require(job.get('run_id') == run['id'] and job.get('head_sha') == run['head_sha'] and type(job.get('id')) is int, 'CodeQL attempt job identity mismatch')
        category = '/language:' + match.group(1)
        e.require(category not in contexts, 'ambiguous CodeQL job context')
        start = e.timestamp(job['started_at']) if job.get('started_at') else None
        end = e.timestamp(job['completed_at']) if job.get('completed_at') else None
        contexts[category] = {'job_id': job['id'], 'started_at': start, 'completed_at': end, 'status': job.get('status'), 'conclusion': job.get('conclusion')}
    return contexts


def metadata_matches(e, item, run, ref, contexts):
    if not isinstance(item, dict) or item.get('commit_sha') != run['head_sha'] or item.get('ref') != ref:
        return False
    if not isinstance(item.get('tool'), dict) or item['tool'].get('name') != 'CodeQL' or item.get('analysis_key') != CODEQL_KEY:
        return False
    category = item.get('category')
    if category not in contexts:
        return False
    e.require(type(item.get('id')) is int and item['id'] > 0 and isinstance(item.get('environment'), str) and len(item['environment']) <= 16384, 'invalid CodeQL analysis metadata')
    environment = e.parse_json(item['environment'])
    if not isinstance(environment, dict) or environment.get('language') != category.removeprefix('/language:') or environment.get('category', category) != category:
        return False
    context = contexts[category]
    created = e.timestamp(item.get('created_at'))
    # Both timestamps come from GitHub. Do not borrow another attempt's same-SHA report.
    return bool(context['started_at'] and context['started_at'] <= created and (context['completed_at'] is None or created <= context['completed_at']))


def sarif_outcome(e, raw, item, repository, ref):
    issues = []
    try:
        sarif = e.parse_json(raw)
        runs = sarif.get('runs') if isinstance(sarif, dict) else None
        if sarif.get('version') != '2.1.0' or not isinstance(runs, list) or not 1 <= len(runs) <= 32:
            return ['invalid-sarif-schema']
        count = 0
        for run in runs:
            if run.get('tool', {}).get('driver', {}).get('name') != 'CodeQL':
                issues.append('sarif-tool-mismatch')
            expected = item['category'].rstrip('/') + '/'
            if run.get('automationDetails', {}).get('id') != expected:
                issues.append('sarif-context-mismatch')
            provenance = run.get('versionControlProvenance', [])
            if not any(x.get('revisionId') == item['commit_sha'] and x.get('branch') == ref and x.get('repositoryUri') in ('https://github.com/' + repository, 'https://github.com/' + repository + '.git') for x in provenance if isinstance(x, dict)):
                issues.append('sarif-source-mismatch')
            results = run.get('results')
            if not isinstance(results, list):
                issues.append('sarif-results-missing')
            else:
                count += len(results)
            for invocation in run.get('invocations', []):
                if invocation.get('executionSuccessful') is False:
                    issues.append('sarif-execution-failed')
                if any(note.get('level') in ('warning', 'error') for note in invocation.get('toolExecutionNotifications', [])):
                    issues.append('sarif-execution-warning-or-error')
        if count != item.get('results_count'):
            issues.append('sarif-result-count-mismatch')
    except (e.EvidenceError, ValueError, TypeError, KeyError, AttributeError):
        issues.append('invalid-sarif-payload')
    return sorted(set(issues))


def possible_other_runs(e, api, run, ref):
    # The provider exposes no workflow run ID. Detect known alternative owners rather than inventing one.
    route = '/actions/runs?event=dynamic&head_sha=' + run['head_sha'] + '&per_page=100&page=1'
    value = api.get(route)
    rows = value.get('workflow_runs') if isinstance(value, dict) else None
    e.require(isinstance(rows, list) and len(rows) < 100 and all(isinstance(x, dict) for x in rows), 'CodeQL run association inventory exceeds bound')
    others = []
    for other in rows:
        if other.get('id') == run['id'] or other.get('path') != CODEQL_PATH or other.get('head_sha') != run['head_sha']:
            continue
        if diagnostic_run(e, {'repository': run['repository']['full_name']}, other) != ref:
            continue
        others.append((e.timestamp(other['created_at']), e.timestamp(other['updated_at']) if other.get('status') == 'completed' else e.now() + dt.timedelta(minutes=5), other['id']))
    return others


def state_path(archive, run):
    return archive.root / 'state' / f"codeql-{run['id']}-{run['run_attempt']}.json"


def collect_codeql(namespace, config, api, archive, run):
    e = engine(namespace)
    ref = diagnostic_run(e, config, run)
    identity = {'repository': config['repository'], 'run_id': run['id'], 'run_attempt': run['run_attempt'], 'revision': run['head_sha'], 'ref': ref}
    path = state_path(archive, run)
    state = e.parse_json(path.read_bytes()) if path.exists() else {'identity': identity, 'next_page': 1, 'analyses': {}, 'discovery_complete': False}
    e.require(state.get('identity') == identity and isinstance(state.get('analyses'), dict) and len(state['analyses']) <= 64, 'CodeQL diagnostic checkpoint identity mismatch')
    e.require(type(state.get('done', False)) is bool and type(state.get('discovery_complete')) is bool and type(state.get('next_page')) is int and 1 <= state['next_page'] <= 101, 'invalid CodeQL diagnostic checkpoint')
    for key, item in state['analyses'].items():
        e.require(isinstance(key, str) and key.isdecimal() and isinstance(item, dict) and type(item.get('analysis_id')) is int and str(item['analysis_id']) == key and e.HEX.fullmatch(item.get('manifest_sha256', '')) and e.HEX.fullmatch(item.get('metadata_sha256', '')) and (item.get('sarif_sha256') is None or e.HEX.fullmatch(item['sarif_sha256'])), 'invalid CodeQL analysis checkpoint')
    if state.get('done'):
        return True
    if state.get('next_retry_at') and e.timestamp(state['next_retry_at']) > e.now():
        return False
    retry_seconds = config.get('codeql_retry_seconds', 300)
    pages_per_poll = config.get('codeql_pages_per_poll', 3)
    e.require(type(retry_seconds) is int and 60 <= retry_seconds <= 3600 and type(pages_per_poll) is int and 1 <= pages_per_poll <= 5, 'invalid CodeQL diagnostic retry budget')
    contexts = job_contexts(e, api, run)
    expected = sorted(contexts) or ['/language:' + x for x in LANGUAGES]
    problem = None
    retryable = False
    others = []
    try:
        others = possible_other_runs(e, api, run, ref)
        if state['discovery_complete'] or run.get('status') != 'completed':
            state['next_page'] = 1
            state['discovery_complete'] = False
        for _ in range(pages_per_poll):
            page = state['next_page']
            e.require(type(page) is int and 1 <= page <= 100, 'CodeQL provider pagination bound reached')
            route = '/code-scanning/analyses?tool_name=CodeQL&ref=' + urllib.parse.quote(ref, safe='') + f'&per_page=100&page={page}'
            rows = api.get(route)
            e.require(isinstance(rows, list) and len(rows) <= 100, 'invalid CodeQL analysis page')
            earliest = min((x['started_at'] for x in contexts.values() if x['started_at']), default=None)
            older = False
            for item in rows:
                if isinstance(item, dict) and item.get('created_at') and earliest and e.timestamp(item['created_at']) < earliest:
                    older = True
                if not metadata_matches(e, item, run, ref, contexts):
                    continue
                e.require(len(state['analyses']) < 64 or str(item['id']) in state['analyses'], 'CodeQL per-run analysis bound reached')
                old = state['analyses'].get(str(item['id']), {})
                fingerprint = e.digest(e.canonical(item))
                if old.get('metadata_sha256') == fingerprint and old.get('sarif_sha256') and old.get('payload_valid') is True:
                    continue
                payloads = {f"codeql/analysis-{item['id']}.json": e.canonical(item)}
                issues = []
                if item.get('warning'):
                    issues.append('provider-warning')
                if item.get('error'):
                    issues.append('provider-error')
                created = e.timestamp(item['created_at'])
                if any(start <= created <= end for start, end, _ in others):
                    issues.append('ambiguous-run-association')
                raw = None
                try:
                    raw = api.request(api.prefix + '/code-scanning/analyses/' + str(item['id']), raw=True, accept='application/sarif+json', max_bytes=e.MAX_FILE, allow_storage_redirect=False)
                    payloads[f"codeql/analysis-{item['id']}.sarif"] = raw
                    issues += sarif_outcome(e, raw, item, config['repository'], ref)
                except e.APIBudgetExceeded:
                    raise
                except e.EvidenceError:
                    issues.append('sarif-unavailable')
                    retryable = True
                details = {'provider': 'CodeQL', 'ref': ref, 'analysis_id': item['id'], 'category': item['category'], 'metadata_sha256': fingerprint, 'sarif_sha256': e.digest(raw) if raw is not None else None, 'payload_valid': raw is not None and not any(x in issues for x in ('invalid-sarif-schema', 'invalid-sarif-payload', 'sarif-tool-mismatch', 'sarif-context-mismatch', 'sarif-source-mismatch', 'sarif-results-missing', 'sarif-result-count-mismatch')), 'status': 'partial' if issues else 'collected', 'issues': sorted(set(issues)), 'binding': 'provider-revision-ref-context-and-attempt-job-window', 'provider_asserts_run_id': False}
                record = save(e, config, api, archive, run, 'codeql-analysis', payloads, details, str(item['id']))
                state['analyses'][str(item['id'])] = {'analysis_id': item['id'], 'category': item['category'], 'manifest_sha256': record['manifest_sha256'], 'metadata_sha256': fingerprint, 'sarif_sha256': details['sarif_sha256'], 'payload_valid': details['payload_valid'], 'status': details['status'], 'issues': details['issues']}
            state['next_page'] = page + 1
            if len(rows) < 100 or older:
                state['discovery_complete'] = True
                break
    except e.APIBudgetExceeded:
        with archive.lock():
            archive.write('state/' + path.name, e.canonical(state), replace=True)
        raise
    except e.EvidenceError as exc:
        problem = 'provider-permission-unavailable' if isinstance(exc, e.GitHubError) and exc.code in (401, 403) else 'provider-output-unavailable-or-bound-exceeded'
        retryable = True
    categories = {x['category'] for x in state['analyses'].values() if x.get('sarif_sha256') and x.get('payload_valid') is True}
    missing = sorted(set(expected) - categories)
    retryable = retryable or any(not x.get('sarif_sha256') or x.get('payload_valid') is not True for x in state['analyses'].values()) or bool(missing) or not state['discovery_complete'] or run.get('status') != 'completed'
    complete = not retryable
    payloads, references = {}, set()
    for item in state['analyses'].values():
        records = [x for x in archive.records() if x['manifest_sha256'] == item['manifest_sha256'] and x['run_id'] == run['id'] and x['run_attempt'] == run['run_attempt']]
        e.require(len(records) == 1, 'CodeQL diagnostic child manifest unavailable')
        child = records[0]
        raw = e.age_decrypt((archive.root / 'manifests' / (child['manifest_sha256'] + '.age')).read_bytes(), config['identity_file'])
        e.require(e.digest(raw) == child['manifest_sha256'], 'CodeQL diagnostic child manifest integrity failure')
        payloads[f"codeql/analysis-{item['analysis_id']}.manifest.json"] = raw
        references.update(child['blobs'])
    details = {'provider': 'CodeQL', 'ref': ref, 'analysis_key': CODEQL_KEY, 'status': 'collected' if complete and all(x['status'] == 'collected' for x in state['analyses'].values()) else 'partial', 'discovery_complete': state['discovery_complete'], 'expected_categories': expected, 'missing_categories': missing, 'analyses': sorted(state['analyses'].values(), key=lambda x: x['analysis_id']), 'missing': [problem] if problem else [], 'provider_asserts_run_id': False, 'binding': 'provider-revision-ref-context-and-attempt-job-window'}
    save(e, config, api, archive, run, 'codeql-summary', payloads, details, 'summary', extra_refs=references)
    # Code scanning retention is independent of temporary Actions artifacts. Age alone never resolves missing SARIF.
    attempts = state.get('retry_count', 0)
    e.require(type(attempts) is int and 0 <= attempts <= 1000000, 'invalid CodeQL retry checkpoint')
    state['retry_count'] = 0 if complete else attempts + 1
    state['done'] = complete
    state['next_retry_at'] = e.iso(e.now() + dt.timedelta(seconds=min(3600, retry_seconds * (2 ** min(attempts, 4)))))
    with archive.lock():
        archive.write('state/' + path.name, e.canonical(state), replace=True)
    return state['done']


def safe_reference(url):
    if not isinstance(url, str) or len(url) > 4096 or any(ord(x) < 32 for x in url):
        return None
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.username or parsed.password or not parsed.hostname or parsed.port not in (None, 443):
            return None
        # Keep vendor path identity but never signed queries, bearer fragments or embedded credentials.
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))
    except ValueError:
        return None


def collect_snyk_statuses(namespace, config, api, archive, run):
    e = engine(namespace)
    route = '/commits/' + run['head_sha'] + '/statuses?per_page=100&page=1'
    try:
        rows = api.get(route)
        e.require(isinstance(rows, list) and len(rows) <= 100, 'invalid commit status response')
        selected = []
        for item in rows:
            if not isinstance(item, dict) or 'snyk' not in str(item.get('context', '')).lower():
                continue
            creator = item.get('creator') if isinstance(item.get('creator'), dict) else {}
            selected.append({'id': item.get('id'), 'context': item.get('context'), 'state': item.get('state'), 'description': e.sanitize_job_log(str(item.get('description') or '').encode()).decode(), 'target_reference': safe_reference(item.get('target_url')), 'created_at': item.get('created_at'), 'updated_at': item.get('updated_at'), 'creator': {'id': creator.get('id'), 'login': creator.get('login')}})
        status = 'status-reference-only' if selected else 'no-statuses-in-bounded-snapshot'
        details = {'provider': 'Snyk', 'status': status, 'association': 'commit-sha-only-not-run-or-complete-vendor-history', 'full_scm_report_exported': False, 'snapshot_truncated': len(rows) == 100}
        payloads = {'providers/snyk-statuses.json': e.canonical(selected)}
    except e.APIBudgetExceeded:
        raise
    except e.EvidenceError:
        details, payloads = {'provider': 'Snyk', 'status': 'unavailable', 'association': 'commit-sha-only-not-run-or-complete-vendor-history', 'full_scm_report_exported': False, 'missing': ['github-commit-status-snapshot']}, {}
    return save(e, config, api, archive, run, 'provider-status', payloads, details, 'snyk-statuses')

#!/usr/bin/env python3
"""Opaque owner-intent descriptors; no private policy or publication authority.

Only independently installed current-main tooling may prepare/verify these.
The artifact proves an original protected owner dispatch for four public fields.
It does not establish the private bundle's meaning, current state, finding age,
retention, a release exception, or any downstream consumer's qualification.
"""
import datetime as dt
import io
import os
from pathlib import Path
import re
import stat
import zipfile

import risk_acceptance as risk

WORKFLOW = '.github/workflows/private-risk-approval.yml'
LEGACY_WORKFLOW = '.github/workflows/risk-approval.yml'
TRUSTED_FILES = (WORKFLOW, LEGACY_WORKFLOW, 'scripts/release/private_descriptor.py', 'scripts/release/risk_acceptance.py')
FIELDS = {'id', 'status', 'expires_at', 'bundle_sha256'}
canonical = risk.canonical


class ApprovalError(ValueError):
    """Disclosure-safe validation failure; private inputs never enter errors."""


def require(value):
    if not value:
        raise ApprovalError('private approval unavailable')


def timestamp(value):
    try:
        return risk.timestamp(value)
    except (ValueError, TypeError, OverflowError):
        raise ApprovalError('private approval unavailable') from None


def public_descriptor(bundle_id, bundle_sha256, expires_at):
    require(isinstance(bundle_id, str) and re.fullmatch(r'review-[a-f0-9]{32}', bundle_id))
    require(isinstance(bundle_sha256, str) and re.fullmatch(r'[a-f0-9]{64}', bundle_sha256))
    timestamp(expires_at)
    return {'id': bundle_id, 'status': 'approved', 'expires_at': expires_at, 'bundle_sha256': bundle_sha256}


def local_bytes(path):
    # Fixed reviewed paths only. Refuse a substituted link/nonregular/oversized
    # file before reading; never import or execute candidate-controlled tooling.
    require(path in TRUSTED_FILES)
    root = Path(__file__).resolve().parents[2]
    fd = os.open(root / path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= risk.MAX_BYTES)
        raw = source.read(risk.MAX_BYTES + 1)
        require(len(raw) <= risk.MAX_BYTES)
        return raw


def trusted_private_run(api, run_id, completed=True):
    require(type(run_id) is int and run_id > 0)
    run, repo = api.get(f'actions/runs/{run_id}'), api.get('')
    owner = repo.get('owner', {})
    require(repo.get('full_name') == risk.REPOSITORY and repo.get('default_branch') == 'main')
    require(owner.get('login') == risk.OWNER_LOGIN and owner.get('id') == risk.OWNER_ID and owner.get('type') == 'User')
    require(run.get('id') == run_id and run.get('repository', {}).get('full_name') == risk.REPOSITORY)
    require(run.get('event') == 'workflow_dispatch' and run.get('path') == WORKFLOW and run.get('head_branch') == 'main' and type(run.get('run_attempt')) is int and run['run_attempt'] == 1)
    for key in ('actor', 'triggering_actor'):
        actor = run.get(key, {})
        require(actor.get('id') == risk.OWNER_ID and actor.get('login') == risk.OWNER_LOGIN and actor.get('type') == 'User')
    require(isinstance(run.get('head_sha'), str) and re.fullmatch(r'[a-f0-9]{40}', run['head_sha']))
    require(run.get('status') == ('completed' if completed else 'in_progress'))
    if completed:
        require(run.get('conclusion') == 'success')
    require(api.get('compare/' + run['head_sha'] + '...main').get('status') in ('ahead', 'identical'))
    for path in TRUSTED_FILES:
        current = api.content(path, 'main')
        require(isinstance(current, bytes) and len(current) <= risk.MAX_BYTES)
        require(api.content(path, run['head_sha']) == current and local_bytes(path) == current)
    environment = api.get('environments/' + risk.ENVIRONMENT)
    require(type(environment.get('id')) is int and environment['id'] > 0 and environment.get('name') == risk.ENVIRONMENT)
    rules = [rule for rule in environment.get('protection_rules', []) if rule.get('type') == 'required_reviewers']
    require(len(rules) == 1 and rules[0].get('prevent_self_review') is False)
    reviewers = rules[0].get('reviewers', [])
    require(len(reviewers) == 1 and reviewers[0].get('type') == 'User' and reviewers[0].get('reviewer', {}).get('id') == risk.OWNER_ID)
    branches = api.get('environments/' + risk.ENVIRONMENT + '/deployment-branch-policies')
    require(environment.get('deployment_branch_policy') == {'protected_branches': False, 'custom_branch_policies': True})
    require([(item.get('name'), item.get('type')) for item in branches.get('branch_policies', [])] == [('main', 'branch')])
    # Current protection alone cannot prove this run required owner review.
    # The documented run-scoped history includes state/user/environments, not
    # review timestamps or attempt IDs. Original attempt1 is enforced above.
    # This workflow has one job/environment: extra reviews are ambiguous and
    # fail closed rather than guessing ordering or accepting a later approval.
    # https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run
    history = api.get(f'actions/runs/{run_id}/approvals')
    require(isinstance(history, list) and len(history) == 1)
    review = history[0]
    require(isinstance(review, dict) and review.get('state') == 'approved')
    reviewer = review.get('user', {})
    require(reviewer.get('id') == risk.OWNER_ID and reviewer.get('login') == risk.OWNER_LOGIN and reviewer.get('type') == 'User')
    reviewed = review.get('environments')
    require(isinstance(reviewed, list) and len(reviewed) == 1 and isinstance(reviewed[0], dict))
    require(type(reviewed[0].get('id')) is int and reviewed[0]['id'] == environment['id'] and reviewed[0].get('name') == risk.ENVIRONMENT)
    return run


def prepare_private(api, bundle_id, bundle_sha256, expires_at, run_id, at=None):
    """Workflow-only owner intent. Accept no record, LAN path or policy data."""
    try:
        at = at or risk.now()
        descriptor = public_descriptor(bundle_id, bundle_sha256, expires_at)
        require(at < timestamp(expires_at) <= at + dt.timedelta(days=90))
        run = trusted_private_run(api, run_id, completed=False)
        created = timestamp(run.get('created_at'))
        require(created <= at and at - created <= dt.timedelta(days=1))
        return descriptor
    except Exception:
        raise ApprovalError('private approval unavailable') from None


def verify_private_descriptor(api, descriptor, run_id, at=None):
    """Revalidate the original live artifact; this is never a release decision."""
    try:
        at = at or risk.now()
        require(isinstance(descriptor, dict) and set(descriptor) == FIELDS)
        expected = public_descriptor(descriptor['id'], descriptor['bundle_sha256'], descriptor['expires_at'])
        require(descriptor == expected and at < timestamp(descriptor['expires_at']))
        run = trusted_private_run(api, run_id)
        require(timestamp(run.get('created_at')) <= at)
        result = api.get(f'actions/runs/{run_id}/artifacts?per_page=100')
        count, artifacts = result.get('total_count'), result.get('artifacts')
        require(type(count) is int and 0 <= count <= 100 and isinstance(artifacts, list) and len(artifacts) == count)
        matches = [item for item in artifacts if item.get('name') == 'ssdf-private-approval-' + descriptor['id']]
        require(len(matches) == 1)
        artifact = matches[0]
        require(artifact.get('expired') is False and type(artifact.get('id')) is int and artifact['id'] > 0)
        require(type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= risk.MAX_BYTES)
        raw = api.get(f"actions/artifacts/{artifact['id']}/zip", raw=True)
        require(isinstance(raw, bytes) and len(raw) <= risk.MAX_BYTES)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            require(len(entries) == 1 and entries[0].filename == 'approval.json' and entries[0].file_size <= 65536)
            require(not entries[0].flag_bits & 1 and stat.S_IFMT(entries[0].external_attr >> 16) in (0, stat.S_IFREG))
            archived = risk.strict_json(archive.read(entries[0]))
        require(archived == expected)
        return expected
    except Exception:
        raise ApprovalError('private approval unavailable') from None

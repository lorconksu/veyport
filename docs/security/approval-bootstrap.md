# Trusted approval bootstrap

This bootstrap installs `.github/workflows/private-risk-approval.yml` and the
descriptor-only `scripts/release/private_descriptor.py` on trusted `main`. It
retires the public Markdown proposal workflow and operational CLI preparation;
historical record parsing and validation remain available. It imports no proposal
or approval and approves no finding, source coverage review, or policy exception.
The helper uses only Python's standard library and the existing
`scripts/release/risk_acceptance.py`; existing risk policy constants are unchanged.

## Protected owner decision

Before any use, the repository owner must verify the `ssdf-risk-approval`
environment has exactly one required reviewer: user `lorconksu` (ID `13374789`).
Sole-owner self-review must be allowed (`prevent_self_review: false`). Use custom
deployment branch policies with exactly `main` of type `branch`; protected-branch
mode must be off. An automatically created, unprotected environment is rejected.
This document does not authorize changing provider settings or dispatching runs.

After the reviewed bootstrap lands, the owner must review the complete private
bundle independently, then dispatch `private-risk-approval.yml` on `main` with
only its opaque `bundle_id`, exact `bundle_sha256`, and UTC `expires_at`. The owner
must also approve the protected environment gate for that original run. The
workflow fetches no private proposal or LAN content. Its public artifact contains
exactly `id`, `status`, `expires_at`, and `bundle_sha256`; `status: approved` records
owner intent for those bytes, not a release-policy decision. Do not dispatch the
retired `risk-approval.yml` or publish records, reasons, findings, or support files.

Preparation and verification require exact owner identity, first-attempt manual
dispatch, trusted main history, unchanged original/current-main/local workflow
and helper bytes, bounded expiry, and one recorded owner environment approval
for this exact run and current environment ID/name. Current protections alone
are insufficient. Verification also requires the original successful run and
its matching artifact. Missing, unavailable, rejected, or ambiguous review
history fails closed. A rerun, descriptor file alone, or successful CI grants no
authority. Changes to any pinned file require renewed explicit approval.

The read-only workflow token grants `contents: read` and `actions: read`.
GitHub documents Actions read access for [getting an environment](https://docs.github.com/en/rest/deployments/environments#get-an-environment),
[listing deployment branch policies](https://docs.github.com/en/rest/deployments/branch-policies#list-deployment-branch-policies),
and [reading a run's review history](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run).
These public read endpoints do not require an administration token. The history
schema supplies reviewer, state and environments; it supplies no review timestamp
or attempt field, so the verifier independently enforces original run attempt 1.

Private LAN policy evaluation, hosted consumption, retention, current bundle
state/revocation checks and release qualification remain unqualified. A descriptor
does not resolve unknown finding discovery dates or authorize a temporary policy
exception. Any downstream consumer must use independently installed trusted
tooling and receive its own review and qualification before activation.

## Publication hold and restoration

The existing `auto-release` job in `.github/workflows/ci.yml` has an unconditional hold:
leading `false &&` in its job condition. This prevents that job from creating a
patch tag or dispatching `release.yml`, including for the bootstrap merge. This
bootstrap does not change CI, release workflows, or that existing hold. Every existing CI test and
security gate remains required and runs normally. The hold remains across later
main pushes until removed by a reviewed PR; there is no automatic expiry.

The existing tag-triggered and manually dispatched Release workflow is unchanged.
Do not create release tags or dispatch it as part of this bootstrap. The hold
does not block a separately initiated release or cancel any previously running
release; verify there is no publication already in flight before merging.

Keep the hold while obtaining authenticated owner decisions and completing the
reviewed qualification for PR #115. Record the exact qualified revision, current
approval validity, required CI/security results, and publication readiness in the
restoration PR. Restoration requires a separately reviewed decision to publish;
the bootstrap merge and owner policy decisions do not supply that authorization.

In that PR, remove the leading `false &&` to restore this job guard and update its
assertion in `scripts/release/test_ci_source_identity.py` to require the restored
guard:

```yaml
if: github.event_name == 'push' && github.ref == 'refs/heads/main'
```

Remove the temporary hold comments, run release/approval helper tests and
`actionlint`, and satisfy all normal required checks and reviews. Treat the
restoration merge as a publication action: its successful main CI run will create
and dispatch the next patch release. If qualification is incomplete, leave the
hold in place; do not substitute skipped CI, a commit-message bypass, or weaker
approval/environment requirements.

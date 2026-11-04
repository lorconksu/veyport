# Trusted approval bootstrap

This change establishes the approval workflow and verifier on `main` without
publishing a release. It does not approve any proposed risk acceptance or source
coverage review. No proposal or approval descriptor is imported by the bootstrap.
The two trusted files are copied unchanged from PR #115 at
`16ef34879397d9f5e1ac08a9c3c0c9dd0aaa148a`:

| File | SHA256 |
| --- | --- |
| `.github/workflows/risk-approval.yml` | `863d4c40b8022e49358ebc6eea5df5352706049cf33266d828194a36c87979f5` |
| `scripts/release/risk_acceptance.py` | `2ddfc8f26c9088c8deb68e4ffe2c120a133f84a041fc533c2698eec917151b1e` |

## Protected owner decision

Before any use, the repository owner must verify the `ssdf-risk-approval`
environment has exactly one required reviewer: user `lorconksu` (ID `13374789`).
Sole-owner self-review must be allowed (`prevent_self_review: false`). Use custom
deployment branch policies with exactly `main` of type `branch`; protected-branch
mode must be off. An automatically created, unprotected environment is rejected.
This document does not authorize changing provider settings or dispatching runs.

After the reviewed bootstrap lands, each decision requires the owner to review
the full proposed Markdown record and its exact scope, then dispatch
`risk-approval.yml` on `main` with its record ID, immutable 40-character record
revision, and SHA256 of the entire record. Fetching a proposal at that revision
reads its bytes without executing its code. The owner must also approve the
protected environment gate. A new or expanded scope needs a new explicit decision.
Coverage reviews bind an exact inventory hash; they do not approve findings.

The verifier requires owner identity, first-attempt manual dispatch, trusted main
history, unchanged workflow/helper bytes, exact record and scope hashes, a bounded
validity window, and a matching artifact from the successful run. A rerun,
descriptor file alone, or successful CI does not grant approval. Changing either
trusted file invalidates earlier approvals while its bytes differ from `main`;
renew explicit approvals rather than assuming they survive an implementation change.

## Publication hold and restoration

The `auto-release` job in `.github/workflows/ci.yml` has an unconditional hold:
leading `false &&` in its job condition. This prevents that job from creating a
patch tag or dispatching `release.yml`, including for the bootstrap merge. Every existing CI test and
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

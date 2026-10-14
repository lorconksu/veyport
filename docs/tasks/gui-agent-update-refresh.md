# GUI agent update refresh regression

Date: 2026-10-14
Status: Implemented; local frontend and browser validation complete. Ordered code
and security reviews passed; PR checks are tracked on the PR.

## Problem and scope

After the GUI accepted an update, it refreshed the fleet while the operation was
still requested. Subsequent verified completion did not refresh fleet version,
availability, or the confirmation check. A closed dialog also retained a pending
attempt that overrode later terminal availability.

Refresh those server-backed views automatically without reloading the page or
reporting success before durable exact-artifact confirmation. Preserve paginated
fleet reads, three availability workers, hidden-tab cancellation, identity-scoped
state, and single-dispatch POST behavior.

## Implementation tasks

- [x] [C:complex] Refresh fleet, page availability, and dialog confirmation once
  for each validated terminal operation/state observed in a visible open dialog.
- [x] [C:complex] Include reported agent version in the page availability key so
  normal fleet polling rechecks a node after its reported version changes.
- [x] [C:complex] Let validated same-operation, same-artifact terminal availability
  supersede the row's retained pending attempt after closing the dialog.
  Uncertain POST attempts remain blocking until reopened status inspection.
- [x] [C:complex] Regress visible version/availability/confirmation updates with
  the dialog open and closed, pending states, non-success terminal outcomes,
  same-version rebuilds, mismatched operations/artifacts, and lost POST responses.
- [x] [C:standard] Document automatic refresh and uncertainty behavior.
- [x] Run focused coverage, TypeScript, production build, full frontend coverage,
  and changed-file lint; verify unrelated full-lint failures against the base.
- [x] Run a built-browser fixture with intercepted APIs.
- [x] Independent code review followed by a separate security review.
- Required PR CI checks are tracked on the PR.

## Constitution check

Read the local constitution at
`/home/wyiu/personal/veyport/.specify/memory/constitution.md` (1.5.0).
This bounded frontend bugfix introduces no dependencies, new polling loops,
protocol changes, authentication changes, or remote agent mutations. Tests first
reproduced the three stale-state paths against the prior implementation.

## Model tier record

Provider: OpenAI. Official model catalog and active runtime verified by the
orchestrator on 2026-10-14: [OpenAI API models](https://developers.openai.com/api/docs/models).
Complex implementation, regression tests, and accompanying documentation:
`gpt-6.1-sol`, reasoning effort `high` (grouped under the highest task tier).
Standard browser fixture: `gpt-6-luna`, reasoning effort `high`.

## Validation evidence

Before the fix, the regression suite failed for open-dialog completion,
closed-dialog completion following a reported version change, and closed-dialog
availability polling with no version change.

- Focused frontend coverage: 63 tests passed (46 dashboard update tests and 17
  update API tests).
- Full frontend coverage: 766 tests across 47 files passed; 94.98% lines and
  88.20% branches, compared with the prior recorded 94.96% and 88.12%.
- `npx tsc --noEmit`, production build, lint for the four changed TypeScript
  files, and `git diff --check` passed.
- Full `npm run lint` reports 23 errors and two warnings in 15 unchanged files.
  An isolated archive of the exact base commit using the same dependencies
  reproduces those 23 errors and two warnings; no changed file has a finding.
- The isolated built-browser fixture passed with 41 intercepted API requests.
  Both rows changed from v2.0.50 to v2.0.51 and **Up to date**, with the dialog
  open and closed. It issued one document request, used no manual refresh or
  reload, sent exactly two explicitly confirmed single-node update POSTs, and
  encountered no unexpected routes or page errors. No real agent was updated.
- Independent code review passed, followed by a separate security review with
  no open findings. The reviewer independently ran all 11 new regression cases
  successfully and verified the browser helper, raw/result output, and both
  screenshot hashes against the supplied evidence.
- PR checks are tracked on the PR. This record does not claim staging or
  deployment validation.

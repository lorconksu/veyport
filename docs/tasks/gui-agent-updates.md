# GUI agent updates: spec, plan, and tasks

Date: 2026-10-13
Status: Implemented; local validation complete. Required CI remains pending in the PR.

## Specification

Add an admin-only action in the **Agent Version** cell of each eligible server
row in the Fleet Dashboard. Show **Update available**, **Up to date**, **Manual
upgrade required**, or **Update unsupported** according to the Hub check. An
administrator can review the node, current and target versions, confirm an
update for one node, and follow that operation's progress and result from the
dashboard. An update is always scoped to one row; selection and bulk actions
must never start updates for multiple nodes.

The fleet table loads 25 nodes per page. Select-all applies only to the current
page, and page, filter, or search changes clear the selection.

Use the existing authenticated agent-update check, start, and status APIs. The
Hub selects the verified artifact for the enrolled node, so the interface must
not imply that it installs the newest release directly from GitHub. Require a
live interactive administrator session. If the Hub reports active or uncertain
node work, fail safely: do not start the update and show that the administrator
should wait and retry. Report success only after the enrolled agent reconnects
and confirms the exact target artifact. Preserve operation status across closing
and reopening the update dialog and after a full page reload, including when the
node is offline. Show failed or uncertain states with a path to inspect status
before retrying.

Do not add a GUI shortcut for legacy bootstrap. Where an older agent requires a
bootstrap idle assertion, continue to require the documented direct-SSH
procedure; the GUI must not assert that the node is idle on the administrator's
behalf. Preserve existing install and re-enrollment flows.

## Plan

Build the fleet-row action and confirmation/progress flow on the existing Hub
API contract. Keep update state tied to its node and durable operation ID, and
refresh status while the dashboard is open. Document eligibility, single-node
scope, activity refusal, reconnect verification, and recovery in the Fleet
Dashboard guide; point to Deployment and CLI for the complete legacy and
recovery procedures. Fetch the latest operation status before enabling a new
update. Keep monitoring while the dialog is open; closing and reopening or
reloading the page retrieves the latest durable operation, including offline
nodes. Status inspection must not resubmit or restart an operation.

## Acceptance criteria

- Only admins can start an update, and only for one eligible enrolled node.
- The confirmation identifies the node and current and Hub-selected target
  versions, and warns that the agent restarts.
- Existing server selection and unregister bulk actions cannot trigger updates.
- The fleet list shows 25 nodes per page; select-all applies only to that page,
  and page/filter/search changes clear selection.
- The Hub remains authoritative for eligibility, idle/activity checks, target
  artifact, and update outcome.
- Active or unconfirmed node work blocks start without being treated as idle.
- The UI displays progress and durable terminal outcomes; success requires
  verified reconnect and target-artifact confirmation.
- The update UI can inspect an operation without resubmitting it; unknown
  outcomes remain blocking until reconciled through the documented recovery
  process. Closing/reopening the dialog or reloading the page recovers the
  latest status, even if the node is offline.
- Legacy bootstrap keeps its direct-SSH flow and explicit idle assertion; no GUI
  assertion is introduced.

## Constitution check

Checked the applicable local constitution at
`/home/wyiu/personal/veyport/.specify/memory/constitution.md` (version 1.5.0;
ignored and therefore absent from this isolated checkout). The feature follows
Principles I–IV and the security constraints: it uses existing frontend
dependencies and design patterns, the existing authenticated Hub update API,
explicit loading/error states and confirmation, and the Hub-selected artifact.
No dependency, protocol, or authentication changes are planned. Principle II
requires appropriate frontend tests; use existing API contract coverage and an
isolated browser fixture for the user-visible update flow. No constitution
deviation is identified.

## Validation tasks

- [x] Frontend tests cover admin visibility, status labels, single-node
  confirmation, target version, progress/status transitions, failed or unknown
  operations, and that inspection never starts or retries an update.
- [x] Frontend tests prove selected-row or select-all bulk actions cannot start
  agent updates and that viewers cannot start one.
- [x] API/UI behavior handles active or unconfirmed work as a safe refusal and
  never displays success before verified reconnect.
- [x] Run the relevant frontend tests and production build; run focused Hub/API
  checks if implementation changes the existing API contract.
- [x] Review the dashboard and deployment docs against the final UI labels and
  behavior.

## Local validation evidence

- Full frontend suite: 755 tests across 47 files passed; coverage was 94.96%
  lines and 88.12% branches. The initial focused frontend run passed 92 tests;
  TypeScript and lint checks passed, and the production build passed.
- Existing Hub REST agent-update tests passed (37.133 s), as did four focused
  gRPC updater regression tests (13.818 s).
- The isolated built-browser fixture passed with 53 intercepted API requests,
  exactly one confirmed update POST, and no viewer update requests. It checked
  the update stages, cancellation, failure and unknown handling, and latest
  operation recovery after a full reload while offline. No real agent was
  restarted or remotely mutated.
- Code and security review passed after all findings were fixed. CI checks remain
  pending for the PR; this artifact does not claim they have passed.

## Model tier record

Runtime verified 2026-10-13. Model catalog: [OpenAI API models](https://developers.openai.com/api/docs/models).
Task tiers: `[C:complex]` for update orchestration, authority/state tests, and
review; `[C:standard]` for documentation and the isolated browser fixture.

- Complex implementation: `gpt-6.1-sol`, reasoning effort `xhigh`.
- Standard documentation and browser-fixture work: `gpt-6-luna`, reasoning
  effort `high`.

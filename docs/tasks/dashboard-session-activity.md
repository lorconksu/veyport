# Bug task: dashboard activity and idle logout

Date: 2026-10-09
Issue: [#90](https://github.com/lorconksu/veyport/issues/90)
Status: Implemented and locally validated; awaiting PR review

## Problem

A user working in a visible dashboard was signed out for inactivity while adding
a node. Browser interaction did not independently reach the Hub's request-based
session clock. A stalled server-list request was reproduced preventing subsequent
React Query polling; the original incident's precise cause remains unproven.

## Fix

The signed-in app shell captures keyboard, pointer, input, touch, and scroll events,
including those inside dialogs. Recent visible-tab interaction sends an authenticated
`HEAD /api/auth/me` check independently of data polling, at most once per 15 seconds.
HEAD validates and touches the session without downloading profile or avatar data.
Checks stop after 30 seconds without interaction or when the tab is hidden.
Returning to a visible tab alone does not start checks.

Activity requests and shared token refresh have ten-second network deadlines.
Network failures allow a later active check to retry; cancelled callers do not
retry or redirect after a shared refresh. The Hub continues to enforce idle,
absolute-expiry, and revocation checks. An expired session cannot be revived.

## Validation

- Full frontend coverage suite: 607 tests passed; the activity hook has 100%
  statement, branch, function, and line coverage.
- Frontend production build passed. Targeted ESLint has no errors and one
  existing AppShell memo dependency warning.
- Hub session lifecycle tests passed, including a real HTTP HEAD regression
  verifying activity updates, an empty response body, and refusal after idle expiry.
- Regression tests cover modal event capture, throttling, unattended and hidden
  tabs, pending-request cancellation and retry, and recovery after stalled refresh.
- Real-browser validation held the server-list request pending: opening and typing
  in Add Server still sent HEAD checks, which stopped when interaction ended.
- The Hub HEAD regression passed five repetitions with the race detector.

## Limits

Authenticated data polling still updates the Hub's session clock and can keep an
unattended visible tab alive until its absolute lifetime. This change preserves
that existing policy. Renewal still requires network connectivity. Documentation
is updated in the repository; the live wiki follows the normal merge workflow.

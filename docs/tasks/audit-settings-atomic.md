# Atomic audit settings updates

## Bug

`PUT /api/audit-logs/settings` could report success after changing audit
settings even when recording `audit.retention_updated` failed. The event was
written after the setting changes through a helper that ignored its error.

## Scope and transaction model

The successful response must mean the settings and matching local audit event
were saved. In Standard mode, both writes use one local transaction; rejection
of either write leaves the previous settings in place and returns failure.
The audit event identifies the authenticated actor, carries the request
correlation ID, and records before and after settings.

The route retains its existing administrator JWT and API-token authorization.
This change adds no separate fresh-MFA step to this endpoint; account
management MFA checks remain unchanged.

Governed settings updates continue to require their existing protected
request, dual approval, external intent/commit/result, and recovery protocol.
They also require the matching local audit event to be durable before the API
reports success. If the external commit has already happened and writing its
result then fails, the change stays applying until recovery records the exact
anchored result; the externally committed transition is not rolled back. This
change does not alter the policy tier or approval rules.

## Routing and model tier

- Routed from `PUT /api/audit-logs/settings` through the existing authenticated,
  admin-only API route.
- Standard changes are local settings-plus-audit transactions.
- Governed changes retain the existing external audit protocol and add the
  local audit record as a success prerequisite.
- Model tier selection for this task: complex `gpt-6.1-sol`; standard
  `gpt-6-luna`.

## Regression and verification

- Added a real-route test that rejects the local audit insert and the settings
  write, then checks the API result, settings, and success event count. Each
  failure, success, and authorization scenario has an independent server
  fixture; admin JWT and admin API-token access are both covered.
- Against base `27923832bbe382f0e920d346dad03ae649a58822`, the isolated audit-
  insert regression failed as expected: the rejected event still returned 200
  and changed settings. The settings-write case protects existing transaction
  rollback behavior. Baseline output is retained privately as
  `regression-before-fix.log`.
- The updated focused route test passed:
  `go test ./internal/server -run '^TestAuditSettingsPUTIsAtomicWithAudit$' -count=1`.
  Output is retained privately as `regression-after-fix.log`.
- Standard store verification passed: `go test ./internal/store -count=1`
  (41.883s); the audit-settings/account-management race selection passed with
  `go test -race ./internal/store -run 'TestAuditSettings|TestPrivilegedReset|TestAccountManagement' -count=1`
  (46.657s), and the commit-failure race case passed separately (2.045s).
  The full and race outputs are retained privately as
  `standard-store-full.log`, `standard-store-race.log`, and
  `standard-store-commit-race.log`.
- Governed verification passed its 24-case fault matrix: 12 boundaries each in
  Enhanced and enrolled, returned-to-Standard modes. The final focused suite
  was `go test ./internal/authorization -run 'TestGovernedAuditSettings|TestGovernanceDurabilityFailures|TestDisableRemainsProtected|TestStoredPolicyHistoryCannotErase' -count=1`; the complete authorization package also passed before the final observer-notification extraction. The review is retained privately as `governed-review.md`.

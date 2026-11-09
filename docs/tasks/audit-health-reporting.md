# Audit health failure reporting

Status (2026-11-03): implementation and local validation complete. Independent code and security reviews
are complete with no open findings. Remote CI remains
pending for this commit and will be recorded in the PR body when available.

## Scope

Audit health must distinguish readable healthy state from unavailable storage.
Public `/api/health` and authenticated `/api/audit-logs/health` must not report
healthy when the configuration store cannot be read. The public response stays
coarse, and both endpoints return a generic server error without exposing store
error details. The UI reports Checking during initial load, Unavailable for
failed or malformed reads. Health may become Unavailable if its state cannot be
persisted. Degraded indicates an observed audit write failure, and Healthy
requires a successfully read non-degraded state. An outstanding failure clears
only after a successful audit log write and durable recovery-state persistence.
Unavailable is not evidence that audit writes succeeded or that stored log
integrity was verified.

No formal change request or risk acceptance is part of this correction. This
work does not remove the broader audit-coverage exclusion.

## Model routing and validation

Model routing verified 2026-11-03: `gpt-6.1-sol` complex backend/reviews;
`gpt-6-luna` standard UI/API/docs.

Regression coverage includes default healthy state, degraded state, recovery,
configuration-read failure with restoration, and a closed database. Baseline
red proof (before backend fix): `go test ./internal/server -run
'TestAuditHealth' -count=1` failed because public health returned HTTP 200 with
`{"status":"ok"}` for both a renamed `_config` table and a closed database.
After the backend fix, the same focused command passed (`ok`, 0.130s). Full
store tests passed (40.298s), targeted store race tests passed (17.988s), and
`go vet` passed. The frontend suite passed with 854 tests and the frontend build
passed; the focused UI suite passed all 28 tests after a maintainability
refactor. Changed-file Gitleaks passed.

`hub/internal/store/audit_health.go` measures 98% statement coverage (100/102)
and is included in Sonar without exemptions. The two uncovered guards handle
SQL-driver `Scan` and `Rows.Err` failures; the private `store-coverage-notes.md`
records this limitation. Code review is complete with no open findings after
the nested ternary was fixed. Independent security review passed. Remote CI remains
pending for this commit; no remote result is claimed here.

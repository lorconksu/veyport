# Bug task: re-enrollment approval test race

Date: 2026-10-09
Issue: [#88](https://github.com/lorconksu/veyport/issues/88)
Status: Implemented and locally validated; awaiting PR review

## Failure

[Release run 37960971772](https://github.com/lorconksu/veyport/actions/runs/37960971772)
failed in `TestHandleReEnrollRequest_SendApprovedFails`. Its approval worker waited
5 ms, looked up the session once, and returned silently when registration had not
finished. The handler writes database and audit records before registering the
session. A slow setup therefore loses the simulated approval, leaving the handler
waiting for its production ten-minute approval timeout until Go aborts the tests.
`TestHandleReEnrollRequest_ApprovalSignal` had the same timing assumption.

## Fix

Both tests use a shared test helper that starts the real handler, waits for session
registration, sends the simulated approval, and waits for the handler result.
A five-second context deadline cancels the mock stream on failure, and test cleanup
joins the handler before closing its store. The send-failure test checks the exact
mock error. Production behavior and timeouts are unchanged.

## Acceptance criteria

- Both approval tests wait for readiness rather than a fixed delay.
- Registration delayed beyond 5 ms is handled successfully.
- Missing registration fails promptly at the test deadline.
- Handler goroutines exit before test resource cleanup.
- Repeated tests with the race detector pass.
- The Hub test suite used by the release workflow passes.

## Validation

- Reproduced the original timeout using a temporary Go overlay: delay handler setup
  by 30 ms and run the old send-failure test with a one-second package timeout.
  The stack blocked at the same approval select as the release failure.
- Both approval tests and registration regression tests passed 100 repetitions.
- The same checks passed 50 repetitions with the race detector (44.9 seconds).
- Full Hub suite (`cd hub && go test ./internal/...`): passed.
- `gofmt` and `git diff --check`: passed.

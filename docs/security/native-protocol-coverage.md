# Native protocol security coverage

Existing fixtures cover the required protocol behaviors broadly. No production
protocol code or redundant Go test was added for this inventory. These fixtures
use disposable in-process servers, synthetic accounts/certificates and test nodes.
Candidate qualification must additionally exercise the exact deployed bytes.

| Requirement | Existing coverage |
| --- | --- |
| Enrollment versus protected gRPC authentication | `grpcserver/exec_stream_test.go` rejects missing peer, enrollment without a certificate, unverified certificate, offline node and replaced control generation |
| Missing node identity, replay/substitution | `grpcserver/execution_authority_failure_regression_test.go`, `application_security_test.go` and `application_rpc_admission_test.go` bind live control identity and attachments |
| TLS chain/pin failure and no insecure fallback | `agent/internal/client/client_test.go`, `execution_test.go` and `application_test.go` exercise pinned verification and separate protected transports |
| Expiry and authorization revocation | `grpcserver/execution_preparation_clock_test.go`, `interactive_terminal_test.go`, `terminal_authorization_watch_test.go`, `sshgw/terminal_authorization_test.go` |
| Malformed input, sequences, EOF and stream limits | `grpcserver/execution_authority_failure_regression_test.go`, `exec_stream_test.go`, `application_rpc_admission_test.go`; agent execution input/control tests |
| SSH wrong CA, expired cert, wrong principal, bare key and unauthorized node | `sshgw/server_test.go`, `certificate_incarnation_test.go`, `disable_certificate_test.go` |
| Execution user and denied forwarding/subsystems/PTY | `sshgw/server_test.go`, `bridge_test.go`, `exec_bridge_test.go` |
| Binary stdin/stdout/stderr, exit status and cancellation | `integration/exec_test.go`, `sshgw/exec_failure_response_regression_test.go`, `session_lifecycle_test.go` |
| Enhanced audit receipt admission and failure | `integration/protected_execution_test.go`, `sshgw/protected_admission_authority_failure_test.go`, `protected_execution_failure_coverage_test.go` cover mismatched/failed receipt, oversized input, lost readiness and revoked authority |
| Real Hub/gRPC/agent/SSH path | `integration/ssh_gateway_test.go`, `exec_test.go`, `protected_execution_test.go` build fixture binaries and exercise actual transports |

Paths without a repository prefix in the table are under `hub/internal/`.
Ordinary logging and enhanced external-receipt auditing have different semantics;
passing ordinary-mode tests never demonstrates enhanced-mode compliance.

`scripts/security/native_protocol.py` verifies required named tests from the
existing Go JSON execution. Missing, skipped or failed tests and package failures
fail the fixture report. Capture the original CI execution as JSON when exporting
evidence instead of launching a second equivalent suite:

```sh
# Execute this as the existing native package test job, with its coverage output.
go test -json -count=1 -covermode=atomic -coverprofile="$COVERAGE" \
  ./internal/grpcserver ./internal/sshgw > "$PRIVATE/native-tests.jsonl"

python3 scripts/security/native_protocol.py "$PRIVATE/native-tests.jsonl" \
  --revision "$REVISION" --output "$PRIVATE/native-fixtures.json"
```

The Go command runs from `hub/`; the exporter runs from the repository root.
The exporter records `native:fixture:grpc` and `native:fixture:ssh`, the execution
digest and `candidate_qualified: false`. Its revision is producer-supplied; the
trusted workflow must bind that execution to its verified checkout. This report
cannot satisfy the release evaluator's `native:grpc` and `native:ssh` scopes.

The [external candidate harness](../../scripts/native-candidate/README.md) now
exercises an actual deployed Hub and the byte-identical public agent on a separate
disposable Linux node. Its Standard-profile prototype checks eighteen live cases,
including required audit-insert failure, denial-marker absence and recovery. It
records `enhanced_receipt_exercised: false`; enhanced source fixtures remain
complementary CI. The first full harness validation used released v2.0.57 on the
local workspace Docker host, not staging or the final PR head.

The remaining rollout requirement is each final candidate's deployment
qualification: verify its live identity, complete artifact inventory and exclusive
lease; run the reviewed installed harness against its own fresh dataset/test
node; bind the result to candidate ID/revision/digests and authenticated
coordinator evidence. Never relabel source-built fixtures or the historical
harness validation as final-candidate qualification. Keep raw transcripts private
and publish only safe coverage/outcome metadata.

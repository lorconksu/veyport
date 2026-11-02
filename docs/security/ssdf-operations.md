# SSDF prototype operations and rollout status

This is the operator status record for the prototype on `feat/ssdf-pipeline`.
It describes evidence gathered so far; it does not activate release gates or
approve a release, merge, exception, scanner retirement or Dependency-Track
cutover. See the [collector runbook](../../infra/evidence-collector/README.md)
and [candidate coordinator runbook](../../infra/candidate-coordinator/README.md)
for configuration and procedures. Hostnames, addresses, mount paths and private
evidence locations intentionally remain in operator configuration.

The implementation remains a draft prototype. Independent code and security
review results and final CI status are tracked on
[PR #115](https://github.com/lorconksu/veyport/pull/115). Trusted rehearsal
`41403473899` on `2debc2a` passed CI, exact-artifact scans, Snyk source/image
assessment execution and the Semgrep step. Eighteen native standard cases
passed with a verified public signed-candidate receipt. The source SAST
assessment failed because this unmerged PR received main-only CodeQL and Sonar
baselines. The archive contained 51 records (31 signed records and 210 verified
payloads); the release gate rejected the final partial signed receipt. The
rehearsal did not publish or promote a candidate. Staging remains v2.0.57,
temporary candidate credentials/configuration were removed, and timers remain
OFF. Current-candidate full-baseline changes are still awaiting validation.

## Established prototype state

- An unprivileged collector is provisioned on the owner's personal
  infrastructure, with a dedicated NFS child dataset. The report payloads are
  age-encrypted; the NAS dataset itself is not encrypted.
- The operator verified the exact mounted source, mount point and sentinel,
  durable write/readback with fsync, decrypt/readback, and recovery using the
  independent age-key copy. The NAS takes daily snapshots with a seven-day
  retention setting; a restore was tested. Snapshots are recovery copies, not
  WORM protection. NAS expiration behavior can retain expired data for up to
  seven additional days.
- The candidate coordinator's firewall egress restrictions and host isolation
  were tested. Its 18-case standard harness passed in the trusted rehearsal
  against exact built native artifacts with a verified public signed-candidate
  receipt. The final partial signed receipt was rejected. Disposable candidates
  were cleaned up. This is not full release qualification. Normal staging
  remains on v2.0.57 and was not changed by the prototype.
- Local validation passed 101 release-helper, 71 collector, 16 coordinator,
  5 scanner, 6 harness, and 3 crypto tests. The CodeQL provider exporter was
  exercised against two existing analyses across five language categories;
  those reports were encrypted on the NAS and read back successfully. Snyk
  snapshots contain GitHub status metadata and safe references, not full SCM
  scan reports. Neither export starts another scan or grants release authority.
- The earlier Sonar issue-export HTTP 400 failure was resolved for the trusted
  rehearsal, and authenticated Snyk source/image assessments executed. Source
  SAST remains incomplete: the unmerged candidate received main-only CodeQL and
  Sonar baselines, so the assessment failed closed. The correction
  uses a dedicated full Sonar branch named
  `release-ssdf-candidate-<40-character-source-SHA>` for trusted prototype and
  stable-release scans, without overwriting `main`; ordinary PR analysis stays
  unchanged. Existing stable tag branches are short-lived and cannot count as
  full baselines. CodeQL reuse requires verifying GitHub's default analysis
  languages and query suite, but the current `security-events:read` workflow
  token receives HTTP 403 from that endpoint, which requires
  `Administration:read`. Credentials will not be broadened; therefore each
  delivery run, including main, must perform a fresh full CodeQL scan. Reuse is
  only a future capability if metadata can be authenticated under an approved
  configuration. Measure the added runtime. Partial failed reuse exports are
  retained diagnostically while qualification fails closed. The initial baseline change passed 124 release-helper tests and 59 focused
  reviewer tests; PR CI and managed CodeQL passed for `6bfbb5d`. Independent code review found no actionable
  findings. Security re-review resolved the CodeQL debug-artifact bypass
  (SEC-01), with no remaining actionable findings. The implementation rejects
  debug-upload environments before initialization and requires debug output to
  remain disabled. See
  [scanner access contracts](scanner-coverage.md) for scope and limits.
- A later trusted Sonar rehearsal, `41413022387`, failed closed on the first
  analysis of the new LONG candidate branch. Sonar returned the complete
  exact-SHA issue inventory and a successful Compute Engine task, but its
  quality-gate status was `NONE`. Keep that result diagnostic/nonpassing; do
  not rerun the same SHA to manufacture an empty-diff green gate. The implemented
  fix keeps the full branch inventory and separately requires a fresh exact-SHA
  `OK` quality gate from the open PR for an unmerged candidate, or from the
  established main analysis for a stable release. `ERROR`, `NONE`, stale or
  mismatched gate evidence blocks qualification. Only inventory analysis uses
  `sonar.qualitygate.wait=false`; ordinary PR analysis still waits. This fix passes 139 release-helper tests and a live read-only export replay;
  independent security re-review is clear, and its workflow rehearsal remains pending. The failed
  rehearsal archive verified 51 records, 29 signatures, 116 payload readbacks,
  14 report bundles and 14 terminal logs. Temporary credentials and services
  were removed; normal staging remained unchanged. Sonar describes the first-branch behavior
  [here](https://community.sonarsource.com/t/quality-gate-status-failed-when-branch-does-not-exist/112706).
- Collector and candidate timers are OFF. No release gate is active, and no
  publication, merge, approval, scanner retirement or Dependency-Track cutover
  has occurred.
- Evidence privacy is not uniform. Newly produced private CI artifacts are
  encrypted, but public `coverage-server-shard` artifacts include
  `go-test.jsonl` used to merge the authenticated test inventory. That
  artifact contains synthetic fixture output; no production credentials were
  supplied. This specific artifact remains a privacy limitation and must not be
  described as private or as encrypted evidence.

## Scanner and release blockers

The SCA baseline contains two unresolved high and three medium frontend
advisories. The scan records also lack upstream `first_seen` values needed to
support 30-day medium and 90-day low tracking. First-seen history and a complete Snyk SCM export,
owner baseline coverage, and risk disposition remain pending. These gaps block
publication. Python cryptography was updated to 50.0.0 and its fresh scan was
clean, but this does not substitute for complete final-revision scans. See
[scanner coverage](scanner-coverage.md) for scope and remaining evidence.

Keep SonarQube, CodeQL and Semgrep active until same-revision coverage and
quality evidence justifies any change. DAST is deferred, not tested and not a
passing gate. Revisit only after the owner has Snyk support's answer and the
separate DAST provisioning and policy review are complete.

## Operator pending checklist

1. Verify the latest commit's CI and review results on PR #115. Retain its
   native rehearsal record and confirm that candidate, source revision and
   evidence identify the same immutable bytes before release qualification.
2. Obtain and verify the repository-scoped collection token with Actions read,
   Code scanning alerts read, Contents read, and commit statuses read/write.
   Provision a separate least-privilege deletion credential; it is currently
   absent.
3. Keep both timers disabled until credentials, trusted source pins, receipt
   key pins, monitoring, storage capacity and the full recovery/deletion
   procedure have been reviewed against the runbooks.
4. Resolve or explicitly disposition the frontend high findings and establish
   reliable `first_seen` evidence or otherwise satisfy the defined remediation
   tracking policy. Complete the Snyk SCM export, owner baseline coverage and
   risk disposition, then confirm final-revision SCA/SAST and exact-artifact
   scans.
5. Review the public `go-test.jsonl` artifact's privacy handling and ensure
   published records describe its synthetic-fixture scope accurately.
6. Reconcile the supervised encrypted CI transport backups retained on the NAS
   while the service credential is pending. They are recovery copies, not
   release-authorizing archive receipts. Exercise authenticated collection,
   signed receipt verification, failure
   behavior, exact-ID artifact deletion and cancellation/mount-loss recovery.
   Failed or missing collection must block publication and must not delete the
   source artifact.
7. Rehearse the complete candidate qualification and release path, including
   gRPC/SSH, rollback, and identical tested/published digests. DAST remains
   excluded and explicitly deferred during this phase.
8. Enable timers and production gates only after the above evidence and reviews
   are complete. This checklist itself grants no approval.

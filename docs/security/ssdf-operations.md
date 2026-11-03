# SSDF prototype operations and rollout status

This is the operator status record for the prototype on `feat/ssdf-pipeline`.
It describes evidence gathered so far; it does not activate release gates or
approve a release, merge, exception, scanner retirement or Dependency-Track
cutover. See the [collector runbook](../../infra/evidence-collector/README.md)
and [candidate coordinator runbook](../../infra/candidate-coordinator/README.md)
for configuration and procedures. Hostnames, addresses, mount paths and private
evidence locations intentionally remain in operator configuration.

PR #115 remains unmerged and the pipeline remains a draft prototype. On baseline
`017dc7b`, PR CI `41419129930` and managed CodeQL `41419123755` passed. The
committed closeout base `5d8f193` passed CI `41719743481` (all 15 checks) and
CodeQL `41719737121` (all five checks); its encrypted evidence was archived and
read back. Closeout follow-up changes require their own final-head CI, tracked on PR #115. Trusted
rehearsal `41419141402` collected full source SAST, passed 18 native cases, and
recorded 51 records with 31 signatures and 225 verified payload readbacks. The
release evaluation correctly BLOCKED on unapproved coverage, finding
dispositions and unknown discovery dates. It did not publish or promote a
candidate. Subsequent local validation passed: server tests in 505.998 seconds
at 86.4% coverage, notify coverage 90.6%, `go vet`, 846 frontend tests, frontend
build, and changed-file Gitleaks with no exclusions. Independent code and
security reviews found no actionable findings. Repository-wide lint retains
the same 20 errors and two warnings. Final-head CI status is tracked on PR #115
and is not claimed passed here. Staging remains v2.0.57 and timers remain OFF.
No merge, release, risk acceptance,
scanner retirement or Dependency-Track cutover occurred.

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
  rehearsal, and authenticated Snyk source/image assessments executed. The
  earlier rehearsal's main-only CodeQL/Sonar baseline failure was corrected:
  rehearsal `41419141402` collected full exact-source CodeQL and Sonar evidence
  and a separate exact-commit PR gate for baseline `017dc7b`. Release policy
  still blocks on outstanding coverage approval, finding dispositions and
  discovery dates. The correction
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
  configuration. The full local CodeQL scan took 330 seconds on one runner; this
  single measurement is not a general runtime estimate. Partial failed reuse
  exports are
  retained diagnostically while qualification fails closed. The initial baseline change passed 124 release-helper tests and 59 focused
  reviewer tests. PR CI `41419129930` and managed CodeQL `41419123755` passed
  for baseline `017dc7b`. Independent code review found no actionable findings.
  Security re-review resolved the CodeQL debug-artifact bypass (SEC-01). The
  implementation rejects
  debug-upload environments before initialization and requires debug output to
  remain disabled. See
  [scanner access contracts](scanner-coverage.md) for scope and limits.
- Earlier trusted Sonar rehearsal `41413022387` failed closed on the first
  analysis of the new LONG candidate branch. Sonar returned the complete
  exact-SHA issue inventory and a successful Compute Engine task, but its
  quality-gate status was `NONE`. Keep that result diagnostic/nonpassing; do
  not rerun the same SHA to manufacture an empty-diff green gate. The implemented
  fix keeps the full branch inventory and separately requires a fresh exact-SHA
  `OK` quality gate from the open PR for an unmerged candidate, or from the
  established main analysis for a stable release. `ERROR`, `NONE`, stale or
  mismatched gate evidence blocks qualification. Only inventory analysis uses
  `sonar.qualitygate.wait=false`; ordinary PR analysis still waits. This fix passes 139 release-helper tests and a live read-only export replay;
  independent security re-review is clear. Trusted rehearsal `41419141402`
  validated the correction for baseline `017dc7b`. The earlier failed
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

The baseline rehearsal surfaced unapproved coverage/finding dispositions that
block publication. Exact fingerprint, rule, location and code-flow matching is
now integrated into the sealed CodeQL source evidence ledger: nine findings
have authenticated provider dates and nine remain unknown. Snyk and Semgrep
dates remain unknown; no historical risk dispositions were inherited. A fresh
development-inclusive web scan of the current working
tree reports four unfixed unique advisory IDs (two high, two medium), with no
minimatch finding after the scoped override. Complete Snyk SCM export, owner
coverage/risk approvals and remaining verified first-seen history remain
outstanding. The owner enabled Snyk development dependencies and existing projects were
refreshed through the API. E2E now matches its lockfile; the frontend still
omits seven required peer dependencies and Python is root-only. The scoped collector read/status
token is installed and supervised authenticated collection has been
demonstrated. Distinct coordinator and cleanup tokens are installed remotely and pass
Actions/Contents read checks; write permissions remain unverified. Cleanup
still needs an independent service identity with appropriate NFS permissions;
root cannot access the root-squashed archive, and no cleanup unit is installed. Unattended activation and reviewed main bootstrap remain pending.
Ninety-three historical publication
identity holds block deletion, not collection. See
[scanner coverage](scanner-coverage.md) for scope and remaining evidence.

Keep SonarQube, CodeQL and Semgrep active until same-revision coverage and
quality evidence justifies any change. DAST is deferred, not tested and not a
passing gate. Revisit only after the owner has Snyk support's answer and the
separate DAST provisioning and policy review are complete.

## Operator pending checklist

1. Verify final-head CI and review status on PR #115. Retain its
   native rehearsal record and confirm that candidate, source revision and
   evidence identify the same immutable bytes before release qualification.
2. Verify write permissions through the intended controlled operations for the
   installed dedicated credentials. Provision a separate cleanup runtime with
   least-privilege NFS access and no private signing/decryption keys. Read-only
   API checks passed; do not reuse the collector credential.
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
   while unattended operation remains disabled. They are recovery
   copies, not release-authorizing archive receipts. Exercise authenticated collection,
   signed receipt verification, failure
   behavior, exact-ID artifact deletion and cancellation/mount-loss recovery.
   Failed or missing collection must block publication and must not delete the
   source artifact.
7. Rehearse the complete candidate qualification and release path, including
   gRPC/SSH, rollback, and identical tested/published digests. DAST remains
   excluded and explicitly deferred during this phase.
8. Enable timers and production gates only after the above evidence and reviews
   are complete. This checklist itself grants no approval.

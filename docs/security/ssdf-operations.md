# SSDF prototype operations and rollout status

This is the operator status record for the prototype on `feat/ssdf-pipeline`.
It describes evidence gathered so far; it does not activate release gates or
approve a release, merge, exception, scanner retirement or Dependency-Track
cutover. See the [collector runbook](../../infra/evidence-collector/README.md)
and [candidate coordinator runbook](../../infra/candidate-coordinator/README.md)
for configuration and procedures. Hostnames, addresses, mount paths and private
evidence locations intentionally remain in operator configuration.

Status (2026-11-06): PR #115 remains draft, unmerged and the pipeline remains a
prototype. The latest captured baseline `28ad4dd30775a32e21e7dbcb236045a75245b9b7`
passed CI `41973613744` (15/15 jobs) and managed CodeQL `41973608508` (5/5
analyses); sequential reviews were clear and encrypted archives/readback were
verified. Those results apply to that revision only; check PR #115 for later
head status. The prior exact-candidate rehearsal passed all 18 standard native
cases, then correctly blocked on unapproved coverage policy; publication was
skipped. PR #122 merged to `main` at `a65fb36` and installed the approval
workflow; automatic release remains held.

The coordinator credential successfully posted its signed candidate result
during rehearsal. Cleanup-token write capability remains untested. Python CLI
resolved ten dependencies in the verified sample; Python SCM coverage remains
root-only. No PR #115 merge, release, risk acceptance, scanner retirement or
Dependency-Track cutover is claimed. Staging remains v2.0.57 and timers remain
OFF. DAST remains deferred.

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
- The frozen PR #115 frontend measurement inventory records 17 configurations
  and 39 rows: 33 SAST rows and six coverage-v8 rows across four c8-bearing
  files; the schema remains version 1. The SAST row set and semantics are
  unchanged, though source hashes and line positions are revision-bound. The SHA256 of
  `web/src/pages/server-detail.tsx` is
  `e3920d70b0fb0798ec0092eecf4f31f9fcc41ca0eca19c336f01c0ea8456747f`; canonical
  inventory SHA256 is
  `ede4b08e8641845b448d62637e0d23a534462093fbdb64b0b659826c66a3c5ed`. The
  preceding LiveTail inventory hash `bb8f6dd81ab31b3b915c6739b5fc09278f971d7f96446a0539df5874022807da`
  is a dated snapshot within PR #115, before upload/delete.
  The earlier Markdown viewer change removed its four c8 markers and added 11
  focused tests. The 2026-11-07 LiveTail change removed only the two c8 range
  markers, fixed four reproduced lifecycle/failure cases, and added focused
  streaming, failure, cleanup and buffering tests. That dated LiveTail
  validation snapshot had 888 frontend tests across 56 files and a passing
  build; LiveTail coverage was 101/101 lines (100%), 63/65 branches (96.92%)
  and 21/21 functions (100%). Overall frontend coverage at that snapshot rose
  from 94.30% to 95.95%. The 2026-11-07 upload/delete change removed four c8
  markers from `server-detail.tsx`, added focused UI coverage, and fixed a
  reproduced second drop after upload entered pending plus stale UI state on
  server navigation. While the pending guard is active, additional drops are ignored;
  changing servers resets this UI state and does not cancel a remote operation.
  The focused suite passed 20/20 cases, with six regression cases failing
  before the fix. The full frontend suite passed 908/908 tests across 57 files
  and the build passed. Dropzone coverage is 63/63 lines (100%), 44/45 branches
  (97.78%) and 13/13 functions (100%); the only uncovered branch is a defensive
  empty-confirmation guard with no reachable UI path. Overall frontend
  coverage rose from 2,887/3,011 lines (95.88%) to 2,894/3,015 (95.98%).
  `server-detail.tsx` measured 378/378 lines, 339/366 branches and 119/121
  functions.
  Changed-lines CI lint passed against main commit `a65fb36`; targeted ESLint
  reports the same four inherited `server-detail.tsx` diagnostics, and the new
  test file is clean. A 16-check browser integration using the actual App against
  a local HTTP fixture passed upload multipart/CSRF/origin/session handling;
  suppression of a second drop after the first upload entered pending;
  success/error/retry/reset feedback; delete confirmation, pending, success,
  error/retry and refreshed listing; cached-server navigation
  isolation; and non-admin hiding. It made 248 requests to the local app origin,
  with no unknown endpoints or JavaScript errors; two expected HTTP 500 console
  messages came from injected failures. This is not real Hub/agent/auth
  qualification. These changes close only executable-range
  subtasks, not an exclusion review or approval. The earlier bounded Chromium
  check exercised the full App/Server Detail UI with a local fixture API/stream
  and passed reconnect, SSE, pause/scroll, line-cap and stop/leave behavior
  without console errors or warnings. Backend/auth/agent full-stack behavior
  remains unverified.
  The binding
  covers the Vitest configuration, actual frontend toolchain configuration and
  supported c8/v8/istanbul/node:coverage ignore hints. Other exclusions remain
  unchanged and require individual owner assessment; this implementation is
  not policy approval. Changed-head sequential review and CI/archive remain
  pending. Candidate detection is bounded to tracked
  `web/src` `.ts`, `.tsx` and `.js` files and conservatively includes matching
  text inside strings; arbitrary configuration imports, transformations and
  source maps are not parsed.
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
dates remain unknown; no historical risk dispositions were inherited.
Complete Snyk SCM export, owner
coverage/risk approvals and remaining verified first-seen history remain
outstanding. The owner enabled Snyk development dependencies and existing
projects were refreshed through the API. E2E matches its 11 locked pairs; the
main frontend SCM graph still omits seven required peer pairs and Python is
root-only. In a separate feature-branch lock fixture, explicitly declaring the
already-installed `@testing-library/dom@10.4.1` peer preserved all 560
package/version pairs and changed the actual Snyk security-test graph from 553
to an exact 560-pair match. The feature-branch change needs to land and the SCM
graph needs a lock-only refresh. The collector graph-completeness check passed
local regression tests and real frontend/E2E graph validation. Do not treat these as completed migration.

Earlier scans returned four advisory IDs, including PICOMATCH `21248802`. Snyk
now confirms that advisory was revoked; this is provider status, not package
remediation or risk acceptance. Current fresh source fixtures return three
unresolved URIJS findings on `uri-js@4.4.1`: `19963961` medium, `19963963` high,
and `20341609` medium. Preserve unknown first-discovery times and do not reset
remediation clocks to project creation or provider refresh dates. The scoped collector read/status
token is installed and supervised authenticated collection has been
demonstrated. The coordinator credential successfully posted its signed
candidate result during rehearsal; cleanup-token write capability remains
untested. Cleanup
still needs an independent service identity with appropriate NFS permissions;
root cannot access the protected NFS archive, and no cleanup unit is installed.
Ninety-three historical publication identity holds block deletion, not
collection. PR #122 merged to `main` at
`a65fb36` and installed the approval workflow; automatic release remains held
and any changed PR #115 head requires its own checks. This workflow installation grants no
coverage or risk approval. See
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

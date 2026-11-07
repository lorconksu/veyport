# PR 115 closeout

Status snapshot (2026-11-07): the latest fully captured CI/CodeQL baseline is revision
`49e96fd56eb2810c43a9ec98fea850f5406a7690`; all CI jobs and the five managed
CodeQL analyses passed there. At capture time, the parallel batch's frontend
coverage validation passed 922 tests across
61 files and `tsc -b && vite build`; all six inherited c8 markers are removed,
and the `src/main.tsx` coverage exclusion is removed. Changed-lines lint is
clean; five inherited lint diagnostics remain outside changed lines. These
local results do not establish current-head CI, review or release
qualification; check [PR #115](https://github.com/lorconksu/veyport/pull/115)
for current checks and review. Coverage/exclusion policy approval and finding
dispositions remain pending; unknown first-seen dates continue to trigger the
existing strict hold. Scanner assessment recommends Snyk Open Source/Container,
Sonar and CodeQL; the owner's two-product Snyk + Sonar option remains open, and
the current gates stay in place pending that choice. The candidate remains
unmerged and unpublished; staging remains v2.0.57 and timers remain OFF.

The 2026-11-07 retention qualification prepared fail-closed, disabled-by-default
configuration and service templates and passed local tests/ACL fixtures. It did
not qualify live cleanup or retention roles, NFS permissions, token write
capability or unattended operation. Cleanup currently writes collector-owned
run indexes and publication state, which conflicts with the proposed read-only
cleanup index/catalog grants. Source/state isolation plus real NFS qualification
remain blockers. Existing 93 publication holds remain unaudited; no deletion,
runtime grant or activation was performed.

Historical status (2026-11-06; superseded by the 2026-11-07 snapshot above): the latest captured baseline at that time was `28ad4dd30775a32e21e7dbcb236045a75245b9b7`. Its CI `41973613744` passed all 15 jobs and managed CodeQL `41973608508` passed all five analyses; sequential code and security reviews were clear, and encrypted CI/CodeQL archives and NAS readback were verified. These results apply to that revision only. They do not validate later changes or approve coverage, findings, merge or release. The draft PR remains unmerged, publication remains held, staging remains v2.0.57 and timers remain OFF. Earlier “refresh checks pending” statements below are superseded by this dated baseline; check PR #115 for any newer head status.

Historical follow-up (2026-11-06): CI `42162344860` on `5a866` failed. Its available nine reports and ten executed logs were independently archived as failure evidence; this is not successful qualification. The failure exposed two issues now corrected in the working tree but not yet reviewed: workflow aggregation now validates exact source/identity before the upstream-success guard so failed-guard reports can be encrypted, while the captured external test remains a hard failure; a hub test now uses only older/legacy history timestamps relative to `f.now` and asserts the exact retained history. These test-only clock changes do not alter production authentication code. Validation reports 172 release-helper tests, seven CI identity tests, 14 nearby top-level tests with 49 subtests under race/atomic, 20 targeted repeats, forced-delay coverage, `go vet` and actionlint passing. Follow current-head checks and review status on [PR #115](https://github.com/lorconksu/veyport/pull/115). No claim is made that the fixes have passed CI or completed review.

## Bounded feature finish line

Five acceptance packages remain, including the coverage package currently
underway; four remain after that package closes. These count outcomes, not
individual bugs, approvals, scans or days. The packages describe the already
agreed feature and are not newly discovered scope.

| Package | Closure evidence | Decision boundary |
| --- | --- | --- |
| 1. Coverage binding and exclusion decisions | Enforce all relevant frontend measurement controls, prepare a fresh exact inventory, then assess executable and configured exclusions individually | Automation may implement and prepare records; only the owner approves exact policy. Binding alone does not close this package. |
| 2. Finding dispositions and discovery history | Final inventory remediated or validly dispositioned, with reliable discovery evidence or policy-compliant handling of unknown dates | Risk dispositions/extensions require authenticated owner approval; never invent or reset dates. |
| 3. Snyk migration and scanner decision | Complete source/SCM/artifact coverage, documented scanner decision, preserved history, then Veyport-only Dependency-Track retirement | Main SCM refresh follows source landing. Retaining complementary scanners is valid when evidence supports it. |
| 4. Unattended collection, cleanup and retention | Qualified separate cleanup identity, reference-safe one-year/180-day retention, reconciled deletion holds, exact archived transport deletion and recovery | Collection is proven in supervised runs; deletion and unattended activation remain held until qualified and authorized. |
| 5. Final candidate qualification, review and delivery | Exact-head reviews/checks/archive; complete candidate, failure/recovery and rollback evidence; authorized merge/release and exact-version staging verification | Green CI is not release authority. Merge, release and activation remain separate decisions. |

These are feature-completion packages, not five mechanical merge checks. A
reviewed merge under the explicit publication hold could precede some rollout
only if the owner deliberately chooses that boundary; that would not complete
the feature. Full candidate lifecycle, hostname, login/TOTP/CSRF and network
confinement evidence remain in package 5 unless later exact evidence closes
them. External web/API DAST is explicitly deferred and is not counted among the
five. One-year release evidence, 180-day other-run evidence, shared-reference
protection, exact archived transport deletion, and Veyport-only Dependency-Track
retirement remain agreed functionality, not optional follow-up.

The following implementation/evidence table preserves the state recorded in
the earlier 2026-11-03 closeout; its “pending” entries are historical and do
not override the dated baseline above or later PR #115 evidence. The owner
authorized completing the remaining implementation and verification on
2026-11-03. Earlier base `5d8f193c0b16a09e8a9e27986edca06b4a342568` passed
CI `41719743481` (15 checks) and CodeQL `41719737121` (five checks), with
encrypted evidence archived and read back. Baseline `16ef348` subsequently
passed CI `41739418814` (15/15) and CodeQL `41739414356` (5/5). Exact-candidate
rehearsal `41739668223` acquired evidence and passed 18 standard native cases,
then blocked on unapproved source-coverage policy; publication was skipped.
These results do not grant a policy exception or release qualification.

## Implementation and evidence

| Work | Completion evidence | State |
| --- | --- | --- |
| Audit and administrator guard coverage | Direct rejection, rollback, expiry, idempotent recovery; original 14 guard gaps directly tested | Included in captured baseline `28ad4dd` CI `41973613744` (15/15 passed); changed-head checks are tracked on PR #115 |
| Audit storage coverage | Transaction, concurrent history, retention failure and recovery; committed-batch deletion counts and exact timestamp precision | Included in captured baseline `28ad4dd` CI `41973613744` (15/15 passed); changed-head checks are tracked on PR #115 |
| Password and encryption coverage | Boundary/reachable failures; normal and real FIPS-only profiles kept distinct | Implemented and verified; FIPS-only profile rejects caller-managed GCM nonces, so application is not claimed FIPS compatible |
| Certificate-authority persistence | Fail-closed read errors/corruption/mismatch; atomic initial persistence and legacy migration; concurrency regressions | Implemented and verified; no rotation/expiry policy added |
| Generated protobuf controls | Pinned verified generation, reproducibility and Buf schema compatibility checks; retain generated-code exclusion | Local controls and actionlint passed; captured baseline `28ad4dd` CI `41973613744` (15/15 passed); changed-head checks are tracked on PR #115 |
| Coverage configuration | Six c8 markers removed; `src/main.tsx` exclusion removed | Current technical inventory is unapproved, with 17 configurations, 33 SAST rows and zero coverage rows (SHA256 `6b1168b0ea10044827ed34a4002bf35bbfa6406356057992dd2932aa7f4ea5ac`). Local frontend validation passed 922 tests across 61 files and build; changed-lines lint passed with five inherited diagnostics outside changed lines. Earlier marker-specific and browser fixture results below this closeout's history are dated snapshots; they do not establish current-head CI, policy approval or release qualification. |
| Finding history | Authenticated exact-match CodeQL history ledger retained with reports; unknown dates stay unknown | Historical ledger snapshot at `16ef348`: 8 dated and 8 unknown; use the exact-candidate sealed ledger for current findings/history. No risk dispositions are inherited. |
| Scanner comparison | Read-only comparison assessed flows, history, scope and timing | Owner choice pending: recommendation is Snyk Open Source/Container + Sonar + CodeQL; Snyk + Sonar remains an option. Keep current gates. Semgrep retirement is not approved. |
| Snyk migration | Nonempty complete source graphs, exact-artifact coverage and preserved prior history before Dependency-Track cutover | Incomplete |
| Final verification | Code review, then independent security review, final-revision CI, encrypted evidence/readback, candidate qualification and recovery | Earlier baseline `28ad4dd` CI `41973613744` (15/15) and CodeQL `41973608508` (5/5) passed, reviews were clear and encrypted archives/readback were verified; the later captured baseline is recorded above. Exact candidate qualification and delivery remain pending; these results do not validate a later revision. |

Complex implementation and review tasks use `gpt-6.1-sol` with high reasoning;
standard tasks use `gpt-6-luna` with medium reasoning. These available model
families were verified on 2026-11-03. Parallel tasks have distinct file ownership;
the root coordinates shared workflow, coverage and documentation changes.

## Owner and operational prerequisites

Risk dispositions and source-coverage approval require the owner's authenticated
review of exact records. Implementation authorization does not approve an
exception. Earlier scans reported four development-tool advisory IDs; later
captured status below records PICOMATCH as provider-revoked and three URIJS
findings. This dated report does not assert current registry availability. The
final candidate inventory must establish exact remaining findings before any
decision is requested.

PR #122 merged to `main` at `a65fb36` and installed the approval workflow.
Automatic release remains held. The baseline PR #115 refresh checks completed
as recorded above; any changed head requires its own checks and review. This
does not approve any finding disposition or coverage exception. Feature-branch
execution or fabricated approval descriptors cannot substitute for genuine
owner review.

The coordinator credential successfully posted its signed candidate result
during rehearsal; cleanup-token write capability remains untested. Cleanup still requires
a separate runtime identity with least-privilege NFS access; root cannot access its protected state,
and no cleanup unit exists. Immutable reviewed source records and historical publication
reconciliation remain prerequisites for unattended operation. Existing
collector credentials must not silently be repurposed. Collection, retention
and publication readiness are separate results; 93 unresolved historical
publication identities continue to block deletion, but not evidence collection.

The owner enabled development dependencies, and an API import refreshed the
existing Snyk projects to include development dependencies. E2E matches all 11
locked pairs. On the feature branch, explicitly declaring the already-installed
`@testing-library/dom@10.4.1` peer left all 560 unique package/version pairs
unchanged. Authenticated security-test graphs improved from 553 reachable pairs
to an exact match of all 560 locked pairs. Frontend build and all 854 tests
passed. This does not refresh the main SCM graph, which remains 552/559 until
the source lands and its existing project is lock-only refreshed. The release
worker's exact graph-equality guard passed local regression and real-report
checks (560 frontend pairs and 11 E2E pairs); final-head CI remains required.
Python CLI resolved ten dependencies in the verified sample, while its SCM
project remains root-only. Do not declare migration complete or remove Veyport's Dependency-
Track history until SCM and release graph equality are verified.

Earlier scans reported four IDs including PICOMATCH `21248802`; Snyk now confirms
that advisory was revoked, not remediated by source change or accepted as risk.
Current fixture scans return three unresolved `uri-js@4.4.1` findings:
`19963961` medium, `19963963` high, and `20341609` medium. Their original
first-discovery dates remain unknown; no project-creation or provider timestamp
was used to reset a remediation clock.

Web/API DAST remains explicitly deferred by the owner. It is not counted as
passing, and its eventual activation needs its own reviewed configuration.
No PR #115 merge, release, scanner retirement, policy exception, or destructive
cleanup is recorded as approved by this closeout document.

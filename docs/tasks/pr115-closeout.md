# PR 115 closeout

The owner authorized completing the remaining implementation and verification
on 2026-11-03. Earlier base `5d8f193c0b16a09e8a9e27986edca06b4a342568` passed
CI `41719743481` (15 checks) and CodeQL `41719737121` (five checks), with
encrypted evidence archived and read back. Baseline `16ef348` subsequently
passed CI `41739418814` (15/15) and CodeQL `41739414356` (5/5). Exact-candidate
rehearsal `41739668223` acquired evidence and passed 18 standard native cases,
then blocked on unapproved source-coverage policy. PR #115 refresh checks remain
pending; these results do not grant a policy exception or release qualification.

## Implementation and evidence

| Work | Completion evidence | State |
| --- | --- | --- |
| Audit and administrator guard coverage | Direct rejection, rollback, expiry, idempotent recovery; original 14 guard gaps directly tested | Implemented and focused/race verified; full final-head CI pending |
| Audit storage coverage | Transaction, concurrent history, retention failure and recovery; committed-batch deletion counts and exact timestamp precision | Implemented and focused/race verified; full final-head CI pending |
| Password and encryption coverage | Boundary/reachable failures; normal and real FIPS-only profiles kept distinct | Implemented and verified; FIPS-only profile rejects caller-managed GCM nonces, so application is not claimed FIPS compatible |
| Certificate-authority persistence | Fail-closed read errors/corruption/mismatch; atomic initial persistence and legacy migration; concurrency regressions | Implemented and verified; no rotation/expiry policy added |
| Generated protobuf controls | Pinned verified generation, reproducibility and Buf schema compatibility checks; retain generated-code exclusion | Local controls and actionlint passed; final-head CI pending |
| Coverage configuration | Blanket Sonar coverage exclusions for handwritten application code were removed; generated code, assets and declaration types remain excluded | Frontend Vitest still excludes `src/main.tsx`, `src/test/**` and `src/types/**`; 16 c8 ignore marker lines remain across five frontend files (five start/stop ranges and six next markers). These measurement exclusions are outside the canonical SAST inventory and need collaborative owner assessment; no approval is claimed |
| Finding history | Authenticated exact-match CodeQL history ledger retained with reports; unknown dates stay unknown | Integrated and replayed: 9 dated, 9 unknown; no risk dispositions inherited |
| Scanner comparison | Per-flow security and quality coverage, justified retained checks and timing | Decision packet pending |
| Snyk migration | Nonempty complete source graphs, exact-artifact coverage and preserved prior history before Dependency-Track cutover | Incomplete |
| Final verification | Code review, then independent security review, final-revision CI, encrypted evidence/readback, candidate qualification and recovery | Baseline `16ef348` CI `41739418814` (15/15) and CodeQL `41739414356` (5/5) passed; exact-candidate rehearsal `41739668223` acquired evidence and passed 18 standard native cases, then blocked on unapproved source-coverage policy. PR #115 refresh checks and final qualification remain pending |

Complex implementation and review tasks use `gpt-6.1-sol` with high reasoning;
standard tasks use `gpt-6-luna` with medium reasoning. These available model
families were verified on 2026-11-03. Parallel tasks have distinct file ownership;
the root coordinates shared workflow, coverage and documentation changes.

## Owner and operational prerequisites

Risk dispositions and source-coverage approval require the owner's authenticated
review of exact records. Implementation authorization does not approve an
exception. Four unresolved development-tool advisory IDs were present in the
last complete scan; current package registry checks still provide no newer
release of the affected packages. A final scan must establish the exact remaining
inventory before any decision is requested.

PR #122 merged to `main` at `a65fb36` and installed the approval workflow.
Automatic release remains held. PR #115 refresh checks are pending; this does
not approve any finding disposition or coverage exception. Feature-branch
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

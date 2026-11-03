# PR 115 closeout

The owner authorized completing the remaining implementation and verification
on 2026-11-03. The starting revision is
`5d8f193c0b16a09e8a9e27986edca06b4a342568`. CI run `41719743481` passed all
15 checks and CodeQL run `41719737121` passed all five checks for that
committed base; encrypted evidence was archived and read back. Closeout follow-up
validation is tracked on PR #115; final-head CI is required. Neither base CI nor these
changes constitute release qualification or approval of scanner exceptions.

## Implementation and evidence

| Work | Completion evidence | State |
| --- | --- | --- |
| Audit and administrator guard coverage | Direct rejection, rollback, expiry, idempotent recovery; original 14 guard gaps directly tested | Implemented and focused/race verified; full final-head CI pending |
| Audit storage coverage | Transaction, concurrent history, retention failure and recovery; committed-batch deletion counts and exact timestamp precision | Implemented and focused/race verified; full final-head CI pending |
| Password and encryption coverage | Boundary/reachable failures; normal and real FIPS-only profiles kept distinct | Implemented and verified; FIPS-only profile rejects caller-managed GCM nonces, so application is not claimed FIPS compatible |
| Certificate-authority persistence | Fail-closed read errors/corruption/mismatch; atomic initial persistence and legacy migration; concurrency regressions | Implemented and verified; no rotation/expiry policy added |
| Generated protobuf controls | Pinned verified generation, reproducibility and Buf schema compatibility checks; retain generated-code exclusion | Local controls and actionlint passed; final-head CI pending |
| Other coverage exclusions and suppressions | Blanket handwritten Go/TypeScript exclusions removed; generated code, assets and declaration types remain excluded | Implemented; remaining exclusions retain scoped rationale; final configuration review pending |
| Finding history | Authenticated exact-match CodeQL history ledger retained with reports; unknown dates stay unknown | Integrated and replayed: 9 dated, 9 unknown; no risk dispositions inherited |
| Scanner comparison | Per-flow security and quality coverage, justified retained checks and timing | Decision packet pending |
| Snyk migration | Nonempty complete source graphs, exact-artifact coverage and preserved prior history before Dependency-Track cutover | Incomplete |
| Final verification | Code review, then independent security review, final-revision CI, encrypted evidence/readback, candidate qualification and recovery | Base `5d8f193` CI/CodeQL passed and encrypted archive readback verified; follow-up final CI and candidate qualification pending |

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

The protected approval environment exists, but the approval workflow is absent
from `main`. A reviewed bootstrap must establish the trusted implementation
before genuine approvals and a passing release qualification are possible.
Feature-branch execution or fabricated approval descriptors cannot substitute
for that step.

Distinct coordinator and cleanup tokens are installed in protected remote
files and pass Actions/Contents read checks. Write permissions remain unverified;
no status receipt or deletion was performed with them. Cleanup still requires
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
checks (560 frontend pairs and 11 E2E pairs); final-head CI remains required. Python remains
root-only. Do not declare migration complete or remove Veyport's Dependency-
Track history until SCM and release graph equality are verified.

Earlier scans reported four IDs including PICOMATCH `21248802`; Snyk now confirms
that advisory was revoked, not remediated by source change or accepted as risk.
Current fixture scans return three unresolved `uri-js@4.4.1` findings:
`19963961` medium, `19963963` high, and `20341609` medium. Their original
first-discovery dates remain unknown; no project-creation or provider timestamp
was used to reset a remediation clock.

Web/API DAST remains explicitly deferred by the owner. It is not counted as
passing, and its eventual activation needs its own reviewed configuration.
No merge, release, scanner retirement, policy exception, or destructive cleanup
is recorded as approved by this closeout document.

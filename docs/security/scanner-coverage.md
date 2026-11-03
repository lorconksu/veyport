# Scanner coverage and migration record

This PR prepares the SSDF pipeline; its collector/coordinator timers are OFF and
the gates are not active. DAST remains deferred and has not been tested.
On baseline `017dc7b`, trusted rehearsal `41419141402` collected full source
SAST and exact-candidate evidence; release evaluation correctly blocked on
unapproved coverage, finding dispositions and unknown discovery dates. This
does not establish coverage or approval for later changes. Local server and
frontend validation passed, and independent code and security reviews found no
actionable findings. Final-head CI status is tracked on PR #115; this record
grants no exception. See
[SSDF operations](ssdf-operations.md) for rollout state and blockers.

## Scan ownership

| Scope | Authoritative execution | Complementary coverage retained |
| --- | --- | --- |
| PR dependency feedback | Existing Snyk GitHub integration | Existing source `govulncheck` gives Go reachability evidence |
| Trusted release source baseline | One fresh Snyk CLI test per explicit manifest, including development dependencies | Full baseline is checked even when no dependency changed |
| Exact release images | One Snyk Container test per selected native OCI manifest | Grype/Syft remain until replacement and failure behavior are fully qualified |
| Every public Go binary | Existing exact-binary `govulncheck`, binary inventory and malware checks | Image OS inventory cannot substitute for binary symbol reachability or malware detection |
| Source SAST | Existing SonarQube, CodeQL and Semgrep, with full exact-source baselines required for trusted release qualification | Snyk Code comparison stays nonblocking; no additional required Code gate |
| gRPC/SSH source fixtures | Existing tests; export their existing Go JSON execution | Deployed candidate qualification is an additional boundary, requiring exact candidate bytes |

The release CLI does not call `monitor`, `report`, or import a project. Repeating
release scans after PR feedback is justified by immutable artifact identity and
fresh vulnerability intelligence. Exporting reports never starts another scan.
Do not add monitored projects for individual CI runs.

## Full source baseline for trusted candidates

Trusted rehearsal `41403473899` exposed a baseline gap: its unmerged PR source
received only main-revision CodeQL and Sonar results, so the full source SAST
assessment failed closed. PR new-code checks remain useful feedback, but do not
establish the complete finding baseline for a candidate SHA.

Sonar's candidate-baseline implementation uses a dedicated long-lived branch
named `release-ssdf-candidate-<40-character-source-SHA>` for trusted prototype
and stable-release scans. The trusted staging dispatch verifies its caller,
prototype context, and exact open same-repository PR. Stable tags must match
their release metadata and main ancestry. A preflight checks the fixed public
project's actual long-lived branch pattern and any existing dedicated branch's
long-lived/non-main type. Exact source identity is verified through the
successful analysis task and provider analysis record; optional branch commit
metadata is not required. The scan does not overwrite `main`, and ordinary PR
analysis remains new-code analysis. Existing stable tag branches are short-lived
and cannot provide a full baseline. The focused Sonar tests and actionlint
checks passed, and a read-only preflight confirmed the current SHA can use the
dedicated branch.
That earlier validation was superseded by baseline `017dc7b` and rehearsal
`41419141402`, described below.

Trusted live rehearsal `41413022387` confirmed that Sonar analysis can finish
successfully and return the full exact-source inventory on the first analysis
of a new LONG branch while reporting quality-gate status `NONE`. This is not a
pass: the rehearsal failed closed, and that first-branch result remains
diagnostic/nonpassing. Sonar documents the initial branch quality-gate behavior
[here](https://community.sonarsource.com/t/quality-gate-status-failed-when-branch-does-not-exist/112706).
Do not rerun the same SHA to try to turn this into an empty-diff green result.

The correction keeps that full LONG-branch inventory and obtains gate
evidence independently: an unmerged candidate requires a fresh `OK` result for
the exact SHA from its open PR analysis; a stable release requires an `OK`
result for the exact SHA from the established main analysis. `ERROR`, `NONE`,
stale or mismatched evidence blocks qualification. Only the trusted inventory
analysis uses `sonar.qualitygate.wait=false`; ordinary PR analysis continues to
wait for its own gate. The CI change captures and validates the gate
analysis separately from the candidate-branch inventory. The 139 release-helper tests, actionlint and secret scan pass. A read-only
replay against the actual candidate inventory and PR gate passed; live workflow
validation subsequently completed for baseline `017dc7b` in rehearsal
`41419141402`. A Sonar context argument parsing
issue was fixed by using `--context=...`; a workflow-level subprocess
regression check covers this invocation path. The separate gate proof preserves
Sonar's actual returned conditions; it does not assert that unconfigured overall-code
conditions were evaluated. Owner coverage review remains required.

CodeQL reuse is allowed only for a fresh (24-hour) full main analysis matching
the exact source SHA, GitHub default analysis identity/configuration, and all
five required languages, without diagnostics or reduced-result markers. The
current workflow token has `security-events:read`, but GitHub's
`code-scanning/default-setup` endpoint returned 403 and requires
`Administration:read` to verify the configured languages and query suite. We
will not broaden the credential for this check. Since the workflow cannot
verify that prerequisite, it must perform a fresh full CodeQL scan on every
delivery run, including main; no current main-reuse or runtime reduction is
claimed. The trusted same-job scan validates its configuration and unmodified
SARIF against the exact candidate and artifact manifest, without uploading
duplicate GitHub results or creating a second provider project. Reuse remains
possible if that provider metadata is authenticated in a future approved
configuration. The extra scan is justified by inability to verify full provider
configuration. The full local CodeQL scan took 330 seconds on one runner; this
single measurement is not a general runtime estimate. The CodeQL
prepare step rejects debug-upload environments before initialization; local
initialization sets `debug: false`, and result validation requires that setting.
Partial failed reuse exports are retained diagnostically and still fail
qualification. Missing, stale, partial or main-only results block qualification;
no gate is weakened.
The initial baseline change passed 124 release-helper tests, 59 focused reviewer
tests, and a local CodeQL CLI 2.27.3 fixture scan. Independent code review
found no actionable findings. Security re-review resolved the debug-artifact
bypass (SEC-01) with no remaining actionable findings. PR CI and managed
CodeQL passed for `6bfbb5d`. For baseline `017dc7b`, PR CI `41419129930`,
managed CodeQL `41419123755`, and trusted rehearsal `41419141402` passed their
stated checks; the rehearsal included a five-language full local CodeQL scan.
It took 330 seconds on one runner, a single measurement rather than a general
runtime estimate. The resulting full baseline remains subject to owner coverage
and finding-disposition review.
This is a full baseline within configured extraction
scope, not a claim that every test file is
analyzed. GitHub's managed Go extractor excludes `*_test.go` by default unless
`CODEQL_EXTRACTOR_GO_OPTION_EXTRACT_TESTS=true`; this change does not expand that
scope. See GitHub's [Go extractor options](https://docs.github.com/en/code-security/reference/code-scanning/codeql/build-options-for-compiled-languages#extractor-options-for-go).
The committed base `5d8f193` passed CI `41719743481` and managed CodeQL
`41719737121`, with encrypted archive/readback verification. Later closeout
changes require their own final-head CI, tracked on PR #115; the older
`017dc7b` full candidate rehearsal does not qualify those later changes.

The initial read-only 2026-10-31 inventory found ten GitHub-origin projects: five
Go modules, frontend npm, Python requirements, two Dockerfiles and one Code
project. The maintainer then imported only the missing E2E manifest through the
existing GitHub integration, bringing Veyport's project count to eleven. No
duplicate project was created. On 2026-11-03 the owner enabled development
coverage. Refreshing the existing projects with lockfile-only import paths
preserved all eleven project IDs. Against unchanged main `dfce2e6`, the E2E
graph now matches all eleven locked dependency name/version pairs. The frontend
graph contains 552 locked pairs but omits seven required peer-dependency pairs
from the 559-pair lock inventory. No unexpected version pairs remain in either
graph. Python still contains only its root node. These are concrete remaining
coverage gaps; successful import or a fresh test timestamp is not completeness.
Imported Dockerfiles are not image evidence. No ignores or Dependency-Track
project deletions were applied.

The earlier GitHub frontend graph contained only 258 dependencies. Enabling
development dependencies improved it, but current PR feedback must not be
treated as a complete baseline while the peer inventory remains incomplete.
Release CLI coverage includes development dependencies and remains separately
bound to the exact source and lockfile. Archived CLI output reports 552
dependencies too, but contains findings and counts rather than a full graph.
It therefore does not prove coverage of the seven missing peer dependencies;
a possible shared resolver gap remains under investigation.

The adjacent `infra/audit-lab/storage/.snyk` configures Python 3.14, without ignore
entries. Snyk documents that the default Python 3.7 SCM resolver can silently omit
incompatible packages; modern Python resolution errors fail instead. A clean
CLI environment and this configuration do not prove the imported graph is fixed:
verify its actual resolved graph after the configuration reaches the scanned
revision. See [Snyk's Python SCM documentation](https://docs.snyk.io/supported-languages/supported-languages-list/python/scm-integrations-and-python).

## Verified SCA sample

The comparison revision is released source
`dfce2e6f584f27dec54f51be4992550bbf8d370a` (v2.0.57). Snyk CLI 1.1308.3 tests
included all severities and dependency paths with ignore policies disabled. Failed
attempts were retained; only scopes needing prerequisite correction were retried.

| Manifest | Resolved dependencies | Baseline outcome |
| --- | ---: | --- |
| `hub/go.mod` | 318 | No findings |
| `agent/go.mod` | 189 | No findings |
| `cli/go.mod` | 83 | No findings |
| `proto/go.mod` | 168 | No findings |
| `infra/application-access/fixture/go.mod` | 28 | No findings |
| `web/package-lock.json` | 552 | Four unique security advisories and 24 package/version license records |
| `tests/e2e/package-lock.json` | 11 | No findings |
| `infra/audit-lab/storage/requirements.txt` | 10 | Six security advisories before the dependency fix |

These counts are scanner dependency counts, not a promise of identical counting
across tools. Frontend findings include two high and two medium unique security
advisories. Its raw report has 51 path records: 13 high and 38 medium, including
license entries. The scanner's MPL-2.0 license records remain separate policy
evidence; a license entry is not automatically a security vulnerability.

The two frontend high advisories currently have no fixed release. Both packages
appear in development/build tooling. That distinction informs review but does not
approve or remove the findings: build tooling processes repository inputs and
release policy includes development dependencies. The private report preserves
every path. Source and shipped-binary scopes remain separate.

The Python dependency changes from `cryptography==46.0.5` to `50.0.0` because the
six reported advisories require fixes across several upstream major versions.
A fresh scan of the changed manifest resolves ten dependencies with no findings.
This changed-manifest scan is not relabelled as a complete final-revision scan.
Local tests verify the existing streaming backup format against a ciphertext
generated by 46.0.5, binary round trips, and rejection of corrupted ciphertext/tag
before extraction. No live lab restoration was run for this dependency update.

All three released Linux/amd64 runtime images were retrieved anonymously by
immutable native manifest digest and scanned without publishing a tag. Each
resolves 20 Wolfi OS packages with no Snyk findings. The native OCI descriptor,
configuration and layer hashes were verified. Snyk returned an OS-package report;
that does not demonstrate coverage of every embedded Go executable or the public
Darwin/arm64 binaries. Retain existing exact-binary checks and image comparison.

**Migration status:** explicit source and three-image scans are demonstrated;
complete final-candidate migration is not yet qualified. Frontend baseline
disposition, final revision/artifact scans, historical Dependency-Track archival
and candidate qualification remain required. Do not remove Dependency-Track's
Veyport history or replace Grype based on this sample.

The fresh development-inclusive web scan reported four unique advisory IDs (two
high, two medium); minimatch is absent after the scoped 11.0.4 override. This is
a changed-scope scan, not a complete final-head scan. Owner dispositions and
verified discovery dates remain outstanding. CodeQL history is now integrated
into the sealed source-SAST evidence ledger: exact matching dated nine of 18
CodeQL findings, with nine unknown. Snyk and Semgrep discovery dates also remain
unknown; no risk dispositions were inherited. This history correlation does
not establish cross-branch Sonar continuity. The Snyk owner enabled development
dependencies and refreshed the API to include development graphs, but graph
completeness and lockfile exactness remain under investigation; Python is still
root-only. Final-head CI and exact final-revision scans remain pending.

## SAST flow and historical comparison

The private content-hashed collection contains Snyk Code's 485 results, CodeQL's
nine Go baseline results plus 21 historical alerts, Sonar's 543 all-state issues
and seven hotspots, and Semgrep's seven results. Sonar issue states include 487
open, 14 resolved and 42 closed records; 522 are code smells, seven bugs and 14
security issues. Quality records and native resolutions remain distinct from
release approvals. The private exporter preserves 1,072 records, including native
severities, suppressions, locations, disposition and history.

| Reviewed flow/history | Observed overlap or gap | Decision |
| --- | --- | --- |
| Build-embedded SQL migration execution | Three Snyk Code errors follow embedded SQL, not an attacker-controlled SQL input; parameterized migration markers were inspected | Proposed false-positive assessment only; no scanner dismissal or release waiver |
| S3 transport checksum | Snyk, Sonar and Semgrep identify MD5 use; it is a transport checksum rather than receipt integrity authority | Record duplicate reviewed use; preserve each raw finding and approval requirements |
| Browser CSRF cookies and deletion | Snyk, Sonar and Semgrep overlap; JavaScript must read the double-submit CSRF cookie; other sink deletes cookies | Reviewed use proposal, scoped to these flows; session-cookie requirements remain |
| Operator credential delivery and pinned TLS bootstrap | CodeQL reports existing flows without corresponding Snyk results in this sample | Preserve CodeQL and unresolved dispositions; custom verification is not proof of scanner equivalence |
| Mail/header boundaries | CodeQL has existing flow results absent from Snyk's sample; header stripping and regression tests exist | Review envelope and header boundaries separately; no automatic dismissal |
| Redirects/proxy responses | Existing CodeQL dismissals and Semgrep annotations have flow-specific guards | Preserve historical decisions and revalidate scope; a native dismissal is not an owner-approved exception |
| React highlighted HTML sinks | Semgrep retains two explicit annotated sink findings; current Snyk results concern different JavaScript locations | No demonstrated equivalent sink coverage; retain Semgrep |
| Historical workflow permission fixes | CodeQL history contains fixed Actions findings; Sonar's configured source roots exclude workflows | Retain CodeQL; a fixed historical alert still demonstrates a relevant language/scope gap |
| Historical SQL/transport fixes | Sonar preserves closed security issues and reviewed dynamic SQL findings | Keep history; current absence does not establish that a competitor detects the historical defect |

No competing scanner was run against deliberately reverted vulnerable code in
this phase. Rule catalogs and raw counts do not establish detection equivalence.
Test/fixture filename heuristics help triage; they never make a finding safe.
All remaining findings, including test-located ones, remain unresolved unless
explicitly reviewed. Keep current SAST gates and Sonar's new-code quality gate:
90% coverage, 1% maximum duplication, 100% hotspot review and A ratings. No
constitution or branch-protection change is justified by the current comparison.

## Commands and private evidence contract

Install the pinned CLI before exposing the scanner token to its execution
environment. Python scanning needs an isolated environment containing the pinned
requirements **and pip**; unresolved packages fail. Go resolution needs the Hub's
ignored frontend embed directory, as the existing CI source scan does. Npm scans
the lockfile with strict synchronization and development dependencies included.

```sh
python3 scripts/security/snyk.py source --root . \
  --output "$PRIVATE/source-sca" --revision "$REVISION" \
  --candidate-id "$CANDIDATE_ID" --artifact-manifest "$CANDIDATE_JSON" \
  --scanner "$SNYK_CLI" --python "$PYTHON_ENV/bin/python"

python3 scripts/security/snyk.py image --image veyport \
  --archive "$NATIVE_OCI" --archive-sha256 "$ARCHIVE_SHA256" \
  --native-manifest-digest "$NATIVE_DIGEST" \
  --output "$PRIVATE/image-veyport" --revision "$REVISION" \
  --candidate-id "$CANDIDATE_ID" --artifact-manifest "$CANDIDATE_JSON" \
  --scanner "$SNYK_CLI"
```

Use a fresh private output directory outside the delivery tree. Reports include
the candidate ID, exact source revision, SHA256 of the complete candidate JSON,
scanner version, explicit scope status, dependency count, raw report digest and
all findings. Operational success means complete collection, not release policy
success. Findings have `classification: unresolved`; missing persistent upstream
`first_seen` stays null, requiring triage evidence rather than renewing deadlines.
Multiple paths are grouped without dropping the original report. An empty tree,
unknown/filtered result, authentication error or partial output fails closed.

Archive raw output and stderr privately. Newly produced private CI artifacts
are encrypted, but public `coverage-server-shard` artifacts include
`go-test.jsonl` for merging the authenticated test inventory. The available
evidence says this is synthetic-fixture output and that no production
credentials were supplied; it remains a specific privacy limitation, not proof
that every report is private. Never attach this output directory to a public
release or plaintext Actions artifact. The comparison exporter verifies
the archived collection's hashes and exports without rescanning:

```sh
python3 scripts/security/compare.py "$PRIVATE_COLLECTION" \
  --output "$PRIVATE/comparison-dispositions.json"
```

Snyk's [test command](https://docs.snyk.io/developer-tools/snyk-cli/commands/test)
documents ignore-policy bypass and dependency options; its
[archive scanning guide](https://docs.snyk.io/developer-tools/snyk-cli/scan-and-maintain-projects-using-the-cli/snyk-cli-for-snyk-container/advanced-use-of-snyk-container-cli)
documents direct OCI scanning. These commands deliberately create no monitored
projects. The existing integration remains the PR feedback path.

### Sonar provider access

The Sonar job exporter and delivery baseline exporter deliberately read this
fixed public project anonymously over verified HTTPS, with redirects disabled.
They check the provider's exact project key and public visibility before and
after retrieval, and preserve the existing exact source, analysis, context,
freshness, pagination and quality-gate checks. The job exporter uses the existing
analysis credential only for `ce/task` identity and rechecks, which are not public.
There is no anonymous fallback after a credential error, and a private project
requires a separately configured reader with the required access.

The provider documents that PR listing accepts Execute Analysis or Browse,
whereas issue retrieval requires Browse. CI scan and quality-gate success did
not establish access to the issue export: repeated issue requests returned HTTP
400 under the CI analysis identity. The stored token type and exact permissions
were not inspected. A successful replay with a different local credential did
not prove the earlier failure was transient. Explicit public reads avoid
expanding that analysis credential; permanent request/authentication failures
remain partial evidence with their original failure reason.

Assessment `authenticated` records trusted report provenance and exact source,
as it already does for local same-run Semgrep; it does not assert a logged-in API
client. Public Sonar exports additionally record
`provider_access: public-project-anonymous` and `client_authenticated: false`.
Public HTTP success alone cannot complete the scope: all source and coverage
checks must pass, and PR new-code evidence still cannot establish a full baseline.

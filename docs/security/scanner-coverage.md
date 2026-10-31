# Scanner coverage and migration record

This PR prepares the SSDF pipeline; its collector/coordinator timers are OFF and
the gates are not active. DAST remains deferred and has not been tested.
Candidate qualification, complete current-revision SAST exports, archival and
owner-approved finding dispositions are prerequisites to publication. This
record grants no exception. See [SSDF operations](ssdf-operations.md) for
prototype rollout state and operator blockers.

## Scan ownership

| Scope | Authoritative execution | Complementary coverage retained |
| --- | --- | --- |
| PR dependency feedback | Existing Snyk GitHub integration | Existing source `govulncheck` gives Go reachability evidence |
| Trusted release source baseline | One fresh Snyk CLI test per explicit manifest, including development dependencies | Full baseline is checked even when no dependency changed |
| Exact release images | One Snyk Container test per selected native OCI manifest | Grype/Syft remain until replacement and failure behavior are fully qualified |
| Every public Go binary | Existing exact-binary `govulncheck`, binary inventory and malware checks | Image OS inventory cannot substitute for binary symbol reachability or malware detection |
| Source SAST | Existing SonarQube, CodeQL and Semgrep | Snyk Code comparison stays nonblocking; no additional required Code gate |
| gRPC/SSH source fixtures | Existing tests; export their existing Go JSON execution | Deployed candidate qualification is an additional boundary, requiring exact candidate bytes |

The release CLI does not call `monitor`, `report`, or import a project. Repeating
release scans after PR feedback is justified by immutable artifact identity and
fresh vulnerability intelligence. Exporting reports never starts another scan.
Do not add monitored projects for individual CI runs.

The initial read-only 2026-10-31 inventory found ten GitHub-origin projects: five
Go modules, frontend npm, Python requirements, two Dockerfiles and one Code
project. The maintainer then imported only the missing E2E manifest through the
existing GitHub integration, bringing Veyport's project count to eleven. No
duplicate project was created. Both the E2E and Python imported dependency graphs
are still empty; import completion does not establish coverage. Imported
Dockerfiles are not image evidence. No ignores or Dependency-Track project
deletions were applied.

The GitHub frontend graph contains 258 dependencies versus 552 in the explicit
development-inclusive CLI test. The integration currently omits JavaScript
development dependencies. Its organization UI setting requires a later operator
change and dependency-graph verification; current PR feedback must not be treated
as complete baseline coverage. Release CLI coverage includes those dependencies.

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

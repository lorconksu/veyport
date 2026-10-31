# SSDF-aligned security pipeline implementation plan

Status: implementation and collector prototype are in progress on `feat/ssdf-pipeline`, reserved for PR #115. No release, merge, risk-acceptance approval, scanner retirement or Dependency-Track cutover has occurred. Collector and candidate coordinator are deployed in personal infrastructure, but their timers are disabled and publication gates are not active. Final-head staging rehearsal and reviews remain pending. DAST is deferred at the owner's request pending Snyk support; it is a future design only.

## Objective and agreed decisions

Improve security coverage and retain reviewable SSDF evidence without adding unnecessary time to PR feedback. Publication may wait for required security results. Do not interpret parallel jobs as a guarantee of unchanged completion time.

- Target two primary platforms, provisionally Snyk and SonarQube. Compare Snyk Code, SonarQube, CodeQL, and relevant Semgrep checks on the same revision before selecting the final SAST coverage and retiring any scanner. Preserve existing quality controls as well as security coverage; do not add Snyk Code as another required gate merely because it is licensed.
- Make Snyk the primary SCA interface after verifying complete project and artifact coverage. After migration is verified and required historical evidence is archived, stop Veyport's Dependency-Track imports and remove its projects/inventories. Preserve Dependency-Track for the owner's other projects.
- Avoid equivalent duplicate scans and duplicate monitored projects. Assign an authoritative scan path to each scope/stage, reuse only verifiably matching and sufficiently fresh evidence, and archive every run's outcome without rerunning scans just to export reports.
- Defer web/API DAST until the owner returns with Snyk support's answer. Its eventual design is authenticated testing through the external candidate endpoint before publication. Record it as deferred in the current phase's policy and evidence, never as a passing or completed scan.
- Run complementary gRPC and SSH security tests inside the private network against the same candidate. Inventory and reuse existing tests before adding missing cases.
- Use a separate disposable candidate instance on the existing staging server, with synthetic data, dedicated accounts, and separate test nodes. Keep normal staging available for manual testing.
- Build candidate artifacts once, scan those bytes, and promote those same artifacts after every gate succeeds. Bind evidence to the source revision and artifact digests.
- Block high/critical vulnerabilities and authentication, authorization, or required-audit failures. The latter block regardless of scanner severity labels. Existing findings require remediation or an explicit, valid exception; do not automatically grandfather them.
- Treat scanner errors, incomplete scans, failed authentication, missing required coverage, and unavailable evidence as failures. An operational scan failure cannot be waived as a vulnerability exception.
- Retain published-release evidence for one year from publication, and all other run evidence for 180 days from completion, including successful non-release, failed, and cancelled runs. Publish only disclosure-safe summaries and links. These are owner-selected retention periods, not claimed SSDF deadlines.
- Use dedicated storage on the owner's personal TrueNAS NFS export. Keep Veyport and its evidence independent of lab, MIL, and corporate infrastructure; keep NAS connection details in private operator configuration.
- The maintainer approves exceptions explicitly. Record justification, scope, approval, expiration, and remediation follow-up under `docs/security/`; retain sensitive evidence privately.
- Successful publication remains followed by deployment of the exact released version to normal staging, with backups, rollback, and runtime verification.

## Prerequisites and access

| Item | State at planning | Required before |
| --- | --- | --- |
| GitHub repository and workflow access | Verified | PR work and release integration |
| Proxmox and staging administration | Verified | Candidate deployment |
| Public HTTPS route | Existing route serves normal staging; candidate cutover pending | Candidate DAST qualification |
| Main Snyk API credential | Re-supplied and verified read-only | SCA configuration and scan integration |
| Snyk API & Web entitlement/provisioning | Owner receives “The account is not accessible”; support confirmation pending | DAST integration activation |
| DAST-specific API credential | Not available until provisioning is resolved | Target configuration and scan execution |
| Private evidence store and workload access | The dedicated collector has a dedicated NFS child dataset. Payloads are age-encrypted; NAS dataset encryption is not enabled. Exact mount/source/sentinel checks, fsync readback, decrypt tests and key-recovery roundtrip passed. Daily snapshots retain 7 days and restore was tested; snapshots are recovery protection, not WORM, and expiration may retain data up to 7 extra days. | Collector activation and publication gate |
| Collector and coordinator | Deployed; collector and candidate timers remain OFF. Candidate firewall egress and host isolation were tested. Normal staging v2.0.57 remains unchanged. | Final-head review, credentials and rehearsal |
| GitHub collection credential | Repository-scoped token not yet supplied (Actions read; Contents read; commit statuses read/write) | Authenticated collection and receipt |
| Separate deletion credential | Not provisioned | Exact-ID temporary artifact cleanup |

The main Snyk API returned `licenses`, `reports`, and `fullVulnDB` entitlements. Those values do not confirm or exclude DAST. Do not silently substitute a different scanner, purchase a plan, or start a trial. The owner has explicitly deferred DAST; the current phase must declare that coverage gap and its active gate set. Once DAST is activated under a reviewed policy, an outage or provisioning problem must not silently bypass its gate.

Prefer dedicated automation identities with narrowly scoped permissions. Separate scan/target management from risk-acceptance approval. Verify effective privileges; an approver-name text field does not authenticate an approval. Keep credentials outside Git and public workflow artifacts. No user credentials or personal TOTP seeds enter the candidate dataset.

## Current pipeline and timing baseline

The existing pipeline uses `.github/workflows/ci.yml`, `release.yml`, `delivery.yml`, and `staging.yml`. Source tests, SonarQube, Semgrep, Gitleaks, and source vulnerability checks gate delivery. CodeQL runs through GitHub's configured analysis. The release workflow runs required CI again before building/scanning delivery artifacts. Existing artifact validation, malware checks, SBOM generation, and digest verification must remain covered.

Measured CI run [41001983872](https://github.com/lorconksu/veyport/actions/runs/41001983872) completed in 38m33s. Its longest server-test shard took 22m21s, followed by E2E at 15m36s; Sonar took 1m17s and Semgrep 51s and finished before E2E. This is a single baseline, not a percentile or performance guarantee. Removing Semgrep alone would not have shortened that run.

Measure comparable PR and release runs separately, including queue time, scan startup, candidate deployment, polling, evidence persistence, and publication waits. Report the median and tail when sufficient samples exist. Do not skip necessary checks to meet a timing target.

Review duplicate CI execution across merge/tag workflows. Reuse evidence only when its exact revision, workflow trust, configuration, scanner/version, required job set, artifact identity, and documented freshness requirements match. Account for vulnerability-intelligence updates even when source is unchanged. Version-dependent binary and candidate checks must validate the final release candidate. Do not reuse results solely because a branch or mutable tag has a green badge. Record the source scan identity and reuse decision in every consuming run.

## Readiness comparison, 2026-10-31

The comparison source is released revision `dfce2e6f584f27dec54f51be4992550bbf8d370a` (v2.0.57). A fresh Snyk Code CLI 1.1308.3 scan completed in 28.3 seconds without creating a monitored project. Existing CodeQL and Sonar analyses and the release CI Semgrep artifact were retrieved for that same revision; collection did not rerun those scanners. Matching source does not make scanner configurations, scopes or vulnerability intelligence identical.

| Source | Observed result | Interpretation |
| --- | --- | --- |
| Snyk Code | 485 results: 3 error, 26 warning, 456 note | 417 results have test/fixture locations under a filename heuristic. Counts require triage, not direct comparison with other tools' severities |
| CodeQL | 9 Go SARIF results; no results in the other retrieved language analyses; 4 currently open alerts | Full baseline differs from PR-only new-finding summaries; existing open findings need explicit disposition |
| Sonar | 543 issue records across open, resolved and closed states; 7 security hotspots | Security findings, quality issues and historical resolutions are separate evidence. Existing new-code quality requirements must be preserved |
| Semgrep | 7 result entries in the release artifact | Raw entries are not a count of new actionable vulnerabilities or proof that another scanner duplicates each rule |

Initial source inspection found that Snyk's three error-level SQL findings execute build-embedded migration files. That supports a false-positive assessment for attacker-controlled SQL injection in this path, subject to recorded review. Other examined alerts involve intentional operator credential output, custom TLS verification, and input sanitization; their presence alone does not establish an exploitable defect or justify automatic dismissal. Complete flow and historical-defect coverage review remains part of P02.

**Decision:** evidence collection is complete for this sample, but scanner retirement is not yet justified. Preserve current gates while recording per-finding dispositions and checking coverage outside production Go/TypeScript code. Keep detailed reports and unresolved finding locations in the private operator archive. No scanner configuration, exception approval or finding state was changed during this comparison.

The collector storage and cryptographic recovery prototype is deployed and tested as summarized in [SSDF operations](../security/ssdf-operations.md). Those checks establish the described storage path and recovery properties only; they do not enable collection or make NAS snapshots immutable. Timers remain disabled pending the checklist in that runbook.

## Proposed flow and trust boundaries

1. **PR validation:** run existing tests and the selected source scanners. Keep independent work concurrent. Untrusted PRs receive no deployment, scanner-management, approval, or private-network credentials.
2. **Trusted candidate preparation:** choose the immutable revision/version, build final candidate images and all public binaries, generate inventories, and assign a unique candidate ID. Preserve current integrity and malware checks.
3. **Private candidate transfer:** move candidate artifacts through an authenticated private store or an authenticated transfer to the trusted personal-stack coordinator. Public GitHub Actions artifacts and public container tags are not private staging storage for plaintext artifacts. The approved evidence transport below uses recipient-encrypted temporary Actions artifacts; it does not authorize uploading plaintext private candidate artifacts. Do not publish prerelease binaries as a workaround for testing before publication.
4. **Candidate deployment:** the trusted coordinator validates the requested repository, allowed workflow/ref, commit and digests, acquires an exclusive deployment lease, and deploys the candidate into the isolated environment. Do not run arbitrary fork/PR code on a privileged persistent self-hosted runner.
5. **Parallel qualification:** run gRPC/SSH checks internally alongside applicable artifact checks; add authenticated external DAST in its later approved phase. Record endpoint identity and candidate digests before and after the scans. Keep the candidate immutable and prevent another run from replacing it mid-scan.
6. **Evaluation and evidence:** obtain completed scan results, verify authentication/coverage, evaluate all relevant findings and exceptions, and durably save the private evidence bundle. Bind the decision to the exact candidate and policy version.
7. **Publication:** authorize only the candidate that passed every required gate. Publish the exact validated digests and binaries without rebuilding. Check exception validity again immediately before publication.
8. **Normal staging update:** back up normal staging consistently, deploy the published version, verify revision/digest, health, authentication behavior, and connected agents, and retain rollback evidence.

Candidate build/deployment can overlap independent CI when the source is trusted, but publication must await the combined results. Use explicit bounded polling, retry policy, and overall deadlines. A timeout, cancellation, superseded candidate, provider outage, or expired deployment lease produces a blocked/failed result, never a successful empty scan. Polling or scan completion must not automatically publish after the owner has canceled the candidate.

The coordinator should pull or receive narrowly defined deployment requests. Use the owner's personal infrastructure independently of lab/MIL/corporate services. Treat artifact manifests, scan metadata, and exception documents as untrusted input; validate schemas, bound sizes, prevent path traversal, and pin trusted issuers/repositories.

## Candidate environment

- Public name: `https://staging.veyport.dev`.
- Use a second instance and a dedicated internal HTTP port; `8082` is the proposed port, subject to availability verification. Normal staging remains on its existing port.
- Once the candidate is ready, change the Cloudflare Tunnel service destination once. Subsequent releases reuse that destination. Confirm available Cloudflare management access; if the owner must make the change, provide the exact verified route and record the dependency before activation.
- Configure the application to recognize the public candidate hostname directly. The current HTTP Host override is temporary and is not proof that login, cookie, CSRF, redirect, or application-proxy flows work correctly at the new origin.
- Use separate databases, volumes, security state, signing keys, synthetic users, node enrollment identities, and test nodes. Never enroll normal staging/production agents into the candidate Hub.
- Candidate administrator access and terminal execution must be confined to disposable test resources. Restrict network reachability so DAST cannot use application features to modify normal staging, production systems, or infrastructure administration services.
- Preserve production authentication and authorization behavior, including TOTP. Configure scanner login sequences/TOTP and session-loss detection with dedicated synthetic accounts; do not disable MFA or add an authentication bypass.
- Test at least an administrator, an ordinary user, and two users with different object access. Record which roles/endpoints were exercised. A single successful login does not establish authorization coverage.
- Verify Cloudflare permits the scanner to reach the application. Browser-style requests currently succeed, while some generic clients were denied. Determine the actual blocking layer; configure a narrowly scoped scanner exception if needed and record its effect on what was tested. Do not disable protections across the whole zone.
- Hold an exclusive lease from dataset initialization through final evidence capture. Retain diagnostic evidence before reset, then revoke synthetic credentials and remove obsolete candidate state.
- Keep gRPC and SSH qualification private. Cloudflare public HTTP hostname routes are not the agent transport. Distinguish internal gRPC `9090`, existing reverse-proxy gRPC `9443`, and SSH gateway `2222`; verify deployed values rather than assuming defaults.

## Scanner work and coverage

### SAST comparison and consolidation

Compare Snyk Code, SonarQube, CodeQL, and relevant Semgrep checks using the same source revision and relevant historical findings. Record configured languages, exclusions, query/rule sets, unresolved findings, reviewed suppressions, remediation history, scan triggers, project identity, and runtime. Distinguish configured rules from rules actually applicable/executed; raw rule counts are not coverage equivalence. The proposed two-platform target is Snyk plus SonarQube, subject to this comparison rather than a claim of equivalent detection.

Classify each scanner's findings as duplicate, unique/actionable, reviewed non-security use, false positive, or unresolved. Review the reasoning behind existing suppressions rather than counting suppressions as proof of safety. Where useful, use isolated regression fixtures or existing historical fixes to check whether a competing scanner catches the same defect. No live exploit testing of user data is required for this comparison. Preserve SonarQube's existing new-code thresholds: at least 90% coverage, at most 1% duplication, 100% security-hotspot review, and A security/reliability/maintainability ratings. Document any proposed replacement before removing the system enforcing a threshold.

If Semgrep has no demonstrated useful incremental coverage, remove its job and required check together, after equivalent gates are verified. Update release dependencies, branch protection, documentation, and the local constitution references in the same transition. If a small set of rules adds value, retain those targeted checks with a documented rationale. Preserve historical evidence. No blanket promise that two analyzers detect identical defects.

Snyk Code remains non-blocking during this assessment. Do not add a fourth required analyzer simply because its license is available.

### SCA and artifact coverage

Reconcile the complete manifest inventory with Snyk projects: all Go modules, frontend and E2E npm projects, and pinned Python requirements. The latest read-only inspection found ten GitHub-origin Veyport projects, including the agent module; earlier missing-import observations must be refreshed. E2E coverage and the previously empty Python project still require verification. Validate dependency counts and lockfile/manifest resolution; an empty project is not evidence of a clean dependency tree.

Assess Snyk Container against exact built image digests; imported Dockerfiles with zero dependencies do not establish image coverage. Preserve every public binary's current vulnerability and malware checks. Keep `govulncheck` when its Go reachability evidence contributes beyond dependency-version matching. Replace overlapping package/image scanners only after exact-artifact coverage and failure behavior are proven.

Check both baseline and newly introduced vulnerabilities under the agreed release policy. A successful PR check reporting no manifest changes does not imply that the baseline has no high/critical findings. Validate scanner dismissals and ignore policies rather than accepting a green status as sufficient evidence.

### Scan ownership and avoiding duplicate work

Inventory GitHub integration scans, scheduled scans, CLI jobs, and monitored project identities before adding checks. The current Snyk integration enables dependency PR checks and has an imported Snyk Code project; Code PR checks are disabled. Multiple projects for distinct manifests or artifact types are legitimate scopes, not automatically duplicates.

- Prefer the existing repository integration for PR feedback where its coverage and exact revision are verifiable. Do not add an equivalent CLI PR scan by default.
- Use CLI scans for the exact release candidate, actual built images, and dependency scopes the integration cannot resolve. Reuse an existing completed scan only under the identity, coverage, trust, policy, and freshness requirements above; document why any additional scan is necessary.
- Export completed scan reports through the supported API or CLI output. Writing a report to the NAS must not trigger another analysis. A mutable dashboard's latest project state is not a substitute for the original run's evidence.
- Separate `test` (assessment) from `monitor` (persistent monitoring snapshot). Do not call `monitor` indiscriminately for every PR attempt or assume matching names merge CLI projects with GitHub-origin projects. Design intentional release monitoring, stable component identities, and links to source scans before creating additional projects. If Snyk Code reporting is selected, validate its separate `--report` mechanism and identity behavior.
- Preserve all reported severity levels, individual scanner results, and assessed/ignored findings needed to explain the decision. Consolidate duplicate findings for presentation without discarding their source evidence or counting one issue twice as separate risk.
- Require a proof case showing one appropriate scan per equivalent scope, no accidental duplicate monitored projects, and complete archival for every consuming run. Changed artifact content, scope, configuration, policy, or required intelligence freshness justifies a new scan.

### Web/API DAST

Deferred from the current phase pending the owner's return with Snyk support's answer. The following requirements apply when activation is reviewed; do not run or claim them now.

After access is confirmed, create target configuration limited to the external candidate hostname, approved application/API paths, and synthetic identities. Import/maintain a suitable API specification or collection and verify crawler coverage for the SPA. Exercise relevant role contexts and supported authorization tests. Define exclusions with reasons and retain coverage evidence.

Use scan-provider completion and authenticated-session evidence, not HTTP 200 at the login page, as success criteria. Verify scanner logout detection and reauthentication. Verify that deliberate authentication failure, unreachable target, invalid API schema, WAF interference, and incomplete scans all prevent publication. Do not assume this scanner covers native gRPC or SSH.

### Native gRPC and SSH qualification

Inventory existing unit, integration, and runtime tests first. Fill gaps at the appropriate layer and avoid copying implementation details into redundant tests.

- gRPC: missing/untrusted/expired certificates on protected RPCs; enrollment versus execution authorization; node identity substitution; authorization revocation; malformed or oversized messages; stream termination and resource bounds.
- SSH: invalid/untrusted/expired certificates and principals; user-to-node authorization; execution-user enforcement; denied forwarding/subsystems; stdin/stdout/stderr and exit status; session cancellation/revocation; required audit admission and failure behavior.
- The listener permits missing client certificates for enrollment. Protected execution RPCs must independently require the verified enrolled-node identity. A successful TLS connection alone is not execution authorization.
- Preserve the selected auditing mode's semantics. For enhanced auditing, exercise external receipt failure and the prohibition on admitting unaudited commands. Do not infer enhanced compliance for deployments using ordinary logging.
- Keep active protocol tests within disposable test nodes. Save outcome and identity metadata without exposing raw sensitive command transcripts publicly.

## Risk acceptance and release enforcement

Implement the policy at `docs/security/risk-acceptance.md` and records under `docs/security/risk-acceptances/RA-0001.md` (one stable identifier per exception). Specify a machine-validated structured header plus human-readable reasoning.

Required fields: ID, scanner/finding identifiers, affected artifact/component and version scope, classification, severity, reason, compensating controls, owner, authorized approver, approval time, expiration time, remediation reference, and private evidence reference when needed. Keep false-positive/not-affected assessments distinguishable from accepting a real unresolved risk.

Use disclosure-safe records in this public repository. Do not commit private report URLs containing bearer tokens, credentials, internal inventory, exploit detail for unresolved vulnerabilities, or raw request/response transcripts. A private evidence identifier can be resolved by authorized reviewers without publishing its contents.

A Markdown file or free-text `approved_by` value is not authorization. Bind approval to a verified maintainer action in the repository platform (or another explicitly designed authenticated approval mechanism), the exact record content/hash, and its scope. Changes to reason, scope, or expiry require renewed approval. Automation that scans or prepares records cannot approve them. Account for this repository's sole-maintainer workflow without inventing a second human approver.

The owner selected a manual GitHub workflow as the approval interface. Automation may prepare the proposed finding record, justification, compensating controls and expiry, but the owner must explicitly dispatch approval for the exact record revision/hash. Verify the authenticated initiating actor against the authorized maintainer identity and record the workflow/run identity, approved content hash, scope, time and expiration. Use the trusted default-branch approval workflow, not workflow code supplied by the exception change. A rerun or automation token must not create a fresh approval, expand scope or renew expiry. Revalidate an approval at release time; a changed, expired or revoked exception no longer permits release while its blocking finding remains applicable. Keep the authenticated approval evidence in the private archive and a disclosure-safe reference in the repository record.

Snyk UI Ignore/Accept Risk decisions can be referenced, but the release evaluator must verify identity, reason, scope, expiry, and agreement with the repository record. SonarQube/CodeQL dismissed findings remain subject to the same policy; missing native expiry support is handled by the evaluator. Query relevant accepted/dismissed findings as well as open findings. Prevent bypass through broad inline suppressions or disabling required rules without reviewed policy changes.

The evaluator rejects missing approvals, unknown records, stale/superseded evidence, invalid timestamps, indefinite temporary exceptions, expired/revoked decisions, and mismatched scope. An exception for one scanner does not automatically waive independent findings from another. Recheck validity at publication time to cover expiry during a long scan. Test malformed and tampered approval evidence.

Track medium findings with a 30-day remediation deadline and low findings with a 90-day deadline. Extensions require explicit owner approval and a documented new deadline. These are owner-selected targets, not claimed regulatory deadlines. Do not turn operational scan failures into accepted-risk records.

## Evidence and SSDF mapping

Store evidence under a dedicated Veyport directory on the owner's personal TrueNAS NFS export; keep hostname/export details in private operator configuration. No database or S3 service is required initially: files plus validated per-run manifests are sufficient. Verify export permissions, encrypted transport/storage, mount-loss behavior, durable readback, NAS snapshots, recovery, and separation of uploader and deletion/retention administration. NFS connectivity alone proves none of these properties. Do not claim immutable retention without testing the actual NAS controls.

A trusted collector runs in a dedicated unprivileged LXC container on the owner's personal Proxmox infrastructure. Mount NFS on the Proxmox host and expose only the dedicated Veyport directory to the container. Verify UID/GID mapping, permissions and mount availability before accepting writes; a missing NFS mount must not silently fall back to local storage. Select placement, resources and a tracked address before provisioning. The collector stores/verifies evidence and does not run submitted repository code or repeat scans.

For evidence transport, the workflow encrypts the bundle to the collector's public key before uploading a temporary GitHub Actions artifact. The decryption key remains under personal-stack operator control, with a verified recovery copy and rotation procedure; encryption of a payload alone does not authenticate its producer. Keep detailed private reports out of public job logs. The collector pulls the encrypted artifact over authenticated HTTPS, validates repository/workflow/run identity and expected digests, safely decrypts and validates its bounded contents, writes the archive, and verifies durable readback. Publication requires an authenticated acknowledgement bound to the complete run manifest. The NFS export stays private.

After verified archival and after all required jobs have finished consuming an artifact, delete only the allowlisted temporary evidence artifact by its exact ID through GitHub's API. Do not delete release assets, workflow records, build artifacts still in use, or unrelated repository artifacts. Record the receipt before deletion, and make retries idempotent. An unavailable NAS or failed verification prevents deletion and release publication. Use a bounded temporary GitHub retention window with alerts/reconciliation before expiry; automatic upstream expiry can still remove an uncollected artifact, so the collector cannot promise indefinite protection solely by withholding deletion. Document storage headroom and recovery for that case. This reduces GitHub storage occupancy; it does not eliminate temporary usage or reverse previously accrued storage charges.

Archive every run, including published releases, successful non-release runs, failures, cancellations, and timeouts. Capture full available structured reports, coverage/test results, sanitized diagnostic logs, scanner/project/scan references, findings, approval evidence, and final status. Use finalization plus independent reconciliation so cancellation is not dependent on an `always()` job that might never execute. Record missing/partial output explicitly and recover it when available; never invent a clean report for a scan that did not complete. An archive of an incomplete attempt is not passing release evidence. Do not retain credentials merely to claim that every raw log byte was preserved.

Published-release evidence is retained for one year from publication. All other runs are retained for 180 days from completion. Apply this independently of GitHub artifact expiry and vendor dashboard retention. Preserve enough private handoff time for collection/retry before upstream cleanup; capture provider results before they are overwritten or expire.

Store identical report payloads once using verified content identifiers, with an independent manifest for every run/release referencing its exact reports. Every reference must resolve within the archive, not only to a vendor URL. Shared reports must live until the latest retention deadline of every referencing record; reuse by a published release extends protection through that release's one-year deadline. Retention cleanup must not break an unexpired reference. Keep unsuccessful attempts and newly discovered findings distinct even when they concern the same commit.

Record candidate ID; source revision; image/binary digests; build/workflow identity; scanner versions and configurations; start/end times; roles/authentication/coverage outcomes; findings and evaluated exception revisions; test results; final decision; and staging deployment verification. Redact credentials and synthetic authentication secrets before storage. Public summaries contain pass/fail, versions, safe counts, and authorized evidence references only.

The implementation must inventory current artifact uploads and release attachments: existing public release evidence and Actions artifacts require explicit review so private DAST reports are not added to public bundles accidentally.

| SSDF practice area | Evidence this work contributes |
| --- | --- |
| PO.3 / PO.4: supporting toolchains and security-check criteria | Selected tools, overlap rationale, gate policy, execution records |
| PS.1 / PS.2 / PS.3: protecting code and release integrity | Trusted workflows, controlled publication, digest-bound artifacts and archived release evidence |
| PW.4: third-party components | Verified inventories, SCA coverage, component findings and decisions |
| PW.7: source review/analysis | SAST coverage, human triage, documented remediation or exception |
| PW.8: executable testing | Authenticated DAST, native protocol tests, coverage and results |
| RV.1 / RV.2 / RV.3: vulnerability response | Ongoing discovery, prioritized remediation, exception review and root-cause follow-up |

This is a contribution to an SSDF assessment, not a claim of certification or full compliance. Use [NIST SP 800-218 v1.1](https://csrc.nist.gov/pubs/sp/800/218/final) as the final reference checked during planning; assess other development and organizational practices separately.

## Implementation tasks and sequencing

Task tiers follow the owner's provider policy. On 2026-10-31 the official OpenAI model catalog (https://developers.openai.com/api/docs/models), local model cache, and callable collaboration runtime agree on `gpt-6.1-sol` for complex work and `gpt-6-luna` for standard work. Complex implementation was dispatched to three `gpt-6.1-sol` agents with supported `high` reasoning: collector/archive, release enforcement, and scanner/native coverage. Standard operator documentation used `gpt-6-luna` with `medium` reasoning. These choices do not change the owner's main conversation model.

| ID | Tier | Task | Depends on | Exit evidence |
| --- | --- | --- | --- | --- |
| P01 | standard | Record current workflow graph, gates, manifests, scan triggers/project identities, timings, and access | None | Baseline report with exact revisions, duplicate-work inventory and blockers |
| P02 | complex | Compare Snyk Code, SonarQube, CodeQL and Semgrep; validate the proposed two-platform target | P01 | Security/quality coverage comparison, runtime and unresolved limits |
| P03 | complex | Design trusted candidate transfer, coordinator lease, private evidence and promotion binding | P01 | Reviewed trust boundaries, failure cases and least-privilege access |
| P04 | standard | Create isolated candidate deployment/configuration and disposable data lifecycle | P03 | Independent volumes/keys/ports, isolation and reset verification |
| P05 | complex | Validate candidate hostname, login/TOTP/CSRF and network confinement | P04 | Positive/negative authentication and isolation checks |
| P06 | complex | Close Snyk SCA gaps, assign scan ownership, verify exact-artifact coverage and retire Veyport Dependency-Track imports after migration | P01, access | Complete inventories, no redundant scan/project creation, archived history, baseline triage and failure behavior |
| P07 | complex | Deferred: configure and integrate authenticated DAST | P05, owner resumes DAST review, provisioning/key | External scan coverage, role evidence, failure-mode verification |
| P08 | complex | Fill verified gRPC/SSH security-test gaps | P01, P04 | Candidate-bound protocol evidence and negative tests |
| P09 | complex | Implement exception schema, verified approval binding and evaluator | P03 | Tampering/expiry/scope/bypass regression checks |
| P10 | standard | Document risk policy/template, maintainer and operator procedures | P09 | Public-safe docs and usable approval workflow |
| P11 | complex | Integrate gated promotion, personal NAS archival, per-run reconciliation and shared-evidence retention | P03, P06, P08, P09; P07 only in the later DAST phase | No-publication failure tests, complete run manifests, safe deduplication/cleanup and identical tested/published digests |
| P12 | complex | Apply supported scanner consolidation and required-check migration | P02, P11 | No uncovered checks; branch protection and constitution synchronized |
| P13 | standard | Publish SSDF evidence mapping and measure PR/release completion | P10-P12 | Comparison against baseline, retained readable evidence |
| P14 | complex | Code review, then security review; resolve findings and re-qualify | P11-P13 | Reviewed exact final head with no unresolved blocking findings |
| P15 | complex | Candidate rehearsal, rollback drill and final monitoring | P14 | Complete passing run, intentional blocking cases, verified rollback |

Keep the work in PR #115 unmerged until reviewed. PR #112 is the earlier paused scanner proposal; do not merge or activate it. Reconcile reusable ideas deliberately rather than stacking unreviewed workflow changes.

## Validation and rollout criteria

- PR validation remains usable without private-network credentials or the DAST service. No privileged pull-request-target execution of untrusted source.
- Missing credentials/provisioning prevent DAST activation; no placeholder green gate claims it ran.
- Candidate authentication remains enabled and each intended role is actually exercised.
- Required gRPC/SSH negative tests and external audit failure checks run against isolated fixtures.
- Baseline high/critical findings cannot disappear through changed-lines-only checks or scanner dismissal alone.
- Reports and tokens do not leak to public logs, artifacts, PR comments, or release attachments.
- Equivalent GitHub/CLI scans and monitored projects are not added without a recorded coverage or freshness reason; exporting/archiving reports does not initiate a new scan.
- Every run has an archive manifest, including successful non-release, failed, cancelled and incomplete attempts. Missing evidence is explicit and recoverable, never silently reported as passing.
- Shared report references remain valid for every consumer's retention period: one year for published releases, 180 days for other runs. Test cleanup, cancellation, collector outage and NAS mount-loss recovery.
- Two simultaneous candidates cannot cross-contaminate scans or publish each other's evidence.
- Expired exceptions, incomplete scans, corrupt evidence, and mismatched artifact identities prevent publication.
- Successful publication promotes exactly the tested bytes, and normal staging receives that published version with a working rollback path.
- The maintainer can find the release decision and its one-year evidence without reading raw CI logs.
- Monitor all triggered jobs, reviews, release work, and authorized deployments to a final verified result. Starting a job is not completion.

## Constitution check

Preserve current quality, test, authentication, and mTLS requirements throughout the transition. The local constitution currently names Semgrep as mandatory; conditional removal must update that requirement and dependent references after the coverage comparison justifies it. The owner approved the comparison and conditional consolidation, not an unverified removal.

Respect collaborative planning: this document formalizes the agreed design at the owner's request. It does not claim the new gates are active, DAST entitlement is confirmed, or risk exceptions have been granted. Access verification comes before lengthy unattended implementation when the owner is preparing to leave.

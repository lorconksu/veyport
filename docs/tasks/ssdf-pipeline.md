# SSDF-aligned security pipeline implementation plan

Status: implementation plan; pipeline changes are not active. This work is reserved for PR #115. The owner approved the design through discussion on 2026-10-30. Snyk API & Web access remains unconfirmed and blocks activating that scanner, not writing or reviewing this plan.

## Objective and agreed decisions

Improve security coverage and retain reviewable SSDF evidence without adding unnecessary time to PR feedback. Publication may wait for required security results. Do not interpret parallel jobs as a guarantee of unchanged completion time.

- Keep SonarQube and CodeQL as the SAST foundation. Compare Semgrep's findings and coverage before deciding whether to remove its required gate. Do not add Snyk Code as another required SAST gate without demonstrated incremental value.
- Make Snyk the primary SCA interface after verifying complete project and artifact coverage. Preserve existing useful checks until replacements are proven. Dependency-Track remains available; any retirement of Veyport imports is a separate documented transition.
- Run authenticated web/API DAST through the external candidate endpoint before publication. Snyk API & Web is the proposed scanner, conditional on confirmed entitlement, provisioning, and API access.
- Run complementary gRPC and SSH security tests inside the private network against the same candidate. Inventory and reuse existing tests before adding missing cases.
- Use a separate disposable candidate instance on the existing staging server, with synthetic data, dedicated accounts, and separate test nodes. Keep normal staging available for manual testing.
- Build candidate artifacts once, scan those bytes, and promote those same artifacts after every gate succeeds. Bind evidence to the source revision and artifact digests.
- Block high/critical vulnerabilities and authentication, authorization, or required-audit failures. The latter block regardless of scanner severity labels. Existing findings require remediation or an explicit, valid exception; do not automatically grandfather them.
- Treat scanner errors, incomplete scans, failed authentication, missing required coverage, and unavailable evidence as failures. An operational scan failure cannot be waived as a vulnerability exception.
- Retain detailed evidence privately for one year. Publish only disclosure-safe summaries and links. One year is an owner-selected retention policy, not a claim that SSDF specifies that duration.
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
| Private evidence store and workload access | Select and validate existing infrastructure during implementation | Persisting detailed reports and enabling publication gate |

The main Snyk API returned `licenses`, `reports`, and `fullVulnDB` entitlements. Those values do not confirm or exclude DAST. Do not silently substitute a different scanner, purchase a plan, start a trial, or bypass the DAST gate to work around provisioning. If unavailable, return to the owner with alternatives and trade-offs.

Prefer dedicated automation identities with narrowly scoped permissions. Separate scan/target management from risk-acceptance approval. Verify effective privileges; an approver-name text field does not authenticate an approval. Keep credentials outside Git and public workflow artifacts. No user credentials or personal TOTP seeds enter the candidate dataset.

## Current pipeline and timing baseline

The existing pipeline uses `.github/workflows/ci.yml`, `release.yml`, `delivery.yml`, and `staging.yml`. Source tests, SonarQube, Semgrep, Gitleaks, and source vulnerability checks gate delivery. CodeQL runs through GitHub's configured analysis. The release workflow runs required CI again before building/scanning delivery artifacts. Existing artifact validation, malware checks, SBOM generation, and digest verification must remain covered.

Measured CI run [41001983872](https://github.com/lorconksu/veyport/actions/runs/41001983872) completed in 38m33s. Its longest server-test shard took 22m21s, followed by E2E at 15m36s; Sonar took 1m17s and Semgrep 51s and finished before E2E. This is a single baseline, not a percentile or performance guarantee. Removing Semgrep alone would not have shortened that run.

Measure comparable PR and release runs separately, including queue time, scan startup, candidate deployment, polling, evidence persistence, and publication waits. Report the median and tail when sufficient samples exist. Do not skip necessary checks to meet a timing target.

Review duplicate CI execution across merge/tag workflows. Reuse evidence only when its exact revision, workflow trust, configuration, required job set, and artifact identity match. Version-dependent binary and candidate checks must validate the final release candidate. Do not reuse results solely because a branch or mutable tag has a green badge.

## Proposed flow and trust boundaries

1. **PR validation:** run existing tests and the selected source scanners. Keep independent work concurrent. Untrusted PRs receive no deployment, scanner-management, approval, or private-network credentials.
2. **Trusted candidate preparation:** choose the immutable revision/version, build final candidate images and all public binaries, generate inventories, and assign a unique candidate ID. Preserve current integrity and malware checks.
3. **Private candidate transfer:** move candidate artifacts through an authenticated private store or an authenticated transfer to the trusted lab coordinator. Public GitHub Actions artifacts and public container tags are not private staging storage. Do not publish prerelease binaries as a workaround for testing before publication.
4. **Candidate deployment:** the trusted coordinator validates the requested repository, allowed workflow/ref, commit and digests, acquires an exclusive deployment lease, and deploys the candidate into the isolated environment. Do not run arbitrary fork/PR code on a privileged persistent self-hosted runner.
5. **Parallel qualification:** run authenticated DAST externally and gRPC/SSH checks internally, alongside applicable artifact checks. Record endpoint identity and candidate digests before and after the scans. Keep the candidate immutable and prevent another run from replacing it mid-scan.
6. **Evaluation and evidence:** obtain completed scan results, verify authentication/coverage, evaluate all relevant findings and exceptions, and durably save the private evidence bundle. Bind the decision to the exact candidate and policy version.
7. **Publication:** authorize only the candidate that passed every required gate. Publish the exact validated digests and binaries without rebuilding. Check exception validity again immediately before publication.
8. **Normal staging update:** back up normal staging consistently, deploy the published version, verify revision/digest, health, authentication behavior, and connected agents, and retain rollback evidence.

Candidate build/deployment can overlap independent CI when the source is trusted, but publication must await the combined results. Use explicit bounded polling, retry policy, and overall deadlines. A timeout, cancellation, superseded candidate, provider outage, or expired deployment lease produces a blocked/failed result, never a successful empty scan. Polling or scan completion must not automatically publish after the owner has canceled the candidate.

The coordinator should pull or receive narrowly defined deployment requests. Evaluate existing lab services before adding infrastructure. Treat artifact manifests, scan metadata, and exception documents as untrusted input; validate schemas, bound sizes, prevent path traversal, and pin trusted issuers/repositories.

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

Compare Semgrep, SonarQube, and CodeQL using the same source revision and relevant historical findings. Record configured languages, exclusions, query/rule sets, unresolved findings, reviewed suppressions, and remediation history. Distinguish configured rules from rules actually applicable/executed; raw rule counts are not coverage equivalence.

Classify Semgrep findings as duplicate, unique/actionable, reviewed non-security use, false positive, or unresolved. Review the reasoning behind existing suppressions rather than counting suppressions as proof of safety. Where useful, use isolated regression fixtures or existing historical fixes to check whether a competing scanner catches the same defect. No live exploit testing of user data is required for this comparison.

If Semgrep has no demonstrated useful incremental coverage, remove its job and required check together, after equivalent gates are verified. Update release dependencies, branch protection, documentation, and the local constitution references in the same transition. If a small set of rules adds value, retain those targeted checks with a documented rationale. Preserve historical evidence. No blanket promise that two analyzers detect identical defects.

Snyk Code remains non-blocking during this assessment. Do not add a fourth required analyzer simply because its license is available.

### SCA and artifact coverage

Reconcile the complete manifest inventory with Snyk projects: all Go modules, frontend and E2E npm projects, and pinned Python requirements. The prior inspection identified missing agent/E2E imports and a zero-dependency Python project requiring investigation. Validate dependency counts and lockfile/manifest resolution; an empty project is not evidence of a clean dependency tree.

Assess Snyk Container against exact built image digests; imported Dockerfiles with zero dependencies do not establish image coverage. Preserve every public binary's current vulnerability and malware checks. Keep `govulncheck` when its Go reachability evidence contributes beyond dependency-version matching. Replace overlapping package/image scanners only after exact-artifact coverage and failure behavior are proven.

Check both baseline and newly introduced vulnerabilities under the agreed release policy. A successful PR check reporting no manifest changes does not imply that the baseline has no high/critical findings. Validate scanner dismissals and ignore policies rather than accepting a green status as sufficient evidence.

### Web/API DAST

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

Snyk UI Ignore/Accept Risk decisions can be referenced, but the release evaluator must verify identity, reason, scope, expiry, and agreement with the repository record. SonarQube/CodeQL dismissed findings remain subject to the same policy; missing native expiry support is handled by the evaluator. Query relevant accepted/dismissed findings as well as open findings. Prevent bypass through broad inline suppressions or disabling required rules without reviewed policy changes.

The evaluator rejects missing approvals, unknown records, stale/superseded evidence, invalid timestamps, indefinite temporary exceptions, expired/revoked decisions, and mismatched scope. An exception for one scanner does not automatically waive independent findings from another. Recheck validity at publication time to cover expiry during a long scan. Test malformed and tampered approval evidence.

Track medium/low findings with owners and remediation deadlines. Select and document default deadlines during implementation; do not invent a regulatory deadline. Do not turn operational scan failures into accepted-risk records.

## Evidence and SSDF mapping

Store the detailed release bundle in private encrypted storage with scoped access, integrity digests, retention controls, and a verified restore/readback path. Enforce one-year retention independently of GitHub artifact expiry and vendor dashboard retention. Separate uploader and deletion permissions where supported; document actual controls rather than claiming immutability without verification.

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

Task tiers are planning classifications. Resolve provider/model IDs against the callable runtime when implementation starts; the owner's policy is latest available Sol for complex work and Luna for standard work under OpenAI, Opus/Sonnet under Claude. No model dispatch is claimed by this plan.

| ID | Tier | Task | Depends on | Exit evidence |
| --- | --- | --- | --- | --- |
| P01 | standard | Record current workflow graph, gates, manifest inventory, timings, and access | None | Baseline report with exact revisions and blockers |
| P02 | complex | Compare Semgrep, SonarQube, CodeQL; propose justified consolidation | P01 | Finding/rule coverage comparison, unresolved limits |
| P03 | complex | Design trusted candidate transfer, coordinator lease, private evidence and promotion binding | P01 | Reviewed trust boundaries, failure cases and least-privilege access |
| P04 | standard | Create isolated candidate deployment/configuration and disposable data lifecycle | P03 | Independent volumes/keys/ports, isolation and reset verification |
| P05 | complex | Validate candidate hostname, login/TOTP/CSRF and network confinement | P04 | Positive/negative authentication and isolation checks |
| P06 | complex | Close Snyk SCA inventory gaps and verify exact-artifact coverage | P01, access | Complete inventories, baseline triage, proven scan failure behavior |
| P07 | complex | Configure and integrate authenticated DAST | P05, DAST provisioning/key | External scan coverage, role evidence, failure-mode verification |
| P08 | complex | Fill verified gRPC/SSH security-test gaps | P01, P04 | Candidate-bound protocol evidence and negative tests |
| P09 | complex | Implement exception schema, verified approval binding and evaluator | P03 | Tampering/expiry/scope/bypass regression checks |
| P10 | standard | Document risk policy/template, maintainer and operator procedures | P09 | Public-safe docs and usable approval workflow |
| P11 | complex | Integrate gated promotion and private evidence retention | P06-P09 | No-publication failure tests and identical tested/published digests |
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
- Two simultaneous candidates cannot cross-contaminate scans or publish each other's evidence.
- Expired exceptions, incomplete scans, corrupt evidence, and mismatched artifact identities prevent publication.
- Successful publication promotes exactly the tested bytes, and normal staging receives that published version with a working rollback path.
- The maintainer can find the release decision and its one-year evidence without reading raw CI logs.
- Monitor all triggered jobs, reviews, release work, and authorized deployments to a final verified result. Starting a job is not completion.

## Constitution check

Preserve current quality, test, authentication, and mTLS requirements throughout the transition. The local constitution currently names Semgrep as mandatory; conditional removal must update that requirement and dependent references after the coverage comparison justifies it. The owner approved the comparison and conditional consolidation, not an unverified removal.

Respect collaborative planning: this document formalizes the agreed design at the owner's request. It does not claim the new gates are active, DAST entitlement is confirmed, or risk exceptions have been granted. Access verification comes before lengthy unattended implementation when the owner is preparing to leave.

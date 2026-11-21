# Snyk Actions policy controllers

The manual scanner, automatic informational PR feedback and owner-requested protected merger are implemented locally. App setup, hosted qualification and production restriction activation remain pending. The automatic-release hold remains in force; none of these controllers activates release/deployment policy. The existing diagnostic trial retains its original seven targets and source pins.

The agreed policy blocks every High or Critical vulnerability, including issues already in main and issues with no fix. High licenses and Unknown licenses block. Medium licenses are reported without blocking. The configured High license set is AGPL-1.0, AGPL-3.0, CPOL-1.02, GPL-2.0, GPL-3.0, and SimPL-2.0. No baseline subtraction or fix-availability exemption applies. Approved exceptions require a separately qualified private consumer; this candidate accepts no exceptions and rejects source `.snyk` policies.

## Controller and source boundaries

The manual scanner accepts only `workflow_dispatch` on `refs/heads/main` in `lorconksu/veyport`, under owner ID 13374789, with both the original and triggering actors restricted to `lorconksu`. It checks out the controller at the event's exact main SHA and source separately from the same repository at a validated lowercase 40-character commit SHA. Source input travels through environment variables or action inputs, never executable shell interpolation. There is no automatic PR trigger, approval ceremony, branch protection change, or release activation.

Source preflight runs controller-owned Python before tool setup or credentials. It verifies the source commit and all tracked regular file bytes against Git objects, rejects symlinks, hardlinks and submodules, and checks supported manifests and resolver inputs. It runs again after preparation, before scanning and each scan attempt, and after scanning. Source scripts and source workflow files are never executed. npm lifecycle scripts are disabled; Go only resolves package graphs with the local toolchain, readonly module files, workspace mode off and CGO disabled. Source package manager configuration, runtime selectors, npm engine/platform selectors, unsupported local npm dependencies/workspaces/registries and Go tool/toolchain directives are rejected. Local Go replacements must use bare tokens and resolve to one of the supported modules. Quoted replacement syntax, including escaped paths and replacements within blocks, is rejected conservatively before dependency preparation; the preflight does not attempt to decode Go strings. Other source changes may need a reviewed expansion of these bounds.

Eight scan targets are explicit:

- `hub/go.mod`
- `agent/go.mod`
- `cli/go.mod`
- `proto/go.mod`
- `infra/application-access/fixture/go.mod`
- `web/package.json`
- `tests/e2e/package.json`
- `infra/audit-lab/storage/requirements.txt`

All corresponding `go.sum` and npm lockfiles are bound too. Tracked and untracked manifest discovery rejects missing or extra recognized ecosystem inputs. The fixed filename inventory includes Deno manifests/locks, Dart pubspecs, Elixir/Erlang manifests/locks, Swift and CocoaPods/Carthage inputs, NuGet project/package inputs, Conan/vcpkg, Scala/Clojure, Gradle/Ivy, legacy Go dependency files, Julia, R renv and Haskell manifests, alongside the existing supported and rejected ecosystem names. The exact recognition set is `MANIFEST_NAMES`, the `requirements` filename prefix and the documented project-file suffixes in `scripts/security/snyk_policy.py`. This is bounded filename recognition: it cannot discover every custom or arbitrary dependency filename. Source inventory review remains necessary before enabling new ecosystems or naming conventions; no universal discovery coverage is claimed. The trusted Python wheel locks are controller inputs, not additional application targets. npm scans include development dependencies, including the E2E dependencies. New ecosystem filenames outside the recognized inventory need explicit support review.

The candidate qualifies exactly `boto3==1.40.72` and `cryptography==50.0.2` (requirements SHA-256 `692f262c74acca037f2042c023dff0835f59775428f62bba6fb017b71021c49e`) with the CPython 3.12/Linux amd64 hash-pinned, binary-only closure in `scripts/security/snyk_policy_requirements.lock`. The other nine closure versions and wheel hashes are retained. Preparation records that controller lock path and digest; scanning, each attempt and final evaluation recheck the binding. Candidate-owned constants select the requirements hash and lock; source content and command-line arguments cannot choose them. The historical seven-target diagnostic keeps its original exact requirements hash, `cryptography==46.0.5`, and byte-identical `scripts/diagnostics/snyk_runner_trial_requirements.lock` through the shared helpers’ defaults. Unqualified requirements fail before the token exists.

Resolver coverage is limited to Linux/amd64, default build tags and CGO disabled. It does not prove dependency coverage for other platforms, build tags or CGO-only paths. CGO disabling avoids compiler execution while resolving source; it differs from the diagnostic trial default and needs comparison during live qualification.

The workflow pins Go 1.26.11, Node major 25, and Python minor 3.12. Node/Python patch versions and all scanner/tool versions are recorded privately and allowlisted in the summary. Unsupported source directives fail; source files never choose a setup-action toolchain. Every run downloads the latest stable official standalone Snyk CLI through the existing bootstrap, verifies its version-specific SHA-256 and actual version, and rechecks the binary against its bootstrap record before use. This is same-origin HTTPS checksum verification, not an independent signature.

## Temporary hosted qualification harness

`.github/workflows/snyk-policy-qualification.yml` is a temporary sibling diagnostic, triggered only by a push to `diagnostic/snyk-policy-qualification`. Its job also requires the exact push event, `lorconksu/veyport`, repository owner ID and actor ID 13374789, both actors `lorconksu`, and the exact diagnostic branch ref. There is no manual dispatch or PR launch path. It runs the same eight-target helper, pinned runtimes, preflight, checksummed latest CLI, tests before credentials, preparation, live controls and scans, evaluation, sealing, encrypted upload, cleanup and final gate as the manual-main candidate. Only the scan step receives the Snyk token. Its private runner root and three-day encrypted artifact have qualification-specific names.

This launch condition has a distinct trust boundary: controller and source are separate checkouts of the same repository at the event's exact, validated 40-character `github.sha`. The controller is reviewed diagnostic branch content, rather than a controller already integrated into main. Because a commit cannot contain its own hash, the owner must independently verify the exact approved snapshot commit before pushing the single diagnostic branch, after the required immutable reviews. An owner push alone is not evidence that the snapshot was reviewed. The original seven-target diagnostic and its source pins remain unchanged.

The harness qualifies hosted Ubuntu execution of the candidate lifecycle without integrating main, changing required checks or activating PR/release policy. It does not invoke reusable CI, Sonar or deployment. Local validation does not establish a hosted pass: record the actual hosted preparation, live-control/scan verdict, encryption, upload and cleanup outcome only after owner-provided run evidence. Findings or incomplete evidence still fail the same final gate.

Both the manual-main candidate and this harness initialize distinct empty user and global npmrc files under their private config directory and export those paths through `GITHUB_ENV` before tool setup. Pointing both settings at `/dev/null` makes Node 25/npm 11.12.1 fail with a double-loading config error before dependency resolution. The separate files retain the isolated home/cache and disabled lifecycle scripts; source-owned npm configuration is still rejected by preflight. Local probes execute each actual initializer and use its derived environment for npm config loading and fresh `npm ci --ignore-scripts --include=dev --no-audit --no-fund` installs of both npm targets without credentials.

## Web tooling dependency qualification

The web manifest scopes two overrides to development tooling: jsdom 29.0.1 uses the compatible undici 7.30.2 patch, and Ajv 6.15.0 uses the exact npm alias `uri-js: npm:fast-uri@4.2.3`. Ajv remains on the major used by ESLint 10.8.0; substituting Ajv 8 would change its draft04 and option contracts. The original uri-js release has no available fixed release for the reported blocker. This alias installs Fastify's separate maintained implementation, with its real `fast-uri` name, version, official registry tarball and integrity retained in the lockfile. It does not rename the original package or suppress scanner findings. Existing overrides and application dependencies are retained.

fast-uri 4.2.3 has no runtime dependencies and uses BSD-3-Clause, replacing uri-js's BSD-2-Clause implementation; undici retains MIT. The substitution changes the upstream code and maintainer trust boundary to the Fastify project. Its exact pin requires deliberate maintenance: recheck upstream releases, license metadata, registry integrity and the consumer tests when updating Ajv, ESLint or fast-uri. It is not a guarantee of general URI API equivalence: fast-uri does not export `resolveComponents`, while the bounded Ajv 6 consumer uses `parse`, `serialize` and `resolve`. These packages remain development tooling and are not imported into the application browser code.

`web/src/__tests__/tooling-uri.test.ts` runs in the existing `test:coverage` suite. It checks the actual implementation resolved through ESLint's Ajv, bounds Unicode U+2028/U+2029 normalization and resolution in child processes, and checks draft04 valid/invalid data with relative, external and fragment references under `id` and `$id`. The original implementation failed the identity assertion and exceeded the three-second Unicode child deadline before the override was applied. The replacement percent-encodes these Unicode separators, including when `iri: true` is supplied; this fixture does not promise preservation of uri-js IRI rendering behavior.

Local Node 25.9.0/npm 11.12.1 qualification passes all 847 web tests, the TypeScript/Vite build, the regression's own lint/typecheck and a repeat `npm ci --ignore-scripts --no-audit --no-fund` without manifest/lock changes. Full lint retains the identical pre-existing 20 errors and two warnings. The targeted dependency graph passes; full `npm ls --all --json` retains the original lockfile's optional `lightningcss-linux-x64-musl` platform validation error on this glibc host, reproduced in a separate clean baseline install. Exact logs and comparisons are private. Fresh Snyk and complete hosted policy qualification remain separate checks.

## Policy result and license controls

The evaluator parses strict legacy Open Source CLI JSON. Duplicate JSON keys, nonfinite values, malformed reports, unknown severity, wrong organization/manager/target, missing or duplicate projects, nonempty or malformed filtered ignore/patch metadata, unknown dependency versions, and processing failures fail closed. `--ignore-policy` is set on every scan to prevent local, organization or project ignores becoming unauthorized exceptions. Both legacy `severity` and `severityWithCritical`, when present, must be recognized; the higher severity wins for application findings. License identity comes from the report's `license` field, never the package `name`. Findings are counted as path records, not deduplicated issue totals. The verified legacy CLI contract intentionally omits `type` on vulnerabilities. The candidate accepts an omitted or explicit `vuln` type only with a recognized `SNYK-...-<numeric ID>` vulnerability namespace and no `license` field. License findings require explicit `type: license`, a canonical nonempty license identifier and a five-part `snyk:lic:<manager>:<package>:<license>` ID with nonempty printable whitespace-free components. The license encoded at the end of that ID must exactly equal the report's `license` field. Contradictory identities, including Unknown or configured High IDs paired with a permissive label, are incomplete rather than nonblocking. Null/unknown types, missing license types with license-like fields/IDs, conflicting markers and unrecognized vulnerability ID shapes make the report incomplete. This preserves the real omitted-type vulnerability output while preventing a medium-rated Unknown or configured High license from being treated as a vulnerability.

The owner-reviewed configuration records the six High license identifiers above and Unknown set to High. The trusted controller encodes this expected configuration, organization and owner-capture digest in a policy digest. It does not consume an `authenticated=true` flag, local attestation, environment pass flag or source-owned policy descriptor. Report metadata `licensesPolicy: {orgLicenseRules: null, severities: null}` still does not export the effective policy table or establish verification by itself.

Each run now verifies live service behavior with two immutable positive controls before application scans, using the same checksum-verified latest CLI, explicit organization and `--ignore-policy`. `scripts/security/snyk_license_canary.json` contains the exact metadata-only package/lockfile bytes that produced the independently saved combined probe. The controller verifies the fixture and both member-file hashes, then materializes only those two files under the private runner root. It scans `--file=package-lock.json` explicitly. No npm install, package tarball installation or package code execution is part of the control. No application `package.json` or lockfile is added to the repository, so the fixture is not a ninth application target.

A successful control requires exit 1, `ok: false`, the expected organization, npm lockfile target, exactly three dependencies, no unknown versions, empty ignore/patch metadata and exactly two license findings. Their identities must match `meld-spec` 0.4.2 / Unknown / `snyk:lic:npm:meld-spec:Unknown` and `languages` 0.1.3 / GPL-3.0 / `snyk:lic:npm:languages:GPL-3.0`. Each reported severity field must be High or Critical; Critical is accepted as stricter enforcement. Missing, duplicated, substituted, downgraded or additional findings fail verification. An unrelated vulnerability cannot replace either required license finding. Complete contradictory or policy-negative responses are not retried. Processing failures have at most two attempts with a 300-second deadline each, and stale output is removed before every attempt.

This is **current Unknown/GPL enforcement smoke verification under owner-reviewed configuration**. It does not empirically retest each of the six individual High settings on every run, export the full provider policy table, or prove a complete license inventory. Snyk's provider limitations remain: newly supported licenses can default to None; mixed licenses with a None component can be omitted from issues; commit-hash package versions lack license support. The gate applies to Snyk-rated issues within this provider scope. It does not establish universal legal compliance or change provider dual-license semantics.

A fresh private run identity binds source/controller revisions, scanner version/hash, policy digest, fixture hashes and available GitHub repository/run/attempt/job provenance. The raw control report and exact exit/attempt metadata are hashed and bound to that identity. Evaluation re-reads those bytes and all eight application reports; neither cached pass fields nor a copied prior-run control record can authorize a pass. Application scans also remove each prior JSON path before launching every attempt, including reused private roots. Each newly produced application report is hashed and bound to its exact project, attempt number, exit/status metadata and fresh run identity. Evaluation rechecks every attempt's raw bytes and binding; missing/malformed metadata or changed report bytes produce exit 2. Historical diagnostic reports without this new binding can be replayed through the parser for compatibility evidence, but cannot authorize a current policy pass. Evidence expires after the workflow's 180-minute time bound. Sealing evaluates the evidence again before publishing sanitized counts.

Technical completion, observed findings and policy verification are separate fields. Exit 0 means all eight application scans are complete, neither blocking vulnerability nor blocking license findings are present, and current controls verify. Exit 1 means the same complete/verified state contains blocking findings, including old or unfixed issues. Exit 2 means application, preparation, scanner or control evidence is incomplete or invalid. Public control counts and status are separate from application findings: the deliberately blocking controls never inflate application blockers.

No exceptions input is supported. Source `.snyk`, report-level attempted exceptions, or filtered suppression cannot authorize a pass. A future consumer must verify explicit approval, scope and expiry privately and undergo independent review.

## Privacy and failure handling

The Snyk token is supplied only to the scan step. Tool bootstrap, dependency preparation, tests, policy evaluation, encryption and uploads receive no Snyk token. Within scanning, the trusted Snyk parent retains that token; the Python resolver wrapper unsets `SNYK_TOKEN` before launching the separate UID65534/GID65534 process with no supplementary groups and no new privileges. Existing tests verify that resolver startup cannot read the scanner parent's environment or explicit private report files. Fresh home/config/cache, scanner tools, explicit reports/logs and immutable control workspace/run identity live under the private runner root. These paths are not permission-broadened for the resolver; the checked private-root permissions deny its access. Its interpreter and fixed public requirements mirror are provided separately, with bounded deadlines and cgroup teardown.

Normal application/control scanner temporary roots are private. **The Python scan is an exception:** its `SNYK_TMP_PATH` is `public_root/resolver-assets` so the separate-UID interpreter can execute the extracted resolver. The wrapper checks the selected extraction directory's canonical location and ownership, rejects symlinks in it, and recursively applies `a+rX` to that entire selected subtree. These are path/ownership checks, not an allowlist or classification of each file's contents. Files in that subtree become readable and directories traversable to UID65534 (and other local UIDs with the path); internal scanner data placed there is therefore not covered by a blanket confidentiality guarantee. The candidate does not prove that every Python scanner temporary file contains only public code or that the scanner never places sensitive contents there. The token's environment handling and the private explicit-evidence destinations are separate boundaries, not a claim about extraction-tree contents. Cleanup removes this public workspace as well as private plaintext.

Captured stdout/stderr, explicit JSON reports, helper error details and raw policy evidence are written to private destinations, then only age ciphertext and a rebuilt allowlist are uploaded. This destination/upload guarantee does not classify internal files in the Python extraction subtree. Public artifacts expose only revision hashes, validated versions, fixed project paths, fixed verification scope/statuses, policy/fixture digests and numeric aggregate counts alongside ciphertext; issue IDs, package names, reasons and raw exception descriptors are excluded from the public summary. The existing public age recipient is retained; no private key is accessed. Artifact retention is three days.

Encryption must succeed before upload. Failed encryption removes stale public output, and plaintext deletion is attempted even after resolver cleanup fails. The final gate independently requires successful scan, policy evaluation, encryption, artifact upload and cleanup, plus the freshly sealed policy exit value exactly 0. After fresh evaluation, successful encryption, summary creation and plaintext removal, the sealer exports that numeric verdict through the current encrypt step's GitHub output. The final gate reads this current step output; absent or malformed values fail closed. It does not reuse the earlier policy step's success as authority for changed evidence. A newly blocked/incomplete verdict keeps encryption successful and the encrypted artifact eligible for upload, then fails the final gate; cleanup still runs unconditionally. A policy failure is not hidden with `continue-on-error`. Cleanup also removes the private control workspace/run identity, home/config/cache and plaintext archive. Hosted-run cancellation can interrupt cleanup; only encrypted artifacts are eligible for upload and the ephemeral runner remains the final disposal boundary.

Cleanup first requires a canonical, owned private root without group/other write access. Before removing private caches, it runs local `go telemetry off` and `go clean -modcache` in a disposable private working directory, with a fresh home/config, no inherited credentials or Go settings, disabled proxy/checksum services, and `GOMODCACHE` bound only to the canonical owned `cache/go-mod` child. This removes Go's read-only extracted module directories without changing resolver behavior. Root/cache/module-cache symlinks cannot redirect the Go cleaner. Each Go command has a 30-second deadline and discards output. An absent module cache needs no Go executable; an existing cache requires successful Go cleanup. Go setup, command or timeout failures retain cleanup failure even if generic deletion succeeds, and every remaining private plaintext deletion is still attempted for a valid root. An invalid private root stops all deletion.

## Validation and rollout

Local tests cover policy severity and license decisions, suppression/malformed input, exact live-control identity and stale/tampered binding rejection, exception refusal, eight-target scanning, source/manifest drift, unsafe resolver inputs, missing credentials, bootstrap binding, evidence failure paths and final outcomes. Existing diagnostic tests remain required. Run from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s scripts/diagnostics -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s scripts/security -p 'test_*.py'
actionlint .github/workflows/snyk-policy.yml .github/workflows/snyk-policy-qualification.yml .github/workflows/snyk-runner-trial.yml
git diff --check
```

Tests include synthetic Git repositories and fake scanners/encryption commands; these do not establish live provider authentication, real encryption success or hosted resource capacity. Saved historical report and combined-control replay are evidence of parser/adapter interpretation only, not a fresh hosted candidate scan. Private state records preparation and scan elapsed seconds; it does not measure peak whole-run memory, disk or runner capacity.

Before a trusted-main run, complete the required immutable security and Claude reviews and owner-authorized integration. Then qualify actual hosted preparation, credentials, live controls with all eight targets, encrypted artifact upload and cleanup. The isolated real combined-control evidence supports this adapter; it does not establish full hosted candidate qualification. The local environment need not contain the hosted pinned runtimes, age or credentials, so offline test success is not full workflow qualification. An automatic PR wrapper requires additional check/source provenance qualification. Keep the eventual PR and release policy identical; activation and any risk acceptance remain separate owner decisions.

## Automatic same-repository PR feedback

`.github/workflows/snyk-pr-policy.yml` listens only for trusted `CI` entering `in_progress` through `workflow_run`. It authenticates repository ID `1188082218`, owner ID `13374789`, upstream workflow ID `251054731` at `.github/workflows/ci.yml`, and the current open PR targeting `main`. Authenticated commit-associated PR metadata resolves empty event PR arrays; ambiguous mappings fail closed. Source and controller are separate exact-SHA checkouts. Forks and colliding current PR heads are rejected without source checkout. The qualified eight-target scanner lifecycle above remains intact.

The exact lowercase repository variable `SNYK_PR_POLICY_ENABLED=true` enables feedback. Admission/publication have only Contents, Actions and Pull requests read plus Checks write on their job-scoped `GITHUB_TOKEN`; separate bounded transport clients constrain metadata reads and check writes. They use no private App, key or environment. Scan has Contents read, and only its scan step receives `SNYK_TOKEN`. The displayed native GitHub Actions check (App ID `15368`) is **`Snyk PR scan`**, with an explicitly informational summary. Its strict envelope purpose is `automatic-pr`; exact current attempt jobs, lifecycle outcomes and the three encrypted/allowlisted artifact files are still validated before publication. Historical same-SHA chronology and collision checks improve feedback freshness.

Commit checks are shared across PRs and can be spoofed by another workflow with check permission. A reused SHA can display an earlier green before admission. This check is not required security authority and must never be used alone to authorize merging. No protected merge consumes its result, check ID, artifact or previous scan. The protected merger independently scans the exact requested PR in its own fresh run, including when another PR has the same head SHA.

## Exact owner-requested protected merge

Use `.github/workflows/protected-merge.yml` from trusted `main`, as owner `lorconksu` (ID `13374789`). It accepts exactly three input keys: `operation` (exact lowercase `verify` or `merge`, default `verify`), canonical positive `pr_number`, and the expected lowercase 40-hex `head_sha`. Inputs are event/environment data, never shell source. Invalid casing, extra inputs, non-owner original/triggering actors, forks, drafts, closed or retargeted PRs, head/base/controller drift and run attempts other than `1` fail closed. Retry by dispatching a new exact request; **Re-run jobs** cannot replay a merge authorization.

Four fresh jobs isolate authority:

1. `admission` checks out only the trusted controller and authenticates the exact live owner request, PR node/number/head/base, current main/controller and workflow run. It produces a purpose-specific admission; outputs are transport hints and each later verifier rederives the identity.
2. `scan` checks out the exact admitted source separately and follows the qualified lifecycle: complete inventory/source checks, checksummed latest stable CLI, credential-free helper tests and preparation, isolated resolvers, all eight targets and live bound license controls, evaluation, encryption, evidence binding, upload, unconditional cleanup and final gate. Only **Scan current source and bound license controls** receives `SNYK_TOKEN`. It receives no App authority.
3. `verify` independently downloads this run's unique `protected-merge-RUN_ID-1` artifact, validates mandatory API digest/provenance, exact `summary.json`, `evidence.tar.gz.age`, `publication.json` contents and strict request/policy/scanner bindings, then checks actual successful admission/scan jobs and every lifecycle step. It emits only strict verified purpose and source hints.
4. `merge` can enter `ssdf-protected-merge` only after successful current-run verification emits purpose `protected-merge` for exact operation `merge`. GitHub expression string equality ignores case; the helper strictly parses the event before emitting that purpose. Inside this fresh job a second read-only preflight also requires the completed successful verify job. Only then does the pinned action mint the narrow App token. The final helper repeats evidence/currentness and live settings checks, checks actual in-progress merge-step metadata, then sends one PR-number-specific merge request with expected head and `merge_method=merge`. It has no PR checkout, scanner token, push path, check override, branch deletion or auto-merge operation.

`verify` uses purpose `protected-merge-preview`, performs fresh admission/scan/evidence verification, and never enters the App environment, mints a token or constructs a mutation client. Preview evidence cannot be reused for merge. `merge` always scans again. Enable the reviewed workflow for owner-only preview using exact `PROTECTED_MERGE_ENABLED=true` before activating the restriction if needed; the flag alone cannot authorize mutation. Merge additionally requires the live active restriction and full classic baseline.

The short-lived token and authenticated installation ID/slug come **directly** from `actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510` (v3.3.0). The action uses its internal App JWT for the repository-installation lookup. No second JWT/private-key helper exists. The final helper validates those action outputs against configured identities, reads strict App metadata and the token's exact sole-repository scope, and retains normal post-job token revocation. Public App metadata alone does not authenticate token identity: pinned action wiring is part of the trust boundary.

## One App setup and protection preservation

Complete setup after immutable reviews, using the owner session. Key material belongs only in the main-only environment secret, never chat, repository files, artifacts or command output. No separate Checks App registration is needed.

1. Register one dedicated GitHub App for `lorconksu`, homepage `https://github.com/lorconksu/veyport`, without callbacks, webhooks or event subscriptions. Grant only repository **Contents: Read and write**, **Administration: Read-only**, and mandatory **Metadata: Read-only**. Leave Actions, Checks, Workflows and every other permission ungranted. Administration read is necessary for classic-protection inspection; never grant Administration write to work around visibility failures.
2. Install the App with **Only select repositories → veyport**. Record its positive numeric App and installation IDs, client ID and actual slug privately. The installation itself must select only `veyport`; the helper separately proves the minted token's narrowed repository scope. Do not substitute a personal token, GitHub Actions ID `15368` or CodeQL ID `57789`.
3. Create environment **`ssdf-protected-merge`**. Under Selected branches and tags allow branch **`main` only**, no tags. Disable administrator bypass of environment protections. Configure no reviewer/wait timer: the exact owner dispatch authorizes the attempt. Verify these controls are enforced for this repository/plan. Enter the PEM as environment secret **`PROTECTED_MERGE_APP_PRIVATE_KEY`**, without a repository-level copy. Preserve repository scan secret `SNYK_TOKEN` separately.
4. Add repository variables **`PROTECTED_MERGE_APP_ID`**, **`PROTECTED_MERGE_INSTALLATION_ID`**, **`PROTECTED_MERGE_APP_CLIENT_ID`** and **`PROTECTED_MERGE_RULESET_ID`** for the reviewed production rule. Leave **`PROTECTED_MERGE_ENABLED`** unset/`false` until reviewed integration and preview qualification. Automatic feedback uses only **`SNYK_PR_POLICY_ENABLED`** and needs none of the obsolete `SNYK_POLICY_APP_*` variables/secrets or publisher environment.
5. Preserve the complete recorded classic `main` protection: all twelve exact context/App-ID pairs (eleven GitHub Actions `15368`; CodeQL `57789`), strict up-to-date checks, administrator enforcement, reviews, conversation resolution, explicitly disabled required signatures (`required_signatures.enabled=false`) and every existing control. The captured personal-repository API omits `restrictions`; absent or explicit `null` both mean no push restrictions. Every other recorded control must be present with its exact value; non-null restrictions, missing required metadata and unknown controls block merging. The offline baseline fixture is the public-safe raw GitHub API response captured on 2026-11-16 using API version `2022-11-28` (`scripts/security/fixtures/github-main-protection-2022-11-28.json`). Add a **separate** repository branch ruleset targeting only `refs/heads/main`, no exclusions, with only **Restrict updates**, `update_allows_fetch_and_merge=false`, and exactly this App Integration as a **pull_request-only** bypass actor. No human/administrator/general bypass and no checks/reviews in this restriction rule. Keep it disabled until platform qualification passes; the App bypass of this one update restriction must not bypass the independent classic protection.

For the single update rule, ruleset detail and effective branch rules may independently omit `parameters` or return exactly `{"update_allows_fetch_and_merge":false}`. Both validators accept only those two forms with exact rule keys and effective-rule provenance; null/empty parameters, missing/nonboolean/true flags, unknown fields and extra rules refuse before mutation.

The merger conservatively rejects any additional active repository/inherited ruleset. The temporary qualification restriction must be **disabled before complete production settings validation or merging**. Main baseline auditing during isolated qualification is a separate read-only check; it is not proof that full production settings validation passed.

## API and hosted qualification limits

The PR merge API atomically checks expected **head SHA**; it offers no atomic expected-base/controller/target predicate. Final live rereads reject observed drift, but a trusted repository writer/main administrator can move/retarget after the final read. Ordered two-parent and actual PR/commit postchecks can detect an irreversible race after mutation; they cannot undo it. Those writers/administrators remain trusted. No atomic base guarantee is claimed.

A timeout, protocol error or malformed response never causes a second PUT. The helper performs at most one read-only outcome reconciliation and reports `unconfirmed` with failure if unresolved. Inspect actual PR/commit state read-only before any new dispatch. After a confirmed merge, follow all downstream checks/jobs to terminal status; retain the automatic-release hold.

Hosted proof is required for App metadata visibility (including a private App), exact token repository scope, Administration-read classic protection reads, complete visible ruleset bypass roster, environment enforcement and live Jobs API step visibility/consistency. Omitted/hidden/stale lifecycle or settings data blocks merging, with no success fallback or broadening of permissions. The current in-progress final step must be visible once and all prior required steps successful. The action's post-job revocation follows mutation; monitor its terminal result too.

Contents write without Workflows write may be insufficient to merge a PR that changes workflow files. Qualify this with the actual least-privilege App and record the outcome; do not silently grant Workflows write or claim workflow-changing PRs are supported before proof. Local offline transports cannot prove GitHub restriction enforcement, App bypass behavior, native required-check selection or these visibility/permission properties.

## Qualification, activation and rollback

1. Complete local security/diagnostic validation, actionlint/shellcheck, root scoped review and ordered immutable Daybreak then independent Claude reviews. Resolve every actionable finding before staging/publication. Integrate the reviewed controller into main only under concrete owner authorization, initially disabled. Capture all current production protections privately and preserve the release hold.
2. Complete the one-App/environment setup. Enable owner-only `verify` preview and automatic informational feedback in a controlled window without changing production update protection. Follow every started job to terminal status and inspect exact request/run/controller identities, all lifecycle outcomes, ciphertext/public summary/envelope and artifact provenance/digest. A green preview alone is not merge or platform enforcement proof.
3. Use a separately reviewed, owner-only qualification harness fixed to **`qualification/protected-merge-20261116`** and a separate restriction. Production helper remains fixed to `main`, with no arbitrary-target switch. Prove humans cannot update the restricted fixture branch, pull_request-only App bypass cannot direct-push, required checks still block the App, a properly checked expected-head PR can merge, and wrong head returns 409. Never drop production contexts or forge a production scan/check. Any isolated synthetic canary proves only its stated primitive; external native providers may not supply all twelve production checks on a fixture branch. Leave the reviewed harness disabled afterward; do not remove it through unreviewed cleanup.
4. Qualify High/Critical vulnerability and High/Unknown license blocks, informational Medium licenses, missing/extra inventory, control/processing/encryption/upload/cleanup failures, cancelled/skipped steps, owner/fork/draft/retarget rejection, head/base/controller changes, rerun refusal, old successful SHA reused by another PR, prior-run/wrong-purpose/malformed evidence, token identity/scope errors and uncertain outcomes. Preview must create zero App authority; a merge request must scan freshly. Demonstrate the least-permission behavior for workflow-changing PRs and actual final-step Jobs API visibility.
5. Disable the temporary qualification restriction. Audit the exact full production baseline and intended rule, activate only the reviewed main update restriction under owner authorization, and demonstrate an exact owner-requested production merge through this workflow while all twelve classic contexts remain enforced. Missing/hidden bypass actors or any unproven platform prerequisite blocks activation. Do not promote `Snyk PR scan` into sole required security authority.
6. Only after replacement is proven, retire the legacy Snyk PR security/license integration checks using the provider's narrowly verified PR-check setting. Preserve Snyk projects/account monitoring, CI/Sonar checks, classic protections and release/deployment controls. Unverified narrow retirement remains pending.

For rollback, disable `PROTECTED_MERGE_ENABLED` and optionally `SNYK_PR_POLICY_ENABLED`, cancel and follow active attempts to terminal, and inspect any uncertain merge outcome read-only. Disabling the workflow while the restriction is active intentionally blocks updates; it does not restore the prior merge route. Restoring that route requires the owner-recorded prior restriction configuration or a proven reviewed replacement, while retaining all twelve classic contexts, strictness and administrator enforcement. Never turn a check green manually or broaden the App bypass to recover. Revoke/rotate credentials in the owner session when necessary and repeat identity/hosted qualification before re-enabling.

Local verification adds these workflows to actionlint and the full security suite:

```sh
PYTHONDONTWRITEBYTECODE=1 python3.12 -B -m unittest discover -s scripts/security -p 'test_*.py'
actionlint -shellcheck=/usr/bin/shellcheck .github/workflows/snyk-pr-policy.yml .github/workflows/protected-merge.yml .github/workflows/protected-merge-qualification.yml
git diff --check
```

Tests use only the standard library and offline transports, execute actual workflow shell guards and constrained GitHub expressions, assert direct credential/output wiring, and reject deliberate damaged-workflow mutants. They establish local contracts, not hosted rollout.

## Fixed isolated qualification harness

The disabled-by-default `.github/workflows/protected-merge-qualification.yml`
uses only `qualification/protected-merge-20261116`. It accepts exactly `case`,
`pr_number` (canonical positive decimal) and `head_sha` (lowercase 40-hex).
There is no target/repository override. Owner `lorconksu`, both original and
triggering identity, trusted current `main`, the exact workflow path and
attempt `1` are independently authenticated by the helper. Non-owner, rerun,
fork, draft, head/base/controller drift and any other base, including `main`,
refuse before mutation. A final independent mutation-layer target guard also
rejects `main` and every other branch. The PR must be open, non-draft, actually
mergeable, have a distinct head/base, and target the literal fixture even for
`main-settings`; missing/stale mergeability is a blocker, not a retry fallback.

After source review/integration, the owner prepares the fixture branch and
same-repository PRs using owner access and records original settings/ref/rule
IDs privately. Copy **all** classic baseline settings and twelve producer-bound
checks to the fixture, including strict checks and administrator enforcement.
Create a separate active repository restriction with only this literal branch
included, no exclusions, only update restriction with
`update_allows_fetch_and_merge=false`, and exactly the same dedicated App as
Integration/pull_request bypass. Set positive repository variable
`PROTECTED_MERGE_QUALIFICATION_RULESET_ID` to this separate rule ID; it must
differ from `PROTECTED_MERGE_RULESET_ID`. The App has no Administration write
or Checks write grant, so it cannot create/edit rules, protections or checks.
Its Contents write grant permits content/ref mutation subject to branch
protections; the PR-only bypass is expected to deny direct updates to the
protected fixture. The helper's App mutation client limits attempts to a ref
PATCH on the literal existing fixture for the direct-push probe or an exact
fixture PR merge. Fixture preparation and owner/human direct-update and
PR-merge refusal probes remain owner-operated; this harness always uses the
App.

Enable only during the qualification window using exact repository variable
`PROTECTED_MERGE_QUALIFICATION_ENABLED=true`. The same main-only
`ssdf-protected-merge` environment holds the same key. Read-only admission and
fresh preflight precede the pinned token action; direct action outputs bind
token, installation ID and App slug. The App grants remain Contents write,
Administration read and mandatory Metadata read. Normal token revocation stays
enabled. No Snyk token or PR source checkout enters the harness. Dispatch a new
run for each exact fixture PR/head; never rerun an attempt to retry a write.

| Fixed case | Fixture prerequisite and allowed proof |
| --- | --- |
| `main-settings` | Read-only App identity/scope and exact complete main classic baseline audit; no mutation client. Does not run full production rules validation or prove main bypass visibility. |
| `settings-diagnostic` | Read-only App settings and bypass visibility on the fixed fixture. The fixture ruleset can remain disabled. |
| `wrong-head` | Sends fixture base SHA as deliberately wrong expected head to exact fixture PR; requires HTTP 409 plus unchanged open PR and unchanged fixture branch. |
| `direct-push` | Head is a real single-parent commit directly above fixture base, making a non-no-op fast-forward PATCH possible. Proof requires unchanged PR/ref and an actual GH013 response identifying “Cannot update this protected ref”. Permission errors, non-fast-forward errors, no-op success, generic denial and uncertainty remain unproven. |
| `native-merge` | Exact head carries all twelve successful native check runs with original names and App IDs. Actual fixture merge/ref and ordered parents must match. |
| `missing-canary`, `pending-canary`, `failed-canary` | Retain all twelve successful native checks and add only required `Protected merge qualification canary`, bound to GitHub Actions `15368`. The trusted native admission producer creates pending/failed canaries; missing-canary creates nothing. Requires HTTP 405 explicitly identifying required-check denial and unchanged PR/ref. Scope is only general check blocking. |
| `workflow-file-merge` | Same twelve actual native successes, plus authenticated PR diff changing `.github/workflows/`; bounded complete diff requires fewer than 100 changed files. Confirms actual merge or records least-permission failure as a blocker. Never grants Workflows write. |

Positive proof may use a genuine already-checked commit as PR head against a
reviewed ancestor fixture base. Check runs must actually name that exact head,
complete successfully, and carry the twelve expected native producer bindings;
ambiguous duplicate names refuse. A custom successful context cannot replace
CodeQL or any other native producer. A fixture must also satisfy the platform's
strict up-to-date/mergeability rules. If providers cannot furnish their genuine
checks on a suitable fixture, record the exact unavailable case and keep it a
qualification limit/blocker. Do not drop a required context or manufacture a
production scanner result to get a positive proof. Synthetic check canaries
establish only their stated general blocking primitive; they do not prove each
native provider's failure enforcement. Per-context native missing/pending/failed
proof remains a separate owner matrix item where real providers support it.

`python3.12 -I -B scripts/security/protected_merge_qualification.py admit|produce-canary|probe`
is the complete CLI; all request data comes from the authenticated event and
GitHub environment. Successful admission emits only `admitted=true` and the
strict case through `GITHUB_OUTPUT`. The platform probe JSON exposes schema version,
case/target/run/PR/head/base identity, HTTP status (null when unknown), outcome,
merge SHA, mutation-attempt flag and evidence scope. It never prints raw API
messages, credentials or exception details. Expected verified denials are
successful qualification outcomes; generic denials, unexpected writes and
uncertainty fail the job. One PATCH/PUT is the maximum. A write with uncertain
response is never retried; read-only PR/ref/commit reconciliation may confirm a
native merge, while unresolved outcomes are `unproven`/`unconfirmed`. A
`refused` result has `mutation_attempted=false`; it does not cover an attempted
write whose reconciliation failed. Retain actual provider responses privately
using owner evidence tooling when a denial needs further attribution; do not
turn a generic permission error into restriction proof.

### Read-only settings diagnostic

For an authorized diagnostic run, select `settings-diagnostic` in the **Protected
merge isolated qualification** workflow on `main`. Supply the exact open fixture
PR number and current head SHA. Use the same qualification flag, environment,
App token action and fixture ruleset ID as above. The fixture ruleset ID must
fit GraphQL's positive 32-bit integer range. The diagnostic uses the existing
App permissions, skips the canary step and creates no App mutation client.

The diagnostic JSON sets `mutation_attempted` to `false` and uses the
`settings-visibility-only` evidence scope. `diagnostic-collected` exits zero
for a report collected after admission, App identity, installation scope and
configuration checks. Individual settings reads can fail in a collected
report. Admission failure exits one with `refused`. An App identity, scope or
configuration refusal exits one with `diagnostic-refused` and stops subsequent
reads. Both the main and fixture classic settings stages use the full classic
baseline validator. The REST ruleset stage records identity, branch target,
conditions, restrictive update rule, enforcement and bypass visibility. The
effective rules stage checks the update rule and its provenance separately.
An empty effective rule list gives `empty: true` even when the fixture rule
is configured but disabled.

The final stage issues one fixed GraphQL query for the configured fixture
ruleset using the same App token. It requires the expected repository and
ruleset identities and a consistent, complete page of at most 100 actor nodes.
For either API, `roster: visible` means the response contained a complete,
recognized roster within the limit. `sole_app_pr_only: true` also requires
exactly the configured App with pull-request-only bypass and no other actor or
role. A missing, null or incomplete roster leaves the match unproven. GraphQL
errors invalidate any partial data. Stage results distinguish HTTP failures
from transport failures and invalid responses, and preserve numeric HTTP
status when observed. The collector makes at most seven App API requests, caps
each network operation at 30 seconds within a shared 120-second budget, and
accepts at most 1 MiB of JSON per response. Redirects and retries are disabled.
Reports contain fixed observations and request binding fields. Treat collection
results as visibility evidence only. Production rollout and merge qualification
require their separate enforcement and merge proofs.

Keep the private qualification matrix recording all twelve producer pairs,
App/environment setup, main baseline visibility, owner-human denials,
non-no-op App denial, wrong-head 409, actual native positive merge,
workflow-file permission behavior and canary limitations. Audit actual run and
merge identities/parents and follow every triggered/downstream job to terminal
status. This harness has no fresh Snyk scan authority and cannot prove the
production final-step Jobs API contract; those require the production workflow's
fresh preview and separately owner-requested merge qualification.

After isolated proof, set `PROTECTED_MERGE_QUALIFICATION_ENABLED=false`, follow
active runs to terminal, and disable the temporary restriction using owner
access. Keep reviewed source and private evidence. The unchanged production
validator rejects **every extra active ruleset**, so main baseline audit during
isolated testing is not full production validation. Only after the temporary
rule is disabled may the complete production validator pass. Cleanup applies
only to recorded qualification resources; preserve main protections, twelve
contexts, release hold and other repository controls.


The qualification admission job alone has native `GITHUB_TOKEN` Checks write;
the probe job explicitly has Checks read. The dedicated App still has no Checks
grant. After exact authenticated owner/current-run/literal-fixture admission,
only `pending-canary` and `failed-canary` invoke the bounded `produce-canary`
command. It rereads/authenticates the request, verifies all twelve genuine native
successful checks on the exact fixture head and refuses **any existing canary**
with that fixed name. It then sends at most one native check POST: the fixed
canary name, exact admitted head, and `in_progress` with null conclusion or
`completed` with `failure` respectively. The response must identify Actions App
`15368`, the same head/name and requested state. No arbitrary name/head/state,
check update/delete, existing native check modification, App key or App token
enters this producer. The missing-canary case creates nothing.

Prepare a **separate fresh fully checked fixture head** for each pending/failed
case, without an existing canary; retain all twelve native producer successes.
A head cannot be reused for these create-only cases after a canary exists.
A POST timeout/malformed response fails as `canary-unconfirmed` with
`mutation_attempted=true`; inspect actual check state read-only and use a fresh
fixture rather than rerunning or rewriting the check. Failed admission prevents
the App probe job. The check is synthetic general-enforcement evidence only;
it cannot substitute for native provider checks or production scanner authority.

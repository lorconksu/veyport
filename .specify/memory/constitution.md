<!--
Sync Impact Report
==================
Version change: (template) → 1.0.0
Rationale: Initial ratification (MAJOR baseline). Four core principles created
per stakeholder direction: code quality, testing standards, user experience
consistency, performance requirements.

Modified principles: n/a (initial adoption)
Added sections:
  - Core Principles (I–IV)
  - Security & Compliance Constraints
  - Development Workflow & Quality Gates
  - Governance
Removed sections: none (all template slots filled)

Templates requiring updates:
  - .specify/templates/plan-template.md ✅ aligned (Constitution Check gates are
    resolved at plan time from this file; no structural change needed)
  - .specify/templates/spec-template.md ✅ aligned (no constitution-specific
    sections required)
  - .specify/templates/tasks-template.md ✅ aligned (test-first task ordering
    already reflected in template phases)

Follow-up TODOs: none
-->

# Veyport Constitution

## Core Principles

### I. Code Quality Gates (NON-NEGOTIABLE)

All code merged to `main` MUST pass the project's static quality gates with no
new violations:

- TypeScript MUST compile cleanly under `npx tsc --noEmit`; Go code MUST pass
  `go vet` and be `gofmt`-formatted.
- The SonarQube quality gate, Semgrep SAST scan, and Gitleaks secret scan MUST
  pass in CI before merge.
- New code MUST NOT be added to the coverage or duplication exclusion lists in
  `sonar-project.properties` without an explicit justification in the PR
  description explaining why the code is structurally untestable.
- Prefer the standard library and existing dependencies; adding a new
  third-party dependency requires stated justification (maintenance cost,
  supply-chain surface, and license MUST be considered).

**Rationale**: Veyport is a self-hosted security-sensitive platform; quality
regressions and unvetted dependencies translate directly into operator risk.

### II. Testing Standards (NON-NEGOTIABLE)

Every feature and bugfix MUST ship with tests at the appropriate level of the
existing pyramid:

- Go unit tests for hub (`hub/internal/...`) and agent packages; Vitest unit
  tests for frontend components and pages.
- Integration tests (`hub/internal/integration/`) for cross-package behavior,
  gRPC contracts, and schema changes.
- Playwright E2E and smoke tests for user-visible flows that span the full
  Docker image.
- Bugfixes MUST include a test that fails before the fix and passes after it
  (regression lock). Test-first development is the default for new behavior.
- All test suites run with coverage instrumentation (`-covermode=atomic`,
  lcov); a change that lowers measured coverage MUST be justified in the PR.

**Rationale**: The hub/agent split communicates over a versioned gRPC contract;
untested contract drift is the project's highest-cost failure mode.

### III. User Experience Consistency

The web UI MUST present one coherent product, not a collection of pages:

- New UI MUST be composed from the established design system: shadcn/ui
  components, Tailwind v4 tokens, and TanStack Query for all server state — no
  ad-hoc fetch logic or one-off styling that duplicates existing primitives.
- New pages and tabs MUST follow existing structural patterns (e.g., the
  settings tab model) rather than inventing parallel layouts.
- Every data-driven view MUST handle loading, empty, and error states
  explicitly; destructive actions MUST require confirmation.
- REST endpoints MUST follow the existing API conventions (resource naming,
  JSON error shape, pagination) documented in `docs/wiki/API-Reference.md`;
  user-facing documentation in `docs/wiki/` MUST be updated in the same PR as
  behavior changes.

**Rationale**: Operators trust consistency; an inconsistent surface in a
security tool erodes confidence and increases operator error.

### IV. Performance Requirements

Veyport's value proposition includes a lightweight footprint; changes MUST
preserve it:

- The agent MUST remain lightweight: no polling loops where the existing gRPC
  bidirectional stream suffices, and no new background goroutines without a
  bounded resource cost stated in the PR.
- The hub MUST remain a single self-contained binary (frontend embedded via
  `go:embed`); changes MUST NOT introduce runtime dependencies on Node.js or
  external services for core operation.
- SQLite access MUST avoid N+1 query patterns; list endpoints MUST paginate
  rather than return unbounded result sets.
- Long-lived or streaming responses (SSE, log tailing, terminal) MUST apply
  backpressure or bounded buffering — unbounded in-memory growth is a defect.
- A change that knowingly regresses latency, memory, or binary size MUST state
  the regression and its justification in the PR description.

**Rationale**: Agents run on customers' production servers; resource bloat
there is a deployment blocker, not a nicety.

## Security & Compliance Constraints

Security requirements supersede convenience in all trade-offs:

- Transport security is fixed: gRPC hub↔agent communication uses mTLS (ECDSA
  P-256); weakening cipher or certificate requirements is prohibited.
- Authentication invariants MUST be preserved: JWT in httpOnly cookies,
  mandatory TOTP 2FA, bcrypt cost ≥ 12, CSRF double-submit protection.
- Secrets MUST never be committed (Gitleaks-enforced) and MUST never be
  returned in API responses (write-only fields; report only `*_set` booleans).
- Changes touching authentication, authorization, certificates, or the agent
  protocol MUST update `docs-internal/engineering/security-model.md` and be
  reviewed against it.
- Auditable actions (config changes, auth events, privileged operations) MUST
  write to the audit log.

## Development Workflow & Quality Gates

- All work lands via PR to `main` from a feature branch; CI MUST be green
  (TypeScript check, frontend tests, hub/agent/integration tests, E2E, smoke,
  SonarQube, Semgrep, Gitleaks) before merge.
- Features of non-trivial scope follow the Spec Kit flow: specification →
  plan (with Constitution Check) → tasks → implementation.
- Schema changes MUST ship as auto-running migrations and MUST be exercised by
  at least one integration test.
- Runtime verification on the dev environment is required before a feature is
  declared complete; "tests pass" alone does not constitute done.

## Governance

This constitution supersedes other development practices where they conflict.

- **Amendments**: proposed via PR modifying this file, including a Sync Impact
  Report and updates to any dependent templates; approval by the repository
  owner ratifies the amendment.
- **Versioning**: semantic versioning. MAJOR for principle removals or
  incompatible redefinitions; MINOR for new principles or materially expanded
  guidance; PATCH for clarifications and wording.
- **Compliance review**: every PR description MUST note Constitution Check
  outcomes when produced via the Spec Kit flow; reviewers MUST verify that
  NON-NEGOTIABLE principles (I, II) are met and that any documented deviations
  carry explicit justification.

**Version**: 1.0.0 | **Ratified**: 2026-06-11 | **Last Amended**: 2026-06-11

# Implementation Plan: LDAP Directory Settings

**Branch**: `feature/ldap-settings-ui` | **Date**: 2026-06-11 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-ldap-directory-settings/spec.md`

**Note**: This plan covers an **in-flight feature**. Core implementation exists
in WIP commit `0259fb0` and all current unit tests pass (hub `go test` LDAP
suite, 64 frontend vitest tests). The plan therefore focuses on (a) recording
the design as built and (b) the **remaining gap work** required by the
constitution before this feature can merge.

## Summary

Administrators configure LDAP directory integration (connection, search,
attribute mappings, transport security, group-to-role mappings) from a new
"Directory" tab on the Settings page, replacing environment-variable
configuration. Settings persist in the hub's SQLite `_config` key-value table,
take effect immediately, keep the bind password write-only and encrypted at
rest, support a pre-save "Test connection" action, and audit-log every change.

**Remaining work (gap analysis, 2026-06-11)**:

1. Integration test: save config → directory sign-in consumes it (none exists today).
2. `docs-internal/engineering/security-model.md` update (constitution: required for auth-touching changes).
3. Decide E2E scope for the Directory tab (Playwright currently has no LDAP coverage).
4. Split or justify the bundled agent certificate-expiry changes (`agent/internal/certs`, `agent/internal/client`) — unrelated to LDAP.
5. Runtime verification on the dev environment before declaring complete.

## Technical Context

**Language/Version**: Go 1.26 (hub backend), TypeScript / React 19 (web frontend)

**Primary Dependencies**: `go-ldap` (pre-existing — used by `ldap_auth.go`), TanStack Query, shadcn/ui, Tailwind v4. **No new dependencies introduced.**

**Storage**: SQLite `_config` key-value table (existing) under `ldap.*` keys; group lists JSON-encoded; bind password encrypted with `enc:` prefix (AES via `encryptConfigSecret`, keyed from JWT secret). **No schema migration required.**

**Testing**: `go test` (hub unit: `handlers_ldap_config_test.go`; integration: `hub/internal/integration/` — gap), Vitest (`settings-directory-tab.test.tsx`), Playwright E2E (gap/decision)

**Target Platform**: Linux server, single self-contained binary (frontend via `go:embed`), Docker image

**Project Type**: Web application (Go API backend + React SPA)

**Performance Goals**: Config changes effective immediately (no restart); "Test connection" verdict ≤ 15 s (implemented: 10 s LDAP operation timeout)

**Constraints**: Bind password write-only (`bind_password_set` flag only) and encrypted at rest; saves transactional (single SQLite transaction — all-or-nothing); admin-only endpoints; local-admin sign-in must survive directory outage

**Scale/Scope**: Single hub instance; one directory configuration per installation; ≤ 64 groups per mapping field, ≤ 255 chars per group name

*No NEEDS CLARIFICATION items — all technical decisions are resolved in the existing implementation and recorded in [research.md](./research.md).*

## Constitution Check

*GATE: evaluated against Constitution v1.0.0 (pre-Phase-0 and re-checked post-design).*

| Gate | Principle | Status | Evidence / Required Action |
|------|-----------|--------|----------------------------|
| G1 | I. Code Quality | ✅ PASS | No new dependencies; `sonar-project.properties` untouched by the WIP commit (new files are not excluded); CI gates (tsc, vet, Sonar, Semgrep, Gitleaks) apply on PR. |
| G2 | II. Testing — unit | ✅ PASS | `handlers_ldap_config_test.go` (339 lines) and `settings-directory-tab.test.tsx` (133 lines) exist and pass. |
| G3 | II. Testing — integration | ⚠️ GAP | Constitution requires integration tests for cross-package behavior. No LDAP coverage in `hub/internal/integration/`. **Action**: add save-config → `ldap_auth` sign-in integration test (mock/fake directory). |
| G4 | II. Testing — E2E | ⚠️ GAP (scoped) | No Playwright LDAP coverage. Full directory E2E needs an LDAP server in the harness — deferred with justification (see Complexity Tracking). **Action**: UI-level E2E of tab rendering + validation errors only. |
| G5 | III. UX Consistency | ✅ PASS | Tab follows existing settings-tab pattern; shadcn/ui + TanStack Query; loading/error/test-feedback states implemented; `docs/wiki/` (API-Reference, Settings, Deployment) updated in the same change. |
| G6 | IV. Performance | ✅ PASS | No polling; single-binary unchanged; bounded inputs (64/255 limits); 10 s test timeout < 15 s budget. Config load is ~20 point lookups per sign-in — bounded, acceptable. |
| G7 | Security & Compliance | ⚠️ GAP | Write-only secret ✅, encrypted at rest ✅, audit logging (`ldap.config_updated`, secrets excluded) ✅, admin-only routes ✅. **Missing**: `docs-internal/engineering/security-model.md` not updated despite auth-touching changes. |
| G8 | Workflow — scope hygiene | ⚠️ GAP | WIP commit bundles unrelated agent certificate-expiry changes (`certUsableNow`, renewal logic in `agent/internal/certs`, `agent/internal/client`). **Action**: split into its own commit/PR, or document why it must ride along. |
| G9 | Workflow — runtime verification | ⏳ PENDING | Required before the feature is declared complete: deploy to dev environment and exercise the Directory tab end-to-end. |

**Pre-Phase-0 verdict**: PASS with 3 gaps + 1 pending — all are *completion*
requirements, not design violations. No principle is violated by the design
itself; proceed.

**Post-Phase-1 re-check**: design artifacts (data-model, contracts) introduce
no new violations. The gap list above is the authoritative input to
`/speckit-tasks`.

## Project Structure

### Documentation (this feature)

```text
specs/001-ldap-directory-settings/
├── spec.md              # Feature specification
├── plan.md              # This file
├── research.md          # Phase 0: decisions as built
├── data-model.md        # Phase 1: entities & validation
├── quickstart.md        # Phase 1: how to exercise the feature
├── contracts/
│   └── ldap-config-api.md   # Phase 1: REST contract
├── checklists/
│   └── requirements.md  # Spec quality checklist (passing)
└── tasks.md             # Phase 2 (/speckit-tasks — not yet created)
```

### Source Code (repository root)

```text
hub/internal/server/
├── handlers_ldap_config.go        # GET/PUT /api/settings/ldap, POST .../test (exists)
├── handlers_ldap_config_test.go   # Unit tests (exists)
├── ldap_auth.go                   # Sign-in flow; loadLDAPConfig() consumes stored config (exists)
├── router.go                      # Admin-only route registration (exists)
└── server.go                      # ldapDial injection point for tests (exists)

hub/internal/model/
└── audit.go                       # AuditLDAPConfigUpdated action (exists)

hub/internal/integration/
└── ldap_config_test.go            # GAP: to be created (G3)

web/src/
├── pages/settings-directory-tab.tsx              # Directory tab (exists)
├── pages/__tests__/settings-directory-tab.test.tsx  # Unit tests (exists)
├── pages/settings.tsx             # Tab registration (exists)
└── types/api.ts                   # LDAPConfig type (exists)

tests/e2e/                         # GAP: Directory-tab UI E2E (G4)

docs/wiki/                         # API-Reference, Settings, Deployment (updated)
docs-internal/engineering/
└── security-model.md              # GAP: to be updated (G7)

agent/internal/{certs,client}/     # G8: unrelated cert-expiry changes to split
```

**Structure Decision**: Existing web-application layout (Go hub + React web).
The feature adds no new directories or architectural elements; remaining work
lands in the existing integration-test, E2E, and internal-docs locations shown
above.

## Complexity Tracking

> Only entries requiring justification are listed.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|--------------------------------------|
| G4: Full directory-backed E2E deferred | A real LDAP server (e.g. OpenLDAP/GLAuth container) in the Playwright harness is significant new CI infrastructure | Covering the sign-in path in a Go integration test with a fake directory (G3) exercises the same contract at far lower cost; UI-level E2E still validates the tab itself. Full E2E harness can be a follow-up feature if directory regressions occur. |

# Implementation Plan: JWT Secret Rotation & Key Separation

**Branch**: `002-jwt-secret-rotation` | **Date**: 2026-06-12 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/002-jwt-secret-rotation/spec.md`

## Summary

Close the 3.13.10 key-management gap in two moves. **Key separation**: introduce
a dedicated `storage_key` config value that derives the AES-256-GCM key for all
encrypted-at-rest secrets (TOTP, SMTP, LDAP bind, CA key); existing installs
migrate losslessly by adopting the current `jwt_signing_key` value as the
storage key (zero re-encryption — the derived key is bit-identical), new
installs generate two independent keys. **Rotation**: a new `veyport admin
rotate-jwt-secret` CLI command atomically replaces the signing secret, revokes
all API tokens, stamps `jwt_secret_rotated_at`, and audit-logs the event;
signature verification makes hard invalidation of all JWTs immediate, and the
running hub picks up the new secret on restart (documented step, seconds of
downtime).

## Technical Context

**Language/Version**: Go 1.26 (hub only; no agent or frontend logic changes — one read-only field surfaced in hub settings API/UI)

**Primary Dependencies**: None new. Reuses `crypto/rand`, existing `auth.DeriveKey`/`Encrypt`/`Decrypt`, existing CLI plumbing (`hub/cmd/veyport/admin.go`), existing audit store.

**Storage**: Two `_config` rows: `storage_key` (new), `jwt_secret_rotated_at` (new). `jwt_signing_key` keeps its key name but becomes rotatable. **No SQL schema migration** — key separation is a code-level startup migration (idempotent, ordered before any consumer).

**Testing**: Unit (key-init matrix: fresh/legacy/already-separated; rotation command; audit emission) + integration (populated DB → rotate → every encrypted-secret consumer still works; legacy-upgrade path; old tokens rejected). E2E not applicable (CLI/ops surface — justified below).

**Target Platform**: Hub binary (Linux/Docker). CLI runs on the hub host against the DB file, matching existing break-glass commands.

**Performance Goals**: Rotation transaction < 1s; hub restart is the only availability impact (single binary, seconds — within SC-001).

**Constraints**: FR-005 atomicity via a single SQLite transaction (WAL); FR-001 no-session requirement (CLI = host-shell credential); secret never printed/logged (FR-007); fail-loud startup if key init fails.

**Scale/Scope**: ~6 production files touched (`server.go`, `ca.go` call sites, `notify` constructor call, `admin.go`, `model/audit.go`, `handlers_hub_config.go`) + tests + docs. Storage-key rotation explicitly out of scope (spec assumption).

*No NEEDS CLARIFICATION — decisions in [research.md](./research.md).*

## Constitution Check

*GATE: evaluated against Constitution v1.0.0.*

| Gate | Principle | Status | Evaluation |
|------|-----------|--------|------------|
| G1 | I. Code Quality | ✅ PASS | No new dependencies; standard library crypto only; no sonar-exclusion changes planned. |
| G2 | II. Testing | ✅ PASS (planned) | Test-first tasks: unit matrix for key init + rotation; integration test on a populated DB exercising all four encrypted-secret consumers post-rotation and the legacy migration (FR-010). |
| G3 | III. UX Consistency | ✅ PASS | UI delta is one read-only "signing secret last rotated" line on the existing hub settings surface; CLI follows the established `veyport admin` pattern and prints no secrets. Docs updated in same PR. |
| G4 | IV. Performance | ✅ PASS | No runtime hot-path changes; one extra config read at startup. |
| G5 | Security & Compliance | ✅ PASS | Strengthens the constitution's secret-handling posture; bind/TOTP/SMTP/CA encryption invariants preserved bit-for-bit through migration; audit events added for rotation and separation; security-model.md update required (FR-009). |
| G6 | Workflow | ✅ PASS | Spec→plan→tasks flow on a numbered feature branch; PR to main; runtime verification before completion. |

**Deviation noted (not a violation)**: no Playwright E2E — the feature is a host-CLI operation with no browser flow beyond a read-only settings field (covered by unit tests). Recorded in Complexity Tracking.

**Post-Phase-1 re-check**: design adds no dependencies, no schema migration, no new endpoints (one field on an existing admin-only response). PASS unchanged.

## Project Structure

### Documentation (this feature)

```text
specs/002-jwt-secret-rotation/
├── spec.md
├── plan.md              # This file
├── research.md          # Phase 0: design decisions D1–D7
├── data-model.md        # Phase 1: keys, config rows, audit events, state machine
├── quickstart.md        # Phase 1: rotation procedure + verification
├── contracts/
│   └── rotation-interfaces.md   # CLI command, settings API field, audit events
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
hub/internal/server/
├── server.go                 # InitStorageKey (new, startup migration); Server.storageKey field;
│                             # consumers switched from jwtSecret → storageKey for encryption
├── handlers_auth.go          # encrypt/decryptTOTPSecret use storageKey
├── ldap_auth.go              # encrypt/decryptConfigSecret use storageKey
├── handlers_ldap_config.go   # encryptConfigSecret call site
├── handlers_notifications.go # encryptSMTPPassword uses storageKey
└── handlers_hub_config.go    # expose jwt_secret_rotated_at (read-only)

hub/internal/ca/ca.go         # InitCA takes storage key (caller change in cmd wiring)
hub/internal/notify/          # Notifier constructed with storage key (param rename/caller)
hub/cmd/veyport/
├── main.go                   # wiring order: InitStorageKey before InitCA/notifier
└── admin.go                  # rotate-jwt-secret subcommand (tx: new secret + revoke API tokens
                              # + rotated_at stamp + audit entry; prints status only, never secrets)
hub/internal/model/audit.go   # AuditJWTSecretRotated, AuditStorageKeySeparated constants
hub/internal/model/audit_catalog.go  # catalog entries for both new events

web/src/pages/...             # read-only "last rotated" display on hub settings (small)
docs/wiki/Deployment.md       # rotation procedure (+ Settings.md if UI shown)
docs-internal sync            # security-model.md key-management lifecycle update (FR-009)
```

**Structure Decision**: All changes inside existing packages; no new packages. The startup key-init lives beside `InitJWTSecret` in `server.go` so initialization order is explicit in `cmd/veyport/main.go`.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|--------------------------------------|
| No E2E coverage (constitution G2 expects E2E for user-visible flows) | Feature surface is a host CLI + one read-only settings field; browser automation adds no assurance over the integration suite, which exercises every consumer end-to-end on a real DB | Faking a CLI run inside Playwright would test the harness, not the feature |

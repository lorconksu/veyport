# Research: JWT Secret Rotation & Key Separation

**Phase 0 output** | Date: 2026-06-12

Decisions grounded in the verified current implementation:
`InitJWTSecret` (generate-once, `_config.jwt_signing_key`),
`auth.DeriveKey` = SHA-256(secret) → AES-256-GCM key, four derived-key
consumers (TOTP `handlers_auth.go`, SMTP `handlers_notifications.go`/`notify`,
LDAP bind `ldap_auth.go`, CA key `ca.go:InitCA`), per-user
`token_generation` claim check in `middleware.go`, hashed (non-JWT) API
tokens, and the `veyport admin` CLI pattern.

## D1: Key separation — adopt-the-legacy-secret migration

- **Decision**: Introduce `_config.storage_key` (random 256-bit, hex). All
  four encryption consumers derive from `storage_key` instead of the signing
  secret. Startup init (`InitStorageKey`, ordered before InitCA/notifier):
  1. `storage_key` exists → use it (idempotent re-run).
  2. else `jwt_signing_key` exists (legacy install) → **copy its current
     value into `storage_key`** and audit `auth.storage_key_separated`.
  3. else (fresh install) → generate independent random keys for both.
- **Rationale**: Step 2 is the lossless trick: the derived AES key is
  bit-identical, so every existing ciphertext (TOTP/SMTP/LDAP/CA) decrypts
  unchanged — **zero re-encryption**, trivially idempotent, and a crash
  between the copy and first use is harmless. After separation, rotating the
  signing secret can never strand data (FR-002/FR-003).
- **Alternatives considered**: Re-encrypt everything under a freshly random
  storage key at migration (rejected: a multi-row re-encryption is exactly
  the crash-fragile operation the spec forbids, for no at-rest gain — the
  legacy secret already sits in the same `_config` table); external KEK via
  env/file (rejected for v1: breaks single-binary zero-config deployment;
  noted as the future hardening that key separation now makes possible);
  keeping derivation from the signing secret with versioned re-encryption on
  rotate (rejected: couples lifecycles forever, the root cause itself).
- **Honesty note for docs**: at-rest posture is unchanged — both keys live in
  the DB, as the signing secret does today. The win is lifecycle decoupling,
  not at-rest strength; security-model.md must say so plainly.

## D2: Rotation mechanism — CLI, single transaction, restart to apply

- **Decision**: `veyport admin rotate-jwt-secret --db <path>`. In one SQLite
  transaction: generate new 256-bit secret → `UPDATE _config
  jwt_signing_key` → revoke all active API tokens → set
  `jwt_secret_rotated_at` (RFC 3339 UTC). Then write the
  `auth.jwt_secret_rotated` audit entry (actor type system, like
  `reset-totp`). The command prints a confirmation + "restart the hub to
  apply" reminder and never prints key material. The running hub holds the
  old secret in memory; the operator restarts it (systemd/compose), which is
  the documented final step.
- **Rationale**: FR-001's no-session requirement and the compromise-response
  case make host-shell the right credential — same trust model as
  `reset-totp`. A single tx on WAL gives FR-005 atomicity for free. Restart
  beats hot-reload for v1: it is seconds of downtime (SC-001 tolerates it),
  removes all in-memory-staleness edge cases, and avoids plumbing a mutable
  secret through `Server`, `grpcserver`, and `notify`.
- **Alternatives considered**: Admin API endpoint (rejected: requires a valid
  session — circular in the compromise case; FR-001); hot-reload via config
  watch or SIGHUP (rejected for v1: concurrency-sensitive plumbing for
  marginal benefit; future enhancement); dual-key acceptance window
  (rejected: spec assumption fixes hard invalidation, and compromise response
  demands it).

## D3: Invalidation layering — signature kills first, generations unchanged

- **Decision**: No change to per-user `token_generation` or the blacklist.
  Document the layering: (1) **signature** — rotation makes every
  outstanding JWT of all four types fail verification before any other check
  runs; (2) **blacklist** — logout-revoked JTIs (rows age out naturally;
  stale entries harmless); (3) **generation** — per-user invalidation for
  password change/role change keeps working within a signing epoch. API
  tokens are hashed DB rows, not JWTs — signature rotation cannot touch
  them, hence the explicit revoke-all inside the rotation tx (FR-004).
- **Rationale**: The mechanisms compose cleanly because they check at
  different layers; bumping every user's generation during rotation would be
  redundant work that muddies the audit story.
- **Alternatives considered**: Global epoch counter embedded in claims
  (rejected: equivalent outcome to changing the signature key, one more
  moving part); deleting blacklist rows at rotation (rejected: harmless
  rows, needless tx growth).

## D4: Visibility — timestamp on the existing hub settings surface

- **Decision**: `jwt_secret_rotated_at` returned in the existing admin-only
  `GET /api/settings/hub` response and shown read-only on the hub settings
  UI; absent/null means "never rotated (initial secret)". The secret value
  itself has no read path anywhere.
- **Rationale**: FR-007/US3 with no new endpoint or permission surface.
- **Alternatives considered**: Health endpoint exposure (rejected: public
  endpoint — rotation recency is mildly sensitive operational metadata).

## D5: Audit events

- **Decision**: Two constants in `model/audit.go` + catalog entries:
  `auth.jwt_secret_rotated` (CLI rotation; actor system; detail: API-token
  revocation count only) and `auth.storage_key_separated` (one-time startup
  migration; actor system). No secret material in details.
- **Rationale**: FR-006; catalog updated in the same change so the
  catalog-lags-constants finding from the re-assessment is not repeated.

## D6: Failure behavior

- **Decision**: `InitStorageKey` failure is fatal at startup (fail loud, per
  spec edge case). Rotation tx failure leaves everything pre-rotation and
  reports the error; the command is safely re-runnable. A backup restored
  from before a rotation is self-consistent (secret + ciphertexts travel
  together) — documented in quickstart.
- **Rationale**: Matches the spec's "fully pre- or fully post-" invariant.

## D7: Test design (FR-010)

- **Decision**: Unit — `InitStorageKey` three-path matrix incl. double-run
  idempotency and legacy-ciphertext decryptability; rotation command logic
  (secret replaced, tokens revoked, stamp set, audit written, old-JWT
  rejection). Integration — populated DB (TOTP user, SMTP password, LDAP
  bind password, CA initialized) → upgrade-init → rotate → assert: old
  access token rejected, fresh login + TOTP works, LDAP bind password
  decrypts, SMTP password decrypts, CA loads, API tokens revoked,
  `rotated_at` exposed via settings endpoint.
- **Rationale**: SC-002/SC-003 verified mechanically; the integration test
  doubles as the SC-005 evidence citation for upgrading CMMC 3.13.10.

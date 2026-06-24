# Feature Specification: JWT Secret Rotation & Key Separation

**Feature Branch**: `002-jwt-secret-rotation`

**Created**: 2026-06-12

**Status**: Draft

**Input**: User description: "the JWT-secret rotation gap (3.13.10) would be my first pick" — close the key-management gap identified in the 2026-06 security re-assessment: the session-signing secret is generated once at first startup, can never be rotated safely, and the same secret also derives the key protecting all encrypted-at-rest secrets, so the two lifecycles are dangerously coupled.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Rotate the session-signing secret safely (Priority: P1)

An administrator (or an operator responding to a suspected compromise) rotates
the hub's session-signing secret with a single administrative command on the
hub host. After rotation, the system keeps working: stored secrets (directory
bind password, email credentials, two-factor secrets, certificate-authority
key) remain usable, agents stay connected, and users simply sign in again.

**Why this priority**: Today rotation is effectively impossible — replacing
the secret would not only end all sessions but permanently destroy access to
every encrypted setting. A compromised signing secret therefore cannot be
remediated without data loss. This is the gap that keeps CMMC practice
3.13.10 at Partially Addressed.

**Independent Test**: On a configured instance (directory auth enabled, email
configured, users enrolled in 2FA), run the rotation command; verify that
existing sessions are rejected, fresh sign-in works end to end (password +
2FA), directory sign-in still works, a test email still sends, and agents
remain connected — with no re-entry of any stored secret.

**Acceptance Scenarios**:

1. **Given** a running instance with active user sessions, **When** the
   administrator rotates the signing secret, **Then** every outstanding
   session and pending login token is rejected on next use and users must
   re-authenticate; no user data or configuration is lost.
2. **Given** stored encrypted settings (directory bind password, email
   password, users' 2FA secrets, CA key), **When** rotation completes,
   **Then** all of them remain usable without re-entry: directory sign-in,
   email sending, 2FA verification, and agent certificate issuance all
   succeed afterwards.
3. **Given** a rotation in progress, **When** the process is interrupted
   (crash/power loss), **Then** on restart the system is in a consistent
   state — either fully pre-rotation or fully post-rotation — and never in a
   state where stored secrets are undecryptable.
4. **Given** a completed rotation, **When** the audit log is reviewed,
   **Then** a rotation event is recorded with actor and timestamp and
   contains no secret material.
5. **Given** API tokens issued before rotation, **When** they are used after
   rotation, **Then** the documented behavior occurs (revoked alongside
   sessions) and their owners can mint replacements.

---

### User Story 2 - Independent lifecycles for signing and storage keys (Priority: P2)

The key that protects encrypted-at-rest settings is managed separately from
the session-signing secret, so rotating one never affects the other. Existing
installations are migrated to this separation automatically and without data
loss; new installations start separated.

**Why this priority**: The coupling is the root cause that makes rotation
dangerous. Separation is what makes US1 safe and keeps it safe — it converts
"rotate the signing secret" from a data-destroying operation into a
session-management operation. It ships with US1 but is articulated separately
because it changes how installations are provisioned and upgraded.

**Independent Test**: Upgrade an existing populated instance; verify all
encrypted settings still work with zero operator action. Then rotate the
signing secret and verify encrypted settings are untouched (no re-encryption
of stored secrets is even necessary for a signing-secret rotation).

**Acceptance Scenarios**:

1. **Given** an existing installation with encrypted settings, **When** it is
   upgraded to a version with key separation, **Then** the migration happens
   automatically at startup, all encrypted values remain usable, and the
   migration is recorded in the audit log.
2. **Given** a separated installation, **When** the signing secret is
   rotated, **Then** no stored secret needs re-encryption and none becomes
   unreadable.
3. **Given** a fresh installation, **When** it is first initialized, **Then**
   signing and storage keys are independent from the start.

---

### User Story 3 - Rotation visibility and guidance (Priority: P3)

An administrator can see when the signing secret was last rotated, and
operators have documented guidance on when and how to rotate (routine
schedule vs. compromise response). The compliance assessment can cite the
capability.

**Why this priority**: A rotation capability nobody can see or remember to
use does not change operational posture. Visibility and documentation are
what turn the mechanism into a practice — and what the CMMC re-assessment
needs to upgrade 3.13.10.

**Independent Test**: After a rotation, an administrator can read the
last-rotated timestamp from the product without host access, and the
operations documentation describes the rotation procedure and its session
impact.

**Acceptance Scenarios**:

1. **Given** a rotation has occurred, **When** an admin checks the hub's
   settings/health surface, **Then** the last-rotation time is visible
   (never the secret itself, in any form).
2. **Given** the published documentation, **When** an operator follows the
   rotation procedure, **Then** the documented steps, expected session
   impact, and verification checks match actual behavior.

---

### Edge Cases

- Rotation while requests are in flight: requests authenticated with the old
  secret that arrive after the switch are rejected like any expired session —
  no partial acceptance window in v1.
- Rotation on a system that has never completed first-time setup: command
  refuses or is a no-op with a clear message (nothing to rotate safely).
- Database restored from a backup taken before a rotation: the restored
  database is self-consistent (its own secret + its own encrypted values), so
  it works; documentation must note that post-backup rotations are undone by
  restore.
- Double rotation in quick succession: each rotation is atomic and
  independent; the second proceeds only after the first completed.
- Compromise response: the same command serves as break-glass — rotation must
  not depend on any in-product session being valid (host access is the
  credential), since the scenario is exactly that sessions can't be trusted.
- Migration failure on upgrade (US2): startup must fail loudly rather than
  run with half-migrated keys; restart retries idempotently.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: An administrator MUST be able to rotate the session-signing
  secret via an administrative command on the hub host, without editing
  files or the database directly, and without any valid in-product session.
- **FR-002**: Rotation MUST NOT render any stored encrypted value unusable —
  directory bind password, email credentials, users' two-factor secrets, and
  the certificate-authority key all remain functional with no re-entry.
- **FR-003**: The at-rest encryption key MUST be independent of the
  session-signing secret: new installations provision them separately, and
  existing installations are migrated automatically, losslessly, and
  idempotently at upgrade.
- **FR-004**: Rotation MUST invalidate all outstanding session material:
  active sessions, refresh capability, pending login/setup flows, and
  API tokens; affected users re-authenticate and token owners re-issue.
- **FR-005**: Rotation MUST be atomic and crash-safe: an interrupted rotation
  leaves the system fully pre- or fully post-rotation after restart.
- **FR-006**: Each rotation (and the one-time key-separation migration) MUST
  produce an audit event with actor context and timestamp, containing no
  secret material.
- **FR-007**: The time of the last rotation MUST be visible to
  administrators in-product; the secret value itself MUST never be
  displayed, logged, or exported anywhere.
- **FR-008**: Agent connectivity MUST be unaffected by rotation: certificate
  trust and established agent streams do not depend on the rotated secret's
  value (beyond the storage-key independence required by FR-002/FR-003).
- **FR-009**: Operations documentation MUST describe the rotation procedure,
  its session impact, the compromise-response use, and the backup/restore
  interaction; the internal security model MUST be updated to reflect the
  new key-management lifecycle.
- **FR-010**: The capability MUST be covered by automated tests at the unit
  and integration level, including the upgrade migration on a populated
  database and post-rotation verification of every encrypted-secret consumer.

### Key Entities

- **Session-signing secret**: signs all short-lived session material;
  rotatable; generation-versioned so old material is rejectable.
- **Storage (at-rest encryption) key**: protects stored secrets; independent
  lifecycle; not touched by signing-secret rotation.
- **Rotation event**: audit record — actor, timestamp, kind (rotation /
  separation migration), no secret material.
- **Rotation status**: last-rotated timestamp exposed to administrators.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An operator can complete a rotation, including verification,
  in under 5 minutes using only the documented procedure; the service
  remains available throughout (no restart-induced downtime beyond seconds).
- **SC-002**: 100% of pre-rotation sessions and API tokens are rejected on
  first use after rotation.
- **SC-003**: Zero loss of encrypted configuration across rotation and
  across the separation migration: directory sign-in, email send, 2FA
  verification, and agent certificate issuance all succeed afterwards
  without any secret re-entry (verified by automated tests).
- **SC-004**: Every rotation appears in the audit log with actor and
  timestamp; zero secret material in any log, response, or export.
- **SC-005**: The CMMC 3.13.10 row can be upgraded to Fully Addressed citing
  this capability, with the citation passing the assessment's
  evidence-or-flag standard.

## Assumptions

- Rotation semantics are **hard invalidation** (everyone re-authenticates).
  A graceful dual-acceptance overlap window is explicitly out of scope for
  v1 — acceptable for a small-fleet tool and required anyway for the
  compromise-response case.
- The administrative command lives alongside the existing break-glass CLI
  surface (host shell access as the credential); an in-product UI trigger is
  out of scope for v1, while in-product *visibility* of rotation status
  (US3) is in scope.
- Scheduled/automatic rotation is out of scope for v1; the documentation
  recommends a cadence, and the audit trail plus visible last-rotation time
  make adherence checkable.
- The storage key itself is not rotatable in v1 (it would require
  re-encrypting all stored secrets); key separation makes that a safe future
  feature with its own lifecycle.
- Existing behavior that derives session invalidation from per-user token
  generations is unchanged; rotation is a global, all-users invalidation on
  top of it.

# Research: LDAP Directory Settings

**Phase 0 output** | Date: 2026-06-11

This feature is in-flight; "research" records the technical decisions already
made in the implementation (WIP commit `0259fb0`) with rationale and the
alternatives they displace. No NEEDS CLARIFICATION items remained after spec
review.

## D1: Configuration storage — existing `_config` key-value table

- **Decision**: Persist all settings as `ldap.*` keys in the hub's existing
  SQLite `_config` table; group lists stored as JSON arrays in the value
  column. All keys for one save written in a single transaction
  (`saveLDAPConfigValues`).
- **Rationale**: Zero schema migration; matches how hub and SMTP settings are
  already stored, so loading, defaulting, and testing follow a proven pattern.
  The single transaction satisfies FR-014 (no partial application).
- **Alternatives considered**: Dedicated `ldap_config` table (rejected:
  migration + one-row-table awkwardness for ~20 scalar fields); config file on
  disk (rejected: not editable via API, complicates backup, breaks
  immediate-effect requirement).

## D2: Bind password secrecy — encrypt-at-rest + write-only API

- **Decision**: Encrypt the bind password with `encryptConfigSecret` (keyed
  from the hub's JWT secret), store with an `enc:` prefix, and never return
  it: responses carry only `bind_password_set`. Requests distinguish three
  intents: empty/redacted value = keep current; new value = replace (encrypted
  on write); `clear_bind_password: true` = remove. Legacy plaintext values are
  detected at load (`enc:` prefix missing), logged with rotation guidance, and
  still honored.
- **Rationale**: Satisfies FR-004/FR-005 and the constitution's write-only
  secret rule; reuses the existing config-secret encryption helper rather than
  inventing new key management.
- **Alternatives considered**: Separate KEK/secrets store (rejected: new key
  management surface for a single secret); returning a masked value
  (`********`) in GET (rejected: ambiguity between "set" and a literal
  password of asterisks — the boolean flag is unambiguous).

## D3: Validation — server-side, enable-gated

- **Decision**: `validateLDAPSettings` enforces, only when `enabled` is true:
  URL, user base DN, and group base DN required; bind password required when
  a bind DN is set; at least one role group mapping; ≤ 64 groups per field and
  ≤ 255 chars per name; transport rules (refuse plain `ldap://` without the
  explicit `allow_insecure_transport` opt-in via `validateLDAPTransport`); CA
  PEM well-formedness via `buildLDAPTLSConfig`. Disabled configs save freely.
- **Rationale**: Gating on `enabled` lets administrators draft partial
  configurations safely (FR-006); building the real TLS config at validation
  time means "valid" equals "usable", not just "parseable".
- **Alternatives considered**: Client-side-only validation (rejected: API is a
  contract surface of its own); always-on validation (rejected: blocks saving
  a disabled draft).

## D4: Connection testing — non-persisting endpoint with injected dialer

- **Decision**: `POST /api/settings/ldap/test` runs the same normalization +
  validation as save, dials the directory (10 s operation timeout), binds with
  the service account when a bind DN is present, and persists nothing. The
  dial function is injectable (`s.ldapDial`) so unit tests run without a real
  directory. When the form password is untouched (redacted sentinel), the
  stored decrypted password is used.
- **Rationale**: FR-008/SC-005; sentinel reuse means admins can test without
  re-entering the secret; injection keeps the unit suite hermetic.
- **Alternatives considered**: Test-on-save only (rejected: couples
  verification to commitment — admins want to probe before applying);
  frontend-direct LDAP (impossible from a browser; would also leak topology).

## D5: Group-to-role mapping — per-role group lists, server-side resolution

- **Decision**: Four mapping fields (admin, auditor, viewer roles + terminal
  permission), each a list of directory group names. Resolution happens in the
  existing sign-in flow (`ldap_auth.go`) against the user's group memberships;
  defaults exist (`veyport-admins`, …) so a fresh enable is functional.
- **Rationale**: Mirrors the product's fixed role model (no custom roles);
  lists-of-names avoids requiring DN-exact configuration.
- **Alternatives considered**: Free-form mapping rules/expressions (rejected:
  large surface, hard to validate, unnecessary for three roles + one
  permission).

## D6: Defaults — conventional OpenLDAP-style schema

- **Decision**: Built-in defaults applied when fields are blank:
  `(uid={username})` user filter, `(|(member={dn})(memberUid={username}))`
  group filter, attributes `uid`/`mail`/`entryUUID`/`cn`.
- **Rationale**: FR-007 — a standard directory works without expert tuning;
  defaults live in `loadLDAPConfig` so both auth and the API observe the same
  effective values.
- **Alternatives considered**: Empty defaults + required fields (rejected:
  raises configuration burden for the common case); Active-Directory-first
  defaults (rejected: `sAMAccountName`/`objectGUID` can be supplied via the
  same fields when needed).

## D7: Frontend — existing settings-tab pattern

- **Decision**: `settings-directory-tab.tsx` follows the established settings
  tab structure (cf. notifications tab): TanStack `useQuery` to load,
  `useMutation` for save and test, shadcn/ui form controls, group lists edited
  as comma-separated text and parsed client-side, inline success/error
  feedback for the connection test.
- **Rationale**: Constitution principle III (UX consistency); zero new
  frontend patterns to maintain.
- **Alternatives considered**: Dedicated admin page outside Settings
  (rejected: directory config *is* a setting; the tab model is where admins
  already look).

## D8: Authorization & audit

- **Decision**: All three endpoints registered admin-only
  (`authMiddleware` + `adminOnly`) in `router.go`. Every successful save emits
  audit action `ldap.config_updated` with a non-secret change summary
  (`ldapConfigAuditDetail`).
- **Rationale**: FR-001/FR-013 and the constitution's audit requirement.
- **Alternatives considered**: Auditing failed attempts too (open question for
  tasks phase — current code audits successful updates; failed validation is a
  4xx without audit, consistent with other settings handlers).

## Open items carried to tasks (from Constitution Check gaps)

1. **G3** integration test: persist config via API → authenticate via
   `ldap_auth` against a fake directory → assert role mapping.
2. **G4** UI-level E2E for tab rendering and validation errors.
3. **G7** `security-model.md` update: config-secret encryption, write-only
   semantics, insecure-transport opt-in, audit action.
4. **G8** split unrelated agent certificate-expiry changes.
5. **G9** runtime verification on the dev environment.

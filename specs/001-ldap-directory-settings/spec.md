# Feature Specification: LDAP Directory Settings

**Feature Branch**: `feature/ldap-settings-ui`

**Created**: 2026-06-11

**Status**: Draft (implementation in-flight — WIP commit `0259fb0` on `feature/ldap-settings-ui`; this spec retroactively documents intent and pins down remaining scope)

**Input**: User description: "Admin-configurable LDAP directory integration settings. Administrators can view and edit the hub's LDAP directory configuration from a new "Directory" tab on the Settings page instead of environment variables. Configuration covers: enable/disable toggle, LDAP server URL, bind DN and bind password (write-only secret), user and group base DNs, user/group search filters, attribute mappings (username, email, external ID, group name), StartTLS with TLS server name, custom CA certificate, and LDAP group-to-role mappings. A "Test connection" action validates settings before saving. All config changes are audit-logged."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Configure directory connection from the admin UI (Priority: P1)

An administrator opens the Settings page, selects the new "Directory" tab, and
configures the organization's LDAP directory: server address, bind credentials,
where to find users and groups (base DNs and search filters), and which
directory attributes map to account fields (username, email, external ID,
group name). Saving applies the configuration immediately — no server restart,
no editing of deployment files.

**Why this priority**: This is the core value of the feature. Today directory
integration requires environment-variable changes and a redeploy, which only
infrastructure operators can perform. Moving it to the admin UI makes
directory sign-in self-service for administrators.

**Independent Test**: With a reachable test directory, an administrator can
fill in the Directory tab, save, and a directory user can sign in — all
without touching the server's deployment configuration.

**Acceptance Scenarios**:

1. **Given** a signed-in administrator on the Settings page, **When** they open
   the Directory tab, **Then** the current directory configuration is shown,
   with the bind password never displayed (only an indicator of whether one is
   stored).
2. **Given** directory integration is disabled, **When** the administrator
   enables it, fills in server URL, bind credentials, and user base DN, and
   saves, **Then** the settings take effect immediately and directory users can
   sign in without a restart.
3. **Given** the administrator enables directory integration but leaves the
   server URL or user base DN empty, **When** they save, **Then** the save is
   rejected with a message naming the missing field, and the previous
   configuration remains in effect.
4. **Given** unsaved edits in the form, **When** the administrator reloads the
   page, **Then** the last saved configuration is shown (no partial state was
   applied).
5. **Given** the administrator leaves optional fields blank (search filters,
   attribute mappings), **When** they save, **Then** sensible default values
   are used so a standard directory works without expert tuning.

---

### User Story 2 - Verify settings with "Test connection" before saving (Priority: P2)

Before committing changes, the administrator clicks "Test connection". The
system attempts to reach the directory with the settings currently in the form
(including the stored bind password if the form's password field is untouched)
and reports success or a specific failure reason.

**Why this priority**: Directory misconfiguration locks out directory users
and is hard to diagnose after the fact. Pre-save verification converts a
production incident into an inline form error.

**Independent Test**: With deliberately wrong settings (bad host, bad
credentials), "Test connection" reports a failure that names the cause; with
correct settings it reports success — in both cases without altering the saved
configuration.

**Acceptance Scenarios**:

1. **Given** valid directory settings in the form, **When** the administrator
   clicks "Test connection", **Then** a success result is shown and the saved
   configuration is unchanged.
2. **Given** an unreachable server address or invalid bind credentials,
   **When** the administrator tests the connection, **Then** a failure message
   describing the problem is shown and nothing is saved.
3. **Given** a stored bind password and an untouched password field, **When**
   the administrator tests the connection, **Then** the stored password is used
   for the test (the administrator does not need to re-enter it).

---

### User Story 3 - Map directory groups to product roles and permissions (Priority: P3)

The administrator assigns directory group names to each product role
(Administrator, Auditor, Viewer) and to the terminal-access permission, so a
user's access level is derived from their directory group membership at
sign-in.

**Why this priority**: Without group mappings every directory user would need
manual role assignment, defeating the purpose of central directory management.
It builds on P1 (a working connection) so it is sequenced after it.

**Independent Test**: Map a known directory group to the Auditor role, sign in
as a directory user in that group, and confirm the account receives the
Auditor role and no more.

**Acceptance Scenarios**:

1. **Given** a directory group mapped to a role, **When** a member of that
   group signs in, **Then** their account holds that role.
2. **Given** a user belonging to groups mapped to multiple roles, **When** they
   sign in, **Then** they receive the highest-privilege mapped role.
3. **Given** more than 64 groups entered for one mapping field, or a group name
   longer than 255 characters, **When** the administrator saves, **Then** the
   save is rejected with a message identifying the limit.

---

### User Story 4 - Secure the directory connection (Priority: P4)

The administrator hardens transport security: enabling StartTLS, setting an
expected TLS server name, and supplying a custom CA certificate for
directories using a private certificate authority. Unencrypted connections
require an explicit opt-in acknowledgment.

**Why this priority**: Security hardening refines an already-working
connection. It is mandatory for production fleets but exercisable only after
P1 works.

**Acceptance Scenarios**:

1. **Given** a directory with a private-CA certificate, **When** the
   administrator pastes the CA certificate and saves, **Then** TLS connections
   to the directory verify successfully.
2. **Given** a malformed certificate value, **When** the administrator saves or
   tests, **Then** the value is rejected with a clear error before anything is
   stored.
3. **Given** a plain (unencrypted) server address without the insecure-
   transport opt-in, **When** the administrator saves, **Then** the save is
   rejected; with the explicit opt-in it is allowed.

---

### Edge Cases

- Clearing a stored bind password: the administrator can explicitly remove the
  stored password (distinct from "leave unchanged").
- A previously stored bind password that is not encrypted at rest is detected,
  flagged in server logs with guidance to rotate it via the admin UI, and
  continues to work.
- Disabling directory integration: validation of directory-specific fields is
  skipped, directory sign-in stops, and local accounts continue to work.
- Directory unreachable at sign-in time (after a previously successful save):
  directory users receive a sign-in error; local administrator accounts are
  unaffected and can still sign in to fix the configuration.
- Two administrators editing simultaneously: last save wins; each save is
  audit-logged separately with its own actor.
- Test connection against a slow or hanging directory: the test fails with a
  timeout rather than blocking the page indefinitely.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Administrators MUST be able to view and edit the directory
  configuration from a "Directory" tab on the Settings page; the tab MUST be
  available only to administrators.
- **FR-002**: Configuration changes MUST take effect immediately upon save,
  without a service restart or deployment-file change.
- **FR-003**: The configuration MUST cover: an enable/disable toggle, server
  URL, bind DN, bind password, user base DN, group base DN, user search
  filter, group search filter, attribute mappings (username, email, external
  ID, group name), StartTLS toggle, TLS server name, custom CA certificate,
  and an explicit insecure-transport opt-in.
- **FR-004**: The bind password MUST be write-only: it is never returned or
  displayed after saving; the UI and responses expose only whether a password
  is stored. The password MUST be stored encrypted at rest.
- **FR-005**: Administrators MUST be able to leave the stored bind password
  unchanged, replace it, or explicitly clear it — three distinct outcomes.
- **FR-006**: When directory integration is enabled, the server URL and user
  base DN MUST be required; saves missing them MUST be rejected with a message
  naming the field. When disabled, these validations MUST NOT block saving.
- **FR-007**: Blank optional fields (search filters and attribute mappings)
  MUST fall back to documented defaults suitable for a standard directory
  deployment.
- **FR-008**: A "Test connection" action MUST verify the form's settings
  against the directory without persisting anything, reusing the stored bind
  password when the form's password is untouched, and MUST report a specific
  failure reason on error.
- **FR-009**: Administrators MUST be able to map directory group names to each
  product role (Administrator, Auditor, Viewer) and to the terminal-access
  permission; mappings are limited to 64 groups per field and 255 characters
  per group name, with violations rejected at save time.
- **FR-010**: A directory user's role and terminal permission MUST be derived
  from their group memberships at sign-in according to the saved mappings.
- **FR-011**: A supplied CA certificate MUST be validated for well-formedness
  before being stored; malformed input MUST be rejected with a clear error.
- **FR-012**: Unencrypted directory connections MUST be refused unless the
  administrator has explicitly enabled the insecure-transport opt-in.
- **FR-013**: Every save of the directory configuration MUST produce an audit
  log entry recording the acting administrator and a summary of what changed,
  excluding secret values.
- **FR-014**: Invalid configuration submissions MUST never partially apply:
  either the full configuration is saved or the previous configuration remains
  in effect.
- **FR-015**: Disabling directory integration MUST NOT affect local-account
  sign-in, and local administrators MUST always retain a sign-in path even
  when the directory is misconfigured or unreachable.

### Key Entities

- **Directory Configuration**: The single set of connection, search, attribute-
  mapping, and transport-security settings governing directory integration.
  One per installation; persisted; secret material stored encrypted and never
  echoed back.
- **Group-to-Role Mapping**: Lists of directory group names associated with
  each product role (Administrator, Auditor, Viewer) and with the terminal-
  access permission. Bounded in count and length.
- **Audit Log Entry**: An immutable record of each configuration change —
  actor, time, and non-secret change summary.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An administrator can configure and verify a working directory
  connection entirely from the Settings page in under 10 minutes, without
  server access or a restart.
- **SC-002**: 100% of configuration reads and responses exclude the stored
  bind password; at no point after saving is the secret visible to any user.
- **SC-003**: 100% of invalid configurations (missing required fields,
  malformed certificate, over-limit group mappings, insecure transport without
  opt-in) are rejected before taking effect, each with a message that names
  the offending field or limit.
- **SC-004**: Every configuration save appears in the audit log with the
  acting administrator; spot-checks find zero secret values in audit entries.
- **SC-005**: "Test connection" returns a verdict (success or named failure)
  within 15 seconds in all cases, including unreachable hosts.
- **SC-006**: A directory user in a mapped group receives the mapped role on
  first sign-in with zero manual role assignment.

## Assumptions

- Only administrators can view or change directory settings; other roles never
  see the Directory tab.
- The persisted configuration is the single source of truth: environment-
  variable-based LDAP configuration is fully replaced, not layered underneath.
- Default search filters and attribute mappings target a conventional
  LDAP schema (e.g., OpenLDAP-style `uid`/`mail`/`cn`), so a standard
  directory works with minimal tuning.
- A single hub instance applies the configuration; multi-instance
  synchronization is out of scope.
- Provisioning of directory user accounts on first sign-in (and the existing
  sign-in flow generally) already exists; this feature only moves its
  configuration into the admin UI and adds group-to-role mapping management.
- Migration tooling for existing deployments (importing prior environment-
  variable values into the stored configuration) is out of scope for this
  feature.

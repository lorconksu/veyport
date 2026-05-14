# FedRAMP High Application Readiness Backlog

This backlog captures application-layer readiness gaps found during the May 14, 2026 review. Infrastructure controls, SSDF process evidence, and authorization package work are intentionally out of scope here.

## Tasks

- [ ] Add phishing-resistant MFA support.
  - Implement OIDC/SAML integration that can enforce PIV/CAC through an IdP, or implement WebAuthn/FIDO2 for privileged and remote-access users.
  - Keep local password plus TOTP as break-glass only, with explicit audit events.
  - Require fresh reauthentication for terminal sessions and privileged administration.

- [ ] Add full account lifecycle controls.
  - Add disabled, locked, dormant, last-login, last-failed-login, and failed-attempt state.
  - Enforce account lockout and unlock workflows in application code.
  - Add administrator disable/enable flows and audit events.
  - Add dormant account detection and review surfaces.

- [ ] Revoke sessions and API tokens on privilege changes.
  - Increment token generation when role, TOTP, terminal access, LDAP identity, or account status changes.
  - Revoke API tokens when access is materially reduced.
  - Audit each revocation and privilege-change event with actor, target, and outcome.

- [ ] Add LDAP deprovisioning and group sync.
  - Revalidate LDAP status during refresh for LDAP-backed users or add a scheduled sync job.
  - Disable or downgrade users removed from required LDAP groups.
  - Invalidate active sessions and API tokens when LDAP authorization changes.

- [ ] Scope API tokens.
  - Add token scopes or permissions rather than treating API tokens as role-equivalent access tokens.
  - Enforce max lifetime and no-expiry policy constraints.
  - Audit token use on sensitive endpoints, not only token creation/revocation.

- [ ] Harden terminal accountability controls.
  - Add terminal idle and absolute session timeouts.
  - Require a reason or ticket for terminal access.
  - Record session metadata and either command/session transcripts or an equivalent audited terminal control.
  - Protect recordings from casual admin modification and restrict review access.

- [ ] Strengthen audit integrity and failure behavior.
  - Add hash-chain verification tooling and alerting.
  - Fail closed or enter a restricted degraded mode for critical actions when audit writes fail.
  - Add signed audit exports and append-only external forwarding support.
  - Make audit retention preserve verifiable continuity or archive before deletion.

- [ ] Add server-side session records.
  - Track active sessions with idle timeout and absolute max lifetime.
  - Rotate and revoke refresh tokens per session.
  - Expose admin session review and forced logout controls.

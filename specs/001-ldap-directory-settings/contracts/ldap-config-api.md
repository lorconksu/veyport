# API Contract: LDAP Directory Configuration

**Phase 1 output** | Date: 2026-06-11

All endpoints: JSON over HTTPS, authenticated session (access token), **admin
role required** (`adminOnly` middleware). Errors use the standard hub error
shape: `{ "error": "<message>" }`.

## GET `/api/settings/ldap`

Returns the effective configuration. **Never returns the bind password.**

**Response 200**:

```json
{
  "enabled": true,
  "url": "ldaps://ldap.example.com:636",
  "bind_dn": "cn=veyport,ou=services,dc=example,dc=com",
  "bind_password": "",
  "bind_password_set": true,
  "user_base_dn": "ou=people,dc=example,dc=com",
  "group_base_dn": "ou=groups,dc=example,dc=com",
  "user_search_filter": "(uid={username})",
  "group_search_filter": "(|(member={dn})(memberUid={username}))",
  "username_attribute": "uid",
  "email_attribute": "mail",
  "external_id_attribute": "entryUUID",
  "group_name_attribute": "cn",
  "start_tls": false,
  "tls_server_name": "",
  "ca_cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "allow_insecure_transport": false,
  "admin_groups": ["veyport-admins"],
  "auditor_groups": ["veyport-auditors"],
  "viewer_groups": ["veyport-viewers"],
  "terminal_groups": ["veyport-terminal"]
}
```

- `bind_password` is always `""`; `bind_password_set` reports whether a
  non-empty password is stored.

**Errors**: `401` unauthenticated · `403` non-admin · `500` load failure.

## PUT `/api/settings/ldap`

Replaces the configuration. Atomic: validation failure leaves prior
configuration untouched.

**Request**: same shape as the GET response, plus:

| Field | Semantics |
|---|---|
| `bind_password` | `""` or redacted sentinel → keep stored password; any other value → replace (encrypted at rest) |
| `clear_bind_password` | `true` → remove the stored password (overrides `bind_password`) |

**Validation (only when `enabled: true`)** — `400` with a message naming the
violation:

- `url`, `user_base_dn`, `group_base_dn` required
- `bind_password` (stored or supplied) required when `bind_dn` is set
- at least one of `admin_groups` / `auditor_groups` / `viewer_groups` non-empty
- ≤ 64 names per group field; ≤ 255 chars per name
- plain `ldap://` without `start_tls` requires `allow_insecure_transport: true`
- `ca_cert_pem`, if set, must be a parseable certificate PEM

**Response 200**: `{ "status": "ok" }` — fetch the effective configuration
via GET (the secret is never echoed back).

**Side effects**: settings effective immediately (next sign-in uses them);
audit entry `ldap.config_updated` recorded with non-secret change summary.

**Errors**: `400` invalid body/validation · `401`/`403` as above · `500`
persistence failure.

## POST `/api/settings/ldap/test`

Validates the submitted configuration and attempts a live connection
(dial + optional StartTLS + service-account bind). **Persists nothing.**

**Request**: identical shape to PUT. The keep/replace password semantics
apply — an untouched password field tests with the stored secret.

**Response 200**:

```json
{ "status": "ok" }
```

**Errors**:

- `400` — validation failure, or connection/bind failure with a specific
  reason (e.g. `"failed to connect to LDAP: ..."`, `"failed to bind LDAP
  service account: ..."`). LDAP operations are capped by a 10-second timeout.
- `401`/`403`/`500` as above.

## Compatibility notes

- New endpoints only — no existing endpoint's contract changes.
- Frontend type: `LDAPConfig` in `web/src/types/api.ts` mirrors this shape.
- Documented for end users in `docs/wiki/API-Reference.md` (updated in this
  feature).

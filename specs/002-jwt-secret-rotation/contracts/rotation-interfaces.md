# Interface Contracts: JWT Secret Rotation & Key Separation

**Phase 1 output** | Date: 2026-06-12

## 1. CLI: `veyport admin rotate-jwt-secret`

```
veyport admin rotate-jwt-secret --db <path> [--yes]
```

- `--db`: SQLite path (default matches other admin subcommands).
- Without `--yes`: prints impact summary (all sessions invalidated, N API
  tokens revoked, restart required) and requires confirmation; `--yes` for
  scripted use.
- Success output (no key material, ever):
  ```
  JWT signing secret rotated.
  Revoked API tokens: N
  All user sessions are now invalid; users must sign in again.
  Restart the hub to apply: systemctl restart veyport  (or: docker compose restart)
  ```
- Exit non-zero with no changes on any failure (tx rollback).
- Refuses with a clear message if the database has no `jwt_signing_key`
  (instance never initialized).

## 2. API: `GET /api/settings/hub` (existing, admin-only)

Response gains one read-only field:

```json
{ "...existing fields...": "...", "jwt_secret_rotated_at": "2026-06-12T04:10:00Z" }
```

`null`/absent = never rotated. PUT ignores the field. No other endpoint
changes; the secret has no read path.

## 3. Audit events

| Action | Emitted by | Detail schema |
|--------|-----------|----------------|
| `auth.jwt_secret_rotated` | rotation CLI | `{"revoked_api_tokens": N}` |
| `auth.storage_key_separated` | startup migration (once) | `{"migrated_from": "jwt_signing_key"}` (names the source key, never values) |

Both registered in the audit catalog (`audit_catalog.go`) in the same change.

## 4. Internal wiring contract

- `server.InitStorageKey(st) (string, error)` runs in `cmd/veyport/main.go`
  **after** `InitJWTSecret`, **before** `ca.InitCA` and `notify.New`.
- `ca.InitCA` and all `encrypt*/decrypt*` helpers receive the storage key;
  the JWT secret is used **only** for token signing/verification after this
  change. `auth.DeriveKey` itself is unchanged.

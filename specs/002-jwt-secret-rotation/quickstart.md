# Quickstart: JWT Secret Rotation

**Phase 1 output** | Date: 2026-06-12

## Rotate (routine or compromise response)

```bash
# On the hub host
docker exec veyport /app/veyport admin rotate-jwt-secret --db /data/veyport.db
docker compose -f /opt/veyport/docker-compose.yml restart   # apply
# bare metal: ./veyport admin rotate-jwt-secret --db veyport.db && systemctl restart veyport
```

## Verify (matches the integration test's assertions)

1. An access token issued before rotation is rejected (401) on any API call.
2. Fresh sign-in (password + TOTP) succeeds — TOTP secrets decrypt.
3. Settings → Directory "Test Connection" passes — LDAP bind password decrypts.
4. Notifications test email sends — SMTP password decrypts.
5. Agents reconnect/stay connected — CA key loads.
6. `GET /api/settings/hub` shows the new `jwt_secret_rotated_at`.
7. Audit log contains `auth.jwt_secret_rotated` with the revoked-token count.

## Upgrade behavior (key separation, automatic)

First startup on this version copies the current signing secret into
`storage_key` (no ciphertext changes) and audits
`auth.storage_key_separated`. Nothing to do; failure aborts startup loudly.

## Backup/restore note

A DB backup is self-consistent (its secret + its ciphertexts). Restoring a
pre-rotation backup undoes the rotation — re-rotate after restoring if the
rotation was a compromise response.

## Dev verification

```bash
cd hub && go test ./internal/server/ -run "StorageKey|Rotate" -count=1
go test ./internal/integration/ -run "Rotation" -count=1
```

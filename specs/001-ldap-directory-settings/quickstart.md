# Quickstart: LDAP Directory Settings

**Phase 1 output** | Date: 2026-06-11

How to exercise this feature end-to-end, locally or on the dev environment.

## 1. Run the test suites (hermetic — no directory needed)

```bash
# Backend handler + validation tests
cd hub && go test ./internal/server/ -run LDAP -count=1

# Frontend Directory tab tests
cd web && npx vitest run src/pages/__tests__/settings-directory-tab.test.tsx
```

Unit tests inject a fake LDAP dialer (`server.ldapDial`), so no real directory
is required.

## 2. Stand up a throwaway test directory (for live verification)

GLAuth is the lightest option:

```bash
docker run -d --name test-ldap -p 3893:3893 glauth/glauth:latest
# default sample config: user serviceuser / mysecret, group svcaccts
```

Or OpenLDAP via `osixia/openldap` if you need StartTLS/LDAPS testing.

## 3. Exercise the UI

1. Sign in as an administrator → **Settings → Directory** tab.
2. Toggle **Enable LDAP**; fill:
   - URL: `ldap://localhost:3893` (check the insecure-transport opt-in for
     plain `ldap://`, or use `ldaps://` in real setups)
   - Bind DN / password: your service account
   - User base DN / Group base DN
   - Leave filters/attributes blank to use defaults
   - Map a known directory group to a role (e.g. Admin groups: `svcaccts`)
3. Click **Test connection** — expect inline success, or a specific failure
   message (bad host/credentials) within ~10 s.
4. **Save** — takes effect immediately, no restart.
5. Sign out; sign in as a directory user from a mapped group; confirm the
   mapped role.
6. Check **Audit Logs** for an `ldap.config_updated` entry with no secret
   content.

## 4. Verify the secret-handling contract via API

```bash
# GET must never return the password
curl -s --cookie "$ADMIN_COOKIE" https://<hub>/api/settings/ldap | jq '.bind_password, .bind_password_set'
# → ""  /  true
```

## 5. Dev-environment runtime verification (required before merge)

Per the constitution's workflow rules: deploy the branch to the dev
environment, then repeat steps 3–4 there and confirm pages load cleanly
(no console/runtime errors) before declaring the feature complete.

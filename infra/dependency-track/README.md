# Private Dependency-Track release integration

The local importer connects Veyport's existing verified release pipeline to a LAN-only Dependency-Track 5.x instance. It needs outbound HTTPS and does not expose Dependency-Track publicly or run GitHub Actions jobs on a private runner.

Every ten minutes the systemd timer checks published stable GitHub releases since `not_before`. For each new version it imports four projects:

| Project | Inventory source |
|---|---|
| `Veyport / veyport` | SPDX evidence from the exact shipped main image, including the embedded Go binaries and OS packages |
| `Veyport / audit-ingest` | Exact published audit-ingest image evidence |
| `Veyport / audit-export` | Exact published audit-export image evidence |
| `Veyport / frontend dependencies` | `web/package.json` and `web/package-lock.json` from the immutable release commit, including development dependencies |

Image inventories are converted to CycloneDX with the same pinned Syft version used by the release pipeline. The frontend inventory is a source lockfile inventory, not a measurement of which packages survived bundling. Each project version uses the release version; component metadata records the commit and image digest where applicable. Stable versions remain separately visible; prereleases and PR builds are excluded. No release gate or vulnerability suppression is added.

## Trust and failure handling

- Public downloads are anonymous and scoped to `lorconksu/veyport`; no personal GitHub token is needed. Redirects are HTTPS-only and restricted to GitHub download hosts.
- The evidence archive must match the digest and size returned by GitHub. Its internal checksums, release version, source revision, and published image bindings must also agree. This verifies consistency with the GitHub-hosted release; it is not an independent publisher signature.
- Archives are parsed in memory without filesystem extraction. Links, traversal, duplicate members, excessive counts and sizes are rejected. Source lockfiles are data only: no checkout, npm install, or lifecycle scripts run.
- The dedicated Dependency-Track credential has `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`, without user, policy, system, or general portfolio administration. These permissions are operation-level, not a project-name restriction; configure Dependency-Track project ACLs if sharing this instance with unrelated tenants.
- Upload success alone is insufficient: the importer waits for the 5.x event token to report `COMPLETED`, covering import, analysis, and policy evaluation. Failed, unknown, or expired tokens fail the run. Completed per-project state survives partial failures; retries skip successful imports.
- Changed evidence for an already observed tag is rejected, including a deleted/recreated GitHub release. Local locking and systemd prevent concurrent runs. State writes are atomic.
- The unprivileged systemd service has a read-only system filesystem, a private temporary directory, bounded memory/CPU/runtime, and a single writable state directory. API credentials use systemd `LoadCredential`; they are never committed, sent to GitHub, or placed in command arguments.

Discovery is bounded to 1,000 releases, and evidence to 16 MiB compressed / 128 MiB expanded with 8 MiB individual files. Exceeding limits fails visibly rather than silently omitting releases. This public-repository integration deliberately does not accept arbitrary repositories or private GitHub credentials.

## Install

Use a Linux host that can resolve and reach the private Dependency-Track HTTPS origin and the public GitHub endpoints. Dependency-Track 5.x is required for terminal event-token statuses. Python 3.10+ and systemd with `DynamicUser` / `LoadCredential` are required; Python has no additional dependencies.

1. Install Syft using `bash scripts/release/install_tools.sh syft /opt/veyport-dependency-track/bin` as an administrator. This verifies the pinned official archive checksum.
2. Install `sync.py` at `/opt/veyport-dependency-track/sync.py`, root-owned, mode 0644. Keep its containing directory and the Syft binary root-owned and non-writable by the service.
3. Create `/etc/veyport-dependency-track` with mode 0755. Copy `config.example.json` to `config.json`, mode 0644. Set the HTTPS origin, integration baseline date, and absolute Syft path. The baseline intentionally excludes older historical releases.
4. In Dependency-Track, create a dedicated automation team with `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`, then generate its API key. Store it in `/etc/veyport-dependency-track/api-key`, root-owned mode 0600, using a secure input/file transfer. Never put it in the config or shell command arguments.
5. Install the `.service` and `.timer` files in `/etc/systemd/system`, mode 0644. Run `systemd-analyze verify` on both, then `systemctl daemon-reload` and `systemctl start veyport-dependency-track.service`. Inspect its completion before `systemctl enable --now veyport-dependency-track.timer`.

The example baseline imports v2.0.55 and subsequent stable releases. Existing release assets already supply the required evidence; enabling the integration does not require publishing another release or merging application changes.

### Vulnerability intelligence

Inventory import is separate from vulnerability-source coverage. In Administration → Vulnerability Sources, enable OSV for **Go**, **npm**, and **Wolfi**, matching the current release inventories; retain NVD for CPE-based matching. Trigger the initial mirror, monitor its result, then analyze imported projects again. OSV requires outbound access to `storage.googleapis.com` but no API credential. It mirrors advisory datasets locally rather than submitting private component lists to a hosted scanner. Revisit selected ecosystems when base images or languages change.

Findings need triage: source lockfile packages may be development-only, and a package advisory is not proof of runtime reachability. Existing Grype/govulncheck release checks remain authoritative release gates. This integration does not import their reachability assessments as VEX or automatically suppress findings.

### Current local deployment

The owner retained Dependency-Track on VM 128, `10.10.1.68`, at `https://dependencytrack-lab.yiucloud.com`. The importer runs on that VM. The existing Traefik proxy terminates TLS and permits private clients only. No private GitHub runner, public DNS record, or inbound internet route was added.

Cloud-init initially mapped the UI's FQDN to `127.0.1.1` on this host. That FQDN was removed from `/etc/hosts`, while retaining the short hostname. Proxmox user-data overrides the local `manage_etc_hosts: false` setting, so `/etc/cloud/templates/hosts.debian.tmpl` also maps only the short hostname to loopback. The UI FQDN resolves through internal DNS to the TLS proxy even when cloud-init regenerates hosts. Originals are backed up at `/etc/hosts.pre-dtrack-sync` and `/etc/cloud/templates/hosts.debian.tmpl.pre-dtrack-sync`.

### Keycloak single sign-on

The local deployment uses `https://keycloak.yiucloud.com/realms/master`, matching the owner's existing SSO services. Open the dashboard and choose **Sign in with Keycloak**. An existing Keycloak browser session can be reused; otherwise Keycloak prompts for the user's normal credentials and any required authentication steps. No separate Dependency-Track password is needed for this path.

The `dependency-track` Keycloak client is a public OpenID Connect client using authorization code with required **S256 PKCE**. Its only redirect URI is `https://dependencytrack-lab.yiucloud.com/static/oidc-callback.html`; its only web origin is `https://dependencytrack-lab.yiucloud.com`. Implicit flow, direct access grants, service accounts, and full scope are disabled. Default client scopes are `profile` and `email`; the frontend requests `openid profile email`. A client-local Group Membership mapper emits the `groups` claim with full group paths in ID tokens, access tokens, and userinfo. No client secret is required or exposed to the browser.

Dependency-Track 5.2.1 needs settings on both Compose services:

```yaml
services:
  apiserver:
    environment:
      DT_OIDC_ENABLED: "true"
      DT_OIDC_ISSUER: "https://keycloak.yiucloud.com/realms/master"
      DT_OIDC_CLIENT_ID: "dependency-track"
      DT_OIDC_USERNAME_CLAIM: "preferred_username"
      DT_OIDC_USER_PROVISIONING: "true"
      DT_OIDC_TEAM_SYNCHRONIZATION: "true"
      DT_OIDC_TEAMS_CLAIM: "groups"
  frontend:
    environment:
      OIDC_ISSUER: "https://keycloak.yiucloud.com/realms/master"
      OIDC_CLIENT_ID: "dependency-track"
      OIDC_SCOPE: "openid profile email"
      OIDC_FLOW: "code"
      OIDC_LOGIN_BUTTON_TEXT: "Sign in with Keycloak"
```

Merge these environment entries into the existing services; this excerpt does not replace their images, database settings, or volumes. API-server discovery must reach the issuer over trusted HTTPS. `GET /api/v1/oidc/available` should return `true`, and `/static/config.json` should report the same issuer and client ID.

In Keycloak, the dedicated group `/dependency-track-admins` initially contains only `wyiu`. In Dependency-Track **Administration → Access Management → OpenID Connect Groups**, that exact group name is mapped to the **Administrators** team. Account provisioning alone grants no team or portfolio permissions. New users need an explicitly mapped group; membership in an unrelated Keycloak group does not grant dashboard access. To add a future read-only audience, create a separate Keycloak group and map it to a Dependency-Track team with only the required view permissions.

Team membership synchronizes at login, not continuously during an existing session. For urgent access removal, remove the Keycloak group membership and also revoke the user's active Dependency-Track and Keycloak sessions. Dependency-Track logout ends the application session; it does not sign the browser out of Keycloak, so the SSO button can sign the user back in without another password prompt.

The existing local `admin` account remains available through **More options** for recovery if Keycloak is unavailable. Its credential remains in the private operator credential store, outside Git. The release importer keeps using its dedicated API key and does not depend on a browser SSO session. The temporary Keycloak administrator credential used during setup is not a runtime dependency.

The live Compose file is `/opt/sca-evaluation/compose.yml`; its pre-SSO backup is `/opt/sca-evaluation/compose.pre-keycloak.yml`. To roll back SSO, restore that backup and recreate only `apiserver` and `frontend` with Compose project name `dependencytrack-lab`. Preserve database volumes and importer state. Disabling the Keycloak client prevents new client logins but does not by itself revoke existing Dependency-Track sessions.

## Operate and troubleshoot

```sh
sudo systemctl list-timers veyport-dependency-track.timer
sudo systemctl status veyport-dependency-track.service
sudo journalctl -u veyport-dependency-track.service --since today
sudo cat /var/lib/veyport-dependency-track/state.json
sudo systemctl start veyport-dependency-track.service
```

An inactive oneshot service after `Result=success` is normal; its timer remains active. Check `last_success` in state and the journal. A failure is retained in systemd/journald and retried at the next interval; no external notification channel is configured. Stopping the timer disables future imports without affecting Dependency-Track or stored inventories. Rotate the API key by replacing the root-owned credential file and revoking the old key in Dependency-Track; the next invocation loads the replacement.

Back up both the Dependency-Track database and the import state. The state prevents redundant uploads and detects replaced release evidence; it does not replace a database backup. To restore missing project data after a database rollback, reconcile affected state entries deliberately before retrying.

Run tests with `python3 -m unittest discover -s infra/dependency-track -p 'test_*.py'`; CI runs the same suite.

References: [Dependency-Track upload and completion semantics](https://dependencytrack.github.io/docs/next/guides/user/uploading-boms/), [vulnerability-source configuration](https://dependencytrack.github.io/docs/next/guides/administration/configuring-vulnerability-sources/), and [OpenID Connect configuration](https://dependencytrack.github.io/docs/next/guides/administration/configuring-oidc/).

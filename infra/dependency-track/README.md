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

Cloud-init initially mapped the UI's FQDN to `127.0.1.1` on this host. That FQDN was removed from `/etc/hosts`, while retaining the short hostname, and `/etc/cloud/cloud.cfg.d/99-dependencytrack-hosts.cfg` disables rewriting that file. The UI FQDN now resolves through internal DNS to the TLS proxy. The original file is backed up at `/etc/hosts.pre-dtrack-sync`.

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

References: [Dependency-Track upload and completion semantics](https://dependencytrack.github.io/docs/next/guides/user/uploading-boms/) and [vulnerability-source configuration](https://dependencytrack.github.io/docs/next/guides/administration/configuring-vulnerability-sources/).

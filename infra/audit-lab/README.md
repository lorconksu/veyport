# Authorized synthetic audit lab

The inventory describes the six-guest Ubuntu 24.04 prototype topology on the
owner's `home` Proxmox cluster: `.59` Hub, `.60` receipt/export service, `.61`
ELK search, `.62` encrypted archive, `.63` independent OpenBao key service, and
`.64` enrolled execution target. Addresses `.65` through `.69` are unused.
`provision.py` refuses VMID/name/tag and backing-volume collisions. NetBox
scripts validate and create native change records attributed
to `NETBOX_ACTOR` (default `wyiu`, the owner in this deployment). They never
overwrite unrelated records. Read the local provisioning evidence before reuse.

Provision using the existing public SSH key and environment-provided Proxmox
API credentials; TLS verification is mandatory:

```sh
python3 infra/audit-lab/provision.py --ssh-public-key ~/.ssh/yiucloud.pub
python3 infra/audit-lab/provision.py --ssh-public-key ~/.ssh/yiucloud.pub --apply
```

All remote commands use explicit guest addresses. Docker is disabled on these
guests. No local Docker context is used. Guest nftables rules isolate service
ports on the shared LAN; management endpoints bind to loopback. This is a
synthetic lab within a shared infrastructure administrator trust boundary.

Generate controller-only PKI and LUKS keys with `pki.py`. Private state is under
`~/.local/share/veyport-audit-lab/secrets`, outside the repository, with directory
mode 0700 and file mode 0600. Do not copy it into public evidence or Git.
`bootstrap.sh` runs through explicit guest SSH with a temporary 0600 key in
`/run/veyport-unlock.key`. The guest retains no unlock key on its root disk.

After a reboot, services cannot start before manual encrypted-volume unlock:

```sh
bash infra/audit-lab/unlock.sh 10.10.1.62 \
  ~/.local/share/veyport-audit-lab/secrets/audit-store-lab.luks.key
ssh -i ~/.ssh/yiucloud cloud-user@10.10.1.62 \
  'sudo systemctl reset-failed; sudo systemctl start postgresql@16-audit veyport-seaweed-master veyport-seaweed-volume veyport-seaweed-filer veyport-seaweed-s3 nginx'
```

The archive mount **must include `sync,nodev,nosuid`**. Its service start guards
reject an absent mount or missing `sync`. OpenBao also requires its encrypted
mount. Swap is disabled. Unlock/restart and restore workflows must preserve
these guards, since writing beneath an unmounted directory would be plaintext.
Keys require `deploy.py keys` to unseal with controller recovery material after
unlock/restart. Keep the LUKS keys, OpenBao shares and independent backup key
separate from the guests and preserve encrypted backups outside those guests.

Storage deployment uses the exact artifacts in `storage/deployment-lock.json`:

```sh
python3 infra/audit-lab/storage/deploy.py keys
python3 infra/audit-lab/storage/deploy.py storage
```

S3 TLS is `https://10.10.1.62:8333`, independent OpenBao TLS is
`https://10.10.1.63:8200`, bucket `audit-originals`, transit key `audit-archive`.
Trust the private lab CA explicitly; never disable certificate verification.
Writer credentials and KMS tokens remain private. The independently signed
receipt/export service is deployed and qualified at `.60:8443`; its captured
deployment and readiness pins are in `receipt/deployment.json`. At the
2026-10-11 pre-publication deployment checkpoint, staging Hub `.96` could reach
the service but remained on stable `2.0.49`, and lab Hub `.59` ran local build
`e7f7c8cb1b62ec8c57dac1dc6a09986d9d875cd2`. This dated state does not assert
what is installed after that checkpoint or imply that the final feature-release
source was installed on staging. For the published prototype's
installation and use instructions, follow the [Deployment guide](../../docs/wiki/Deployment.md)
after verifying the release page and artifact digest.

Synthetic original promises are 24 hours minimum, with a 2-day backend
COMPLIANCE default. `audit-governance`
contains only small synthetic policy/idempotency metadata with a 3,650-day
application minimum and 3,651-day backend default. The extra backend day handles
observed whole-second default-retention timestamps while preserving exact
fractional application promises. These are prototype implementation settings,
not regulatory defaults or specific owner-stated retention requirements.
Existing COMPLIANCE versions cannot be deleted through S3 before expiry;
changing a default does not shorten existing versions. Raw payloads stay in originals.
The `.61` ELK deployment uses the Basic license and seven-day search retention.
The sanitized two-bucket projection, replay, outage and recovery checks passed;
see `elk/projection-qualification.json` and `elk/deployment-lock.json`. This
search projection does not extend raw-original retention or replace the
independent receipt/archive admission path.

`qualify.py`, `conditional.py`, `crash.py` and `backup-restore.py` perform actual
synthetic mutation/fault tests. `crash.py` stops only archive VM121, three times;
`backup-restore.py` stops only archive/key services and preserves old encrypted
directories before authenticated restoration. Do not run fault and restore
tests concurrently. Never remove retained originals to make a test pass.

The initial asynchronous filesystem failed acknowledged-write power-loss
qualification. Its index was repaired from preserved data only after the failure
was recorded. A synchronous mount is a required configuration change, whose
qualification depends on fresh fault tests. A reachable endpoint or successful
PUT alone is insufficient for enhanced receipts. Only a completed, digest-pinned
qualification report for the exact deployment may enable that path.

The completed synthetic archive report is `storage/qualification.md`, with
actual captured settings in `storage/configuration.json`. Review and pin the
exact raw SHA256 of `storage/qualification-originals.json` and
`storage/qualification-governance.json` separately. Both records bind the same
report/configuration and their own actual bucket default; application promises
remain 24 hours and 3,650 days. They qualify the tested guest fault and restore
behavior, with the limitations recorded in the report.

To repeat the consistent encrypted backup and actual restore test during an
authorized lab interruption, first ensure both encrypted mounts are unlocked,
preserve private recovery keys, and stop concurrent writers/fault tests:

```sh
python3 infra/audit-lab/storage/backup-restore.py
```

This stops the archive and key services, streams their consistent directories
through SSH into separate authenticated ciphertext backups in private
controller state, authenticates before extraction, preserves the original
encrypted directories, replaces the active paths and unseals the restored key
service. Success requires bounded exact-version control-object readiness and
verification of every saved version/hash/retention/key identifier. Backup
creation alone does not prove restoration. Restore configuration captures and
qualification pins must be reviewed again after any change.

OpenBao issues the archive transit token for 168 hours. It has no default policy
and cannot renew itself; the private controller operator performs maintenance.
Check it daily, and renew before fewer than 24 hours remain:

```sh
python3 infra/audit-lab/storage/renew-kms-token.py
python3 infra/audit-lab/storage/renew-kms-token.py --renew
```

The script loads the restricted token and operator credential from private 0600
files, uses verified TLS and prints only expiry, remaining seconds, policy names
and renewable status. It calls `auth/token/lookup` and, with `--renew`,
`auth/token/renew` using the operator credential. Renewal can be capped by the
server's maximum lifetime; always inspect the new expiry. An expired credential
cannot be renewed. Archive operations fail closed while keys are unavailable.
At maximum lifetime or expiry, preserve the old private token file under a
different private name, run `deploy.py keys` to issue another token with the
same restricted policy, then `deploy.py storage` to load it. This is a planned
archive interruption: verify exact-version reads and recapture configuration;
changed privileges/settings require requalification before receipt activation.
This procedure is explicit lab maintenance, not automatic production rotation.

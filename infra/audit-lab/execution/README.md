# Isolated production-runtime execution checks

This tooling addresses only the owner-authorized `.59` hub and `.64` enrolled
target. It never installs into staging and never changes receipt, ELK, archive
or key-service guests. Receipt ingestion creates retained synthetic records in
the existing separately qualified `.60` service. The three principals and their
person IDs are explicitly synthetic; their votes are test fixtures and represent
no human or owner approvals.

The initial report qualifies API, CLI and native execution transport. It makes
no browser/UI claim: the hub build embeds the currently available `hub/web/dist`.
Browser qualification requires rebuilding the final reviewed frontend before
the corresponding hub build and redeployment.

After the reviewed backend checkpoint and patched dependency gates, build and
deploy native binaries using Go 1.26.9:

```sh
python3 infra/audit-lab/execution/deploy.py
python3 infra/audit-lab/execution/deploy.py --build --apply
python3 infra/audit-lab/execution/qualify.py
python3 infra/audit-lab/execution/qualify.py --apply --prepare-only
# Run the actual browser bootstrap after rebuilding/redeploying reviewed web UI.
python3 infra/audit-lab/execution/qualify.py --apply
```

Deployment preserves SQLite databases, agent certificates, installation IDs,
enrollment markers and all external versions. The installer rejects an existing
database without the dedicated lab ownership marker. Services require the
pre-provisioned dm-crypt mount and private spool directories. The agent uses
normal one-use enrollment with the exact hub CA fingerprint; protected capability
advertisement requires actual encrypted storage readiness.

REST is loopback-only behind a dedicated HTTPS listener on `.59:8443`, using
the existing `/srv/veyport/tls` certificate and private CA. Python trusts that CA
explicitly, rejects proxies and redirects; actual `vey` uses the same CA through
the normal Go system-root `SSL_CERT_FILE` mechanism. No TLS bypass is used.
HTTPS access/error logging is disabled to keep one-use original handles private.

Controller passwords, MFA seeds, refresh tokens, SSH private keys and mTLS
credentials stay under `~/.local/share/veyport-audit-lab/secrets`, mode 0700/0600.
Each principal gets a separate CLI configuration directory and normal file
credential fallback. The CLI obtains real password/MFA login sessions and
rotates refresh tokens normally. Fresh MFA waits for unused TOTP periods and
respects the shared rate limiter; no cache or authority override exists.

Preparation preserves the pristine never-enrolled Standard policy for the actual
three-person browser bootstrap. The subsequent qualification submits a bounded
same-profile policy revision through CLI quorum; it never reboots governance or
resets enrolled identities, markers or anchors.

Qualification exercises real built `vey security secret`, request, two
independent approvals, apply and status against the production runtime. Native
`vey ssh` then sends one complete finite script, verifies exact output/exit and
one remote marker, and checks an independent ES256 signature against the pinned
public key and stored execution identity. A temporary `.59` egress rule blocks
only receipt `.60:8443`, proves no protected process side effect, then restores
connectivity. It never stops or modifies `.60`.

If the controller is interrupted during the fault, remove only its dedicated
table before retrying:

```sh
ssh -i ~/.ssh/yiucloud cloud-user@10.10.1.59 \
  'sudo nft delete table inet veyport_lab_receipt_fault'
```

Public reports contain only source/binary digests, synthetic IDs, signed record
hashes, version references and outcomes. This is prototype deployment/fault
evidence; it does not complete the final code-quality gate or imply certification.

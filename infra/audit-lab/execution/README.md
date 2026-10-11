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

## Bounded Enhanced load fixture

`load.py` is separate from bootstrap and policy qualification. Its default mode
prints a plan and reads no credentials or network state. Root must review the
source and serialize the actual run with browser/MFA/VM tests before opting in:

```sh
python3 -m unittest discover -s infra/audit-lab/execution -p 'test_*.py' -v
python3 infra/audit-lab/execution/load.py
# Root only, after reviewed binary deployment and an idle Enhanced target:
python3 infra/audit-lab/execution/load.py --apply
```

The run requires the existing ready Enhanced policy to cover the enrolled
`lab-encrypted-target` node. It preserves the three-person bootstrap identities,
votes, policy, enrollment and archives. The existing officer authenticates
through normal password and fresh MFA solely to create two separately named
synthetic operational administrators (`lab_synthetic_load_a` and
`lab_synthetic_load_b`). Neither receives security-officer, security-approver,
original-reader or a protected person binding. Password/MFA setup and CLI login
use normal APIs and the real shared limiter; no SQL authority writes, forged
tokens, approval changes, agent restart or service fault is performed.

Extra passwords, MFA seeds and fixture progress are stored only in the separate
0600 `execution-load-fixture.json` under the private controller directory. CLI
credentials use separate `execution-cli/load-a` and `execution-cli/load-b`
directories. Temporary complete script originals are private 0600 files removed
after the run. An interrupted run can leave these accounts enabled; root should
disable only the two exact fixture-created IDs with the ordinary account status
API. Normal completion or a handled failure disables both, preserving records and
audit attribution for later runs. The fixture can reenable only those accounts.
MFA pacing starts from the later of bootstrap/load fixture timestamps and waits
for an unused officer TOTP period. Interrupted marker paths are retained only in
private state; a retry refuses to overwrite them until root inspects and removes
that exact fixture directory. Handled failures retain bounded public progress
with `passed:false`; account cleanup must complete before `passed:true` is written.

Eight complete `/bin/sh -s` scripts wait on one unique lab-only start barrier:
four commands per actor respect the actor limit, while all eight share the node
limit. One bounded remote snapshot must observe all eight live process markers
before release. Each returns a
distinct 4 MiB binary stream, a binary stderr marker and its own exit code. A
separate 8 MiB stream has its local stdout reader withheld for eight seconds;
the quiet command must finish during that interval, and every slow-stream byte
must drain before its final exit is accepted. Cancellation then interrupts the
real CLI, drains delivered output within twelve seconds and verifies the owned
remote descendant terminates without its later marker effect. Already delivered
bytes and earlier side effects are not represented as rolled back.

Only unique `/tmp/veyport-load-<random>` files on `.64` are used for synchronization
and removed. The controller bounds stdout to 9 MiB, stderr to 1 MiB and each
collection deadline; it owns and cleans up only its isolated local process
groups. The fixture confirms exact script hashes, two actor IDs, node, Enhanced
policy version, final process/evidence state and independent admission receipt
signatures using read-only lab metadata. It never retries an execution.
The receipt verifier reads the production compact JWT storage format, checks the
ES256 signature and signed manifest, and independently reconstructs the exact
actor and execution/details binding hashes, including command/script digests,
limits and preparation expiry, and enforces retention from that execution's
immutable policy version. Historical verification never authorizes reuse of
an expired admission receipt. Representative local fixtures use a temporary
signing key and Go-generated binding digest constants, never real lab tokens.

`load-qualification.json` contains hashes, lengths, synthetic IDs, timings and
truthful process/evidence states; no commands, scripts, output, credentials or
receipt tokens. A prepared fixture and local collector tests do not constitute
actual VM load evidence. Root must retain the actual outcome and final source
and binary identity separately before closing the qualification gate.

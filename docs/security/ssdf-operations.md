# SSDF prototype operations and rollout status

This is the operator status record for the prototype on `feat/ssdf-pipeline`.
It describes evidence gathered so far; it does not activate release gates or
approve a release, merge, exception, scanner retirement or Dependency-Track
cutover. See the [collector runbook](../../infra/evidence-collector/README.md)
and [candidate coordinator runbook](../../infra/candidate-coordinator/README.md)
for configuration and procedures. Hostnames, addresses, mount paths and private
evidence locations intentionally remain in operator configuration.

The implementation remains a draft prototype. Independent code and security
review results and the final commit's CI status are tracked on
[PR #115](https://github.com/lorconksu/veyport/pull/115). The current local
validation includes 101 release-helper and 71 collector tests. A manual isolated
native rehearsal at `0962b374` passed all 18 cases; it explicitly reported
`release_qualified:false`. These results do not establish credentialed automatic
collection or a complete publication rehearsal.

## Established prototype state

- An unprivileged collector is provisioned on the owner's personal
  infrastructure, with a dedicated NFS child dataset. The report payloads are
  age-encrypted; the NAS dataset itself is not encrypted.
- The operator verified the exact mounted source, mount point and sentinel,
  durable write/readback with fsync, decrypt/readback, and recovery using the
  independent age-key copy. The NAS takes daily snapshots with a seven-day
  retention setting; a restore was tested. Snapshots are recovery copies, not
  WORM protection. NAS expiration behavior can retain expired data for up to
  seven additional days.
- The candidate coordinator's firewall egress restrictions and host isolation
  were tested. Its 18-case harness passed against the released baseline locally
  and against revision `0962b374` on isolated staging, exercising the installed
  coordinator and exact built native artifacts. Disposable candidates were
  cleaned up. This is a manual native rehearsal, not full release qualification.
  Normal staging remains on v2.0.57 and was not changed by the prototype.
- Local validation passed 101 release-helper, 71 collector, 16 coordinator,
  5 scanner, 6 harness, and 3 crypto tests. The CodeQL provider exporter was
  exercised against two existing analyses across five language categories;
  those reports were encrypted on the NAS and read back successfully. Snyk
  snapshots contain GitHub status metadata and safe references, not full SCM
  scan reports. Neither export starts another scan or grants release authority.
- CI runs 41182748494 and 41185877716 passed functional tests and scanner
  quality gates but failed Sonar report export. The latter recorded repeated
  HTTP 400 responses from the issues endpoint; a transient cause was not
  established. The corrected exporter deliberately separates authenticated CE
  task verification from anonymous reads of the verified public project's
  reports. The same analysis was successfully replayed through this split.
  It preserves exact source checks, partial output and all finding states;
  permanent request/authentication errors fail immediately. See
  [scanner access contracts](scanner-coverage.md) for the evidence and limits.
- Collector and candidate timers are OFF. No release gate is active, and no
  publication, merge, approval, scanner retirement or Dependency-Track cutover
  has occurred.
- Evidence privacy is not uniform. Newly produced private CI artifacts are
  encrypted, but public `coverage-server-shard` artifacts include
  `go-test.jsonl` used to merge the authenticated test inventory. That
  artifact contains synthetic fixture output; no production credentials were
  supplied. This specific artifact remains a privacy limitation and must not be
  described as private or as encrypted evidence.

## Scanner and release blockers

The SCA baseline contains two unresolved high frontend advisories. The scan
records also lack upstream `first_seen` values needed to support 30-day medium
and 90-day low tracking. First-seen history and a complete Snyk SCM export,
owner baseline coverage, and risk disposition remain pending. These gaps block
publication. Python cryptography was updated to 50.0.0 and its fresh scan was
clean, but this does not substitute for complete final-revision scans. See
[scanner coverage](scanner-coverage.md) for scope and remaining evidence.

Keep SonarQube, CodeQL and Semgrep active until same-revision coverage and
quality evidence justifies any change. DAST is deferred, not tested and not a
passing gate. Revisit only after the owner has Snyk support's answer and the
separate DAST provisioning and policy review are complete.

## Operator pending checklist

1. Verify the latest commit's CI and review results on PR #115. Retain its
   native rehearsal record and confirm that candidate, source revision and
   evidence identify the same immutable bytes before release qualification.
2. Obtain and verify the repository-scoped collection token with Actions read,
   Code scanning alerts read, Contents read, and commit statuses read/write.
   Provision a separate least-privilege deletion credential; it is currently
   absent.
3. Keep both timers disabled until credentials, trusted source pins, receipt
   key pins, monitoring, storage capacity and the full recovery/deletion
   procedure have been reviewed against the runbooks.
4. Resolve or explicitly disposition the frontend high findings and establish
   reliable `first_seen` evidence or otherwise satisfy the defined remediation
   tracking policy. Complete the Snyk SCM export, owner baseline coverage and
   risk disposition, then confirm final-revision SCA/SAST and exact-artifact
   scans.
5. Review the public `go-test.jsonl` artifact's privacy handling and ensure
   published records describe its synthetic-fixture scope accurately.
6. Reconcile the supervised encrypted CI transport backups retained on the NAS
   while the service credential is pending. They are recovery copies, not
   release-authorizing archive receipts. Exercise authenticated collection,
   signed receipt verification, failure
   behavior, exact-ID artifact deletion and cancellation/mount-loss recovery.
   Failed or missing collection must block publication and must not delete the
   source artifact.
7. Rehearse the complete candidate qualification and release path, including
   gRPC/SSH, rollback, and identical tested/published digests. DAST remains
   excluded and explicitly deferred during this phase.
8. Enable timers and production gates only after the above evidence and reviews
   are complete. This checklist itself grants no approval.

# SSDF prototype operations and rollout status

This is the operator status record for the prototype on `feat/ssdf-pipeline`.
It describes evidence gathered so far; it does not activate release gates or
approve a release, merge, exception, scanner retirement or Dependency-Track
cutover. See the [collector runbook](../../infra/evidence-collector/README.md)
and [candidate coordinator runbook](../../infra/candidate-coordinator/README.md)
for configuration and procedures. Hostnames, addresses, mount paths and private
evidence locations intentionally remain in operator configuration.

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
  were tested. Its 18-case harness passed against released revision
  `dfce2e6f584f27dec54f51be4992550bbf8d370a` using local Docker only. It has not
  yet completed a final-head rehearsal on the staging host or review. Normal staging remains
  on v2.0.57 and was not changed by the prototype.
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
and 90-day low tracking. These gaps block publication pending finding
disposition and usable tracking evidence. Python cryptography was updated to
50.0.0 and its fresh scan was clean, but this does not substitute for complete
final-revision scans. See [scanner coverage](scanner-coverage.md) for scope and
remaining evidence.

Keep SonarQube, CodeQL and Semgrep active until same-revision coverage and
quality evidence justifies any change. DAST is deferred, not tested and not a
passing gate. Revisit only after the owner has Snyk support's answer and the
separate DAST provisioning and policy review are complete.

## Operator pending checklist

1. Complete final-head rehearsal on the staging host and code/security reviews. Confirm that
   the tested candidate, source revision and evidence all identify the same
   immutable bytes.
2. Obtain and verify the repository-scoped collection token with Actions read,
   Contents read, and commit statuses read/write. Provision a separate
   least-privilege deletion credential; it is currently absent.
3. Keep both timers disabled until credentials, trusted source pins, receipt
   key pins, monitoring, storage capacity and the full recovery/deletion
   procedure have been reviewed against the runbooks.
4. Resolve the frontend high findings and establish reliable `first_seen`
   evidence or otherwise satisfy the defined remediation tracking policy.
   Confirm complete final-revision SCA/SAST and exact-artifact scans.
5. Review the public `go-test.jsonl` artifact's privacy handling and ensure
   published records describe its synthetic-fixture scope accurately.
6. Exercise authenticated collection, signed receipt verification, failure
   behavior, exact-ID artifact deletion and cancellation/mount-loss recovery.
   Failed or missing collection must block publication and must not delete the
   source artifact.
7. Rehearse the complete candidate qualification and release path, including
   gRPC/SSH, rollback, and identical tested/published digests. DAST remains
   excluded and explicitly deferred during this phase.
8. Enable timers and production gates only after the above evidence and reviews
   are complete. This checklist itself grants no approval.

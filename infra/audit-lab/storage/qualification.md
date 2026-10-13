# Synthetic archive qualification

Status: passed for the exact synthetic lab configuration recorded below on
2026-10-11. This includes actual archive and independent key restoration, not
only backup creation. Both bucket qualification records pin this report and
the same captured configuration; their raw digests must be reviewed and pinned
by the receipt operator before activation.

Scope: six owner-authorized new VMs; archive `audit-store-lab`, VM121,
`10.10.1.62`, and independent key guest `audit-keys-lab`, VM122,
`10.10.1.63`. No existing workload was altered. S3 endpoint
`https://10.10.1.62:8333`, buckets `audit-originals` and `audit-governance`, OpenBao transit key
`audit-archive`. TLS uses a private lab CA with IP SAN validation. Private
credentials and recovery keys remain outside the repository.

Versions and artifact digests are recorded in `deployment-lock.json`. SeaweedFS
4.48 reports commit `530be3e37337488ecc34d58441e0bc476e121c93`; independent
OpenBao is 2.7.1. PostgreSQL 16 provides synchronous filer metadata. The archive
uses encrypted LUKS2 ext4 mounted **sync,nodev,nosuid**, PostgreSQL `fsync=on`,
`synchronous_commit=on`, `full_page_writes=on`, and filer `/buckets/` `fsync=true`.
Archive service guards reject an absent encrypted mount or missing `sync`. SeaweedFS and OpenBao use separate dedicated Unix users (`veyport-seaweed` and `veyport-openbao`), private owned config/TLS/data directories, empty capability bounding sets, NoNewPrivileges and restrictive service filesystem/device protections. PostgreSQL retains its own Unix identity. Actual negative start tests rejected an asynchronous archive mount and skipped an absent encrypted mount without creating plaintext service files.

The writer uses an attached exact IAM policy, with `PutObject`, exact-version
read/retention and bucket inspection privileges. It explicitly denies
`DeleteObject`, `DeleteObjectVersion`, `PutObjectRetention` and
`PutObjectLegalHold`. Uploads inherit COMPLIANCE retention from the bucket; explicit retention PUT
headers are forbidden for this identity. Application minimum promises remain
24 hours for originals and 3,650 days for governance metadata. Backend defaults
are 2 days and 3,651 days, respectively, a prototype implementation margin for
the observed whole-second S3 default timestamps.
Consumers must verify the actual exact-version deadline satisfies their minimum.
A second bucket, `audit-governance`, uses COMPLIANCE for 3,651 days for small synthetic policy envelopes/manifests/anchor indexes and event/type/hash/manifest-reference idempotency metadata. This is a prototype implementation setting for policy continuity, not a specific owner retention requirement or a regulatory default. Raw payloads remain in the originals bucket, with a 24-hour application minimum and 2-day backend lock. New governance versions expire 3,651 days after PUT; pre-margin synthetic versions preserve their original 3,650-day expiry and cannot be deleted through S3 before then; changing a default does not shorten existing versions. No production retention advice is implied.

Admin, writer and reader credentials are separate. Management APIs bind only to
loopback; TLS S3 is reachable only from ingest and the operator.

## Observed failure and required correction

The first configuration used an asynchronous ext4 mount, synchronous PostgreSQL
metadata and filer data `fsync=true`. Process SIGKILL checks passed, but an
unclean QEMU stop lost recent volume index entries despite acknowledged writes.
Four recent objects became unreadable; earlier versions remained readable.
The data file contained the recent bytes while the index file was shorter than
the expected persisted entries. DAT, IDX and derived index evidence were
preserved on the encrypted filesystem before offline index reconstruction.
Every saved exact-version hash and retention deadline was recovered after that
repair. Recovery does not establish the acknowledged-write guarantee.

The pinned source explains the observed gap: normal durable write paths call
`DataBackend.Sync()` for DAT; index updates use `WriteAt`, and normal writes do
not call `NeedleMap.Sync()`. See pinned
[volume_write.go](https://github.com/seaweedfs/seaweedfs/blob/4.48/weed/storage/volume_write.go#L293)
and [needle_map.go](https://github.com/seaweedfs/seaweedfs/blob/4.48/weed/storage/needle_map.go#L84).
The required synchronous filesystem makes index writes synchronous as well.
This is a configuration-specific mitigation, whose qualification requires fresh
power-loss tests; ordinary volume data fsync alone is insufficient.

A subsequent power-loss cycle initially returned S3 `InternalError` while the
master had not yet registered volume 1. The journal distinguished unavailable
volume lookup from missing needle bytes. Later all saved exact hashes and
retention deadlines passed without repair. `HEAD Bucket` only proves metadata
availability. Fault tests now use a bounded 180-second known exact-version
read/hash startup gate, recording unavailable attempts and readiness latency;
after that gate opens every fresh object is verified with zero retries. Receipt
operations must fail closed during startup unavailability.

The final hardened crash matrix killed filer/volume and PostgreSQL processes
0.506 and 0.207 seconds after the last protected acknowledgement; exact recovery
completed in 2.281 and 6.967 seconds. Three QEMU stops occurred 1.894, 1.877 and
2.004 seconds after the last protected PUT (fresh original, conditional manifest,
then governance metadata). Full guest/manual-unlock/read recovery took 162.804,
165.126 and 168.204 seconds; post-start exact-read readiness took 14.206, 14.234
and 18.776 seconds. Startup unavailable responses are preserved. No fresh-object
verification retries or index repairs occurred in this matrix.

After that matrix, a default-retention-only adjustment added one backend day
because exact fractional promises were initially undershot by 0.555502 seconds
for originals and 0.750982 seconds for governance. The final defaults, writer and
admin denials, exact-version headers, canonical fractional promise metadata and
actual minimum coverage were requalified in both buckets. Actual margin was
86,399.920224 and 86,399.751148 seconds. Existing retained versions were unchanged.
The storage binary, durability settings, mounts and hardened units were unchanged.
Final backup restoration covers the new defaults and precision-probe versions.

## Qualification matrix

| Check | Observed result |
|---|---|
| Versioning and exact reads | Four versions of one key retained separate exact bytes/hashes. |
| COMPLIANCE retention | Original application minimum 24 hours, backend default 2 days; governance minimum 3,650 days, backend default 3,651 days; admin deletion, shortening and governance bypass denied. Admin delete marker preserved all exact versions. |
| Writer privileges | Delete marker, exact-version deletion and retention administration denied. |
| SSE-KMS | Explicit `aws:kms`/`audit-archive`; stopping independent OpenBao causes encrypted GET to fail, restart/unseal recovers exact bytes. |
| Conditional manifest creation | In both buckets, second `If-None-Match:*` returns 412 without adding a version. Sixteen contenders yield exactly one version. |
| Discarded response | Raw TLS upload response never read; separate exact-version reconciliation recovers matching immutable manifest. |
| 16 MiB admission | Hardened synchronous SSE-KMS PUT: 0.485 seconds (earlier measurement 0.550 seconds); exact SHA256 readback matches. This is one synthetic measurement, not a throughput SLO. |
| Process crash | Fresh data and conditional manifest survive filer/volume SIGKILL and separate PostgreSQL SIGKILL. |
| Guest power loss | Three fresh hardened cycles passed exact hashes/key IDs/COMPLIANCE deadlines in both buckets, including fresh governance metadata. QEMU stops only VM121; hosts/Ceph remain healthy. |
| Encrypted backup restoration | Passed consistent offline AES-256-GCM backup, whole-ciphertext authentication before extraction, actual archive data/config/TLS directory replacement, exact-version read readiness in 12.026 seconds and all 66 saved versions verified. |
| Independent key restoration | Passed independent OpenBao Raft/config/TLS backup and actual replacement; restarted, unsealed with controller shares and decrypted all originals and governance versions through the restored transit key. |

Local evidence records timestamps, object/version IDs, SHA256 values, fault
latencies and restore results. Public configuration capture redacts credentials,
passwords and tokens and records actual service units, encryption settings,
binary hashes, PostgreSQL durability settings and mount options. Qualification
JSON pins hashes of this report and that configuration. A report for any
different configuration cannot authorize this deployment.

The final exact configuration SHA256 is
`3200ee5e273902509a9a66e7ab2922b793b02db43e2e1e83c55fbff0b0c8023b`.
The public object/version/hash/deadline manifest `qualification-objects.json`
contains 54 original and 12 governance versions; its exact SHA256 is
`101da817845fffa1cb498552626d1f6b6526bd37a0d34de1e670a7d841b490d5`.
Restoration verified each manifest entry with zero verification retries,
including the final fractional minimum promises and preserved canonical
metadata. Readiness failures before the bounded control-object gate opened
remain in local evidence.

The authenticated archive ciphertext backup is 54,127,888 bytes, SHA256
`3b4c32dc60f80d4ec25194c23e2c8c5021fa141c9b452267e6341cac0b55d372`;
the independent key ciphertext is 83,481 bytes, SHA256
`38075a34e7d495b807d700af181f36b7eaf0b0aa40f21f63d75a646398c32dd7`.
Ciphertexts and their separate recovery key remain in private controller state.
Original encrypted directories were preserved at
`/srv/veyport/before-restore-959165c12b1f` on the archive guest and
`/srv/veyport/before-restore-3787de0795a9` on the key guest. The restored service
paths are active; these were actual restorations rather than spare-directory
read tests. No retained S3 version was removed.

## Limits and recovery

These tests establish only the tested synthetic lab behavior. They do not certify
regulatory compliance or tolerance of infrastructure administrator compromise,
host/Ceph power loss, whole-site loss, or correlated storage/key loss. Archive
and key services each have one VM within the owner's infrastructure trust
boundary. Qualification covers guest power loss and independent service faults.

Manual LUKS unlock uses controller-only 0600 keys after reboot. Keep OpenBao
recovery shares and the separate authenticated backup key outside both guests.
Start guards prevent writes beneath an unmounted encrypted directory. Backup
and restore scripts authenticate the entire ciphertext before extraction into
the mounted encrypted filesystem, and preserve original encrypted directories.
The transit token has a renewable 168-hour lifetime and requires the private
operator renewal procedure in `../README.md`; it has no self-renewal permission.
An actual restricted-token renewal passed and reported expiry
`2026-10-18T06:20:02.066747098Z`. Daily expiry checks and renewal before fewer than
24 hours remain are required lab maintenance. The storage key cache is disabled;
expired or unavailable key access fails closed.
Do not delete retained evidence to resolve failures. Synthetic originals retain
24 hours minimum, with a 2-day backend default; small governance metadata has a 3,650-day minimum and 3,651-day backend default as the prototype setting; planned ELK search retention is seven days. Paid ELK features are not
part of this archive qualification.

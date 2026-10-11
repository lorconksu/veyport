# Independent audit receipt service

This optional binary implements the protected archive boundary for Enhanced
auditing. Standard does not start it or depend on it. Run with
`veyport-audit-ingest --config /srv/veyport/ingest.json`; `--version` is available
without accessing configuration. Errors omit input, credentials and backend
details. There is no qualification bypass flag.

`auditingest.FileConfig` is the strict configuration schema. Keep the config,
TLS private key, ES256 signing private key and S3 credential file regular,
non-symlink files with owner-only permissions. The storage credential JSON has
only `access_key` and `secret_key`; config contains its path. Signing and storage
encryption keys are separate. The hub receives public receipt keys only.

The archive endpoint must use TLS with a supplied CA and an exact host:port
allowlist. DNS endpoints additionally require explicit resolved address pins.
IP endpoints implicitly pin their allowed address; loopback requires an explicit
pin, and metadata/link-local/multicast addresses are rejected. Clients do not use
proxies or redirects. The same transport is used by the receipt client and S3
SDK.

## Archive qualification and retention

Both archives are mandatory and use distinct buckets:

| Records | Configuration | Client verification |
| --- | --- | --- |
| Execution and original-read events, envelopes and script attachments | `archive_bucket`, `qualification_path`, `qualification_sha256`, `retention_seconds` | `VerifierConfig.QualificationSHA256` |
| All `policy.*` records, latest-policy indices, and global event-id/hash indices | `governance_bucket`, `governance_qualification_path`, `governance_qualification_sha256`, `governance_retention_seconds` | `VerifierConfig.GovernanceQualificationSHA256` |

Each qualification SHA256 pins the **exact bytes of its own report**. Reports
bind endpoint, bucket, archive version, KMS key, actual bucket default retention,
reviewed configuration digest and evidence report digest. Each must explicitly
pass versioning, COMPLIANCE retention, SSE-KMS, exact-version reads, conditional
creation, writer deletion/retention-reduction denial, process-crash and power-loss
durability, encrypted backup restoration and key restoration. Requalify and
review new pins when that configuration changes. A reachable server or successful
HEAD cannot replace the qualification evidence. No periodic report expiry is
invented; future timestamps beyond the allowed skew are rejected.

The isolated synthetic lab promises 24 hours for originals and 3650 days for
small governance records. Its bucket defaults are two days and 3651 days,
respectively, including a storage-only precision margin. These are lab choices,
not production compliance defaults. No command or attachment may enter a `policy.*` envelope. Governance
retention must cover policy reconciliation and latest-policy checks; renew the
policy before its protected anchor expires. Missing, unreadable or expired
authority fails closed.

Retention promises use the precise service acceptance time plus the configured
duration. Every attachment, envelope and manifest has that same exact promised
deadline, serialized with RFC3339Nano precision. JWT validity timestamps use
whole seconds. The writer relies on the bucket's default COMPLIANCE policy and
does not send explicit object-retention headers. If a store truncates retention
timestamps, its qualified default must include enough margin to cover the full
promise; the service never rounds the promise down or grants retention-changing
permissions. Exact-version HEAD/GetRetention and reads must demonstrate the
actual deadline is at least the promised deadline. Canonical references retain
the immutable promised deadline, so a later actual bucket deadline cannot change
the reference during lost-response recovery.

## Credentials and endpoints

Assign each credential exactly one scope; separate credentials cannot share a
token hash or certificate fingerprint. TLS always authenticates the service.
Use mTLS client fingerprints, or enable bearer authentication explicitly and
provide strong bearer-token hashes. There are no presigned/public object URLs.

| Scope | Endpoints | Access |
| --- | --- | --- |
| `ingest` | `POST /v1/records` | Strict JSON or streamed multipart; creates protected records and receipts |
| `admin` | `GET /v1/records/{event}?sha256={exactHash}` | Exact-event evidence lookup; receipt and metadata only |
| `admin` | `GET /v1/anchors/{installation}?nonce={freshNonce}` | Latest retained policy anchor; policy envelope and nonce-bound receipt |
| `admin` | `GET /v1/ready` | Current archive configuration reachability, both qualification pins, and both promised retention durations |
| `read` | `POST /v1/originals` | Exact object version named by a preserved, current original-read intent |

The S3 writer needs conditional PutObject, exact/version GetObject,
GetObjectRetention, ListBucket, GetBucketVersioning and
GetBucketObjectLockConfiguration. Deny DeleteObject, DeleteObjectVersion,
PutObjectRetention and PutObjectLegalHold. Use private encryption/KMS authority
appropriate to the qualified backend. The public receipt API does not expose
these storage credentials.

`auditgate.Client` instances must use separate ingest, admin and read credentials.
`ReceiptEvidence` uses the governance receipt pin; execution `Gate` uses the
originals receipt pin. Set both verifier pins when one verifier handles both
domains. `Client.Anchor` verifies the latest policy envelope and fresh nonce
internally. Initial bootstrap can accept only an authenticated TLS 404 with a
typed `anchor_not_found` body bound to the requested installation and nonce;
other 404, authentication and availability errors fail closed. This is not an
offline signed absence proof and is never sufficient after enrollment.
Readiness is advisory: each command still requires its
own protected receipt and durable dispatch claim.

## Integration boundaries

`auditrecord.ExpectedFor` hashes exact submitted bytes and validates bounded
schema fields. Duplicate fields, unknown fields, case aliases, invalid versions,
oversize data and trailing JSON are rejected. Event ID plus identical bytes is
idempotent; different bytes or event types conflict across both buckets.

`Service.Preserve` archives attachments, envelope, manifest, external event ledger
and any policy anchor index before signing ES256. Writes use conditional creation;
an ambiguous response reconciles the exact retained version without overwriting.
Historical policy/lifecycle/result evidence may receive fresh proof while still
retained. Execution admissions and original-read intents retain their original
expiry and cannot renew an expired preparation or access grant.

`auditgate.Gate.Admit` verifies exact content, actor, node, identity, preparation,
boot, policy, manifest version, retention and expiry before invoking the durable
`Consumer.Claim(executionID, preparationID, receiptSHA256)`. The execution owner
must implement that claim in the dispatch transaction and recheck live authority.
Already admitted processes do not depend on receipt availability thereafter.

Original reads additionally require the hub's fresh MFA, permission rechecks and
one-use handle; the service verifies the preserved intent, exact object reference,
receipt and at-most-60-second intent age with bounded future skew. Admin lookups
never return raw execution originals. The hub owns policy approval/quorum
validation and redacted projections; this service archives their exact evidence.

Envelopes are bounded to 128 KiB, commands to 32 KiB UTF-8, and attachment totals
to 16 MiB with at most four attachments. The hub streams scripts with at most
32 KiB reads and no request replay. The ingestor admits at most four requests;
its bounded live attachment arrays are at most 192 MiB across those requests,
within a 256 MiB application budget. Archive operations have a ten-second
deadline. Latest-anchor listing is bounded to 16,000 keys and fails closed beyond
that limit.

AWS SDK for Go v2 supplies maintained SigV4 and S3 protocol handling under the
[Apache 2.0 license](https://github.com/aws/aws-sdk-go-v2/blob/main/LICENSE.txt).
SDK retries are limited to one attempt; application reconciliation handles lost
responses. See official documentation on
[retries/timeouts](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-retries-timeouts.html),
[conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html),
and [Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html).

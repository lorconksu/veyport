# Protected audit runtime

`veyport-hub --audit-runtime-config /private/receipt-runtime.json
--execution-spool-dir /encrypted/hub-input` connects the governance and execution
paths to independently qualified receipt services. Both options are absent by
default; Standard remains standalone. Enhanced activation requires live archive
qualification, a successful explicit write test, the actual SSH listener, a
service-owned encrypted hub spool, and protected capabilities from every node
covered by actor or node scope.

The JSON configuration's top-level endpoint is the **fixed governance
authority**. Its separate ingest and admin mTLS credentials preserve policy
evidence and authenticate latest anchors. Changing an approved execution
destination never changes this authority or its trust; database restoration does
not reset it. Optional `destinations` entries allow additional execution archives.
Each entry uses the same public trust and admin credential fields. The operator
must retain old destination trust and immutable credential references for
completion and historical evidence continuity.

The exact configuration fields are defined by `FileConfig` and `EndpointConfig`
in `config.go`. They include the HTTPS endpoint, explicit allowed addresses for
DNS names, issuer, audience, public ES256 key paths, private CA path, distinct
originals and governance qualification SHA256 pins, and mTLS certificate/key
paths. The fixed authority requires `clients.hub-ingest` and `clients.hub-admin`
to be different certificates. `clients.hub-original-reader` and
`clients.redactor-index` are recognized for compatibility but are not loaded or
used by this runtime. No archive writer, KMS credential, or receipt signing
private key belongs in the hub.

All referenced files must be regular, service-owned, mode 0600 files without
symlinks. File sizes and destination counts are bounded. Trust and fixed service
credentials are loaded once at startup. HTTPS transport pins the endpoint and
allowed addresses, validates the private CA, and refuses redirects and proxies.
Changes to operator configuration require a restart and review of governance
continuity; an empty replacement authority cannot authorize re-enrollment.

Execution ingestion credentials are encrypted, immutable references created
through `POST /api/security/secrets`. With `kind: "destination"`, `value` contains
an exact JSON string of either `{"bearer":"..."}` (32–512 bytes) or
`{"certificate_pem":"...","private_key_pem":"..."}`. Mixed credentials are
rejected. The API limits the secret value to 8192 bytes and returns only the new
reference; no read API exposes its value. A policy pins that reference, exact
destination, signing key IDs, qualification hash, and required originals
retention. `ResolveArchive` checks the exact stored policy version and digest
without borrowing credentials or trust from a newer policy.

`GET /api/audit-policy` performs bounded, read-only service and transport checks.
Its `readiness.governance` checks the independently qualified fixed authority and
validates latest-anchor continuity without mutating policy state.
`readiness.archive_and_transport` checks the active Enhanced destination and live
execution transport; it is false when Enhanced does not apply.
`readiness.enrollment_marker` means an existing private marker matching the
installation and active or known pending policy, never merely a configured path.
It is false before enrollment; `governance_enrolled: false` indicates that the
marker does not yet apply. Governance and transport probes run independently in
one bounded context. A failed GET writes no records and changes no policy state.
`POST /api/audit-policy/test` and Enhanced activation perform an explicit bounded
write test. The probe is a synthetic completed lifecycle event with state
`synthetic-readiness-no-process`; it contains no command or attachment, grants
no execution permit, represents no human approval, and launches no process.
Every actual protected execution still needs its own verified admission receipt.

Governance records require 3650 days of retention; submitted originals require at
least the approved policy retention (24 hours minimum). These are separately
qualified archives and trust pins. Their actual backend lifetime is reported by
the independent service and verified in signed evidence. The lab's long
governance retention is a prototype setting, not a certification or regulatory
default. A former originals outage cannot redirect or invalidate fixed
governance lookup; a governance outage prevents policy changes and recovery.

Behavior tests use synthetic identities and an independent in-process TLS/mTLS
receipt service with a real ES256 signer. They cover read-only polling, explicit
qualification, actor/node scope, strict configuration, secret references,
three-person HTTP MFA approval, protected recovery, destination changes,
unconfirmed writes, authenticated latest-anchor failures, and recovery after
originals expire. These fixtures are test evidence, never staging approvals or
archive qualification reports.

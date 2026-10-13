# Qualified archive search projection lab

Elasticsearch, Kibana and Logstash use official native **9.5.5** Debian packages.
The deployment verifies their official SHA-512 files on the controller and guest;
`deployment-lock.json` records the immutable artifact pins. The lab uses the
Basic license, confirmed through the authenticated Elasticsearch license API.

Elasticsearch listens only on `127.0.0.1:9200` with TLS. Kibana serves TLS on
`10.10.1.61:5601`, restricted by the existing firewall to the operator. The TLS
HTTP Logstash input on `10.10.1.61:5044` accepts only the receipt VM and requires
a certificate issued by a dedicated exporter CA. Receipt client certificates
cannot authenticate to this input. Elasticsearch identities separate projection
ingest, read-only search and search-index administration. The ingest role cannot
search; the search role cannot delete indices. All service data, configuration,
credentials, persistent queues, temporary files and logs are on the mounted LUKS
service volume. Service startup checks the exact encrypted mount. Core dumps and
JVM heap dumps are disabled. Native packages remain on the guest system volume.

The independent `veyport-redactor` OS identity on the receipt VM reads exact
immutable manifest/envelope versions with a read-only S3 credential. Its separate
`export-index` mTLS identity can enumerate only a bounded page of event ledger
references. It cannot issue receipts, inspect administrative readiness or use the
original-access API. Writer credentials and the signing private key belong to
the receipt identity. No archive configuration or qualification pin changes are
needed for export. Both original and governance buckets are projected.

`schema_version: 1` and `redaction_rule_version:
structured-omit-arguments-v1` identify the projection contract. Explicit fields
contain event/actor/person/node/run-as IDs and snapshots, policy/digests,
command/script byte counts and hashes, manifest version/digest, correlation,
process state and archived evidence state. UID/GID are absent when an execution
identity was never prepared; an actual root identity retains UID/GID zero.

Command summaries expose only a fixed executable vocabulary and the text
`[arguments redacted]`. Unknown executables, shell assignment prefixes and
multiline submissions receive an omitted-command summary. Arguments, environment
values, quoted strings, credentials in URLs/headers, raw scripts, operator reasons,
approval payloads/proofs, sessions and HTTP metadata do not reach search. Script
attachments are never read by the exporter. The Logstash filter applies a second
explicit field allowlist and validates the summary vocabulary. This conservative
rule cannot identify secrets deliberately put in actor/node names or stable IDs;
operators must treat those identity fields as searchable metadata. Redaction is
not a universal secret detector, and search still requires access controls.

The worker processes at most eight references per step, one envelope at a time,
under a fifteen-second deadline. Failures retry with two-to-128-second exponential
backoff. A mode-0600 checkpoint on the encrypted volume records the current
bounded cursor, accepted/skipped attempts, last accepted time, last complete scan,
failure category, retry time and pending occurrence time. Accepted counts include
idempotent replays. Inspect it through the privileged service operator, together
with `systemctl status veyport-audit-export`; do not expose its containing private
configuration directory. A growing pending age or a stale complete scan shows
lag. No raw payload queue exists in the hub or redactor.

Logstash has a bounded 256 MiB encrypted persistent queue. Its HTTP acknowledgment
means input acceptance, not successful Elasticsearch indexing or protected
archive admission. The worker resets the cursor after every complete scan and
replays stable event document IDs. This recovers output failures and deleted
search indices without writing to or deleting archive objects. The worker skips
expired archive references and source events older than seven days. The index
template assigns the seven-day ILM delete policy; ILM evaluates index age from
creation, and deletion follows its normal polling interval. The investigation
dashboard also selects the last seven days. Archive retention remains separately
qualified at a minimum 24 hours for originals and 3650 days for governance.

Replay requires the exact manifest and envelope to remain retained and readable.
The prototype's backend original default is two days, shorter than seven-day
search retention. This worker conservatively stops replaying an original when
its receipt's promised `retain_until` has passed (currently 24 hours), even if the
backend still holds that version. Already indexed metadata can remain searchable
for seven days. A deleted index cannot be fully reconstructed for expired
originals; a ten-year event ledger preserves references and digests without
retaining raw execution bytes for that duration. Governance replay uses its
separately qualified long retention. Increasing original retention or changing
replay guarantees requires an approved retention/storage change.

Build the optional worker and receipt binaries from the reviewed feature source,
then run the controller deployment scripts in `receipt/` and `elk/deploy.py` with
the private lab state available. `import-dashboard.py` imports and verifies four
saved objects. Open `/app/dashboards#/view/veyport-investigation` in the TLS Kibana
instance with a search identity. `detections.json` provides reviewed query
examples for refused execution, prepared root identities, uncertain outcomes and
protected original-read activity. They are examples, not enabled notifications.

Run `tests/projection.py` for the actual two-bucket TLS archive/index/outage matrix.
It preserves synthetic admission, lifecycle and policy-result records, verifies
indexed canary absence, replays into a disposable empty index, deletes/recreates
that index, and verifies exact originals still match afterward. It stops only
Logstash, verifies visible exporter failure/lag and independent receipt admission,
then restarts Logstash in a `finally` block and verifies recovery. It never
dispatches a remote process or represents fixture identities as real approval
quorum. `projection-qualification.json` contains the sanitized result. Integration
owners separately verify real command admission and protected original-read audit
ordering; the exporter does not grant original access.

Basic supports the TLS/native-role/query/ILM features used here. Elasticsearch and
Kibana security audit logging require a qualifying paid subscription and are not
enabled by this lab. Machine-learning detections, field/document security,
external notification connectors and Watcher have separate subscription limits;
these examples do not claim those features. Check the current [subscription
matrix](https://www.elastic.co/subscriptions) and [Stack audit logging
guide](https://www.elastic.co/docs/deploy-manage/monitor/stack-audit-logging) before
turning on licensed features. The prototype has one ELK guest and a shared
hypervisor administrator trust boundary; it is not a regulatory certification.

Official operational references: [Debian Elasticsearch
installation](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-with-debian-package),
[Logstash installation](https://www.elastic.co/docs/reference/logstash/installing-logstash),
[TLS HTTP input](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http),
[persistent queues](https://www.elastic.co/docs/reference/logstash/persistent-queues).

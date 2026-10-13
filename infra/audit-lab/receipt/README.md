# Independent receipt and privileged redactor deployment

The native receipt service runs on the authorized `audit-ingest-lab` guest as
`veyport-receipt`, with its independent ES256 signing key outside the hub. The
hub receives only public signing trust and scoped client credential references.
The live TLS endpoint and issuer are `https://10.10.1.60:8443`; the audience is
`veyport-audit-lab` and signing key ID is `lab-receipt-20261011`.

Separate mTLS identities authorize `ingest`, `admin`, `original-read` and
`export-index`. Bearer authentication is disabled. Administrative readiness checks
both archives and publishes the exact separate qualification pins and promised
retention. Ingest can preserve records but cannot read originals or administer
the service. Original readers must submit a preserved current original-read
intent through the controlled original API. The exporter identity can enumerate
only event ledger references, at most 32 per API call; its worker requests eight.
It cannot supply an arbitrary prefix or enumerate raw envelope/attachment keys.

Receipt configuration, credentials and keys remain mode 0600 under a private
encrypted service directory. The dedicated receipt identity uses the archive
writer credential and has no search-index credential. The distinct
`veyport-redactor` identity uses the preexisting two-bucket archive reader,
separate scoped index certificate and an ingest-only Logstash client certificate.
It cannot access receipt signing or writer files. Its checkpoint is protected
metadata on the encrypted spool. Private controller state stays outside this
repository; deployment scripts transmit it through explicit guest SSH stdin and
never print it. No default Docker context is used.

Both services refuse to start without the exact mounted LUKS service volume, run
without Linux capabilities, disable swap/core dumps and restrict writable paths
to their bounded spools. An encrypted volume requires the operator's existing
manual unlock procedure after reboot. The service has no automatic fallback to
unqualified archives. Deployment never mutates the qualified archive/key guests.

`deploy.py` installs the receipt binary built from the reviewed source and records
the runtime references privately for hub integration. `deploy-exporter.py` installs
the independently built optional worker after ELK TLS configuration is ready.
These local prototype binaries are not published release artifacts. Rebuild and
redeploy them from the final tested feature revision before delivery. The
[ELK runbook](../elk/README.md) describes projection limits, lag, replay, role
separation and the actual sanitized qualification evidence.

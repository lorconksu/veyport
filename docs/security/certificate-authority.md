# Certificate-authority storage and startup

The Hub's stored certificate authority is its enrollment trust identity. A
database error must not be interpreted as permission to replace that identity.

Initialization reads the certificate and private key in one SQLite transaction.
Only two absent configuration rows permit initial generation. Existing empty
values, an incomplete pair, database read errors, malformed data, an incorrect
storage secret, a mismatched key, or a certificate that cannot sign certificates
stop initialization. The stored certificate must have valid CA basic constraints
and the certificate-signing key usage.

Initial generation saves the certificate and encrypted private key together.
A failed write or commit leaves neither half of a new identity persisted.
Concurrent initializers cannot successfully return different stored identities;
a conflicting SQLite transaction may fail, and a retry loads the committed
identity. This is not automatic CA rotation.

Legacy plaintext private keys remain readable for migration, but startup succeeds
only after encryption and persistence complete in the same transaction. A failed
migration preserves the previous stored bytes and returns an error. Certificate
and encrypted-key storage formats remain unchanged.

If startup reports an incomplete or invalid identity, restore the matching
certificate, key, and storage secret from a verified backup, and investigate the
storage error. Deleting the rows to force regeneration replaces the enrollment
trust root and is not a recovery procedure. This change introduces no new expiry,
renewal, or rotation policy.

## Verification and limits

Regression tests reproduce failed-read replacement of an existing root,
unacknowledged legacy migration failure, partial initial persistence, invalid
pairs, and concurrent initialization before verifying the corrected behavior.
Tests also exercise actual entropy-reader errors without replacing cryptographic
algorithms. Password and encryption boundaries remain independently tested.

The normal CA test profile measures 133 of 137 statements. The four remaining
defensive guards handle marshaling a valid internally generated P-256 key and
parsing certificate DER immediately after successful standard-library encoding.
Their input invariants were reviewed against the Go implementation; the guards
remain in place and remain visible in coverage. They are not excluded to claim
100% coverage.

Encryption's normal and separately instrumented FIPS-only tests cover different
runtime paths. The FIPS-only test verifies that the current caller-managed GCM
nonce construction is rejected by that restricted runtime. CI merges both real
coverage profiles. This does not establish application FIPS compatibility or a
validated cryptographic module deployment.

## Documentation location

The local constitution still references `docs-internal/engineering/security-model.md`,
which is absent from this checkout. This tracked document records the certificate
authority security invariants for this change and is linked from the architecture
wiki; no update to an unavailable internal document is claimed.

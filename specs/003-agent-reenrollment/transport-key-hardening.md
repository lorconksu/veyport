# Transport-Key Hardening — KEK Release Encrypted to the Node (design + plan)

Closes the "KEK released before proof" residual by encrypting the KEK release so
that **only the real node** (holder of its X25519 transport private key) can read
it. A bare-serverID attacker who gets a bogus request human-approved receives a
ciphertext they cannot decrypt — no KEK harvest. (A disk-clone still has the
transport key; that path remains human-gated by design, unchanged.)

Added on branch `003-agent-reenrollment` (part of PR #55, not yet merged).

## Sealed-box construction — "veyport-kek-transport-v1" (BOTH sides implement identically)

Node holds an **X25519 transport keypair** `(tPriv, tPub)`, generated at enrollment,
stored **UNSEALED** on the node (it must be usable without the KEK). `tPub` is
registered with the hub at enrollment.

**Hub seals `kek` (32 bytes) for `tPub`:**
1. Generate ephemeral X25519 keypair `(ePriv, ePub)` via `crypto/ecdh` `X25519()`.
2. `shared = ECDH(ePriv, tPub)` (32 bytes).
3. `key = HKDF-SHA256(ikm=shared, salt=nil, info="veyport-kek-transport-v1" || ePub || tPub, len=32)`.
   (Use stdlib `crypto/hkdf` — Go 1.24+. If the module's Go version lacks it, inline HKDF-Extract/Expand with `crypto/hmac`+`crypto/sha256`; do NOT add a new module dependency.)
4. `nonce = 12 random bytes` (crypto/rand).
5. `ct = AES-256-GCM(key).Seal(nonce, kek)` → the standard nonce-prepended form: `sealed = nonce || ciphertext||tag`.
6. Output: `ephemeralPub = ePub` (32 bytes, `ePub.Bytes()`), `encryptedKek = sealed`.

**Agent opens (`tPriv`, `ePub`, `encryptedKek`) → `kek`:**
1. `shared = ECDH(tPriv, ePub)`.
2. `key = HKDF-SHA256(shared, nil, "veyport-kek-transport-v1" || ePub || tPub)` — the agent knows its own `tPub`.
3. `nonce = encryptedKek[:12]`, `ct = encryptedKek[12:]`; `kek = AES-256-GCM(key).Open(nonce, ct)`.

Interop is proven by the e2e integration test (hub module imports `agent/internal/nodekey`): the hub seals, the agent-side opens, round-trips the KEK.

## Wire / storage changes
- Proto `RegisterAgent`: add `bytes node_transport_pubkey = <next>`.
- Proto `ReEnrollApproved`: currently `{ bytes kek, bytes challenge }`. Change to `{ bytes ephemeral_pub = 1, bytes encrypted_kek = 2, bytes challenge = 3 }` (remove the raw `kek` field — feature unmerged, safe to change). Regenerate.
- Store: `servers.node_transport_pubkey TEXT` (base64), migration `020_node_transport_pubkey.sql`. Extend `SetNodeCrypto`/`GetNodeCrypto` (or add `SetNodeTransportPub`/read it in `GetNodeCrypto`) to carry it.
- Enrollment stays raw-KEK-over-TLS in `RegisterAck` (authenticated by the registration token) — only the RE-ENROLL release is transport-encrypted.

## Tasks (TDD, reviewed, same rigor as the rest of the feature)

### H1 — proto + store + migration
- `RegisterAgent.node_transport_pubkey`; `ReEnrollApproved{ephemeral_pub, encrypted_kek, challenge}`; `make proto` (PATH incl. /home/wyiu/go/bin).
- Migration `020_node_transport_pubkey.sql` (additive TEXT column); bump the migration-count test.
- Store method(s) to set/get `node_transport_pubkey`. TDD round-trip.

### H2 — sealed-box crypto (both sides) + interop
- Agent `nodekey`: `GenerateTransport() (x25519Priv, pubB64/bytes)`; `SealTransportPriv`? NO — transport priv stored unsealed; add persistence helpers or let the client store it; `OpenKEK(tPriv, ephemeralPub, encryptedKek) ([]byte, error)` implementing the construction.
- Hub (new `grpcserver/kektransport.go`): `sealKEKToNode(tPubBytes, kek []byte) (ephemeralPub, encryptedKek []byte, err error)`.
- TDD each side. Add an **interop test** (in the hub integration package, which can import `agent/internal/nodekey`): seal with hub, open with agent nodekey, assert KEK round-trips; wrong transport key fails.

### H3 — wiring + e2e
- Agent: `sendRegister` generates+persists the transport keypair (e.g. `<certDir>/node_transport.key`, 0600, unsealed) and sends `node_transport_pubkey`; `New` loads it; `handleReEnrollApproved` now takes `{ephemeral_pub, encrypted_kek, challenge}` → `nodekey.OpenKEK` → open identity key → sign.
- Hub: store `node_transport_pubkey` at enrollment (T4 path); the approval send (`handleReEnrollRequest`'s approve branch / `ReleaseKEK`) now `sealKEKToNode(storedTransportPub, kek)` and sends `ReEnrollApproved{ephemeral_pub, encrypted_kek, challenge}`.
- Update the e2e `integration/reenroll_test.go`: the simulated agent generates a transport keypair, registers its pub, and decrypts the KEK via `nodekey.OpenKEK` before signing. Keep happy + deny green (twice).
- Backward-compat: if a node has no stored transport pubkey (old enrollment), fall back to raw-KEK release OR require re-register — document which. (Prefer: if `node_transport_pubkey` empty, the hub denies re-enroll with a clear "re-register to enable" — safer than a silent raw fallback that reopens the hole.)

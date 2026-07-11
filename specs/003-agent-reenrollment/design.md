# Design: Agent Certificate Lifecycle & Human-Approved Re-Enrollment

| Field | Value |
|-------|-------|
| **Feature** | 003-agent-reenrollment |
| **Status** | Draft (brainstorming output — pending review) |
| **Date** | 2026-07-11 |
| **Author** | William Yiu (with Claude) |
| **Depends on** | Existing agent mTLS + CA (`hub/internal/ca`), gRPC agent stream (`hub/internal/grpcserver`), TOTP auth (`hub/internal/server/handlers_auth.go`) |

## 1. Problem

Managed nodes silently go **offline and cannot recover** without a manual
`unregister` + `re-register`. This was triggered in production by a power event
(2026-07-03): when the hub restarted, every agent's long-lived gRPC stream
dropped, and on reconnect the hub rejected the agents.

### Root cause (confirmed on the live node)

| Observation | Evidence |
|-------------|----------|
| Agent mTLS **client cert lives ~12 hours** | `/etc/veyport/tls/client.crt`: `notBefore May 27 23:02`, `notAfter May 28 11:02` (issued via `ca.SignCSR(..., validity)`) |
| Agent stayed "online" for **weeks** on an expired cert | An established TLS/gRPC stream is not re-validated mid-session; the cert only matters at handshake |
| A forced reconnect (hub restart) presents the **expired cert** → hub rejects | Agent log, every 60s: `remote error: tls: expired certificate` |
| **Renewal exists but drifts** | `certRenewalThreshold = 6h`, `startCertRenewalTicker` → `CertRenewRequest`; hub `handleCertRenewal` re-issues; agent stores it but logs *"will use on next reconnect"* and **never proactively reconnects to adopt it** |
| **No cold-start recovery** | Renewing requires an already-authenticated stream (valid cert). Once the cert is expired, the agent cannot renew — chicken-and-egg |
| Manual recovery is the **only** path | `resolveConfig`: while `agent.conf` exists, the agent reuses its serverID and *ignores any bootstrap token* — it only attempts mTLS reconnect, never re-bootstrap. Recovery = delete config + register with a fresh token → **new serverID + ghost record** |

### Why this matters

- **Reliability:** any outage longer than the cert lifetime (or any silent
  renewal gap) permanently strands a node.
- **Operational cost:** recovery requires on-box access and re-registration —
  which defeats the product's purpose (brokered, audited access *without*
  handing out direct server logins) and orphans the node's history/assignments.

## 2. Goals & Non-Goals

### Goals

1. A node whose cert has expired **recovers without manual re-registration**,
   preserving its **existing serverID** (no ghost records, history intact).
2. Recovery is **human-gated**: an admin explicitly approves a returning node
   from the dashboard — never by touching the box.
3. The approval carries a **verifiable identity signal** ("who is re-enrolling")
   so approval is informed, not blind.
4. Steady-state renewal **never drifts** — a continuously-connected node keeps a
   fresh cert without human involvement.
5. **No new per-node secret to memorize** — reuse the admin's existing TOTP.

### Non-Goals (explicitly out of scope)

| Out of scope | Rationale |
|--------------|-----------|
| Defending a node against a **compromised hypervisor** (Proxmox host/storage) | The hypervisor sits below the guest's security boundary; host access = game over. Mitigated by **hardening Proxmox** as a separate ops track, not by app crypto. |
| Defending against a **compromised hub** | The hub is the CA and root of trust; its compromise is total regardless of this design. |
| **vTPM / PAKE / physical TPM** binding | Over-engineering for this threat model (a virtual TPM's state file is itself clonable via a Proxmox full-clone/backup; a compromised host beats it anyway). Deferred as optional future hardening. |
| Defending a **live-rooted** node abusing its own key in place | Hardware/crypto can't stop it; the human-approval + anomaly signals are the backstop. |

## 3. Design Overview — Two Tiers

The fix splits by risk: automate the safe path, put a human on the risky one.

| Tier | When | Human? | Mechanism |
|------|------|--------|-----------|
| **1 — Steady-state renewal** | Cert still valid | **No** | Agent renews over its authenticated stream **and adopts the new cert on the live connection** (fixes today's drift) |
| **2 — Re-enrollment** | Cert expired / identity lost | **Yes** | Agent phones home → **Pending** in dashboard → admin **TOTP-approves** → hub **releases the KEK** → same serverID gets a fresh cert |

### 3.1 Identity & anti-clone model

Three orthogonal concerns, each with a dashboard-side control:

| Concern | Stops | Mechanism |
|---------|-------|-----------|
| Authenticate the **approver** | a request self-approving | Admin **TOTP** step-up on the approval action (reuses existing TOTP) |
| Prove the **node's continuity** | an attacker on *another* host | **Durable node keypair** (separate from the 12h cert; survives expiry); hub verifies the re-enroll signature against the pubkey stored at enrollment |
| Resist **clones / stolen copies** | a copied disk/backup/snapshot rejoining silently | Node's durable private key is **encrypted at rest under a hub-held KEK**. The KEK is *not on the node*; it is released only after a human TOTP approval → a clone cannot self-unlock |

**Verify-to-release, not decrypt-with.** A TOTP *code* is ephemeral (30s) and
low-entropy (~20 bits), so it cannot itself be an encryption key. Instead, the
random high-entropy **KEK lives on the hub**; a valid **TOTP approval** triggers
the hub to *release* the KEK to the node so it can decrypt its durable key. This
gives the "one authenticator unlocks it, no per-node passphrase" ergonomics the
owner wanted, while keeping the unlock secret off the node (so clones are inert).

**Clone detection (defense in depth, cheap):** the agent reports a soft VM
fingerprint (`/sys/class/dmi/id/product_uuid` on Proxmox, which changes on a
naive clone) at enrollment. A re-enrollment whose fingerprint differs, or that
arrives while the original is still heartbeating, is **flagged** in the approval
screen ("possible clone — original last seen 2 min ago"). Detection, not
prevention — prevention against a perfect copy is impossible without a secret
off the box, which the KEK+TOTP already provides.

## 4. Data Flow

### 4.1 Tier 1 — steady-state renewal (fix the drift)

```mermaid
sequenceDiagram
    participant A as Agent
    participant H as Hub
    Note over A: cert has < 6h left (still valid)
    A->>H: CertRenewRequest (CSR) over authenticated stream
    H->>H: SignCSR (same serverID)
    H-->>A: CertRenewResponse (new cert)
    A->>A: store new cert
    A->>A: NEW: reload the live connection's client cert<br/>(hot-swap or graceful reconnect) — no drift
    Note over A,H: connection now uses the fresh cert; no human involved
```

### 4.2 Tier 2 — human-approved re-enrollment (expired cert)

```mermaid
sequenceDiagram
    participant A as Agent
    participant H as Hub
    participant D as Dashboard (Admin)
    Note over A: cert expired; mTLS reconnect rejected
    A->>H: ReEnrollRequest over CA-pinned bootstrap TLS<br/>(serverID, node-key ref, DMI fingerprint, new CSR)
    H->>H: park PENDING re-enrollment; compute anomaly flags
    D->>H: admin opens dashboard, sees Pending node<br/>(hostname, IP, fingerprint delta, "original last seen…")
    D->>H: Approve + TOTP code
    H->>H: verify TOTP (step-up)
    H-->>A: release KEK (over CA-pinned channel) + challenge
    A->>A: decrypt durable key with KEK; sign challenge + CSR; wipe secrets
    A->>H: signed proof + CSR
    H->>H: verify signature vs stored node pubkey; SignCSR (same serverID)
    H-->>A: fresh mTLS cert
    Note over A,H: node reconnects with mTLS, same serverID, history intact
```

## 5. Components

### 5.1 Agent (`agent/internal/client`)

| Change | Detail |
|--------|--------|
| **Adopt renewed cert live** | After `handleCertRenewResponse`, proactively reload the live gRPC connection's client cert (hot-swap `tls.Config`'s `GetClientCertificate`, or a controlled reconnect). Removes the "only on next reconnect" drift. |
| **Durable node keypair** | Generate at enrollment; store private key **encrypted under the hub-issued KEK**; discard KEK. Store public key ref. |
| **Re-enroll on expiry** | When the cert is expired/rejected (or `NeedsRenewal` but no valid stream), stop looping on `errReconnectWithMTLS`/registration failures and instead initiate a `ReEnrollRequest` over the CA-pinned bootstrap channel. Wait (pending) with backoff; do **not** self-terminate. |
| **KEK handling** | On approval, receive KEK, decrypt durable key in memory only, sign challenge + CSR, zeroize KEK and key material. |
| **Fingerprint** | Read `/sys/class/dmi/id/product_uuid` (root; agent runs as root) and include in enrollment + re-enroll. |
| **Fix self-terminate** | The 3-strike "server unregistered — exiting" path must not fire for expired-cert/pending-approval states (those are recoverable, not unregistered). |

### 5.2 Hub (`hub/internal/grpcserver`, `hub/internal/server`, `hub/internal/ca`)

| Change | Detail |
|--------|--------|
| **KEK issuance & storage** | On enrollment, generate a random 256-bit KEK, store it at rest (encrypted under the existing `storage_key`, like other secrets) keyed by serverID; return it once to the agent. |
| **Re-enroll intake** | New RPC/message: accept `ReEnrollRequest` over bootstrap TLS; create a **pending** record; compute anomaly flags (fingerprint delta, original-online, geo/IP change). |
| **Approval endpoint** | `POST /api/servers/{id}/reenroll/approve` (adminOnly + **TOTP step-up**); on success, release KEK + challenge to the waiting agent, verify the signed proof against the stored node pubkey, then `SignCSR` for the **same serverID**. |
| **Deny / expire** | Deny endpoint (flag as suspicious → audit); pending requests expire after N minutes. |
| **Cert lifetime knob** | Make `validity` configurable (default reviewed; 12h is aggressive with no safety margin — candidate for a few days, still short-lived, with renewal). |
| **Audit** | New audit events: `agent.reenroll_requested`, `agent.reenroll_approved`, `agent.reenroll_denied`, `agent.clone_suspected`. |

### 5.3 Dashboard (`web/`)

- A **Pending re-enrollment** surface (badge on the node / a review queue):
  hostname, IP, last-seen, **fingerprint delta**, anomaly banner, Approve/Deny.
- Approve action prompts for a **TOTP code** (step-up).

### 5.4 Data model

| Store change | Purpose |
|--------------|---------|
| `servers.node_pubkey` | durable node public key (continuity verification) |
| `servers.node_kek_enc` | KEK, encrypted under `storage_key` |
| `servers.enroll_fingerprint` | DMI UUID captured at enrollment (clone detection) |
| `reenroll_requests` (new) | pending requests: serverID, requested_at, IP, fingerprint, status, challenge |

## 6. Error Handling & Edge Cases

| Case | Behavior |
|------|----------|
| Node offline **longer than cert life** (long outage) | Falls into Tier 2 re-enrollment on return — the intended path, not a failure |
| Renewal request fails while connected | Retry (existing in-flight/timeout logic); if the cert then expires, degrade to Tier 2 |
| **KEK release fails / channel drops** mid-approval | Re-enroll request stays pending; agent retries; approval is idempotent |
| **Wrong TOTP** on approval | Reject, audit, no KEK release; request stays pending |
| **Clone suspected** (fingerprint delta / original online) | Surface prominently; admin may Deny; Deny audits as `clone_suspected` |
| **Hub restart** mid-flow | Pending requests persisted; agents retry over bootstrap TLS |
| **Existing fleet (migration)** | Nodes without a durable key/KEK yet: issue them on next *successful* renewal while still authenticated (opportunistic enrollment of the new material), so they gain re-enroll capability before their next expiry. Document a one-time re-register for already-stranded nodes. |
| Agent self-terminate loop | Removed for recoverable states (see 5.1) |

## 7. Migration / Compatibility

- **Backward compatible:** agents/hubs without the new material keep using the
  existing renew/reconnect path; new material is issued opportunistically.
- **Already-stranded nodes** (e.g., the current bastion node): recovered via the
  existing manual re-register once; thereafter they carry the durable key + KEK.
- **Cert lifetime change** is independent and can ship first as a quick safety
  margin improvement.

## 8. Testing

| Layer | Tests |
|-------|-------|
| Agent unit | renewal adopts cert live (no drift); re-enroll triggered on expiry; KEK decrypt→sign→zeroize; fingerprint read |
| Hub unit | KEK issue/store/release; TOTP-gated approval; signature verification vs stored pubkey; anomaly-flag computation; pending expiry |
| Integration | full Tier-2 flow (expire → phone home → approve+TOTP → fresh cert, same serverID); deny path; clone-detection flag; hub-restart-mid-flow |
| Regression | steady-state renewal over a long-lived connection keeps a fresh live cert across the old drift window |

## 9. Parallel Track (not this feature)

**Harden Proxmox** — the highest-leverage control for the clone/host threat
(restrict host & storage access, protect backups/snapshots, MFA on Proxmox,
network isolation of the management plane). Tracked separately; this design
assumes the hypervisor is trusted.

## 10. Open Questions / Deferred

- Cert lifetime target (keep 12h + renewal, or lengthen to a few days for margin?).
- One admin TOTP for all nodes vs. optional per-node step-up for sensitive nodes.
- Whether to add the DMI fingerprint to the KDF (weak binding) or use it purely
  as a detection signal (leaning: detection only).
- vTPM / PAKE as a future hardening tier (explicitly deferred).

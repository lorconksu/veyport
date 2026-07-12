# Human-Approved Re-Enrollment (Tier 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When an agent's cert is expired, let the node **re-enroll itself** — preserving its serverID — gated by a human admin who approves from the dashboard with a **TOTP step-up**, with a **hub-held KEK** so a cloned disk can't silently rejoin.

**Architecture:** At enrollment the agent generates a durable Ed25519 **node key**; the hub issues a random **KEK**, the agent encrypts its node private key under the KEK and discards the KEK (hub keeps it). On expiry the agent phones home over the CA-pinned bootstrap stream with a `ReEnrollRequest`; the hub parks it **pending** with clone-anomaly flags. An admin approves via `POST /api/servers/{id}/reenroll/approve` (admin-role + per-admin TOTP); the hub releases the KEK + a challenge; the agent decrypts its node key, signs the challenge, the hub verifies against the stored node pubkey and re-issues a cert for the **same serverID**. Builds on Plan 1's `reconnectCh` (adopt the fresh cert live).

**Tech Stack:** Go (agent `internal/client`, new `internal/nodekey`; hub `internal/grpcserver`, `internal/server`, `internal/store`, `internal/auth`, `internal/ca`); protobuf (`make proto`); React + TypeScript + vitest (`web/`); SQLite `_config`/`servers` schema in `hub/internal/store/store.go`.

## Global Constraints

- Go toolchain: existing (`hub/go.mod`, `agent/go.mod`) — do not bump. No new Go deps beyond stdlib `crypto/ed25519`.
- **Depends on Plan 1** (merged): reuse `Client.reconnectCh` to adopt the re-issued cert; reuse `h.clientCertValidity()` for the re-issued cert lifetime.
- Crypto: KEK = 32 random bytes. **At rest on the hub**, store `auth.Encrypt(kek, auth.DeriveKey(storageKey))` hex-encoded. **On the node**, the durable Ed25519 private key is stored AES-256-GCM-encrypted under the KEK (new `agent/internal/nodekey`), and the KEK is never persisted on the node.
- Agent must **never import hub packages** (separate modules) — agent gets its own AES-GCM helper in `agent/internal/nodekey`.
- Backward compatible: nodes without node-key material fall back to today's manual re-register; hubs issue material opportunistically (Task 4 note). No behavior change until both sides updated.
- TOTP step-up reuses `auth.ValidateTOTPWithReplay(s.totpCache, adminID, secret, code)` and is **audited to the approving admin** (design §3.2). LDAP terminal users are not admins → excluded by `s.adminOnly`.
- Proto regen: after editing `proto/veyport/v1/agent.proto`, run `make proto` and commit the generated `*.pb.go` alongside.

---

### Task 1: Data model — node-crypto columns, re-enroll table, store methods

**Files:**
- Modify: `hub/internal/store/store.go` (schema: additive `ALTER`/`CREATE` in the migration block)
- Create: `hub/internal/store/reenroll.go` (store methods)
- Test: `hub/internal/store/reenroll_test.go`

**Interfaces:**
- Produces:
  - `(s *Store) SetNodeCrypto(serverID, nodePubKeyB64, kekEncHex, enrollFingerprint string) error`
  - `(s *Store) GetNodeCrypto(serverID string) (nodePubKeyB64, kekEncHex, enrollFingerprint string, err error)`
  - `(s *Store) CreateReEnrollRequest(r *model.ReEnrollRequest) error`
  - `(s *Store) GetReEnrollRequest(id string) (*model.ReEnrollRequest, error)`
  - `(s *Store) ListPendingReEnroll() ([]model.ReEnrollRequest, error)`
  - `(s *Store) UpdateReEnrollStatus(id, status, decidedBy string) error`
- Consumes: existing `Store` DB handle + migration pattern in `store.go`.

- [ ] **Step 1: Add the model type**

Create `model.ReEnrollRequest` in `hub/internal/model/` (new file `reenroll.go`):

```go
package model

type ReEnrollRequest struct {
	ID           string `json:"id"`
	ServerID     string `json:"server_id"`
	RequestedAt  string `json:"requested_at"`
	IPAddress    string `json:"ip_address"`
	Fingerprint  string `json:"fingerprint"`
	Status       string `json:"status"` // pending | approved | denied | expired
	AnomalyFlags string `json:"anomaly_flags"` // JSON: {"fingerprint_changed":bool,"original_online":bool}
	DecidedBy    string `json:"decided_by,omitempty"`
}
```

- [ ] **Step 2: Write the failing store test**

Create `hub/internal/store/reenroll_test.go` (use the package's existing test-store constructor — match `store_extra_test.go`):

```go
func TestNodeCryptoRoundTrip(t *testing.T) {
	s := newTestStore(t)
	seedServer(t, s, "srv-1") // helper: insert a server row with id srv-1
	if err := s.SetNodeCrypto("srv-1", "PUBKEY_B64", "KEKENC_HEX", "fp-abc"); err != nil {
		t.Fatalf("set: %v", err)
	}
	pub, kek, fp, err := s.GetNodeCrypto("srv-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if pub != "PUBKEY_B64" || kek != "KEKENC_HEX" || fp != "fp-abc" {
		t.Fatalf("round-trip mismatch: %q %q %q", pub, kek, fp)
	}
}

func TestReEnrollRequestLifecycle(t *testing.T) {
	s := newTestStore(t)
	seedServer(t, s, "srv-2")
	r := &model.ReEnrollRequest{ID: "re-1", ServerID: "srv-2", RequestedAt: "2026-07-11 00:00:00", IPAddress: "1.2.3.4", Fingerprint: "fp", Status: "pending", AnomalyFlags: "{}"}
	if err := s.CreateReEnrollRequest(r); err != nil {
		t.Fatalf("create: %v", err)
	}
	pend, err := s.ListPendingReEnroll()
	if err != nil || len(pend) != 1 {
		t.Fatalf("list pending: %v n=%d", err, len(pend))
	}
	if err := s.UpdateReEnrollStatus("re-1", "approved", "admin-9"); err != nil {
		t.Fatalf("update: %v", err)
	}
	pend, _ = s.ListPendingReEnroll()
	if len(pend) != 0 {
		t.Fatalf("expected 0 pending after approval, got %d", len(pend))
	}
}
```

- [ ] **Step 3: Run — expect FAIL**

Run: `cd hub && go test ./internal/store/ -run 'TestNodeCrypto|TestReEnroll' -v`
Expected: compile FAIL (`SetNodeCrypto` etc. undefined). If `newTestStore`/`seedServer` names differ, align to the existing store test helpers (do not invent).

- [ ] **Step 4: Add schema (additive migration)**

In `hub/internal/store/store.go`, in the schema/migration block, add (SQLite ignores `IF NOT EXISTS`; keep additive so existing DBs upgrade in place):

```sql
ALTER TABLE servers ADD COLUMN node_pubkey TEXT;
ALTER TABLE servers ADD COLUMN node_kek_enc TEXT;
ALTER TABLE servers ADD COLUMN enroll_fingerprint TEXT;

CREATE TABLE IF NOT EXISTS reenroll_requests (
	id TEXT PRIMARY KEY,
	server_id TEXT NOT NULL,
	requested_at TEXT NOT NULL,
	ip_address TEXT,
	fingerprint TEXT,
	status TEXT NOT NULL DEFAULT 'pending',
	anomaly_flags TEXT DEFAULT '{}',
	decided_by TEXT
);
```

Follow the file's existing idempotent-migration convention (guard `ALTER` in a helper that ignores "duplicate column" errors if that's the established pattern).

- [ ] **Step 5: Implement the store methods**

Create `hub/internal/store/reenroll.go` with the six methods from **Interfaces**, using the package's existing `s.db` query style (see `servers.go`). `SetNodeCrypto` = `UPDATE servers SET node_pubkey=?, node_kek_enc=?, enroll_fingerprint=? WHERE id=?`. `ListPendingReEnroll` = `SELECT ... WHERE status='pending' ORDER BY requested_at`.

- [ ] **Step 6: Run — expect PASS**

Run: `cd hub && go test ./internal/store/ -run 'TestNodeCrypto|TestReEnroll' -v` → PASS
Then: `cd hub && go build ./... && go test ./internal/store/...` → PASS

- [ ] **Step 7: Commit**

```bash
git add hub/internal/store/store.go hub/internal/store/reenroll.go hub/internal/store/reenroll_test.go hub/internal/model/reenroll.go
git commit -m "feat(hub): schema + store for node-crypto material and re-enroll requests

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Proto — node-key material at enrollment + re-enroll messages

**Files:**
- Modify: `proto/veyport/v1/agent.proto`
- Regenerate: `proto/veyport/v1/agent.pb.go`, `agent_grpc.pb.go` (via `make proto`)

**Interfaces (new proto):**
- `RegisterAgent` (existing) — add `bytes node_pubkey = <n>;` and `string enroll_fingerprint = <n+1>;`
- Register response message (the one carrying `client_cert`/`ca_cert`) — add `bytes node_kek = <n>;`
- `AgentMessage.payload` oneof — add `ReEnrollRequest reenroll_request` and `ReEnrollProof reenroll_proof`
- `HubMessage.payload` oneof — add `ReEnrollApproved reenroll_approved` and `ReEnrollDenied reenroll_denied`
- New messages:
  - `ReEnrollRequest { string server_id = 1; bytes csr = 2; string fingerprint = 3; }`
  - `ReEnrollApproved { bytes kek = 1; bytes challenge = 2; }`
  - `ReEnrollProof { bytes signature = 1; }`
  - `ReEnrollDenied { string reason = 1; }`

- [ ] **Step 1: Edit `agent.proto`** — add the fields/messages above (use the next free field numbers in each message; append new oneof entries with fresh numbers).

- [ ] **Step 2: Regenerate**

Run: `make proto`
Expected: `proto/veyport/v1/agent.pb.go` + `agent_grpc.pb.go` regenerate with no error.

- [ ] **Step 3: Verify it builds**

Run: `cd hub && go build ./... && cd ../agent && go build ./...`
Expected: PASS (new types exist; not yet referenced).

- [ ] **Step 4: Commit**

```bash
git add proto/veyport/v1/agent.proto proto/veyport/v1/agent.pb.go proto/veyport/v1/agent_grpc.pb.go
git commit -m "proto: node-key material at register + re-enroll messages

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Agent `nodekey` package — durable key + KEK encryption + fingerprint

**Files:**
- Create: `agent/internal/nodekey/nodekey.go`
- Test: `agent/internal/nodekey/nodekey_test.go`

**Interfaces:**
- `Generate() (priv ed25519.PrivateKey, pubB64 string, err error)`
- `Seal(priv ed25519.PrivateKey, kek []byte) (ciphertextHex string, err error)` — AES-256-GCM(nonce‖ct), key = `sha256(kek)`
- `Open(ciphertextHex string, kek []byte) (ed25519.PrivateKey, error)`
- `Sign(priv ed25519.PrivateKey, challenge []byte) []byte`
- `Fingerprint() string` — reads `/sys/class/dmi/id/product_uuid`, trimmed; `""` on error

- [ ] **Step 1: Write the failing test**

```go
package nodekey

import (
	"crypto/ed25519"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	priv, _, err := Generate()
	if err != nil { t.Fatalf("gen: %v", err) }
	kek := []byte("0123456789abcdef0123456789abcdef")
	ct, err := Seal(priv, kek)
	if err != nil { t.Fatalf("seal: %v", err) }
	got, err := Open(ct, kek)
	if err != nil { t.Fatalf("open: %v", err) }
	if !got.Equal(priv) { t.Fatal("round-trip key mismatch") }
}

func TestOpenWrongKEKFails(t *testing.T) {
	priv, _, _ := Generate()
	ct, _ := Seal(priv, []byte("0123456789abcdef0123456789abcdef"))
	if _, err := Open(ct, []byte("WRONGWRONGWRONGWRONGWRONGWRONGWR")); err == nil {
		t.Fatal("expected open to fail with wrong KEK (clone protection)")
	}
}

func TestSignVerify(t *testing.T) {
	priv, pubB64, _ := Generate()
	sig := Sign(priv, []byte("challenge"))
	pub, err := DecodePub(pubB64)
	if err != nil { t.Fatalf("decode pub: %v", err) }
	if !ed25519.Verify(pub, []byte("challenge"), sig) { t.Fatal("verify failed") }
}
```

- [ ] **Step 2: Run — expect FAIL** — `cd agent && go test ./internal/nodekey/ -v` → compile FAIL.

- [ ] **Step 3: Implement `nodekey.go`** — `Generate` (ed25519.GenerateKey, pub base64.StdEncoding), `Seal`/`Open` (AES-256-GCM, `key := sha256.Sum256(kek)`, nonce prepended — mirror the hub's `auth.Encrypt`/`Decrypt` shape), `Sign` (`ed25519.Sign`), `DecodePub`, `Fingerprint` (`os.ReadFile("/sys/class/dmi/id/product_uuid")`, `strings.TrimSpace`, return "" on error).

- [ ] **Step 4: Run — expect PASS** — `cd agent && go test ./internal/nodekey/ -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add agent/internal/nodekey/
git commit -m "feat(agent): nodekey package (durable ed25519 key, KEK sealing, fingerprint)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Hub — issue & store KEK + node material at registration

**Files:**
- Modify: `hub/internal/grpcserver/handler.go` (`handleRegister` / register response assembly)
- Create: `hub/internal/grpcserver/nodekek.go` (`generateKEK`, `sealKEK`, `openKEK` using `auth.Encrypt/Decrypt` + `auth.DeriveKey(h.storageKey)`)
- Test: `hub/internal/grpcserver/nodekek_test.go`

**Interfaces:**
- `(h *Handler) sealKEK(kek []byte) (string, error)` → hex of `auth.Encrypt(kek, auth.DeriveKey(h.storageKey))`
- `(h *Handler) openKEK(hexStr string) ([]byte, error)` → inverse
- `handleRegister` now: generate KEK, `SetNodeCrypto(serverID, reg.NodePubkey(b64), sealKEK(kek), reg.EnrollFingerprint)`, and return `kek` in the register response's `node_kek`.

- [ ] **Step 1: Write the failing test** for `sealKEK`/`openKEK` round-trip (construct `&Handler{storageKey: "test-storage-key"}`):

```go
func TestKEKSealOpen(t *testing.T) {
	h := &Handler{storageKey: "test-storage-key-0123456789"}
	kek := make([]byte, 32)
	for i := range kek { kek[i] = byte(i) }
	sealed, err := h.sealKEK(kek)
	if err != nil { t.Fatalf("seal: %v", err) }
	got, err := h.openKEK(sealed)
	if err != nil { t.Fatalf("open: %v", err) }
	if !bytes.Equal(got, kek) { t.Fatal("KEK round-trip mismatch") }
}
```

- [ ] **Step 2: Run — expect FAIL** — `cd hub && go test ./internal/grpcserver/ -run TestKEKSealOpen -v`.

- [ ] **Step 3: Implement `nodekek.go`** (uses `auth.Encrypt(kek, auth.DeriveKey(h.storageKey))`, hex encode; `openKEK` hex-decode → `auth.Decrypt`). Confirm `Handler` has `storageKey` (it holds `h.caKey`/`h.storageKey` for at-rest crypto; if the field name differs, use the existing one).

- [ ] **Step 4: Wire into `handleRegister`** — after `ActivateServer`, generate KEK (`crypto/rand`, 32 bytes), `h.store.SetNodeCrypto(...)`, and thread `node_kek` into the register response. Guard: if `reg.NodePubkey` is empty (old agent), skip node-crypto (backward compat — Global Constraints).

- [ ] **Step 5: Run tests + build** — `cd hub && go build ./... && go test ./internal/grpcserver/ -run TestKEK -v` → PASS.

- [ ] **Step 6: Commit** — `feat(hub): issue and store per-node KEK + pubkey + fingerprint at registration`.

---

### Task 5: Agent — generate node key at enroll; re-enroll on expiry

**Files:**
- Modify: `agent/cmd/veyport-agent/main.go` / `agent/internal/client/client.go` (`sendRegister`, register-response handling, `Run`/`connectAndStream`)
- Test: `agent/internal/client/client_test.go`

**Interfaces:**
- Consumes Task 3 `nodekey`, Task 2 proto fields, Plan 1 `reconnectCh`.
- Produces: `(c *Client) buildReEnrollRequest() (*pb.ReEnrollRequest, error)`; `(c *Client) handleReEnrollApproved(*pb.ReEnrollApproved) (*pb.ReEnrollProof, error)`.

- [ ] **Step 1: Write failing tests**

```go
func TestBuildReEnrollRequest_IncludesServerIDCSRFingerprint(t *testing.T) {
	certStore := certs.NewMemoryStore()
	c := &Client{serverID: "srv-re", certStore: certStore}
	req, err := c.buildReEnrollRequest()
	if err != nil { t.Fatalf("build: %v", err) }
	if req.ServerId != "srv-re" || len(req.Csr) == 0 {
		t.Fatalf("bad request: %+v", req)
	}
}

func TestHandleReEnrollApproved_DecryptsAndSigns(t *testing.T) {
	// node key sealed under a known KEK, stored where handleReEnrollApproved reads it
	priv, _, _ := nodekey.Generate()
	kek := make([]byte, 32)
	sealedHex, _ := nodekey.Seal(priv, kek)
	c := &Client{serverID: "srv-re", sealedNodeKeyHex: sealedHex}
	proof, err := c.handleReEnrollApproved(&pb.ReEnrollApproved{Kek: kek, Challenge: []byte("nonce")})
	if err != nil { t.Fatalf("approve: %v", err) }
	if len(proof.Signature) == 0 { t.Fatal("expected signature") }
}
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement enrollment key-gen** — in `sendRegister`, call `nodekey.Generate()`, attach `node_pubkey` + `nodekey.Fingerprint()` to `RegisterAgent`; on the register response, `nodekey.Seal(priv, resp.NodeKek)` → persist sealed hex to `certDir/node_key.enc` (add `sealedNodeKeyHex` load in `New`), zeroize `priv` + `kek`.

- [ ] **Step 4: Implement re-enroll flow** — add a `reEnroll(ctx)` path: dial bootstrap TLS, send `ReEnrollRequest`, block on the stream for `ReEnrollApproved`/`ReEnrollDenied`; on approved → `handleReEnrollApproved` → send `ReEnrollProof`; on the subsequent cert message → `certStore.StoreCert` + signal `reconnectCh`. In `Run`, when `connectAndStream` fails with a `tls: expired certificate`/cert-rejected error, route to `reEnroll` instead of the self-terminate path; **remove the 3-strike exit for the expired-cert case**.

- [ ] **Step 5: Run — expect PASS** — `cd agent && go build ./... && go test ./internal/client/ -run 'ReEnroll' -v`.

- [ ] **Step 6: Commit** — `feat(agent): durable node key at enroll; self-initiated re-enroll on cert expiry`.

---

### Task 6: Hub — re-enroll intake, pending queue, anomaly flags, audit constants

**Files:**
- Modify: `hub/internal/grpcserver/handler.go` (`routeAgentMessage` case for `ReEnrollRequest`; hold stream in `connMgr` keyed by pending id)
- Create: `hub/internal/grpcserver/reenroll.go` (`handleReEnrollRequest`, `computeAnomalyFlags`)
- Modify: `hub/internal/model/audit.go` + `audit_catalog.go` (new actions)
- Test: `hub/internal/grpcserver/reenroll_test.go`

**Interfaces:**
- `(h *Handler) computeAnomalyFlags(serverID, fingerprint string) (jsonFlags string)` — `{"fingerprint_changed":<enroll_fingerprint != fingerprint>,"original_online":<server status online>}`
- New audit actions: `AuditReEnrollRequested = "agent.reenroll_requested"`, `AuditReEnrollApproved`, `AuditReEnrollDenied`, `AuditCloneSuspected = "agent.clone_suspected"` + `AuditCatalog` entries.

- [ ] **Step 1: Failing test** for `computeAnomalyFlags`:

```go
func TestComputeAnomalyFlags_FingerprintChanged(t *testing.T) {
	st := newTestStore(t)
	seedServer(t, st, "srv-a")
	_ = st.SetNodeCrypto("srv-a", "pub", "kek", "fp-original")
	h := &Handler{store: st}
	flags := h.computeAnomalyFlags("srv-a", "fp-DIFFERENT")
	if !strings.Contains(flags, `"fingerprint_changed":true`) {
		t.Fatalf("expected fingerprint_changed true, got %s", flags)
	}
}
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement** `computeAnomalyFlags` + `handleReEnrollRequest` (validate server exists + has node material; `CreateReEnrollRequest` with flags; register the live stream so the approval path can push down it; if `fingerprint_changed` or `original_online`, also `auditLog(AuditCloneSuspected)`). Add the audit constants + catalog entries. Wire the `routeAgentMessage` case.

- [ ] **Step 4: Run — expect PASS**; `cd hub && go build ./... && go test ./internal/grpcserver/ -run 'Anomaly|ReEnroll' -v`.

- [ ] **Step 5: Commit** — `feat(hub): re-enroll intake, pending queue, clone-anomaly flags + audit events`.

---

### Task 7: Hub — approval/deny endpoint (TOTP step-up → KEK release → verify → re-issue)

**Files:**
- Modify: `hub/internal/server/handlers_servers.go` (or new `handlers_reenroll.go`), `hub/internal/server/router.go`
- Test: `hub/internal/server/handlers_reenroll_test.go`

**Interfaces:**
- `POST /api/servers/{id}/reenroll/approve` body `{ "request_id": "...", "totp_code": "123456" }` — `adminOnly`; verifies TOTP via `auth.ValidateTOTPWithReplay(s.totpCache, adminID, decryptedAdminTOTPSecret, code)`; on success: release `ReEnrollApproved{kek: openKEK(...), challenge: rand32}` down the held agent stream; await `ReEnrollProof`; `ed25519.Verify(storedPubKey, challenge, sig)`; `ca.SignCSR(..., h.clientCertValidity())`; push cert; `UpdateReEnrollStatus(id,"approved",adminID)`; audit `AuditReEnrollApproved` (Target=serverID, UserID=adminID).
- `POST /api/servers/{id}/reenroll/deny` — `adminOnly`; `UpdateReEnrollStatus(id,"denied",adminID)`; audit.
- `GET /api/servers/reenroll/pending` — `adminOnly`; `ListPendingReEnroll`.

- [ ] **Step 1: Failing tests** (match the existing server-handler HTTP test harness — `newTestServer`, authed request helpers):

```go
func TestReEnrollApprove_RequiresValidTOTP(t *testing.T) {
	ts := newTestServer(t)
	admin, _ := ts.seedAdminWithTOTP(t) // returns id + secret
	// ... seed server srv + a pending reenroll request re-1 + node material ...
	// wrong TOTP -> 401/403, status stays pending
	resp := ts.authedPOST(t, admin, "/api/servers/srv/reenroll/approve", `{"request_id":"re-1","totp_code":"000000"}`)
	if resp.Code == http.StatusOK { t.Fatal("must reject bad TOTP") }
	// correct TOTP -> 200, status approved, cert re-issued for same serverID
	code := totpNow(t, secret)
	resp = ts.authedPOST(t, admin, "/api/servers/srv/reenroll/approve", `{"request_id":"re-1","totp_code":"`+code+`"}`)
	if resp.Code != http.StatusOK { t.Fatalf("want 200, got %d", resp.Code) }
}
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement** the three handlers + register routes in `router.go` behind `s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(...))`. Reuse the admin-TOTP decrypt+validate pattern from `handlers_auth.go:720-728`. The approve handler coordinates with the held gRPC stream via the `grpcserver` (expose a `ReleaseKEK(requestID, kek, challenge) (proofSig []byte, err error)` method on the gRPC handler that the HTTP layer calls).

- [ ] **Step 4: Run — expect PASS**; `cd hub && go build ./... && go test ./internal/server/ -run ReEnroll -v`.

- [ ] **Step 5: Commit** — `feat(hub): TOTP-gated re-enroll approval with KEK release + same-serverID re-issue`.

---

### Task 8: Integration test — full expire → re-enroll → approve → fresh cert

**Files:**
- Test: `hub/internal/integration/reenroll_test.go` (use existing integration harness — `testhelpers.go`)

- [ ] **Step 1: Write the integration test** — spin up hub + register an agent (gets node material), force cert expiry, agent phones home (ReEnrollRequest), admin approves with TOTP, assert: agent receives a fresh cert, **same serverID**, node reconnects with mTLS; a denied path leaves status `denied` and no cert. (Follow `SetupAdmin`/harness patterns in `hub/internal/integration/testhelpers.go`.)
- [ ] **Step 2: Run — iterate to green** — `cd hub && go test ./internal/integration/ -run ReEnroll -v`.
- [ ] **Step 3: Commit** — `test: end-to-end re-enrollment (expire, approve, same-serverID re-issue)`.

---

### Task 9: Dashboard — pending re-enrollment surface + TOTP approval

**Files:**
- Modify: `web/src/lib/api.ts` (client methods), `web/src/types/api.ts` (types), `web/src/hooks/use-servers.ts` (or new `use-reenroll.ts`)
- Create: `web/src/components/reenroll-approval.tsx` (banner + Approve/Deny + TOTP prompt)
- Modify: `web/src/pages/server-detail.tsx` (render the surface when a pending request exists)
- Test: `web/src/components/__tests__/reenroll-approval.test.tsx`

**Interfaces:**
- `api.listPendingReEnroll(): Promise<ReEnrollRequest[]>`, `api.approveReEnroll(serverId, requestId, totpCode)`, `api.denyReEnroll(serverId, requestId)` — mirror existing `api.ts` fetch helpers.

- [ ] **Step 1: Failing component test** (vitest + testing-library, matching `add-server-modal.test.tsx`):

```tsx
it("shows a clone warning and requires a TOTP code to approve", async () => {
  render(<ReEnrollApproval request={{ id: "re-1", server_id: "srv", fingerprint: "fp2",
    status: "pending", anomaly_flags: '{"fingerprint_changed":true,"original_online":true}' } as any} />);
  expect(screen.getByText(/possible clone/i)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /approve/i }));
  expect(screen.getByText(/enter.*totp|authenticator code/i)).toBeInTheDocument();
});
```

- [ ] **Step 2: Run — expect FAIL** — `cd web && npx vitest run reenroll-approval`.
- [ ] **Step 3: Implement** the component (anomaly banner when flags set; Approve opens a TOTP input then calls `api.approveReEnroll`; Deny calls `api.denyReEnroll`), the api/types/hook, and render it in `server-detail.tsx`. Follow existing component/query patterns.
- [ ] **Step 4: Run — expect PASS** — `cd web && npx vitest run` (full suite green).
- [ ] **Step 5: Commit** — `feat(web): pending re-enrollment approval UI with clone warning + TOTP step-up`.

---

## Self-Review

**Spec coverage (design §3–§8):**
- Durable node key + KEK, clone-inert at rest → Tasks 1,3,4. ✓
- Verify-to-release (hub-held KEK released on TOTP) → Tasks 4,7. ✓
- Per-admin TOTP step-up, audited to approver (§3.2) → Task 7 + audit in 6/7. ✓
- Phone-home on expiry, no self-terminate, same serverID → Tasks 5,7,8. ✓
- Pending queue + clone-anomaly flags/detection (§3.1) → Tasks 6,9. ✓
- Adopt re-issued cert live → reuses Plan 1 `reconnectCh` (Task 5). ✓
- Dashboard approval surface (§5.3) → Task 9. ✓
- Data model (§5.4) + audit events → Tasks 1,6. ✓
- Migration/backward-compat (§7) → Global Constraints + Task 4 guard. ✓
- **Deferred (correctly out of scope):** dual approval/four-eyes, vTPM/PAKE (design §11); cert-lifetime tuning + fingerprint-in-KDF (design §10).

**Placeholder scan:** implementation code is concrete for the crypto/proto/hub core; test harness names (`newTestStore`, `seedServer`, `newTestServer`, `seedAdminWithTOTP`, `authedPOST`, `totpNow`) are explicitly directed to **match existing helpers** in each package rather than be invented — the executing engineer wires to the real ones (same approach validated in Plan 1).

**Type consistency:** `SetNodeCrypto/GetNodeCrypto` args ordered `(pubkeyB64, kekEncHex, fingerprint)` throughout; KEK is 32 raw bytes end-to-end (`ReEnrollApproved.Kek`), sealed-at-rest as hex on the hub and as `sealedNodeKeyHex` on the agent; challenge/signature are Ed25519 over `ReEnrollApproved.Challenge`; `clientCertValidity()` (Plan 1) reused for re-issue.

**Ordering / dependencies:** 1 (data) → 2 (proto) → 3 (agent crypto) & 4 (hub KEK) → 5 (agent flow) & 6 (hub intake) → 7 (approval) → 8 (integration) → 9 (UI). Tasks 3/4 and 5/6 are parallelizable; everything else is sequential.

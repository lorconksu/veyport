# Renewal Hardening (Tier 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a continuously-connected agent always run a fresh mTLS cert by *adopting* a renewed cert immediately (not "on next reconnect"), and make the hub's client-cert lifetime configurable with a safer default.

**Architecture:** The agent already requests a renewed cert 6h before expiry (`startCertRenewalTicker` → `CertRenewRequest`; hub `handleCertRenewal` re-issues; agent `handleCertRenewResponse` stores it) — but it only logs *"will use on next reconnect"* and never reconnects, so the live gRPC stream keeps using the old cert until it expires. We add a buffered `reconnectCh` that `handleCertRenewResponse` fires after storing the new cert; `connectAndStream`'s select returns `errReconnectWithMTLS`, and the existing `Run` loop reconnects (via `dialHub` → `certStore.TLSConfig()`), adopting the fresh cert. Separately, the hub's two hardcoded `12*time.Hour` cert validities become a config value (default 24h).

**Tech Stack:** Go; agent gRPC bidi stream (`agent/internal/client`); `agent/internal/certs.Store`; hub gRPC handler (`hub/internal/grpcserver`); `hub/internal/ca.SignCSR`; hub `_config` table via `store.GetConfig`.

## Global Constraints

- Go version: use the module's existing toolchain (`hub/go.mod`, `agent/go.mod`) — do not bump.
- **Reuse `errReconnectWithMTLS`** for the renewal-triggered reconnect. The `Run` loop already treats it as a clean reconnect that **resets backoff and resets the 3-strike `regFailures` counter**, so this must NOT trip the "server unregistered — exiting" path.
- Additive & backward-compatible: a hub/agent without these changes keeps working; no new dependencies; no proto changes.
- Best-effort, non-fatal: a failed renewal/reconnect must never crash the agent (existing retry/backoff stays).

---

### Task 1: Agent adopts a renewed certificate immediately

**Files:**
- Modify: `agent/internal/client/client.go` (add `reconnectCh` field; init in `New`; signal in `handleCertRenewResponse`; consume in `connectAndStream`)
- Test: `agent/internal/client/client_test.go`

**Interfaces:**
- Produces: `Client.reconnectCh chan struct{}` (buffered, cap 1). `handleCertRenewResponse` performs a non-blocking send on it after a successful `certStore.StoreCert(...)`. `connectAndStream` selects on it and returns `errReconnectWithMTLS`.
- Consumes: existing `certStore.StoreCert(clientCert, caCert []byte) error`, `CertRenewResponse{ClientCert, CaCert []byte, Error string}`, `errReconnectWithMTLS`.

- [ ] **Step 1: Write the failing test**

Add to `agent/internal/client/client_test.go` (mirrors the existing `storeClientCert` / renewal-ticker test patterns):

```go
// makeRenewedCertPair builds a CA-signed client cert (CN=serverID) and returns
// the client + CA cert DER, as the hub would return in a CertRenewResponse.
func makeRenewedCertPair(t *testing.T, serverID string, notAfter time.Time) (clientDER, caDER []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(200),
		Subject:               pkix.Name{CommonName: "Test Agent CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(201),
		Subject:      pkix.Name{CommonName: serverID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return clientDER, caDER
}

func TestHandleCertRenewResponse_SignalsReconnectToAdoptCert(t *testing.T) {
	certStore := certs.NewMemoryStore()
	storeClientCert(t, certStore, "srv-adopt", time.Now().Add(30*time.Minute)) // old cert
	c := &Client{
		serverID:    "srv-adopt",
		certStore:   certStore,
		reconnectCh: make(chan struct{}, 1),
	}
	clientDER, caDER := makeRenewedCertPair(t, "srv-adopt", time.Now().Add(12*time.Hour))

	c.handleCertRenewResponse(&pb.HubMessage_CertRenewResponse{
		CertRenewResponse: &pb.CertRenewResponse{ClientCert: clientDER, CaCert: caDER},
	})

	select {
	case <-c.reconnectCh:
		// success: renewal signalled a reconnect to adopt the new cert
	case <-time.After(time.Second):
		t.Fatal("expected reconnect signal after successful renewal")
	}
}

func TestHandleCertRenewResponse_NoSignalOnError(t *testing.T) {
	c := &Client{serverID: "srv-x", certStore: certs.NewMemoryStore(), reconnectCh: make(chan struct{}, 1)}
	c.handleCertRenewResponse(&pb.HubMessage_CertRenewResponse{
		CertRenewResponse: &pb.CertRenewResponse{Error: "denied"},
	})
	select {
	case <-c.reconnectCh:
		t.Fatal("must not signal reconnect when renewal was rejected")
	case <-time.After(100 * time.Millisecond):
		// ok
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd agent && go test ./internal/client/ -run TestHandleCertRenewResponse -v`
Expected: FAIL to compile — `reconnectCh` is not a field of `Client`.

- [ ] **Step 3: Add the `reconnectCh` field and initialize it**

In `agent/internal/client/client.go`, add to the `Client` struct (next to the other channels/fields):

```go
	reconnectCh     chan struct{} // signals connectAndStream to reconnect (e.g. to adopt a renewed cert)
```

In `New(cfg Config) *Client`, add to the returned struct literal:

```go
		reconnectCh:     make(chan struct{}, 1),
```

- [ ] **Step 4: Signal the reconnect after a successful renewal**

In `handleCertRenewResponse`, replace the final log line:

```go
	log.Printf("mTLS certificate renewed (will use on next reconnect)")
```

with:

```go
	// Proactively reconnect so the live connection re-handshakes with the fresh
	// cert instead of drifting until the old one expires. Non-blocking: if a
	// reconnect is already pending, drop this signal.
	select {
	case c.reconnectCh <- struct{}{}:
	default:
	}
	log.Printf("mTLS certificate renewed; reconnecting to adopt it")
```

- [ ] **Step 5: Run the renewal tests to verify they pass**

Run: `cd agent && go test ./internal/client/ -run TestHandleCertRenewResponse -v`
Expected: PASS (both tests).

- [ ] **Step 6: Consume the signal in `connectAndStream`**

In `connectAndStream`, add a case to the main `select` loop (alongside `ctx.Done()`, `recvErr`, `sendCh`):

```go
		case <-c.reconnectCh:
			log.Printf("adopting renewed certificate via reconnect")
			return errReconnectWithMTLS
```

- [ ] **Step 7: Guard against a nil channel for struct-literal Clients**

Some tests construct `Client{}` directly without `New`. In `connectAndStream`, before the select loop, ensure the channel exists (defensive, keeps existing tests green):

```go
	if c.reconnectCh == nil {
		c.reconnectCh = make(chan struct{}, 1)
	}
```

- [ ] **Step 8: Build and run the full agent test suite**

Run: `cd agent && go build ./... && go test ./...`
Expected: PASS (existing integration tests exercise `connectAndStream`; the returned `errReconnectWithMTLS` is already handled by `Run` as a clean, backoff-resetting reconnect).

- [ ] **Step 9: Commit**

```bash
git add agent/internal/client/client.go agent/internal/client/client_test.go
git commit -m "fix(agent): adopt renewed mTLS cert via reconnect instead of drifting

The agent renewed its cert 6h before expiry but only used it 'on next
reconnect' and never reconnected, so a long-lived stream kept the old cert
until it expired. Signal a reconnect after storing a renewed cert so the
connection re-handshakes with the fresh cert. Reuses errReconnectWithMTLS
(resets backoff, does not count as a registration failure).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Configurable client-cert lifetime on the hub

**Files:**
- Modify: `hub/internal/grpcserver/handler.go` (add `clientCertValidity()` helper; use it at the two `SignCSR` call sites — currently `:438` register, `:486` renewal)
- Test: `hub/internal/grpcserver/handler_extra_test.go`

**Interfaces:**
- Produces: `(h *Handler) clientCertValidity() time.Duration` — reads config key `agent_cert_validity_hours`, default `24h`, floors to `> 0`.
- Consumes: existing `h.store.GetConfig(key string) (string, error)` and `ca.SignCSR(..., validity time.Duration)`.

- [ ] **Step 1: Write the failing test**

Add to `hub/internal/grpcserver/handler_extra_test.go` (use the package's existing test `Store` constructor — match how other handler tests build `h`/`h.store`):

```go
func TestClientCertValidity_DefaultAndConfigured(t *testing.T) {
	st := newTestStore(t) // existing helper used by other handler tests
	h := &Handler{store: st}

	// Default when unset.
	if got := h.clientCertValidity(); got != 24*time.Hour {
		t.Fatalf("default: want 24h, got %v", got)
	}

	// Honors a valid config value.
	if err := st.SetConfig("agent_cert_validity_hours", "72"); err != nil {
		t.Fatalf("set config: %v", err)
	}
	if got := h.clientCertValidity(); got != 72*time.Hour {
		t.Fatalf("configured: want 72h, got %v", got)
	}

	// Falls back to default on invalid / non-positive values.
	for _, bad := range []string{"", "0", "-5", "abc"} {
		_ = st.SetConfig("agent_cert_validity_hours", bad)
		if got := h.clientCertValidity(); got != 24*time.Hour {
			t.Fatalf("invalid %q: want 24h default, got %v", bad, got)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd hub && go test ./internal/grpcserver/ -run TestClientCertValidity -v`
Expected: FAIL to compile — `h.clientCertValidity` undefined. (If `newTestStore`/`SetConfig` names differ, align them to the existing helpers in `hub/internal/grpcserver/*_test.go` / `hub/internal/store` — do not invent new ones.)

- [ ] **Step 3: Implement the helper**

In `hub/internal/grpcserver/handler.go`, add (ensure `strconv` and `time` are imported):

```go
// clientCertValidity is the lifetime of issued agent client certs.
// Configurable via the "agent_cert_validity_hours" config key; defaults to 24h.
func (h *Handler) clientCertValidity() time.Duration {
	const def = 24 * time.Hour
	v, err := h.store.GetConfig("agent_cert_validity_hours")
	if err != nil || v == "" {
		return def
	}
	hours, err := strconv.Atoi(v)
	if err != nil || hours <= 0 {
		return def
	}
	return time.Duration(hours) * time.Hour
}
```

- [ ] **Step 4: Use it at both `SignCSR` call sites**

In `hub/internal/grpcserver/handler.go`, replace both occurrences of `12*time.Hour` passed to `ca.SignCSR(...)` (register path and renewal path) with `h.clientCertValidity()`:

```go
	clientCert, err := ca.SignCSR(h.caCert, h.caKey, csr, serverID, h.clientCertValidity())
```
```go
	clientCert, err := ca.SignCSR(h.caCert, h.caKey, req.Csr, serverID, h.clientCertValidity())
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd hub && go test ./internal/grpcserver/ -run TestClientCertValidity -v`
Expected: PASS.

- [ ] **Step 6: Build and run the hub suite**

Run: `cd hub && go build ./... && go test ./internal/...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add hub/internal/grpcserver/handler.go hub/internal/grpcserver/handler_extra_test.go
git commit -m "feat(hub): make agent client-cert lifetime configurable (default 24h)

Replace the two hardcoded 12h SignCSR validities with a config-driven value
(agent_cert_validity_hours, default 24h) for a safer renewal margin. Paired
with the agent renewal-adoption fix.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage (against design §3 Tier 1 + §5.1/§5.2 + §10):**
- "adopt the new cert on the live connection (fixes today's drift)" → Task 1. ✓
- "Fix self-terminate: must not fire for recoverable states" → reuse of `errReconnectWithMTLS` (Global Constraints) means the renewal reconnect resets `regFailures`; no separate change needed for this tier. ✓
- "Cert lifetime knob (configurable; 12h aggressive)" → Task 2. ✓
- Tier 2 items (durable key, KEK, re-enrollment, dashboard, fingerprint) → **out of scope for this plan**, covered by Plan 2. ✓

**Placeholder scan:** none — all steps carry real code and exact commands. The one flagged assumption (hub test-store helper names `newTestStore`/`SetConfig`) is explicitly directed to match existing helpers rather than invent them.

**Type consistency:** `reconnectCh chan struct{}` used consistently (declare → init → send → receive); `clientCertValidity() time.Duration` matches `ca.SignCSR(..., validity time.Duration)`; `CertRenewResponse` fields `ClientCert`/`CaCert`/`Error` match the proto.

## Notes for Plan 2 (Tier 2 — separate plan)

Task 1's `reconnectCh` and the "reconnect to adopt new material" pattern are reused by re-enrollment (adopting a freshly re-issued cert after approval). Plan 2 will add: durable node keypair + hub-held KEK, a `ReEnrollRequest` proto/flow, the pending queue + `POST /api/servers/{id}/reenroll/approve` (per-admin TOTP step-up, §3.2), DMI fingerprint capture + clone-detection flags, dashboard surface, data-model columns, and audit events.

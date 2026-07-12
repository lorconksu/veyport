package grpcserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

// seedServer inserts a minimal offline server record for the given ID.
func seedServer(t *testing.T, h *Handler, serverID string) {
	t.Helper()
	if err := h.store.CreateServer(&model.Server{ID: serverID, Name: serverID, Status: "offline", Labels: "{}"}); err != nil {
		t.Fatalf("seedServer %s: %v", serverID, err)
	}
}

// --- TDD RED: computeAnomalyFlags ---

func TestComputeAnomalyFlags_FingerprintChanged(t *testing.T) {
	h, st := testHandler(t)
	seedServer(t, h, "srv-a")
	_ = st.SetNodeCrypto("srv-a", "pub", "kek", "fp-original")
	flags := h.computeAnomalyFlags("srv-a", "fp-DIFFERENT")
	if !strings.Contains(flags, `"fingerprint_changed":true`) {
		t.Fatalf("expected fingerprint_changed true, got %s", flags)
	}
}

func TestComputeAnomalyFlags_FingerprintUnchanged(t *testing.T) {
	h, st := testHandler(t)
	seedServer(t, h, "srv-b")
	_ = st.SetNodeCrypto("srv-b", "pub", "kek", "fp-same")
	flags := h.computeAnomalyFlags("srv-b", "fp-same")
	if !strings.Contains(flags, `"fingerprint_changed":false`) {
		t.Fatalf("expected fingerprint_changed false, got %s", flags)
	}
}

func TestComputeAnomalyFlags_OriginalOnline(t *testing.T) {
	h, st := testHandler(t)
	// Create server and mark it online
	if err := st.CreateServer(&model.Server{ID: "srv-c", Name: "srv-c", Status: "online", Labels: "{}"}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	_ = st.SetNodeCrypto("srv-c", "pub", "kek", "fp-c")
	flags := h.computeAnomalyFlags("srv-c", "fp-c")
	if !strings.Contains(flags, `"original_online":true`) {
		t.Fatalf("expected original_online true for online server, got %s", flags)
	}
}

func TestComputeAnomalyFlags_OriginalOffline(t *testing.T) {
	h, st := testHandler(t)
	seedServer(t, h, "srv-d")
	_ = st.SetNodeCrypto("srv-d", "pub", "kek", "fp-d")
	flags := h.computeAnomalyFlags("srv-d", "fp-d")
	if !strings.Contains(flags, `"original_online":false`) {
		t.Fatalf("expected original_online false for offline server, got %s", flags)
	}
}

func TestComputeAnomalyFlags_UnknownServer(t *testing.T) {
	h, _ := testHandler(t)
	// Server doesn't exist — should return safe defaults (false/false), not panic.
	flags := h.computeAnomalyFlags("nonexistent", "fp-x")
	if flags == "" {
		t.Fatal("expected non-empty flags for unknown server")
	}
	if !strings.Contains(flags, `"fingerprint_changed"`) {
		t.Fatalf("expected valid JSON with fingerprint_changed, got %s", flags)
	}
}

// --- registry helpers ---

func TestReEnrollRegistry_RegisterLookupClear(t *testing.T) {
	h, _ := testHandler(t)
	h.reEnrollSessions = make(map[string]*reEnrollSession)

	sess := h.registerReEnroll("srv-x", []byte("csr"), "fp1")
	if sess == nil {
		t.Fatal("expected non-nil session")
	}
	if sess.approve == nil || sess.result == nil {
		t.Fatal("expected buffered channels to be initialized")
	}

	got, ok := h.lookupReEnroll("srv-x")
	if !ok || got != sess {
		t.Fatal("expected lookupReEnroll to return registered session")
	}

	h.clearReEnroll("srv-x", sess)
	_, ok = h.lookupReEnroll("srv-x")
	if ok {
		t.Fatal("expected clearReEnroll to remove session")
	}
}

func TestReEnrollRegistry_LookupMissing(t *testing.T) {
	h, _ := testHandler(t)
	h.reEnrollSessions = make(map[string]*reEnrollSession)

	_, ok := h.lookupReEnroll("ghost")
	if ok {
		t.Fatal("expected lookupReEnroll to return false for missing server")
	}
}

// ---------------------------------------------------------------------------
// handleReEnrollRequest error branches
// ---------------------------------------------------------------------------

// TestHandleReEnrollRequest_UnknownServer: server not in store → sendDenied → returns (false, nil)
func TestHandleReEnrollRequest_UnknownServer(t *testing.T) {
	h, _ := testHandler(t)

	stream := &mockStream{ctx: context.Background()}
	req := &pb.ReEnrollRequest{
		ServerId:    "srv-unknown",
		Fingerprint: "fp-x",
		Csr:         testRegistrationCSR(t),
	}

	approvalSent, err := h.handleReEnrollRequest(stream, req)
	if err != nil {
		t.Fatalf("expected nil error for unknown server, got: %v", err)
	}
	if approvalSent {
		t.Fatal("expected approvalSent=false for unknown server")
	}
	// Stream should have received a ReenrollDenied message.
	if len(stream.sent) == 0 {
		t.Fatal("expected denied message to be sent on stream")
	}
	if stream.sent[0].GetReenrollDenied() == nil {
		t.Fatalf("expected ReenrollDenied payload, got %T", stream.sent[0].Payload)
	}
}

// TestHandleReEnrollRequest_ContextCancel: cancel context → returns false, nil (no approval)
func TestHandleReEnrollRequest_ContextCancel(t *testing.T) {
	h, st := testHandler(t)
	h.storageKey = "test-storage-key-0123456789"

	// Seed server with node crypto so GetNodeCrypto returns valid data.
	seedServer(t, h, "srv-ctx-cancel")
	if err := st.SetNodeCrypto("srv-ctx-cancel", "dGVzdC1wdWI=", "00112233", "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel the context immediately so the select picks context.Done().
	cancel()

	stream := &mockStream{ctx: ctx}
	req := &pb.ReEnrollRequest{
		ServerId:    "srv-ctx-cancel",
		Fingerprint: "fp-x",
		Csr:         testRegistrationCSR(t),
	}

	approvalSent, err := h.handleReEnrollRequest(stream, req)
	if err != nil {
		t.Fatalf("expected nil error on context cancel, got: %v", err)
	}
	if approvalSent {
		t.Fatal("expected approvalSent=false when context is cancelled")
	}
}

// TestHandleReEnrollRequest_ApprovalSignal: register session, send approval signal → returns true, nil
func TestHandleReEnrollRequest_ApprovalSignal(t *testing.T) {
	h, st := testHandler(t)
	h.storageKey = "test-storage-key-0123456789"

	// Seed server with node crypto.
	seedServer(t, h, "srv-approve")
	if err := st.SetNodeCrypto("srv-approve", "dGVzdC1wdWI=", "00112233", "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	stream := &mockStream{ctx: context.Background()}
	req := &pb.ReEnrollRequest{
		ServerId:    "srv-approve",
		Fingerprint: "fp-x",
		Csr:         testRegistrationCSR(t),
	}

	// Send an approval signal via goroutine after a tiny delay, so the select
	// in handleReEnrollRequest can pick it up.
	go func() {
		time.Sleep(5 * time.Millisecond)
		sess, ok := h.lookupReEnroll("srv-approve")
		if !ok {
			return
		}
		sess.approve <- reEnrollApproval{
			ephemeralPub: make([]byte, 32),
			encryptedKek: make([]byte, 44),
			challenge:    make([]byte, 32),
			decidedBy:    "admin-1",
		}
	}()

	approvalSent, err := h.handleReEnrollRequest(stream, req)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if !approvalSent {
		t.Fatal("expected approvalSent=true when approval signal is delivered")
	}
	// Stream should have received a ReenrollApproved message.
	var foundApproved bool
	for _, msg := range stream.sent {
		if msg.GetReenrollApproved() != nil {
			foundApproved = true
			break
		}
	}
	if !foundApproved {
		t.Fatalf("expected ReenrollApproved message on stream, got %d messages", len(stream.sent))
	}
}

// ---------------------------------------------------------------------------
// handleReEnrollProof branches
// ---------------------------------------------------------------------------

// TestHandleReEnrollProof_NoSession: no session registered → sendDenied
func TestHandleReEnrollProof_NoSession(t *testing.T) {
	h, _ := testHandler(t)

	stream := &mockStream{ctx: context.Background()}
	proof := &pb.ReEnrollProof{Signature: []byte("bad-sig")}

	err := h.handleReEnrollProof(stream, "srv-no-session", proof)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	// Stream should receive a denied message.
	if len(stream.sent) == 0 || stream.sent[0].GetReenrollDenied() == nil {
		t.Fatalf("expected ReenrollDenied for missing session, got %v", stream.sent)
	}
}

// TestHandleReEnrollProof_InvalidPubKey: session exists but node has bad base64 pubkey
func TestHandleReEnrollProof_InvalidPubKey(t *testing.T) {
	h, st := testHandler(t)

	seedServer(t, h, "srv-badpub")
	// Store a non-base64 pubkey so DecodeString fails.
	if err := st.SetNodeCrypto("srv-badpub", "not!!valid-base64", "00112233", "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	// Register a session for this server.
	sess := h.registerReEnroll("srv-badpub", testRegistrationCSR(t), "fp-x")
	sess.requestID = "re-badpub-1"
	sess.challenge = make([]byte, 32)

	stream := &mockStream{ctx: context.Background()}
	proof := &pb.ReEnrollProof{Signature: []byte("sig")}

	err := h.handleReEnrollProof(stream, "srv-badpub", proof)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	// Stream should receive a denied message.
	var foundDenied bool
	for _, msg := range stream.sent {
		if msg.GetReenrollDenied() != nil {
			foundDenied = true
			break
		}
	}
	if !foundDenied {
		t.Fatalf("expected ReenrollDenied for invalid pubkey, got %v", stream.sent)
	}
}

// TestHandleReEnrollProof_SignatureVerifyFails: correct session, wrong signature → denied
func TestHandleReEnrollProof_SignatureVerifyFails(t *testing.T) {
	h, st := testHandler(t)

	seedServer(t, h, "srv-badsig")

	// Generate a real ed25519 key pair and store the public key.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if err := st.SetNodeCrypto("srv-badsig", pubB64, "00112233", "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	// Register session with a non-nil challenge.
	sess := h.registerReEnroll("srv-badsig", testRegistrationCSR(t), "fp-x")
	sess.requestID = "re-badsig-1"
	challenge := make([]byte, 32)
	sess.challenge = challenge

	stream := &mockStream{ctx: context.Background()}
	// Pass a wrong signature — verification must fail.
	proof := &pb.ReEnrollProof{Signature: []byte("wrong-signature-bytes")}

	err = h.handleReEnrollProof(stream, "srv-badsig", proof)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	var foundDenied bool
	for _, msg := range stream.sent {
		if msg.GetReenrollDenied() != nil {
			foundDenied = true
			break
		}
	}
	if !foundDenied {
		t.Fatalf("expected ReenrollDenied for bad signature, got %v", stream.sent)
	}
}

// TestHandleReEnrollProof_CertIssuanceFails: correct session, correct signature, handler has no CA → cert issuance fails
func TestHandleReEnrollProof_CertIssuanceFails(t *testing.T) {
	h, st := testHandler(t)

	// Remove the CA so cert issuance will fail.
	h.caCert = nil
	h.caKey = nil

	seedServer(t, h, "srv-noca")

	// Generate a real ed25519 key pair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if err := st.SetNodeCrypto("srv-noca", pubB64, "00112233", "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	// Register session with a known challenge.
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatalf("random challenge: %v", err)
	}

	sess := h.registerReEnroll("srv-noca", testRegistrationCSR(t), "fp-x")
	sess.requestID = "re-noca-1"
	sess.challenge = challenge
	sess.decidedBy = "admin-1"

	// Sign the challenge with the correct private key.
	sig := ed25519.Sign(priv, challenge)

	stream := &mockStream{ctx: context.Background()}
	proof := &pb.ReEnrollProof{Signature: sig}

	err = h.handleReEnrollProof(stream, "srv-noca", proof)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	// The stream should receive a denied message because CA is nil.
	var foundDenied bool
	for _, msg := range stream.sent {
		if msg.GetReenrollDenied() != nil {
			foundDenied = true
			break
		}
	}
	if !foundDenied {
		t.Fatalf("expected ReenrollDenied when CA is nil, got %v", stream.sent)
	}
	// The result channel should have an error posted.
	select {
	case resultErr := <-sess.result:
		if resultErr == nil {
			t.Fatal("expected non-nil error on sess.result when CA is nil")
		}
	default:
		t.Fatal("expected error posted on sess.result")
	}
}

// ---------------------------------------------------------------------------
// ReleaseKEK error branches
// ---------------------------------------------------------------------------

// TestReleaseKEK_NoSession: no pending session → error "no pending re-enroll for server"
func TestReleaseKEK_NoSession(t *testing.T) {
	h, _ := testHandler(t)

	err := h.ReleaseKEK("srv-no-session", "admin-1")
	if err == nil {
		t.Fatal("expected error when no session exists")
	}
	if !strings.Contains(err.Error(), "no pending re-enroll") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestReleaseKEK_StorageKeyNotSet: session exists but handler has no storageKey → openKEK fails
func TestReleaseKEK_StorageKeyNotSet(t *testing.T) {
	h, st := testHandler(t)
	// storageKey is empty by default — do not set it.

	seedServer(t, h, "srv-nostorage")
	// Provide some node crypto so GetNodeCrypto succeeds but openKEK will fail.
	if err := st.SetNodeCrypto("srv-nostorage", "dGVzdC1wdWI=", "aabbcc", "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	// Register a live session.
	_ = h.registerReEnroll("srv-nostorage", testRegistrationCSR(t), "fp-x")

	err := h.ReleaseKEK("srv-nostorage", "admin-1")
	if err == nil {
		t.Fatal("expected error when storageKey is not set")
	}
	if !strings.Contains(err.Error(), "storageKey not configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestReleaseKEK_NoTransportPub: session + KEK OK, but no transport pub set → error
func TestReleaseKEK_NoTransportPub(t *testing.T) {
	h, st := testHandler(t)
	h.storageKey = "test-storage-key-0123456789"

	seedServer(t, h, "srv-notransport")

	// Seal a real KEK so openKEK succeeds.
	kekRaw := make([]byte, 32)
	kekEnc, err := h.sealKEK(kekRaw)
	if err != nil {
		t.Fatalf("sealKEK: %v", err)
	}
	if err := st.SetNodeCrypto("srv-notransport", "dGVzdC1wdWI=", kekEnc, "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}
	// Do NOT call SetNodeTransportPub — it stays NULL.

	_ = h.registerReEnroll("srv-notransport", testRegistrationCSR(t), "fp-x")

	err = h.ReleaseKEK("srv-notransport", "admin-1")
	if err == nil {
		t.Fatal("expected error when no transport pubkey is set")
	}
	if !strings.Contains(err.Error(), "no transport key") && !strings.Contains(err.Error(), "transport") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestReleaseKEK_BadTransportPub: session with bad base64 transport pub → decode error
func TestReleaseKEK_BadTransportPub(t *testing.T) {
	h, st := testHandler(t)
	h.storageKey = "test-storage-key-0123456789"

	seedServer(t, h, "srv-badtransport")

	// Seal a real KEK.
	kekRaw := make([]byte, 32)
	kekEnc, err := h.sealKEK(kekRaw)
	if err != nil {
		t.Fatalf("sealKEK: %v", err)
	}
	if err := st.SetNodeCrypto("srv-badtransport", "dGVzdC1wdWI=", kekEnc, "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}
	// Store invalid base64 as transport pub.
	if err := st.SetNodeTransportPub("srv-badtransport", "not!!valid-base64"); err != nil {
		t.Fatalf("SetNodeTransportPub: %v", err)
	}

	_ = h.registerReEnroll("srv-badtransport", testRegistrationCSR(t), "fp-x")

	err = h.ReleaseKEK("srv-badtransport", "admin-1")
	if err == nil {
		t.Fatal("expected error for bad base64 transport pub")
	}
	if !strings.Contains(err.Error(), "decode transport pubkey") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestReleaseKEK_ResultError: approval delivered, but proof handler posts an error on sess.result.
// This tests the result-channel path in ReleaseKEK (without waiting 30 seconds for real timeout).
func TestReleaseKEK_ResultError(t *testing.T) {
	h, st := testHandler(t)
	h.storageKey = "test-storage-key-0123456789"

	seedServer(t, h, "srv-result-err")

	// Seal a real KEK.
	kekRaw := make([]byte, 32)
	kekEnc, err := h.sealKEK(kekRaw)
	if err != nil {
		t.Fatalf("sealKEK: %v", err)
	}
	if err := st.SetNodeCrypto("srv-result-err", "dGVzdC1wdWI=", kekEnc, "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	// Store a valid 32-byte X25519 public key (the KAT transport pub from kektransport_test.go).
	transportPubHex := "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
	transportPubBytes := make([]byte, 32)
	if _, err := fmt.Sscanf(transportPubHex, "%x", &transportPubBytes); err != nil {
		// Decode hex manually.
		for i := 0; i < 32; i++ {
			b := transportPubHex[i*2 : i*2+2]
			var v byte
			fmt.Sscanf(b, "%02x", &v)
			transportPubBytes[i] = v
		}
	}
	transportPubB64 := base64.StdEncoding.EncodeToString(transportPubBytes)
	if err := st.SetNodeTransportPub("srv-result-err", transportPubB64); err != nil {
		t.Fatalf("SetNodeTransportPub: %v", err)
	}

	sess := h.registerReEnroll("srv-result-err", testRegistrationCSR(t), "fp-x")

	// Goroutine: receive from sess.approve (ReleaseKEK sends to it), then post an error on sess.result.
	go func() {
		<-sess.approve
		sess.result <- errors.New("proof verification failed")
	}()

	releaseErr := h.ReleaseKEK("srv-result-err", "admin-1")
	if releaseErr == nil {
		t.Fatal("expected error from ReleaseKEK when proof fails")
	}
	if !strings.Contains(releaseErr.Error(), "proof verification failed") {
		t.Fatalf("unexpected error: %v", releaseErr)
	}
}

// TestHandleReEnrollProof_Success drives the proof happy-path: a valid ed25519
// signature over the challenge results in a signed client cert delivered via
// CertRenewResponse, the DB status flipped to "approved", and a nil error posted
// on sess.result. This covers the success block of handleReEnrollProof
// (SignCSR → CertRenewResponse send → UpdateReEnrollStatus → result<-nil).
func TestHandleReEnrollProof_Success(t *testing.T) {
	h, st := testHandler(t) // testHandler wires a real CA.

	seedServer(t, h, "srv-proof-ok")

	// Real ed25519 key pair; store the public key so verification passes.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if err := st.SetNodeCrypto("srv-proof-ok", pubB64, "00112233", "fp-x"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	// Persist a re-enroll request row so UpdateReEnrollStatus("approved") succeeds.
	reqRow := &model.ReEnrollRequest{
		ID: "re-proof-ok-1", ServerID: "srv-proof-ok", RequestedAt: "2026-07-11 00:00:00",
		IPAddress: "10.0.0.1", Fingerprint: "fp-x", Status: "pending", AnomalyFlags: "{}",
	}
	if err := st.CreateReEnrollRequest(reqRow); err != nil {
		t.Fatalf("CreateReEnrollRequest: %v", err)
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatalf("random challenge: %v", err)
	}

	sess := h.registerReEnroll("srv-proof-ok", testRegistrationCSR(t), "fp-x")
	sess.requestID = "re-proof-ok-1"
	sess.challenge = challenge
	sess.decidedBy = "admin-9"

	sig := ed25519.Sign(priv, challenge)
	stream := &mockStream{ctx: context.Background()}
	proof := &pb.ReEnrollProof{Signature: sig}

	if err := h.handleReEnrollProof(stream, "srv-proof-ok", proof); err != nil {
		t.Fatalf("expected nil error on proof success, got: %v", err)
	}

	// The stream must have received a CertRenewResponse carrying the client + CA certs.
	var certResp *pb.CertRenewResponse
	for _, msg := range stream.sent {
		if cr := msg.GetCertRenewResponse(); cr != nil {
			certResp = cr
			break
		}
	}
	if certResp == nil {
		t.Fatalf("expected CertRenewResponse on stream, got %v", stream.sent)
	}
	if len(certResp.ClientCert) == 0 || len(certResp.CaCert) == 0 {
		t.Fatal("expected issued client + CA certificates in CertRenewResponse")
	}

	// The result channel must carry nil (success).
	select {
	case resultErr := <-sess.result:
		if resultErr != nil {
			t.Fatalf("expected nil error on sess.result, got: %v", resultErr)
		}
	default:
		t.Fatal("expected a value posted on sess.result")
	}

	// DB status must be "approved" with the decidedBy admin recorded, and the
	// session must be cleared from the registry.
	dbReq, err := st.GetReEnrollRequest("re-proof-ok-1")
	if err != nil {
		t.Fatalf("GetReEnrollRequest: %v", err)
	}
	if dbReq.Status != "approved" {
		t.Fatalf("expected status approved, got %q", dbReq.Status)
	}
	if dbReq.DecidedBy != "admin-9" {
		t.Fatalf("expected decided_by admin-9, got %q", dbReq.DecidedBy)
	}
	if _, ok := h.lookupReEnroll("srv-proof-ok"); ok {
		t.Fatal("expected session to be cleared after successful proof")
	}
}

// TestHandleReEnrollProof_NoNodeCrypto covers the "server not enrolled" branch:
// a live session exists but GetNodeCrypto returns empty pubkey → denied + error
// posted on sess.result.
func TestHandleReEnrollProof_NoNodeCrypto(t *testing.T) {
	h, _ := testHandler(t)

	seedServer(t, h, "srv-no-crypto")
	// Intentionally do NOT call SetNodeCrypto — pubkey stays empty.

	sess := h.registerReEnroll("srv-no-crypto", testRegistrationCSR(t), "fp-x")
	sess.requestID = "re-no-crypto-1"
	sess.challenge = make([]byte, 32)

	stream := &mockStream{ctx: context.Background()}
	proof := &pb.ReEnrollProof{Signature: []byte("sig")}

	if err := h.handleReEnrollProof(stream, "srv-no-crypto", proof); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(stream.sent) == 0 || stream.sent[0].GetReenrollDenied() == nil {
		t.Fatalf("expected ReenrollDenied for un-enrolled server, got %v", stream.sent)
	}
	select {
	case resultErr := <-sess.result:
		if resultErr == nil {
			t.Fatal("expected non-nil error on sess.result")
		}
	default:
		t.Fatal("expected error posted on sess.result")
	}
}

// TestHandleReEnrollRequest_CloneSuspectedAudit exercises the anomaly-flag audit
// path: an online original server with a changed fingerprint triggers both
// anomaly flags, causing handleReEnrollRequest to emit a clone-suspected audit.
// The request then blocks; we cancel the context to unblock the select.
func TestHandleReEnrollRequest_CloneSuspectedAudit(t *testing.T) {
	h, st := testHandler(t)
	h.storageKey = "test-storage-key-0123456789"

	// Server is ONLINE and the stored fingerprint differs from the request → both
	// anomaly flags set.
	if err := st.CreateServer(&model.Server{ID: "srv-clone", Name: "srv-clone", Status: "online", Labels: "{}"}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	if err := st.SetNodeCrypto("srv-clone", "dGVzdC1wdWI=", "00112233", "fp-original"); err != nil {
		t.Fatalf("SetNodeCrypto: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel so the blocking select returns immediately after the audit is emitted.

	stream := &mockStream{ctx: ctx}
	req := &pb.ReEnrollRequest{
		ServerId:    "srv-clone",
		Fingerprint: "fp-DIFFERENT",
		Csr:         testRegistrationCSR(t),
	}

	approvalSent, err := h.handleReEnrollRequest(stream, req)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if approvalSent {
		t.Fatal("expected approvalSent=false when context is cancelled")
	}

	// A clone-suspected audit entry must have been logged.
	action := model.AuditCloneSuspected
	entries, total, err := st.ListAuditLogs(model.AuditFilter{Action: &action, Limit: 10})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if total < 1 || len(entries) < 1 {
		t.Fatalf("expected a clone-suspected audit entry, got total=%d", total)
	}
}

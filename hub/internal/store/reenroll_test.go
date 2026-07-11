package store_test

import (
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
)

// seedServer inserts a minimal server row with the given id.
func seedServer(t *testing.T, s interface {
	CreateServer(*model.Server) error
}, id string) {
	t.Helper()
	if err := s.CreateServer(&model.Server{
		ID:     id,
		Name:   id,
		Status: "pending",
		Labels: "{}",
	}); err != nil {
		t.Fatalf("seed server %s: %v", id, err)
	}
}

// TestNodeTransportPubRoundTrip verifies that SetNodeTransportPub and
// GetNodeTransportPub persist and retrieve the X25519 transport public key.
func TestNodeTransportPubRoundTrip(t *testing.T) {
	s := testStore(t)
	seedServer(t, s, "srv-tp")

	// Newly seeded server has no transport pubkey — must return empty string.
	got, err := s.GetNodeTransportPub("srv-tp")
	if err != nil {
		t.Fatalf("GetNodeTransportPub (empty): %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty transport pubkey, got %q", got)
	}

	// Store a transport pubkey.
	const wantPub = "TRANSPORT_PUBKEY_B64=="
	if err := s.SetNodeTransportPub("srv-tp", wantPub); err != nil {
		t.Fatalf("SetNodeTransportPub: %v", err)
	}

	// Retrieve and verify.
	got, err = s.GetNodeTransportPub("srv-tp")
	if err != nil {
		t.Fatalf("GetNodeTransportPub (set): %v", err)
	}
	if got != wantPub {
		t.Fatalf("transport pubkey round-trip mismatch: got %q, want %q", got, wantPub)
	}

	// Unknown server must return errServerNotFound.
	_, err = s.GetNodeTransportPub("no-such-server")
	if err == nil {
		t.Fatal("expected error for unknown server, got nil")
	}

	// SetNodeTransportPub on unknown server must also fail.
	if err := s.SetNodeTransportPub("no-such-server", wantPub); err == nil {
		t.Fatal("expected error for SetNodeTransportPub on unknown server, got nil")
	}
}

func TestNodeCryptoRoundTrip(t *testing.T) {
	s := testStore(t)
	seedServer(t, s, "srv-1")
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
	s := testStore(t)
	seedServer(t, s, "srv-2")
	r := &model.ReEnrollRequest{
		ID:           "re-1",
		ServerID:     "srv-2",
		RequestedAt:  "2026-07-11 00:00:00",
		IPAddress:    "1.2.3.4",
		Fingerprint:  "fp",
		Status:       "pending",
		AnomalyFlags: "{}",
	}
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

// TestGetReEnrollRequestNullableColumns verifies that GetReEnrollRequest
// succeeds when nullable columns (ip_address, fingerprint, anomaly_flags,
// decided_by) contain NULL — the typical state of a freshly-created pending
// request before any decision has been recorded.
func TestGetReEnrollRequestNullableColumns(t *testing.T) {
	s := testStore(t)
	seedServer(t, s, "srv-null")

	// Insert a row with explicit NULLs for the four nullable columns so that
	// we reproduce the exact condition that breaks GetReEnrollRequest when it
	// scans into plain string fields instead of sql.NullString.
	_, err := s.DB().Exec(
		`INSERT INTO reenroll_requests (id, server_id, requested_at, ip_address, fingerprint, status, anomaly_flags, decided_by)
		 VALUES (?, ?, ?, NULL, NULL, 'pending', NULL, NULL)`,
		"re-null", "srv-null", "2026-07-11 00:00:00",
	)
	if err != nil {
		t.Fatalf("seed row: %v", err)
	}

	got, err := s.GetReEnrollRequest("re-null")
	if err != nil {
		t.Fatalf("GetReEnrollRequest with NULL columns: %v", err)
	}
	if got.ID != "re-null" {
		t.Fatalf("expected id=re-null, got %q", got.ID)
	}
	// NULL columns must map to empty string.
	if got.IPAddress != "" || got.Fingerprint != "" || got.AnomalyFlags != "" || got.DecidedBy != "" {
		t.Fatalf("expected empty strings for NULL columns, got ip=%q fp=%q flags=%q decided=%q",
			got.IPAddress, got.Fingerprint, got.AnomalyFlags, got.DecidedBy)
	}
}

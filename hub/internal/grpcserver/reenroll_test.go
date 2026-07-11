package grpcserver

import (
	"strings"
	"testing"

	"github.com/wyiu/veyport/hub/internal/model"
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

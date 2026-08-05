package commands

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// TestLogout_InvalidatesServerSideAndDeletesLocal covers FR-006 / US1-4:
// logout invalidates the session server-side (POST /api/auth/logout with
// the session's bearer) and deletes the local store entry.
func TestLogout_InvalidatesServerSideAndDeletesLocal(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	var logoutCalls int
	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		logoutCalls++
		if !requireBearer(r, "access-1") {
			t.Errorf("logout request missing expected session bearer")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "alice",
		Role:         "admin",
		ObtainedAt:   time.Now(),
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, nil)
	code := RunLogout(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
	}
	if logoutCalls != 1 {
		t.Errorf("POST /api/auth/logout calls = %d, want 1", logoutCalls)
	}

	store, err := auth.NewStore(configDir, nil)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	if _, ok, err := store.Load(srv.URL); err != nil {
		t.Fatalf("store.Load: %v", err)
	} else if ok {
		t.Errorf("session for %s still present after logout", srv.URL)
	}
}

// TestLogout_ServerCallFails_StillExit0 covers "Exit 0 even if the server
// call fails, with a stderr note."
func TestLogout_ServerCallFails_StillExit0(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "boom"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "alice",
		Role:         "admin",
		ObtainedAt:   time.Now(),
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, nil)
	code := RunLogout(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK) even on server-call failure; stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
	}
	if stderr.String() == "" {
		t.Errorf("stderr = empty, want a note about the failed server-side invalidation")
	}

	store, err := auth.NewStore(configDir, nil)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	if _, ok, err := store.Load(srv.URL); err != nil {
		t.Fatalf("store.Load: %v", err)
	} else if ok {
		t.Errorf("session for %s still present after logout despite server-call failure", srv.URL)
	}
}

// TestLogout_NothingToLogout_SessionMode covers "exit 3 only if there was
// nothing to log out."
func TestLogout_NothingToLogout_SessionMode(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("POST /api/auth/logout should not be called when there is nothing to log out")
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, nil)
	code := RunLogout(ctx)
	if code != cmdutil.ExitAuth {
		t.Fatalf("exit code = %d, want %d (ExitAuth); stdout=%q stderr=%q", code, cmdutil.ExitAuth, stdout.String(), stderr.String())
	}
}

// TestLogout_APITokenMode_NothingLocal covers: "API-token mode: nothing to
// log out locally → exit 3 with note that token comes from env/config."
func TestLogout_APITokenMode_NothingLocal(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "adt_abcdefgh12345678")

	srv := httptest.NewServer(http.NewServeMux())
	defer srv.Close()

	configDir := t.TempDir()
	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, nil)
	code := RunLogout(ctx)
	if code != cmdutil.ExitAuth {
		t.Fatalf("exit code = %d, want %d (ExitAuth); stdout=%q stderr=%q", code, cmdutil.ExitAuth, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "env") && !strings.Contains(stderr.String(), "config") {
		t.Errorf("stderr = %q, want a note that the token comes from env/config", stderr.String())
	}
}

// TestLogout_NoHubExitUsage covers RunLogout's RequireHub failure branch.
func TestLogout_NoHubExitUsage(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")
	ctx, stdout, stderr := newCmdContext("", t.TempDir(), false, nil)
	code := RunLogout(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
}

// TestLogout_AuthContextFailure covers RunLogout's newAuthContext error
// branch via a malformed VEYPORT_TOKEN.
func TestLogout_AuthContextFailure(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "malformed-token")
	srv := httptest.NewServer(http.NewServeMux())
	defer srv.Close()

	ctx, stdout, stderr := newCmdContext(srv.URL, t.TempDir(), false, nil)
	code := RunLogout(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
}

// TestLogout_StoreDeleteFails covers RunLogout's store.Delete error branch:
// the credential store is file-backed in this environment (no OS keyring),
// so making its directory read-only makes the atomic rewrite Delete
// performs fail with a permission error, without touching any source file.
func TestLogout_StoreDeleteFails(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1", Username: "alice", Role: "admin", ObtainedAt: time.Now(),
	})

	store, err := auth.NewStore(configDir, io.Discard)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	if store.Backend() != auth.BackendFile {
		t.Skipf("credential store backend = %q, want %q for this permission-based test", store.Backend(), auth.BackendFile)
	}

	if err := os.Chmod(configDir, 0o500); err != nil {
		t.Fatalf("chmod configDir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(configDir, 0o700) })

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, nil)
	code := RunLogout(ctx)
	if code != cmdutil.ExitError {
		t.Fatalf("exit code = %d, want %d (ExitError); stdout=%q stderr=%q", code, cmdutil.ExitError, stdout.String(), stderr.String())
	}
}

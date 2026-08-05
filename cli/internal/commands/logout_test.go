package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

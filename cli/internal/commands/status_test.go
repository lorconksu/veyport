package commands

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/wyiu/veyport/cli/internal/config"
)

// --- shared scaffolding (also used by logout_test.go and servers_test.go) ---
//
// These commands need a real *Context wired to an httptest hub, a
// file-backed credential store seeded with a StoredSession (so AuthContext
// resolves to session mode), and a stub /api/auth/refresh so the session's
// access token can be minted from the seeded refresh token
// (specs/004-cli-connector/tasks.md T011).

// newCmdContext builds a *Context whose hub is hubURL (supplied as the
// --hub flag, so ctx.HubSource == "flag"), backed by a fresh Printer that
// captures stdout/stderr into the returned buffers.
func newCmdContext(hubURL, configDir string, jsonMode bool, args []string) (*Context, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	printer := cmdutil.NewPrinter(&stdout, &stderr, jsonMode)
	c := NewContext(hubURL, "", config.Config{}, configDir, printer, args)
	return c, &stdout, &stderr
}

// seedSession persists sess for hubURL in configDir's credential store, so
// a command run against a Context pointed at configDir resolves to session
// auth mode for that hub.
//
// warnW is nil, not io.Discard: per auth.NewStore's docs, nil suppresses the
// keyring-fallback warning without consuming the process-wide one-time
// budget, whereas a non-nil writer (even a discarding one) does consume it.
// seedSession runs ahead of nearly every test in this package, so using
// io.Discard here would silently exhaust that budget before any test that
// actually asserts the warning's behavior gets to run.
func seedSession(t *testing.T, configDir, hubURL string, sess auth.StoredSession) {
	t.Helper()
	store, err := auth.NewStore(configDir, nil)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	if err := store.Save(hubURL, sess); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
}

// mountRefresh registers the /api/auth/refresh stub every session-mode test
// needs so AuthContext can mint an access token from the seeded refresh
// token.
func mountRefresh(mux *http.ServeMux, accessToken, refreshToken string) {
	mux.HandleFunc("POST /api/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	})
}

// requireBearer reports whether r carries exactly "Bearer "+want.
func requireBearer(r *http.Request, want string) bool {
	return r.Header.Get("Authorization") == "Bearer "+want
}

// decodeJSON decodes stdout (a single JSON document, per the --json
// contract) into a generic map for loose field assertions.
func decodeJSON(t *testing.T, stdout *bytes.Buffer) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("decode stdout JSON: %v (stdout: %q)", err, stdout.String())
	}
	return out
}

// --- vey status ---------------------------------------------------------

// TestStatus_SessionMode_Reachable covers contracts/cli-commands.md `vey
// status`: session mode, hub reachable via GET /api/auth/me, --json shape
// {hub, hub_source, mode, username, role, reachable, storage}.
func TestStatus_SessionMode_Reachable(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mux.HandleFunc("GET /api/auth/me", func(w http.ResponseWriter, r *http.Request) {
		if !requireBearer(r, "access-1") {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"username": "alice", "role": "admin"})
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

	ctx, stdout, _ := newCmdContext(srv.URL, configDir, true, nil)
	code := RunStatus(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q", code, cmdutil.ExitOK, stdout.String())
	}

	got := decodeJSON(t, stdout)
	if got["hub"] != srv.URL {
		t.Errorf("hub = %v, want %v", got["hub"], srv.URL)
	}
	if got["hub_source"] != "flag" {
		t.Errorf("hub_source = %v, want %q", got["hub_source"], "flag")
	}
	if got["mode"] != "session" {
		t.Errorf("mode = %v, want %q", got["mode"], "session")
	}
	if got["username"] != "alice" {
		t.Errorf("username = %v, want %q", got["username"], "alice")
	}
	if got["role"] != "admin" {
		t.Errorf("role = %v, want %q", got["role"], "admin")
	}
	if got["reachable"] != true {
		t.Errorf("reachable = %v, want true", got["reachable"])
	}
	storage, _ := got["storage"].(string)
	if storage != auth.BackendKeyring && storage != auth.BackendFile {
		t.Errorf("storage = %v, want %q or %q", got["storage"], auth.BackendKeyring, auth.BackendFile)
	}
}

// TestStatus_NotSignedIn covers the "not signed in" mode: no stored
// session, no API token → mode "none", reachable false, exit 3.
func TestStatus_NotSignedIn(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/me", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("GET /api/auth/me should not be called when nothing is signed in")
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	ctx, stdout, _ := newCmdContext(srv.URL, configDir, true, nil)
	code := RunStatus(ctx)
	if code != cmdutil.ExitAuth {
		t.Fatalf("exit code = %d, want %d (ExitAuth); stdout=%q", code, cmdutil.ExitAuth, stdout.String())
	}

	got := decodeJSON(t, stdout)
	if got["mode"] != "none" {
		t.Errorf("mode = %v, want %q", got["mode"], "none")
	}
	if got["reachable"] != false {
		t.Errorf("reachable = %v, want false", got["reachable"])
	}
}

// TestStatus_APIToken_Prefix covers api_token mode: the human-readable
// report shows only the token's first 8 characters plus an ellipsis, never
// the full secret (contracts/cli-commands.md: "vey status shows token
// prefix only").
func TestStatus_APIToken_Prefix(t *testing.T) {
	const token = "adt_1234567890abcdef"
	t.Setenv("VEYPORT_TOKEN", token)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/me", func(w http.ResponseWriter, r *http.Request) {
		if !requireBearer(r, token) {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"username": "svc", "role": "operator"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	ctx, stdout, _ := newCmdContext(srv.URL, configDir, false, nil)
	code := RunStatus(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q", code, cmdutil.ExitOK, stdout.String())
	}

	out := stdout.String()
	if !bytes.Contains([]byte(out), []byte("adt_1234")) {
		t.Errorf("stdout = %q, want it to contain the 8-char token prefix %q", out, "adt_1234")
	}
	if bytes.Contains([]byte(out), []byte(token)) {
		t.Errorf("stdout = %q, must never contain the full token %q", out, token)
	}
}

// TestStatus_Unreachable_ConnError covers connectivity failure mapping to
// exit 6 (contracts/cli-commands.md: reachability failures map to exit
// 3/6; connection errors specifically to 6).
func TestStatus_Unreachable_ConnError(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	srv := httptest.NewServer(mux)
	hubURL := srv.URL
	srv.Close() // nothing is listening anymore: every round trip fails to connect

	configDir := t.TempDir()
	seedSession(t, configDir, hubURL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "alice",
		Role:         "admin",
		ObtainedAt:   time.Now(),
	})

	ctx, stdout, _ := newCmdContext(hubURL, configDir, true, nil)
	code := RunStatus(ctx)
	if code != cmdutil.ExitConn {
		t.Fatalf("exit code = %d, want %d (ExitConn); stdout=%q", code, cmdutil.ExitConn, stdout.String())
	}

	got := decodeJSON(t, stdout)
	if got["reachable"] != false {
		t.Errorf("reachable = %v, want false", got["reachable"])
	}
}

// TestStatus_EmptyConfigDir_StoreConstructionError covers newAuthContext's
// own auth.NewStore failure branch (shared helper, status.go): an empty
// ConfigDir fails store construction outright, independent of any TTY or
// credential state.
func TestStatus_EmptyConfigDir_StoreConstructionError(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")
	ctx, stdout, stderr := newCmdContext("https://hub.example.com", "", true, nil)
	code := RunStatus(ctx)
	if code != cmdutil.ExitError {
		t.Fatalf("exit code = %d, want %d (ExitError); stdout=%q stderr=%q", code, cmdutil.ExitError, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty (RunStatus's own newAuthContext failure never reaches printStatus)", stdout.String())
	}
}

// TestStatus_AuthContextFailure covers RunStatus's newAuthContext error
// branch via auth.Resolve failing (a malformed VEYPORT_TOKEN, rejected by
// local validation before any hub round trip).
func TestStatus_AuthContextFailure(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "malformed-token")
	ctx, stdout, stderr := newCmdContext("https://hub.example.com", t.TempDir(), false, nil)
	code := RunStatus(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
}

// TestStatus_HumanMode_SessionAndNotSignedIn covers humanMode's "session"
// case and printStatus's human-mode rendering: every other status test in
// this file runs with --json, so the human-readable report is otherwise
// unexercised.
func TestStatus_HumanMode_SessionAndNotSignedIn(t *testing.T) {
	t.Run("session", func(t *testing.T) {
		t.Setenv("VEYPORT_TOKEN", "")
		mux := http.NewServeMux()
		mountRefresh(mux, "access-1", "refresh-2")
		mux.HandleFunc("GET /api/auth/me", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"username": "alice", "role": "admin"})
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		configDir := t.TempDir()
		seedSession(t, configDir, srv.URL, auth.StoredSession{
			RefreshToken: "refresh-1", Username: "alice", Role: "admin", ObtainedAt: time.Now(),
		})

		ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, nil)
		code := RunStatus(ctx)
		if code != cmdutil.ExitOK {
			t.Fatalf("exit code = %d, want %d (ExitOK); stderr=%q", code, cmdutil.ExitOK, stderr.String())
		}
		out := stdout.String()
		if !strings.Contains(out, "interactive session as alice (admin)") {
			t.Errorf("stdout = %q, want the human session line", out)
		}
		if !strings.Contains(out, "Reachable: true") {
			t.Errorf("stdout = %q, want a Reachable line", out)
		}
	})

	t.Run("not_signed_in", func(t *testing.T) {
		t.Setenv("VEYPORT_TOKEN", "")
		srv := httptest.NewServer(http.NewServeMux())
		defer srv.Close()

		ctx, stdout, stderr := newCmdContext(srv.URL, t.TempDir(), false, nil)
		code := RunStatus(ctx)
		if code != cmdutil.ExitAuth {
			t.Fatalf("exit code = %d, want %d (ExitAuth); stderr=%q", code, cmdutil.ExitAuth, stderr.String())
		}
		if !strings.Contains(stdout.String(), "not signed in") {
			t.Errorf("stdout = %q, want the human not-signed-in line", stdout.String())
		}
	})
}

// TestStatus_ReachableAuthError_ExitAuth covers RunStatus's final fallback
// return (exit 3) when GET /api/auth/me fails with something other than a
// connectivity error: the session itself has been invalidated hub-side.
func TestStatus_ReachableAuthError_ExitAuth(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")
	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mux.HandleFunc("GET /api/auth/me", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "session revoked"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1", Username: "alice", Role: "admin", ObtainedAt: time.Now(),
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, nil)
	code := RunStatus(ctx)
	if code != cmdutil.ExitAuth {
		t.Fatalf("exit code = %d, want %d (ExitAuth); stdout=%q stderr=%q", code, cmdutil.ExitAuth, stdout.String(), stderr.String())
	}
	got := decodeJSON(t, stdout)
	if got["reachable"] != false {
		t.Errorf("reachable = %v, want false", got["reachable"])
	}
}

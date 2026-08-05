package commands

// JSON/no-TTY conformance tests for User Story 2 (spec 004-cli-connector
// T017): every *implemented* command's --json stdout is exactly one
// parseable JSON document with zero non-JSON bytes, diagnostics land on
// stderr only, error paths leave stdout empty and emit the {"error","code"}
// shape on stderr, and no command ever attempts a prompt when stdin is not a
// TTY (SC-004, contracts/cli-commands.md "Global behavior" / "Output
// discipline").
//
// Scope matches T019's sweep: login, logout, status, servers list/get.
// files/logs/audit are still stubs (T021/T025/T027) and are out of scope
// here, same as for the sweep.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// --- shared assertions ------------------------------------------------

// assertSingleJSONDoc verifies data decodes as exactly one JSON document
// with nothing but optional trailing whitespace after it — the "stdout is
// exactly one JSON document" / "zero non-JSON bytes" contract.
func assertSingleJSONDoc(t *testing.T, label string, data []byte) {
	t.Helper()
	if len(data) == 0 {
		t.Fatalf("%s: stdout is empty, want exactly one JSON document", label)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("%s: stdout is not a single valid JSON document: %v (stdout=%q)", label, err, data)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatalf("%s: stdout contains more than one JSON document / trailing non-JSON bytes (stdout=%q)", label, data)
	}
}

// assertEmptyStdout verifies nothing was written to stdout — the "NOTHING on
// stdout" half of the error-path contract.
func assertEmptyStdout(t *testing.T, label string, stdout *bytes.Buffer) {
	t.Helper()
	if stdout.Len() != 0 {
		t.Errorf("%s: stdout = %q, want empty on an error path", label, stdout.String())
	}
}

// assertJSONErrorShape verifies stderr is exactly one {"error","code"}
// document with the expected code and a non-empty message, and nothing
// beyond it.
func assertJSONErrorShape(t *testing.T, label string, stderr *bytes.Buffer, wantCode int) {
	t.Helper()
	data := stderr.Bytes()
	dec := json.NewDecoder(bytes.NewReader(data))
	var payload struct {
		Error string `json:"error"`
		Code  int    `json:"code"`
	}
	if err := dec.Decode(&payload); err != nil {
		t.Fatalf("%s: stderr is not the {error,code} JSON shape: %v (stderr=%q)", label, err, data)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatalf("%s: stderr contains more than the one JSON error document (stderr=%q)", label, data)
	}
	if payload.Error == "" {
		t.Errorf("%s: stderr JSON \"error\" field is empty", label)
	}
	if payload.Code != wantCode {
		t.Errorf("%s: stderr JSON \"code\" = %d, want %d", label, payload.Code, wantCode)
	}
}

// withNonTTYStdin swaps the process's os.Stdin for a plain (non-terminal)
// temp file for the duration of the test, restoring it on cleanup. Command
// entry points (e.g. RunLogin) read os.Stdin directly rather than taking it
// as a parameter, so exercising the "no prompt without a TTY" contract at
// the command level has to go through the real package variable — the same
// thing a piped invocation (`echo | vey login`) would present.
func withNonTTYStdin(t *testing.T) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = old })
}

// --- vey login -----------------------------------------------------------

// TestJSONLogin_NonTTY_NoPromptNoNetwork covers SC-004 at the command level:
// with stdin not a TTY, `vey login --json` fails fast (exit 3, API-token
// guidance), writes nothing to stdout, emits the {"error","code"} shape on
// stderr, and never attempts a prompt or a hub round trip.
func TestJSONLogin_NonTTY_NoPromptNoNetwork(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	var loginCalls, totpCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		loginCalls++
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"totp_token": "tt-abc"})
	})
	mux.HandleFunc("POST /api/auth/login/totp", func(w http.ResponseWriter, r *http.Request) {
		totpCalls++
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	withNonTTYStdin(t)

	configDir := t.TempDir()
	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, nil)
	code := RunLogin(ctx)
	if code != cmdutil.ExitAuth {
		t.Fatalf("exit code = %d, want %d (ExitAuth); stdout=%q stderr=%q", code, cmdutil.ExitAuth, stdout.String(), stderr.String())
	}

	assertEmptyStdout(t, "login non-tty", stdout)
	assertJSONErrorShape(t, "login non-tty", stderr, cmdutil.ExitAuth)
	if !strings.Contains(stderr.String(), "VEYPORT_TOKEN") {
		t.Errorf("stderr = %q, want it to point at VEYPORT_TOKEN as the non-interactive alternative", stderr.String())
	}
	if loginCalls != 0 || totpCalls != 0 {
		t.Errorf("login hit the hub with no TTY attached: login=%d totp=%d, want 0 and 0", loginCalls, totpCalls)
	}
}

// --- vey logout ------------------------------------------------------------

// TestJSONLogout_Success_SingleDocument covers the success shape: exactly
// one JSON document {hub,status} on stdout, nothing unparseable mixed in.
func TestJSONLogout_Success_SingleDocument(t *testing.T) {
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

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, nil)
	code := RunLogout(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
	}
	assertSingleJSONDoc(t, "logout success", stdout.Bytes())

	got := decodeJSON(t, stdout)
	if got["hub"] != srv.URL {
		t.Errorf("hub = %v, want %v", got["hub"], srv.URL)
	}
	if got["status"] != "signed_out" {
		t.Errorf("status = %v, want %q", got["status"], "signed_out")
	}
}

// TestJSONLogout_ServerCallFails_StdoutStillCleanJSON covers the "exit 0
// even if the server call fails" path: the failure note goes to stderr
// (plain text is fine there — only stdout is JSON-only), while stdout still
// carries exactly the documented success document.
func TestJSONLogout_ServerCallFails_StdoutStillCleanJSON(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1", Username: "alice", Role: "admin", ObtainedAt: time.Now(),
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, nil)
	code := RunLogout(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
	}
	assertSingleJSONDoc(t, "logout server-call-fails", stdout.Bytes())
	if stderr.Len() == 0 {
		t.Errorf("stderr = empty, want a diagnostic note about the failed server-side invalidation")
	}
}

// TestJSONLogout_ErrorPaths_EmptyStdoutJSONStderr covers "nothing to log
// out" in both flavors (API-token mode, no stored session): stdout must be
// empty and stderr must carry the {"error","code"} shape, not a mix of the
// two.
func TestJSONLogout_ErrorPaths_EmptyStdoutJSONStderr(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{"api_token_mode", "adt_abcdefgh12345678"},
		{"nothing_stored", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VEYPORT_TOKEN", tc.token)

			srv := httptest.NewServer(http.NewServeMux())
			defer srv.Close()

			configDir := t.TempDir()
			ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, nil)
			code := RunLogout(ctx)
			if code != cmdutil.ExitAuth {
				t.Fatalf("exit code = %d, want %d (ExitAuth); stdout=%q stderr=%q", code, cmdutil.ExitAuth, stdout.String(), stderr.String())
			}
			assertEmptyStdout(t, tc.name, stdout)
			assertJSONErrorShape(t, tc.name, stderr, cmdutil.ExitAuth)
		})
	}
}

// --- vey status --------------------------------------------------------

// TestJSONStatus_AlwaysSingleDocument covers that `vey status --json`
// always emits its one documented shape on stdout — reachable, not signed
// in, and unreachable are normal reported states per contracts/cli-commands.md,
// not generic command failures, so unlike other commands' error paths they
// still produce a stdout payload even at a non-zero exit code.
func TestJSONStatus_AlwaysSingleDocument(t *testing.T) {
	t.Run("reachable_session", func(t *testing.T) {
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

		ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, nil)
		code := RunStatus(ctx)
		if code != cmdutil.ExitOK {
			t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
		}
		assertSingleJSONDoc(t, "status reachable", stdout.Bytes())
		if stderr.Len() != 0 {
			t.Errorf("stderr = %q, want empty on a clean reachable report", stderr.String())
		}
	})

	t.Run("not_signed_in", func(t *testing.T) {
		t.Setenv("VEYPORT_TOKEN", "")

		srv := httptest.NewServer(http.NewServeMux())
		defer srv.Close()

		configDir := t.TempDir()
		ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, nil)
		code := RunStatus(ctx)
		if code != cmdutil.ExitAuth {
			t.Fatalf("exit code = %d, want %d (ExitAuth); stdout=%q stderr=%q", code, cmdutil.ExitAuth, stdout.String(), stderr.String())
		}
		assertSingleJSONDoc(t, "status not signed in", stdout.Bytes())
	})

	t.Run("unreachable", func(t *testing.T) {
		t.Setenv("VEYPORT_TOKEN", "")

		mux := http.NewServeMux()
		mountRefresh(mux, "access-1", "refresh-2")
		srv := httptest.NewServer(mux)
		hubURL := srv.URL
		srv.Close() // nothing listening: every round trip now fails to connect

		configDir := t.TempDir()
		seedSession(t, configDir, hubURL, auth.StoredSession{
			RefreshToken: "refresh-1", Username: "alice", Role: "admin", ObtainedAt: time.Now(),
		})

		ctx, stdout, stderr := newCmdContext(hubURL, configDir, true, nil)
		code := RunStatus(ctx)
		if code != cmdutil.ExitConn {
			t.Fatalf("exit code = %d, want %d (ExitConn); stdout=%q stderr=%q", code, cmdutil.ExitConn, stdout.String(), stderr.String())
		}
		assertSingleJSONDoc(t, "status unreachable", stdout.Bytes())
	})
}

// TestJSONStatus_NoHub_EmptyStdoutJSONStderr covers the one genuine
// command-failure path status has (hub resolution itself fails): unlike the
// reachability states above, this is a usage error and must leave stdout
// empty.
func TestJSONStatus_NoHub_EmptyStdoutJSONStderr(t *testing.T) {
	configDir := t.TempDir()
	ctx, stdout, stderr := newCmdContext("", configDir, true, nil)
	code := RunStatus(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
	assertEmptyStdout(t, "status no hub", stdout)
	assertJSONErrorShape(t, "status no hub", stderr, cmdutil.ExitUsage)
}

// --- vey servers list ------------------------------------------------------

// TestJSONServersList_SingleDocument covers the --json envelope passthrough
// as exactly one document, both with rows and with zero rows.
func TestJSONServersList_SingleDocument(t *testing.T) {
	t.Run("with_rows", func(t *testing.T) {
		mux, srv, configDir := seedForServers(t, "tok-1")
		mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(api.ServersPage{
				Servers: []api.Server{{ID: "s1", Name: "web-1", Status: "online"}},
				Total:   1, Limit: 20, Offset: 0,
			})
		})

		ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"list"})
		code := RunServers(ctx)
		if code != cmdutil.ExitOK {
			t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
		}
		assertSingleJSONDoc(t, "servers list with rows", stdout.Bytes())
	})

	t.Run("zero_rows", func(t *testing.T) {
		mux, srv, configDir := seedForServers(t, "tok-1")
		mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(api.ServersPage{Servers: nil, Total: 0, Limit: 20, Offset: 0})
		})

		ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"list"})
		code := RunServers(ctx)
		if code != cmdutil.ExitOK {
			t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
		}
		assertSingleJSONDoc(t, "servers list zero rows", stdout.Bytes())
	})
}

// TestJSONServersList_BadFlag_EmptyStdoutJSONStderr covers a usage error
// (unparseable flag value) before any hub call: stdout empty, stderr JSON.
func TestJSONServersList_BadFlag_EmptyStdoutJSONStderr(t *testing.T) {
	_, srv, configDir := seedForServers(t, "tok-1")

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"list", "--limit", "not-a-number"})
	code := RunServers(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
	assertEmptyStdout(t, "servers list bad flag", stdout)
	assertJSONErrorShape(t, "servers list bad flag", stderr, cmdutil.ExitUsage)
}

// --- vey servers get ---------------------------------------------------

// TestJSONServersGet_SingleDocument covers the --json server-object shape
// for a direct ID hit.
func TestJSONServersGet_SingleDocument(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.Server{ID: "s1", Name: "web-1", Status: "online"})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"get", "s1"})
	code := RunServers(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
	}
	assertSingleJSONDoc(t, "servers get by id", stdout.Bytes())
}

// TestJSONServersGet_ErrorPaths_EmptyStdoutJSONStderr covers ambiguous
// name, unknown server, and missing argument: none of these ever leave
// stdout non-empty, and all three carry the {"error","code"} shape on
// stderr.
func TestJSONServersGet_ErrorPaths_EmptyStdoutJSONStderr(t *testing.T) {
	t.Run("ambiguous", func(t *testing.T) {
		mux, srv, configDir := seedForServers(t, "tok-1")
		mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(api.ServersPage{
				Servers: []api.Server{{ID: "s1", Name: "web"}, {ID: "s2", Name: "web"}},
				Total:   2,
			})
		})

		ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"get", "web"})
		code := RunServers(ctx)
		if code != cmdutil.ExitUsage {
			t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
		}
		assertEmptyStdout(t, "servers get ambiguous", stdout)
		assertJSONErrorShape(t, "servers get ambiguous", stderr, cmdutil.ExitUsage)
	})

	t.Run("unknown", func(t *testing.T) {
		mux, srv, configDir := seedForServers(t, "tok-1")
		mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(api.ServersPage{Servers: nil, Total: 0})
		})

		ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"get", "ghost"})
		code := RunServers(ctx)
		if code != cmdutil.ExitNotFound {
			t.Fatalf("exit code = %d, want %d (ExitNotFound); stdout=%q stderr=%q", code, cmdutil.ExitNotFound, stdout.String(), stderr.String())
		}
		assertEmptyStdout(t, "servers get unknown", stdout)
		assertJSONErrorShape(t, "servers get unknown", stderr, cmdutil.ExitNotFound)
	})

	t.Run("missing_arg", func(t *testing.T) {
		_, srv, configDir := seedForServers(t, "tok-1")

		ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"get"})
		code := RunServers(ctx)
		if code != cmdutil.ExitUsage {
			t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
		}
		assertEmptyStdout(t, "servers get missing arg", stdout)
		assertJSONErrorShape(t, "servers get missing arg", stderr, cmdutil.ExitUsage)
	})
}

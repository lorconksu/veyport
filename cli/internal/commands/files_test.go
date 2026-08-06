package commands

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// mountServerLookup registers the direct GET /api/servers/{id} lookup used
// by resolveServerID's first probe: matching id succeeds, anything else
// 404s so the search fallback kicks in (mirrors servers_test.go's inline
// per-test handlers, kept local here since files_test.go must not touch
// servers_test.go).
func mountServerLookup(mux *http.ServeMux, id string) {
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != id {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.Server{ID: id, Name: id})
	})
}

// --- vey files ls ----------------------------------------------------------

// TestFilesLs_HumanTable covers contracts/cli-commands.md `vey files ls`:
// ls -l-style listing (type marker, size, name), unreadable entries
// annotated.
func TestFilesLs_HumanTable(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mountServerLookup(mux, "s1")
	mux.HandleFunc("GET /api/servers/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		if !requireBearer(r, "tok-1") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if id := r.PathValue("id"); id != "s1" {
			t.Errorf("path id = %q, want %q", id, "s1")
		}
		if got := r.URL.Query().Get("path"); got != "/var/log" {
			t.Errorf("path query = %q, want %q", got, "/var/log")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.FileListing{
			Files: []api.FileEntry{
				{Name: "nginx", IsDir: true, Size: 4096, Readable: true},
				{Name: "secret.log", IsDir: false, Size: 128, Readable: false},
			},
		})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"ls", "s1", "/var/log"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stderr=%q", code, cmdutil.ExitOK, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{"d", "nginx", "secret.log", "unreadable", "4096", "128"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want it to contain %q", out, want)
		}
	}
}

// TestFilesLs_JSONPassthrough covers --json: the hub's {files: [...]}
// envelope passed through verbatim (rest-api.md: key is `files` per hub
// model.FileListResult).
func TestFilesLs_JSONPassthrough(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mountServerLookup(mux, "s1")
	mux.HandleFunc("GET /api/servers/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.FileListing{
			Files: []api.FileEntry{{Name: "a.txt", Size: 10, Readable: true}},
		})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"ls", "s1", "/tmp"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stderr=%q", code, cmdutil.ExitOK, stderr.String())
	}

	var got api.FileListing
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode stdout JSON: %v (stdout: %q)", err, stdout.String())
	}
	if len(got.Files) != 1 || got.Files[0].Name != "a.txt" || got.Files[0].Size != 10 {
		t.Errorf("got %+v", got)
	}
}

// TestFilesLs_ByName covers server-ref resolution by unique name (the same
// ID-or-unique-name resolution `vey servers get` uses), via exactly one
// fallback search call after the direct-ID probe 404s.
func TestFilesLs_ByName(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mountServerLookup(mux, "s1") // "web-1" != "s1", so this 404s, forcing the search fallback

	var searchCalls int
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		searchCalls++
		if got := r.URL.Query().Get("search"); got != "web-1" {
			t.Errorf("search query param = %q, want %q", got, "web-1")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ServersPage{
			Servers: []api.Server{{ID: "s1", Name: "web-1", Status: "online"}},
			Total:   1,
		})
	})
	mux.HandleFunc("GET /api/servers/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		if id := r.PathValue("id"); id != "s1" {
			t.Errorf("path id = %q, want %q", id, "s1")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.FileListing{Files: nil})
	})

	ctx, _, stderr := newCmdContext(srv.URL, configDir, false, []string{"ls", "web-1", "/tmp"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stderr=%q", code, cmdutil.ExitOK, stderr.String())
	}
	if searchCalls != 1 {
		t.Errorf("search calls = %d, want exactly 1", searchCalls)
	}
}

// TestFilesLs_MissingArgs covers "missing args → exit 2 usage": both
// <server> and <path> are required.
func TestFilesLs_MissingArgs(t *testing.T) {
	_, srv, configDir := seedForServers(t, "tok-1")

	for name, args := range map[string][]string{
		"no args":      {"ls"},
		"missing path": {"ls", "s1"},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, _, stderr := newCmdContext(srv.URL, configDir, false, args)
			code := RunFiles(ctx)
			if code != cmdutil.ExitUsage {
				t.Fatalf("exit code = %d, want %d (ExitUsage); stderr=%q", code, cmdutil.ExitUsage, stderr.String())
			}
		})
	}
}

// --- vey files cat -----------------------------------------------------

// TestFilesCat_BinaryPassthrough covers contracts/cli-commands.md `vey
// files cat`: raw bytes streamed to stdout unmodified, binary-safe, no
// JSON wrapping, no trailing newline added.
func TestFilesCat_BinaryPassthrough(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mountServerLookup(mux, "s1")
	binary := []byte{0x00, 0x01, 0xFF, 'h', 'i', 0x00, 0x7F, 0xFE}
	mux.HandleFunc("GET /api/servers/{id}/files/read", func(w http.ResponseWriter, r *http.Request) {
		if !requireBearer(r, "tok-1") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if id := r.PathValue("id"); id != "s1" {
			t.Errorf("path id = %q, want %q", id, "s1")
		}
		if got := r.URL.Query().Get("path"); got != "/bin/data" {
			t.Errorf("path query = %q, want %q", got, "/bin/data")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(binary)
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"cat", "s1", "/bin/data"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stderr=%q", code, cmdutil.ExitOK, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), binary) {
		t.Errorf("stdout = %v, want exact binary passthrough %v", stdout.Bytes(), binary)
	}
}

// TestFilesCat_JSONModeStillRawPassthrough covers "no --json variant beyond
// error shape (binary-safe passthrough)": --json must not alter cat's
// stdout content.
func TestFilesCat_JSONModeStillRawPassthrough(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mountServerLookup(mux, "s1")
	content := []byte("hello, world\n")
	mux.HandleFunc("GET /api/servers/{id}/files/read", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"cat", "s1", "/etc/motd"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stderr=%q", code, cmdutil.ExitOK, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), content) {
		t.Errorf("stdout = %q, want unwrapped content %q", stdout.String(), content)
	}
}

// TestFilesCat_MissingArgs covers "missing args → exit 2 usage" for cat.
func TestFilesCat_MissingArgs(t *testing.T) {
	_, srv, configDir := seedForServers(t, "tok-1")
	ctx, _, stderr := newCmdContext(srv.URL, configDir, false, []string{"cat", "s1"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stderr=%q", code, cmdutil.ExitUsage, stderr.String())
	}
}

// --- shared error mapping (ls and cat share the same error path) ---------

// TestFilesLs_Forbidden403 covers "403 → exit 4" (contracts/rest-api.md
// Files table: "path outside permitted roots").
func TestFilesLs_Forbidden403(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mountServerLookup(mux, "s1")
	mux.HandleFunc("GET /api/servers/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "path outside permitted roots"})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"ls", "s1", "/etc/shadow"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitForbidden {
		t.Fatalf("exit code = %d, want %d (ExitForbidden); stdout=%q stderr=%q", code, cmdutil.ExitForbidden, stdout.String(), stderr.String())
	}
}

// TestFilesCat_Forbidden403 covers the same 403 → exit 4 mapping for cat.
func TestFilesCat_Forbidden403(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mountServerLookup(mux, "s1")
	mux.HandleFunc("GET /api/servers/{id}/files/read", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "path outside permitted roots"})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"cat", "s1", "/etc/shadow"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitForbidden {
		t.Fatalf("exit code = %d, want %d (ExitForbidden); stdout=%q stderr=%q", code, cmdutil.ExitForbidden, stdout.String(), stderr.String())
	}
}

// TestFiles_OfflineAgent_ConnExit6 covers "offline agent → exit 6": the hub
// itself is unreachable (connection refused), the same transport-level
// failure the API client maps to ExitConn for any route, files included
// (contracts/rest-api.md Files table: "agent offline → non-2xx mapped to
// exit 6").
func TestFiles_OfflineAgent_ConnExit6(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	mux := http.NewServeMux()
	mountRefresh(mux, "tok-1", "refresh-2")
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

	ctx, stdout, stderr := newCmdContext(hubURL, configDir, false, []string{"ls", "s1", "/var/log"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitConn {
		t.Fatalf("exit code = %d, want %d (ExitConn); stdout=%q stderr=%q", code, cmdutil.ExitConn, stdout.String(), stderr.String())
	}
}

// TestFilesLs_RateLimited429 covers "429 fileOpsLimiter → exit 7"
// (contracts/rest-api.md: "Rate-limited (fileOpsLimiter)"; "any
// rate-limited route: surface as exit 7; the CLI MUST NOT auto-retry into
// a limiter").
func TestFilesLs_RateLimited429(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mountServerLookup(mux, "s1")
	var calls int
	mux.HandleFunc("GET /api/servers/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "too many requests"})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"ls", "s1", "/tmp"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitRateLimited {
		t.Fatalf("exit code = %d, want %d (ExitRateLimited); stdout=%q stderr=%q", code, cmdutil.ExitRateLimited, stdout.String(), stderr.String())
	}
	if calls != 1 {
		t.Errorf("files endpoint calls = %d, want exactly 1 (no auto-retry into a limiter)", calls)
	}
}

// TestFilesCat_RateLimited429 covers the same 429 → exit 7 mapping for cat.
func TestFilesCat_RateLimited429(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mountServerLookup(mux, "s1")
	mux.HandleFunc("GET /api/servers/{id}/files/read", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "too many requests"})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"cat", "s1", "/tmp/x"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitRateLimited {
		t.Fatalf("exit code = %d, want %d (ExitRateLimited); stdout=%q stderr=%q", code, cmdutil.ExitRateLimited, stdout.String(), stderr.String())
	}
}

// --- RunFiles dispatch ------------------------------------------------------

// TestRunFiles_NoArgs covers the bare `vey files` invocation.
func TestRunFiles_NoArgs(t *testing.T) {
	_, srv, configDir := seedForServers(t, "tok-1")
	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, nil)
	code := RunFiles(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
}

// TestRunFiles_UnknownSubcommand covers `vey files bogus`.
func TestRunFiles_UnknownSubcommand(t *testing.T) {
	_, srv, configDir := seedForServers(t, "tok-1")
	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"bogus", "s1", "/tmp"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "bogus") {
		t.Errorf("stderr = %q, want it to name the unknown subcommand", stderr.String())
	}
}

// --- resolveHubAuth failures (shared by ls and cat) -------------------------

// TestFilesLs_NoHubExitUsage covers runFilesLs's resolveHubAuth error branch
// via a RequireHub failure (no hub configured).
func TestFilesLs_NoHubExitUsage(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")
	ctx, stdout, stderr := newCmdContext("", t.TempDir(), false, []string{"ls", "s1", "/tmp"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
}

// TestFilesCat_AuthContextFailure covers runFilesCat's resolveHubAuth error
// branch via a newAuthContext failure (malformed VEYPORT_TOKEN).
func TestFilesCat_AuthContextFailure(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "malformed-token")
	srv := httptest.NewServer(http.NewServeMux())
	defer srv.Close()

	ctx, stdout, stderr := newCmdContext(srv.URL, t.TempDir(), false, []string{"cat", "s1", "/tmp/x"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
}

// TestFilesCat_UnknownServerExit5 covers runFilesCat's resolveServerID error
// branch: neither the direct lookup nor the fallback search finds the
// server.
func TestFilesCat_UnknownServerExit5(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ServersPage{Servers: nil, Total: 0})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"cat", "ghost", "/tmp/x"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitNotFound {
		t.Fatalf("exit code = %d, want %d (ExitNotFound); stdout=%q stderr=%q", code, cmdutil.ExitNotFound, stdout.String(), stderr.String())
	}
}

// TestFilesLs_AmbiguousServerName covers resolveServerID's ambiguous-match
// branch (shared code path with `vey servers get`, but exercised here
// through `vey files ls` since resolveServerID is duplicated in this file).
func TestFilesLs_AmbiguousServerName(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ServersPage{
			Servers: []api.Server{
				{ID: "s1", Name: "web"},
				{ID: "s2", Name: "web"},
			},
			Total: 2,
		})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"ls", "web", "/tmp"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
	for _, want := range []string{"s1", "s2"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr = %q, want it to list candidate %q", stderr.String(), want)
		}
	}
}

// TestFilesLs_SearchFallbackCallError covers resolveServerID's fallback
// search actx.Do error branch: the direct lookup 404s, then the search call
// itself fails.
func TestFilesLs_SearchFallbackCallError(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"ls", "web-1", "/tmp"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitError {
		t.Fatalf("exit code = %d, want %d (ExitError); stdout=%q stderr=%q", code, cmdutil.ExitError, stdout.String(), stderr.String())
	}
}

// TestFilesCat_InterruptedStream_ExitConn covers runFilesCat's PayloadRaw
// error branch: the stream starts (200, headers sent) but is cut off
// mid-body, same hijack technique as audit_test.go's interrupted-stream
// test.
func TestFilesCat_InterruptedStream_ExitConn(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mountServerLookup(mux, "s1")
	const partial = "partial file conten"
	mux.HandleFunc("GET /api/servers/{id}/files/read", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("response writer does not support hijacking")
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		defer conn.Close()

		_, _ = bufrw.WriteString("HTTP/1.1 200 OK\r\n")
		_, _ = bufrw.WriteString("Content-Length: 4096\r\n\r\n")
		_, _ = bufrw.WriteString(partial)
		_ = bufrw.Flush()
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"cat", "s1", "/bin/data"})
	code := RunFiles(ctx)
	if code != cmdutil.ExitConn {
		t.Fatalf("exit code = %d, want %d (ExitConn); stdout=%q stderr=%q", code, cmdutil.ExitConn, stdout.String(), stderr.String())
	}
	if stdout.String() != partial {
		t.Errorf("stdout = %q, want the partial body %q preserved", stdout.String(), partial)
	}
}

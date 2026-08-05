package commands

import (
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

// seedForServers wires up an httptest hub with the /api/auth/refresh stub
// and a seeded session, returning the mux (so the test can register its own
// /api/servers* handlers), the server, and the configDir.
func seedForServers(t *testing.T, accessToken string) (*http.ServeMux, *httptest.Server, string) {
	t.Helper()
	t.Setenv("VEYPORT_TOKEN", "")

	mux := http.NewServeMux()
	mountRefresh(mux, accessToken, "refresh-2")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "alice",
		Role:         "admin",
		ObtainedAt:   time.Now(),
	})
	return mux, srv, configDir
}

// --- vey servers list ----------------------------------------------------

// TestServersList_TableAndPaginationPassthrough covers contracts/cli-commands.md
// `vey servers list`: flags forwarded as query params, aligned human table
// NAME/STATUS/ID, "total" footer to stderr.
func TestServersList_TableAndPaginationPassthrough(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")

	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		if !requireBearer(r, "tok-1") {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		q := r.URL.Query()
		if got := q.Get("status"); got != "online" {
			t.Errorf("status query param = %q, want %q", got, "online")
		}
		if got := q.Get("search"); got != "web" {
			t.Errorf("search query param = %q, want %q", got, "web")
		}
		if got := q.Get("limit"); got != "5" {
			t.Errorf("limit query param = %q, want %q", got, "5")
		}
		if got := q.Get("offset"); got != "10" {
			t.Errorf("offset query param = %q, want %q", got, "10")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ServersPage{
			Servers: []api.Server{
				{ID: "s1", Name: "web-1", Status: "online"},
				{ID: "s2", Name: "web-2", Status: "offline"},
			},
			Total: 2, Limit: 5, Offset: 10,
		})
	})

	args := []string{"list", "--status", "online", "--search", "web", "--limit", "5", "--offset", "10"}
	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, args)
	code := RunServers(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stderr=%q", code, cmdutil.ExitOK, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{"NAME", "STATUS", "ID", "web-1", "online", "s1", "web-2", "offline", "s2"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want it to contain %q", out, want)
		}
	}
	if !strings.Contains(stderr.String(), "total 2") {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), "total 2")
	}
}

// TestServersList_JSONPassthrough covers the --json envelope passthrough.
func TestServersList_JSONPassthrough(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")

	want := api.ServersPage{
		Servers: []api.Server{{ID: "s1", Name: "web-1", Status: "online"}},
		Total:   1, Limit: 20, Offset: 0,
	}
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	})

	ctx, stdout, _ := newCmdContext(srv.URL, configDir, true, []string{"list"})
	code := RunServers(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stdout=%q", code, cmdutil.ExitOK, stdout.String())
	}

	var got api.ServersPage
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode stdout JSON: %v (stdout: %q)", err, stdout.String())
	}
	if got.Total != want.Total || len(got.Servers) != 1 || got.Servers[0].ID != "s1" {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// TestServersList_ZeroRows covers "Exit 0 even when zero servers match."
func TestServersList_ZeroRows(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ServersPage{Servers: nil, Total: 0, Limit: 20, Offset: 0})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"list"})
	code := RunServers(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK) on zero rows; stdout=%q stderr=%q", code, cmdutil.ExitOK, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "total 0") {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), "total 0")
	}
}

// --- vey servers get ------------------------------------------------------

// TestServersGet_ByID covers direct ID resolution.
func TestServersGet_ByID(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireBearer(r, "tok-1") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if id := r.PathValue("id"); id != "s1" {
			t.Errorf("path id = %q, want %q", id, "s1")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.Server{ID: "s1", Name: "web-1", Status: "online"})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"get", "s1"})
	code := RunServers(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stderr=%q", code, cmdutil.ExitOK, stderr.String())
	}

	var got api.Server
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode stdout JSON: %v (stdout: %q)", err, stdout.String())
	}
	if got.ID != "s1" || got.Name != "web-1" {
		t.Errorf("got %+v, want ID=s1 Name=web-1", got)
	}
}

// TestServersGet_ByUniqueName covers name resolution via exactly one
// fallback search call after the direct-ID lookup 404s.
func TestServersGet_ByUniqueName(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")

	var searchCalls int
	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	})
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

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"get", "web-1"})
	code := RunServers(ctx)
	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stderr=%q", code, cmdutil.ExitOK, stderr.String())
	}
	if searchCalls != 1 {
		t.Errorf("search calls = %d, want exactly 1", searchCalls)
	}

	var got api.Server
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode stdout JSON: %v (stdout: %q)", err, stdout.String())
	}
	if got.ID != "s1" {
		t.Errorf("got ID = %q, want %q", got.ID, "s1")
	}
}

// TestServersGet_AmbiguousName covers ambiguity → exit 2 listing candidates.
func TestServersGet_AmbiguousName(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")

	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	})
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ServersPage{
			Servers: []api.Server{
				{ID: "s1", Name: "web", Status: "online"},
				{ID: "s2", Name: "web", Status: "offline"},
			},
			Total: 2,
		})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"get", "web"})
	code := RunServers(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("stdout = %q, want empty on ambiguity error", stdout.String())
	}
	for _, want := range []string{"s1", "s2"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr = %q, want it to list candidate %q", stderr.String(), want)
		}
	}
}

// TestServersGet_Unknown covers "Unknown → exit 5."
func TestServersGet_Unknown(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "tok-1")

	mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	})
	mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ServersPage{Servers: nil, Total: 0})
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"get", "ghost"})
	code := RunServers(ctx)
	if code != cmdutil.ExitNotFound {
		t.Fatalf("exit code = %d, want %d (ExitNotFound); stdout=%q stderr=%q", code, cmdutil.ExitNotFound, stdout.String(), stderr.String())
	}
}

// TestServersGet_MissingArg covers "arg required (missing → exit 2 usage)."
func TestServersGet_MissingArg(t *testing.T) {
	_, srv, configDir := seedForServers(t, "tok-1")

	ctx, _, stderr := newCmdContext(srv.URL, configDir, false, []string{"get"})
	code := RunServers(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stderr=%q", code, cmdutil.ExitUsage, stderr.String())
	}
}

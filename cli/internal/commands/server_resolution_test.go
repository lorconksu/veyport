package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

func seedViewerSession(t *testing.T, configDir, hubURL string) {
	t.Helper()
	seedSession(t, configDir, hubURL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "alice",
		Role:         "viewer",
		ObtainedAt:   time.Now(),
	})
}

func assertServerNameSearch(t *testing.T, r *http.Request, ref string) {
	t.Helper()
	if !requireBearer(r, "tok-1") {
		t.Error("name search did not retain the caller's authentication")
	}
	q := r.URL.Query()
	if q.Get("search") != ref || q.Get("limit") != "100" || q.Get("offset") != "0" || len(q) != 3 {
		t.Errorf("name search query = %v, want search=%q, limit=100, offset=0", q, ref)
	}
}

// A viewer's direct name probe is indistinguishable from an inaccessible or
// nonexistent ID. Only the authenticated list's exact matches can resolve it.
func TestServerResolution_VisibleNamesAndDenials(t *testing.T) {
	visible := api.Server{ID: "visible-id", Name: "web", Status: "online"}
	complete := api.ServersPage{Servers: []api.Server{visible}, Total: 1, Limit: 100}
	fullPage := api.ServersPage{Total: 100, Limit: 100}
	for i := 0; i < 99; i++ {
		fullPage.Servers = append(fullPage.Servers, api.Server{ID: fmt.Sprintf("copy-%d", i), Name: fmt.Sprintf("web-copy-%d", i)})
	}
	fullPage.Servers = append(fullPage.Servers, visible)
	cases := []struct {
		name, ref, directMessage, searchMessage, wantID, wantError string
		directStatus, searchStatus, wantCode, wantSearchCalls      int
		page                                                       api.ServersPage
	}{
		{name: "viewer exact name", directStatus: 403, page: complete, wantID: visible.ID, wantSearchCalls: 1},
		{name: "ID succeeds without search", ref: visible.ID, directStatus: 200, wantID: visible.ID},
		{name: "admin name after 404", directStatus: 404, page: complete, wantID: visible.ID, wantSearchCalls: 1},
		{name: "inaccessible ID", ref: "hidden-id", directStatus: 403, wantCode: cmdutil.ExitForbidden, wantError: "access denied", wantSearchCalls: 1},
		{name: "unknown ID", ref: "unknown-id", directStatus: 403, wantCode: cmdutil.ExitForbidden, wantError: "access denied", wantSearchCalls: 1},
		{name: "substring is not an exact name", directStatus: 403, page: api.ServersPage{Servers: []api.Server{{ID: "other-id", Name: "web-backup"}}, Total: 1}, wantCode: cmdutil.ExitForbidden, wantError: "access denied", wantSearchCalls: 1},
		{name: "case differs", directStatus: 403, page: api.ServersPage{Servers: []api.Server{{ID: "other-id", Name: "Web"}}, Total: 1}, wantCode: cmdutil.ExitForbidden, wantError: "access denied", wantSearchCalls: 1},
		{name: "404 with no exact match", directStatus: 404, wantCode: cmdutil.ExitNotFound, wantError: "no server found", wantSearchCalls: 1},
		{name: "ambiguous visible names", directStatus: 403, page: api.ServersPage{Servers: []api.Server{{ID: "z-id", Name: "web"}, {ID: "a-id", Name: "web"}}, Total: 2}, wantCode: cmdutil.ExitUsage, wantError: "web (a-id), web (z-id)", wantSearchCalls: 1},
		{name: "exact name among substring results", directStatus: 403, page: api.ServersPage{Servers: []api.Server{{ID: "other-id", Name: "web-backup"}, visible}, Total: 2}, wantID: visible.ID, wantSearchCalls: 1},
		{name: "exact name at full page boundary", directStatus: 403, page: fullPage, wantID: visible.ID, wantSearchCalls: 1},
		{name: "one exact match in incomplete page", directStatus: 403, page: api.ServersPage{Servers: []api.Server{visible}, Total: 101, Limit: 100}, wantCode: cmdutil.ExitUsage, wantError: "use a server ID", wantSearchCalls: 1},
		{name: "404 with incomplete page", directStatus: 404, page: api.ServersPage{Total: 101, Limit: 100}, wantCode: cmdutil.ExitUsage, wantError: "use a server ID", wantSearchCalls: 1},
		{name: "403 with incomplete page and no exact match", directStatus: 403, page: api.ServersPage{Total: 101, Limit: 100}, wantCode: cmdutil.ExitForbidden, wantError: "access denied", wantSearchCalls: 1},
		{name: "unexpected offset cannot establish uniqueness", directStatus: 403, page: api.ServersPage{Servers: []api.Server{visible}, Total: 1, Offset: 1}, wantCode: cmdutil.ExitUsage, wantError: "use a server ID", wantSearchCalls: 1},
		{name: "legacy page without pagination metadata", directStatus: 403, page: api.ServersPage{Servers: []api.Server{visible}}, wantID: visible.ID, wantSearchCalls: 1},
		{name: "direct unauthenticated", directStatus: 401, wantCode: cmdutil.ExitAuth, wantError: "access denied"},
		{name: "direct locked", directStatus: 423, wantCode: cmdutil.ExitAuth, wantError: "access denied"},
		{name: "direct disabled", directStatus: 403, directMessage: "account disabled", wantCode: cmdutil.ExitAuth, wantError: "account disabled"},
		{name: "direct dormant", directStatus: 403, directMessage: "account dormant", wantCode: cmdutil.ExitAuth, wantError: "account dormant"},
		{name: "direct rate limited", directStatus: 429, wantCode: cmdutil.ExitRateLimited},
		{name: "direct server error", directStatus: 500, wantCode: cmdutil.ExitError},
		{name: "direct transport failure", directStatus: -1, wantCode: cmdutil.ExitConn},
		{name: "search permission denied", directStatus: 403, searchStatus: 403, searchMessage: "search denied", wantCode: cmdutil.ExitForbidden, wantError: "search denied", wantSearchCalls: 1},
		{name: "search unauthenticated", directStatus: 403, searchStatus: 401, wantCode: cmdutil.ExitAuth, wantSearchCalls: 2},
		{name: "search disabled", directStatus: 403, searchStatus: 403, searchMessage: "account disabled", wantCode: cmdutil.ExitAuth, wantSearchCalls: 2},
		{name: "search rate limited", directStatus: 403, searchStatus: 429, wantCode: cmdutil.ExitRateLimited, wantSearchCalls: 1},
		{name: "search server error", directStatus: 403, searchStatus: 500, wantCode: cmdutil.ExitError, wantSearchCalls: 1},
		{name: "search transport failure", directStatus: 403, searchStatus: -1, wantCode: cmdutil.ExitConn, wantSearchCalls: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := tc.ref
			if ref == "" {
				ref = "web"
			}
			mux, srv, dir := seedForServers(t, "tok-1")
			seedViewerSession(t, dir, srv.URL)
			mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
				if tc.directStatus == http.StatusOK {
					_ = json.NewEncoder(w).Encode(visible)
					return
				}
				writeServerResolutionFailure(t, w, tc.directStatus, tc.directMessage)
			})
			var searchCalls atomic.Int32
			mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
				searchCalls.Add(1)
				assertServerNameSearch(t, r, ref)
				if tc.searchStatus != 0 {
					writeServerResolutionFailure(t, w, tc.searchStatus, tc.searchMessage)
					return
				}
				_ = json.NewEncoder(w).Encode(tc.page)
			})
			cmd, _, _ := newCmdContext(srv.URL, dir, false, nil)
			_, actx, err := newAuthContext(cmd, srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			got, err := resolveSSHServer(context.Background(), actx, ref)
			if cmdutil.Code(err) != tc.wantCode || got.ID != tc.wantID {
				t.Fatalf("server=%+v, error=%v (code %d); want ID %q, code %d", got, err, cmdutil.Code(err), tc.wantID, tc.wantCode)
			}
			if tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
				t.Errorf("error=%v, want %q", err, tc.wantError)
			}
			if calls := int(searchCalls.Load()); calls != tc.wantSearchCalls {
				t.Errorf("search calls=%d, want %d", calls, tc.wantSearchCalls)
			}
		})
	}
}

func writeServerResolutionFailure(t *testing.T, w http.ResponseWriter, status int, message string) {
	t.Helper()
	if status == -1 {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
		return
	}
	if message == "" {
		message = "access denied"
	}
	// Keep transport-failure cases on fresh connections so Go's automatic
	// replay of a GET on a stale reused connection does not obscure call counts.
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func TestSSH_ServerResolution_ViewerNameAndCommand(t *testing.T) {
	command := "  printf '%s\\n' '$HOME;$(touch local)' | cat\n# café  "
	for _, tc := range []struct {
		name, ref, command string
		visible            bool
		wantCode, searches int
	}{
		{name: "interactive name", ref: "web", visible: true, searches: 1},
		{name: "command name", ref: "web", command: command, visible: true, wantCode: 42, searches: 1},
		{name: "command ID", ref: "visible-id", command: command, visible: true, wantCode: 42},
		{name: "invisible name", ref: "hidden", wantCode: cmdutil.ExitForbidden, searches: 1},
		{name: "unknown name", ref: "unknown", wantCode: cmdutil.ExitForbidden, searches: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, srv, dir := seedForSSH(t, "tok-1")
			seedViewerSession(t, dir, srv.URL)
			seedSSHMaterial(t, dir, srv.URL, "alice", time.Now().Add(time.Hour))
			mountSSHHostKey(mux)
			visible := api.Server{ID: "visible-id", Name: "web", Status: "online"}
			mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
				if r.PathValue("id") == visible.ID {
					_ = json.NewEncoder(w).Encode(visible)
					return
				}
				writeServerResolutionFailure(t, w, http.StatusForbidden, "access denied")
			})
			var searchCalls atomic.Int32
			mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
				searchCalls.Add(1)
				assertServerNameSearch(t, r, tc.ref)
				page := api.ServersPage{}
				if tc.visible {
					page = api.ServersPage{Servers: []api.Server{visible}, Total: 1}
				}
				_ = json.NewEncoder(w).Encode(page)
			})
			stubSSHTTY(t, true)
			captured := stubExecSSH(t, func(_ context.Context, _ string, argv []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
				if stdout != os.Stdout || stderr != os.Stderr {
					t.Error("SSH streams changed during name resolution")
				}
				if tc.command != "" && (argv[len(argv)-1] != tc.command || stdin != nil) {
					t.Errorf("command=%q, stdin=%v; want exact command and terminal EOF", argv[len(argv)-1], stdin)
				}
				return tc.wantCode, nil
			})
			args := []string{tc.ref}
			if tc.command != "" {
				args = append(args, "--", tc.command)
			}
			cmd, stdout, stderr := newCmdContext(srv.URL, dir, false, args)
			if code := RunSSH(cmd); code != tc.wantCode || int(searchCalls.Load()) != tc.searches {
				t.Fatalf("code=%d, searches=%d; want %d, %d; stderr=%q", code, searchCalls.Load(), tc.wantCode, tc.searches, stderr.String())
			}
			if !tc.visible {
				if *captured != nil || stdout.Len() != 0 || stderr.String() != "Error: access denied\n" {
					t.Fatalf("denial executed SSH or changed privacy response: argv=%q stdout=%q stderr=%q", *captured, stdout.String(), stderr.String())
				}
				return
			}
			destination := (*captured)[len(*captured)-1]
			if tc.command != "" {
				destination = (*captured)[len(*captured)-2]
			}
			if !strings.HasPrefix(destination, "alice+web@") {
				t.Errorf("SSH destination=%q, want resolved visible name", destination)
			}
			assertSSHTempDirCleanedUp(t, *captured)
		})
	}
}

// Every command must use the same viewer-visible resolution, while its
// subsequent resource endpoint still enforces its own permissions.
func TestServerResolution_CommandsKeepResourceAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint string
		args           []string
		run            func(*Context) int
	}{
		{name: "servers get", args: []string{"get", "web"}, run: RunServers},
		{name: "files ls", endpoint: "/files", args: []string{"ls", "web", "/tmp"}, run: RunFiles},
		{name: "files cat", endpoint: "/files/read", args: []string{"cat", "web", "/tmp/file"}, run: RunFiles},
		{name: "logs tail", endpoint: "/logs/tail", args: []string{"tail", "web", "/tmp/log"}, run: RunLogs},
		{name: "servers update check", endpoint: "/agent-update", args: []string{"update", "web", "--check"}, run: RunServers},
	} {
		for _, deny := range []bool{false, true} {
			if deny && tc.endpoint == "" {
				continue
			}
			t.Run(fmt.Sprintf("%s/denied=%t", tc.name, deny), func(t *testing.T) {
				mux, srv, dir := seedForServers(t, "tok-1")
				seedViewerSession(t, dir, srv.URL)
				mux.HandleFunc("GET /api/servers/{id}", func(w http.ResponseWriter, r *http.Request) {
					writeServerResolutionFailure(t, w, http.StatusForbidden, "access denied")
				})
				var searchCalls atomic.Int32
				mux.HandleFunc("GET /api/servers", func(w http.ResponseWriter, r *http.Request) {
					searchCalls.Add(1)
					assertServerNameSearch(t, r, "web")
					_ = json.NewEncoder(w).Encode(api.ServersPage{Servers: []api.Server{{ID: "visible-id", Name: "web"}}, Total: 1})
				})
				var resourceCalls atomic.Int32
				if tc.endpoint != "" {
					mux.HandleFunc("GET /api/servers/{id}"+tc.endpoint, func(w http.ResponseWriter, r *http.Request) {
						resourceCalls.Add(1)
						if r.PathValue("id") != "visible-id" || !requireBearer(r, "tok-1") {
							t.Errorf("resource used ID %q or different authentication", r.PathValue("id"))
						}
						if deny {
							writeServerResolutionFailure(t, w, http.StatusForbidden, "resource denied")
							return
						}
						switch tc.endpoint {
						case "/files":
							_ = json.NewEncoder(w).Encode(api.FileListing{})
						case "/files/read":
							_, _ = io.WriteString(w, "visible content")
						case "/logs/tail":
							w.Header().Set("Content-Type", "text/event-stream")
							_, _ = io.WriteString(w, logFrame("visible content\n"))
						case "/agent-update":
							_ = json.NewEncoder(w).Encode(api.AgentUpdateCheck{Supported: true})
						}
					})
				}
				cmd, stdout, stderr := newCmdContext(srv.URL, dir, true, tc.args)
				wantCode := cmdutil.ExitOK
				if deny {
					wantCode = cmdutil.ExitForbidden
				} else if tc.endpoint == "/logs/tail" {
					wantCode = cmdutil.ExitConn // A closed tail is an unexpected disconnect.
				}
				if code := tc.run(cmd); code != wantCode || searchCalls.Load() != 1 {
					t.Fatalf("code=%d, searches=%d; want %d, 1; stdout=%q stderr=%q", code, searchCalls.Load(), wantCode, stdout.String(), stderr.String())
				}
				if tc.endpoint != "" && resourceCalls.Load() != 1 {
					t.Errorf("resource calls=%d, want 1", resourceCalls.Load())
				}
				if deny && (stdout.Len() != 0 || !strings.Contains(stderr.String(), "resource denied")) {
					t.Errorf("resource permission denial changed: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
			})
		}
	}
}

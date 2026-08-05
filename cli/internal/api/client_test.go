package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// newTestClient builds a Client pointed at srv with the given bearer token.
func newTestClient(srv *httptest.Server, token string) *Client {
	return NewClient(srv.URL, token)
}

func requireBearer(t *testing.T, r *http.Request, want string) {
	t.Helper()
	got := r.Header.Get("Authorization")
	if want == "" {
		if got != "" {
			t.Errorf("Authorization header = %q, want empty", got)
		}
		return
	}
	if got != "Bearer "+want {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer "+want)
	}
}

func codeOf(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	return cmdutil.Code(err)
}

// --- Auth contract shapes ---------------------------------------------

func TestLogin_TOTPPending202(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/auth/login" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"totp_token": "tok-abc123"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "")
	var out LoginTOTPPending
	err := c.Post(context.Background(), "/api/auth/login", map[string]string{"username": "alice", "password": "hunter2"}, &out)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if out.TOTPToken != "tok-abc123" {
		t.Errorf("TOTPToken = %q, want tok-abc123", out.TOTPToken)
	}
}

func TestLogin_SetupRequired200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"setup_token":          "setup-xyz",
			"requires_totp_setup":  true,
			"must_change_password": false,
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "")
	var out LoginSetupRequired
	if err := c.Post(context.Background(), "/api/auth/login", map[string]string{"username": "bob", "password": "pw"}, &out); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if out.SetupToken != "setup-xyz" || !out.RequiresTOTPSetup {
		t.Errorf("got %+v, want SetupToken=setup-xyz RequiresTOTPSetup=true", out)
	}
}

func TestLogin_BadCredentials401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "")
	err := c.Post(context.Background(), "/api/auth/login", map[string]string{"username": "x", "password": "y"}, nil)
	if code := codeOf(t, err); code != cmdutil.ExitAuth {
		t.Errorf("exit code = %d, want %d (ExitAuth)", code, cmdutil.ExitAuth)
	}
	if !strings.Contains(err.Error(), "invalid credentials") {
		t.Errorf("error message %q does not contain server's error text", err.Error())
	}
}

func TestLogin_RateLimited429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "too many requests"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "")
	err := c.Post(context.Background(), "/api/auth/login", map[string]string{"username": "x", "password": "y"}, nil)
	if code := codeOf(t, err); code != cmdutil.ExitRateLimited {
		t.Errorf("exit code = %d, want %d (ExitRateLimited)", code, cmdutil.ExitRateLimited)
	}
}

func TestLoginTOTP_200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/login/totp" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		// The hub sets auth cookies here too; the CLI must ignore them.
		http.SetCookie(w, &http.Cookie{Name: "veyport_access", Value: "cookie-should-be-ignored"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-1",
			"refresh_token": "refresh-1",
			"user":          map[string]string{"username": "alice", "role": "admin"},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "")
	var out TokenPair
	if err := c.Post(context.Background(), "/api/auth/login/totp", map[string]string{"totp_token": "t", "code": "123456"}, &out); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if out.AccessToken != "access-1" || out.RefreshToken != "refresh-1" {
		t.Errorf("got %+v", out)
	}
	if out.User.Username != "alice" || out.User.Role != "admin" {
		t.Errorf("User = %+v, want {alice admin}", out.User)
	}
}

func TestRefresh_200And401(t *testing.T) {
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "access-2",
				"refresh_token": "refresh-2",
			})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid or expired refresh token"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "")

	var out TokenPair
	if err := c.Post(context.Background(), "/api/auth/refresh", map[string]string{"refresh_token": "old"}, &out); err != nil {
		t.Fatalf("Post (200 case): %v", err)
	}
	if out.AccessToken != "access-2" || out.RefreshToken != "refresh-2" {
		t.Errorf("got %+v", out)
	}

	err := c.Post(context.Background(), "/api/auth/refresh", map[string]string{"refresh_token": "old"}, &out)
	if code := codeOf(t, err); code != cmdutil.ExitAuth {
		t.Errorf("exit code = %d, want %d (ExitAuth)", code, cmdutil.ExitAuth)
	}
}

func TestMe_200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, r, "access-token-123")
		if r.URL.Path != "/api/auth/me" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"username": "carol", "role": "viewer"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "access-token-123")
	var out Me
	if err := c.Get(context.Background(), "/api/auth/me", nil, &out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.Username != "carol" || out.Role != "viewer" {
		t.Errorf("got %+v", out)
	}
}

// --- Servers contract shape --------------------------------------------

func TestServersList_Page200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, r, "tok")
		if got, want := r.URL.Query().Get("limit"), "25"; got != want {
			t.Errorf("limit query = %q, want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"servers": []map[string]any{
				{"id": "s1", "name": "web-1", "status": "online"},
				{"id": "s2", "name": "web-2", "status": "offline"},
			},
			"total":  2,
			"limit":  25,
			"offset": 0,
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	q := url.Values{"limit": []string{"25"}}
	var out ServersPage
	if err := c.Get(context.Background(), "/api/servers", q, &out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.Total != 2 || len(out.Servers) != 2 || out.Servers[0].Name != "web-1" {
		t.Errorf("got %+v", out)
	}
}

func TestServerGet_NotFound404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "server not found"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.Get(context.Background(), "/api/servers/unknown-id", nil, &Server{})
	if code := codeOf(t, err); code != cmdutil.ExitNotFound {
		t.Errorf("exit code = %d, want %d (ExitNotFound)", code, cmdutil.ExitNotFound)
	}
}

// --- Files contract shapes ----------------------------------------------

func TestFilesList_200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"files": []map[string]any{
				{"name": "access.log", "path": "/var/log/nginx/access.log", "is_dir": false, "size": 1048576},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	var out FileListing
	if err := c.Get(context.Background(), "/api/servers/srv1/files", url.Values{"path": []string{"/var/log/nginx"}}, &out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(out.Files) != 1 || out.Files[0].Name != "access.log" || out.Files[0].Size != 1048576 {
		t.Errorf("got %+v", out)
	}
}

func TestFiles_Forbidden403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "access denied"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.Get(context.Background(), "/api/servers/srv1/files", nil, &FileListing{})
	if code := codeOf(t, err); code != cmdutil.ExitForbidden {
		t.Errorf("exit code = %d, want %d (ExitForbidden)", code, cmdutil.ExitForbidden)
	}
}

func TestFiles_OfflineAgent_ConnectionRefused(t *testing.T) {
	// Simulate an unreachable/offline agent path by pointing the client at
	// a server that has already stopped listening: the request fails at
	// the transport level (connection refused), which the client maps to
	// ExitConn — the same bucket as "agent offline" per contracts/rest-api.md.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached — server is closed before the request")
	}))
	srv.Close()

	c := newTestClient(srv, "tok")
	err := c.Get(context.Background(), "/api/servers/srv1/files", nil, &FileListing{})
	if code := codeOf(t, err); code != cmdutil.ExitConn {
		t.Errorf("exit code = %d, want %d (ExitConn)", code, cmdutil.ExitConn)
	}
}

func TestFiles_RateLimited429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "too many requests"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.Get(context.Background(), "/api/servers/srv1/files", nil, &FileListing{})
	if code := codeOf(t, err); code != cmdutil.ExitRateLimited {
		t.Errorf("exit code = %d, want %d (ExitRateLimited)", code, cmdutil.ExitRateLimited)
	}
}

func TestFilesRead_200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"data":       "aGVsbG8=",
			"total_size": 5,
			"mime_type":  "text/plain",
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	var out FileContent
	if err := c.Get(context.Background(), "/api/servers/srv1/files/read", url.Values{"path": []string{"/etc/hostname"}}, &out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.Data != "aGVsbG8=" || out.TotalSize != 5 || out.MimeType != "text/plain" {
		t.Errorf("got %+v", out)
	}
}

// --- GetStream passthrough (used by cat/export/logs) ---------------------

func TestGetStream_PassesBodyThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, r, "tok")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("streamed content"))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	rc, err := c.GetStream(context.Background(), "/api/audit-logs/export", nil)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	defer rc.Close()

	buf := make([]byte, 32)
	n, _ := rc.Read(buf)
	if got := string(buf[:n]); got != "streamed content" {
		t.Errorf("got %q, want %q", got, "streamed content")
	}
}

func TestGetStream_ErrorMapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "admin/auditor role required"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	_, err := c.GetStream(context.Background(), "/api/audit-logs/export", nil)
	if code := codeOf(t, err); code != cmdutil.ExitForbidden {
		t.Errorf("exit code = %d, want %d (ExitForbidden)", code, cmdutil.ExitForbidden)
	}
}

// --- Cross-cutting client behavior ---------------------------------------

func TestBearerHeaderOmittedWhenTokenEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, r, "")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer srv.Close()

	c := newTestClient(srv, "")
	if err := c.Get(context.Background(), "/api/auth/me", nil, &Me{}); err != nil {
		t.Fatalf("Get: %v", err)
	}
}

func TestNoCookieJar_SetCookieIgnoredAcrossRequests(t *testing.T) {
	// The hub sets auth cookies on login/totp, but the CLI relies solely
	// on Bearer headers and must never send a stored cookie back on a
	// subsequent request.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "veyport_access", Value: "should-never-be-sent-back"})
			w.WriteHeader(http.StatusOK)
			return
		}
		if c, err := r.Cookie("veyport_access"); err == nil {
			t.Errorf("unexpected cookie sent on second request: %s=%s", c.Name, c.Value)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	if c.HTTP.Jar != nil {
		t.Fatal("Client.HTTP.Jar must be nil (no cookie jar)")
	}

	if err := c.Get(context.Background(), "/set", nil, nil); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if err := c.Get(context.Background(), "/second", nil, nil); err != nil {
		t.Fatalf("second request: %v", err)
	}
}

func TestUnknownFieldsTolerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"username":                "dave",
			"role":                    "admin",
			"a_field_from_the_future": "should not break decoding",
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	var out Me
	if err := c.Get(context.Background(), "/api/auth/me", nil, &out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.Username != "dave" {
		t.Errorf("got %+v", out)
	}
}

// --- TLS trust (R9) -------------------------------------------------------

func TestUntrustedCertificate_MapsToExitConnWithGuidance(t *testing.T) {
	// httptest.NewTLSServer uses a self-signed certificate not present in
	// any trust store; the default client (no custom TLS config, per R9)
	// must reject it, and the resulting error must name the certificate
	// problem and point at OS trust-store installation.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached — TLS handshake must fail first")
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := c.Get(ctx, "/api/auth/me", nil, &Me{})
	if err == nil {
		t.Fatal("expected an error connecting to a self-signed TLS server with default verification")
	}

	if code := cmdutil.Code(err); code != cmdutil.ExitConn {
		t.Errorf("exit code = %d, want %d (ExitConn)", code, cmdutil.ExitConn)
	}

	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "certificate") {
		t.Errorf("error message %q does not name the certificate problem", err.Error())
	}
	if !strings.Contains(msg, "trust store") {
		t.Errorf("error message %q does not point at OS trust-store installation", err.Error())
	}

	// Also confirm this isn't accidentally reachable via any interface
	// this package might expose for disabling verification — there must
	// be none (R9).
	var coded *cmdutil.CodedError
	if !errors.As(err, &coded) {
		t.Fatal("expected err to be a *cmdutil.CodedError")
	}
}

func TestClient_NoInsecureSkipVerifyAnywhere(t *testing.T) {
	// Structural guard for R9: a freshly constructed client must not carry
	// a custom Transport/TLSClientConfig at all — the zero value (nil)
	// which means Go's default, OS-trust-store verification.
	c := NewClient("https://example.invalid", "tok")
	if c.HTTP.Transport != nil {
		t.Error("Client.HTTP.Transport must be nil (default transport, default TLS verification) — R9 forbids any custom TLS config, including a permissive one")
	}
}

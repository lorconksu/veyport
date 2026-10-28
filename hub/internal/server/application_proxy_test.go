package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/applicationtransport"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/proto/applicationproxy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type appTestDialer struct{}

func (appTestDialer) DialApplication(ctx context.Context, t applicationtransport.Target) (net.Conn, error) {
	return (&applicationproxy.Dialer{}).DialTarget(ctx, t)
}
func (appTestDialer) ApplicationAvailability(string) (bool, bool) { return true, true }
func applicationFixture(t *testing.T, backend string) (*Server, *model.Application, string) {
	t.Helper()
	s := testServer(t)
	s.applicationDomain = "apps.example.test"
	s.applicationPortalOrigin = "https://portal.example.test"
	s.applicationDialer = appTestDialer{}
	u := &model.User{ID: uuid.NewString(), Username: uuid.NewString(), Email: uuid.NewString() + "@example.test", Role: model.RoleViewer, TOTPEnabled: true}
	if e := s.store.CreateUser(u); e != nil {
		t.Fatal(e)
	}
	now := s.now()
	a := &model.Application{ID: uuid.NewString(), Slug: "demo", Name: "Demo", PublicHostname: "demo.apps.example.test", Route: "hub", BackendURL: backend, AllowedCIDRs: []string{"127.0.0.0/8"}, Enabled: true}
	if e := s.store.CreateApplication(a, now); e != nil {
		t.Fatal(e)
	}
	if e := s.store.ReplaceApplicationGrants(a.ID, []model.ApplicationGrant{{Kind: "user", SubjectID: u.ID}}, 1, now); e != nil {
		t.Fatal(e)
	}
	a, e := s.store.GetApplication(a.ID)
	if e != nil {
		t.Fatal(e)
	}
	anchor := model.ApplicationAnchor{ID: uuid.NewString(), UserID: u.ID, CompletedMFAAt: now}
	if e = s.store.EnsureApplicationAnchor(anchor); e != nil {
		t.Fatal(e)
	}
	revision, e := s.store.ApplicationAccessRevision(u.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.store.CreateApplicationTicket(model.ApplicationLaunchTicket{Digest: "ticket", ApplicationID: a.ID, UserID: u.ID, AnchorID: anchor.ID, Hostname: a.PublicHostname, Path: "/", ConfigVersion: a.ConfigVersion, AccessRevision: revision, ExpiresAt: now.Add(time.Minute)}); e != nil {
		t.Fatal(e)
	}
	cookie := "opaque-app-credential"
	if _, e = s.store.ConsumeApplicationTicket("ticket", a.PublicHostname, model.ApplicationSession{ID: uuid.NewString(), CredentialDigest: refreshDigest(cookie), ExpiresAt: now.Add(12 * time.Hour)}, now); e != nil {
		t.Fatal(e)
	}
	return s, a, cookie
}
func appRequest(a *model.Application, cookie, method, path string) *http.Request {
	r := httptest.NewRequest(method, "https://"+a.PublicHostname+path, nil)
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.AddCookie(&http.Cookie{Name: applicationCookie, Value: cookie})
	return r
}
func TestApplicationNativeHeadersAndCookiesStaySeparated(t *testing.T) {
	var cookies, authorization string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookies = r.Header.Get("Cookie")
		authorization = r.Header.Get("Authorization")
		http.SetCookie(w, &http.Cookie{Name: "native", Value: "yes", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: cookieAccess, Value: "forged", Path: "/"})
		w.Write([]byte("native-app"))
	}))
	defer backend.Close()
	s, a, c := applicationFixture(t, backend.URL)
	r := appRequest(a, c, "POST", "/form?native=keep")
	r.Header.Set("Origin", "https://"+a.PublicHostname)
	r.Header.Set("Authorization", "Bearer native-token")
	r.AddCookie(&http.Cookie{Name: "native-login", Value: "yes"})
	r.AddCookie(&http.Cookie{Name: cookieRefresh, Value: "portal-refresh"})
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "native-app" {
		t.Fatalf("proxy %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(cookies, "veyport") || strings.Contains(cookies, c) || !strings.Contains(cookies, "native-login=yes") || authorization != "Bearer native-token" {
		t.Fatal("native/gateway header separation failed")
	}
	for _, v := range w.Result().Cookies() {
		if reservedApplicationCookie(v.Name) {
			t.Fatal("forged upstream gateway cookie")
		}
	}
}
func TestApplicationSiblingMutationAndUnknownHostNeverReachBackend(t *testing.T) {
	var count atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1) }))
	defer backend.Close()
	s, a, c := applicationFixture(t, backend.URL)
	for _, tc := range []struct{ host, origin, fetch, cookie string }{{a.PublicHostname, "https://evil.apps.example.test", "same-site", c}, {a.PublicHostname, "", "same-site", c}, {"unknown.apps.example.test", "", "", c}, {a.PublicHostname, "https://" + a.PublicHostname, "", "invalid"}} {
		r := appRequest(a, tc.cookie, "POST", "/api/auth/login")
		r.Host = tc.host
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Sec-Fetch-Site", tc.fetch)
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, r)
		if w.Code == 200 {
			t.Fatalf("unexpected allow %+v", tc)
		}
	}
	if count.Load() != 0 {
		t.Fatal("denial contacted backend")
	}
}
func TestApplicationIndependentIdleAndAbsoluteClock(t *testing.T) {
	s, a, c := applicationFixture(t, "http://127.0.0.1:9999")
	ss, _ := s.store.GetApplicationSession(refreshDigest(c))
	now := s.now()
	s.SetClock(func() time.Time { return now.Add(44 * time.Minute) })
	if e := s.checkApplicationSession(context.Background(), a, ss, true); e != nil {
		t.Fatal(e)
	}
	fresh, _ := s.store.GetApplicationSession(refreshDigest(c))
	s.SetClock(func() time.Time { return now.Add(89*time.Minute + time.Second) })
	if e := s.checkApplicationSession(context.Background(), a, fresh, false); e == nil {
		t.Fatal("idle allowed")
	}
	s.SetClock(func() time.Time { return now.Add(12 * time.Hour) })
	if e := s.checkApplicationSession(context.Background(), a, ss, false); e == nil {
		t.Fatal("absolute allowed")
	}
}
func TestApplicationLogoutRefreshRevokesMissingDashboardSource(t *testing.T) {
	s, a, c := applicationFixture(t, "http://127.0.0.1:9999")
	ss, _ := s.store.GetApplicationSession(refreshDigest(c))
	_, refresh, e := auth.GenerateSessionTokenPair(s.jwtSecret, ss.UserID, "viewer", 0, ss.AnchorID)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", s.applicationPortalOrigin+"/api/auth/logout", nil)
	r.Header.Set("Origin", s.applicationPortalOrigin)
	r.Header.Set("X-CSRF-Token", "csrf")
	r.AddCookie(&http.Cookie{Name: cookieCSRF, Value: "csrf"})
	r.AddCookie(&http.Cookie{Name: cookieRefresh, Value: refresh})
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("logout %d %s", w.Code, w.Body.String())
	}
	ss, _ = s.store.GetApplicationSession(refreshDigest(c))
	if ss.EndedAt == nil || s.checkApplicationSession(context.Background(), a, ss, false) == nil {
		t.Fatal("logout missed app")
	}
}
func TestApplicationPrivateCAValidation(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("verified")) }))
	defer backend.Close()
	s, a, c := applicationFixture(t, backend.URL)
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, appRequest(a, c, "GET", "/"))
	if w.Code != 502 {
		t.Fatal("untrusted TLS accepted")
	}
	a.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw}))
	b, e := json.Marshal(a)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.store.DB().Exec(`UPDATE applications SET config_json=? WHERE id=?`, string(b), a.ID); e != nil {
		t.Fatal(e)
	}
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, appRequest(a, c, "GET", "/"))
	if w.Code != 200 || w.Body.String() != "verified" {
		t.Fatalf("private CA %d %s", w.Code, w.Body.String())
	}
}
func TestApplicationRevocationClosesLiveSSE(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: ready\n\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer backend.Close()
	s, a, c := applicationFixture(t, backend.URL)
	gateway := httptest.NewServer(s.routes())
	defer gateway.Close()
	r, _ := http.NewRequest("GET", gateway.URL+"/events", nil)
	r.Host = a.PublicHostname
	r.AddCookie(&http.Cookie{Name: applicationCookie, Value: c})
	client := &http.Client{Timeout: 8 * time.Second}
	resp, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	b := make([]byte, 13)
	if _, e = io.ReadFull(resp.Body, b); e != nil {
		t.Fatal(e)
	}
	ss, _ := s.store.GetApplicationSession(refreshDigest(c))
	start := time.Now()
	if e = s.store.RevokeApplicationFamily(ss.UserID, ss.AnchorID, "revoked_admin", s.now()); e != nil {
		t.Fatal(e)
	}
	_, _ = io.ReadAll(resp.Body)
	if time.Since(start) > 5*time.Second {
		t.Fatal("SSE revoke exceeded5s")
	}
}
func TestApplicationPathValidation(t *testing.T) {
	for _, v := range []string{"//evil", "/a/../b", "/%2e%2e/private", "/%5cevil", "/_veyport/launch", "/x\r\nHost:evil"} {
		if _, e := applicationPath(v); e == nil {
			t.Errorf("accepted %q", v)
		}
	}
	v := "/native?next=https%3A%2F%2Fexample.test"
	if out, e := applicationPath(v); e != nil || out != v {
		t.Fatal("native query lost")
	}
}
func TestApplicationCertificateTrustRejectsPrivateKeysAndGarbage(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer backend.Close()
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw}))
	if !applicationCertificatePEM(cert) {
		t.Fatal("valid certificate refused")
	}
	for _, v := range []string{cert + "garbage", cert + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")})), ""} {
		if applicationCertificatePEM(v) {
			t.Fatal("non-certificate trust accepted")
		}
	}
}
func TestApplicationLDAPStartTLSStallIsBounded(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	closed := make(chan struct{})
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 4096)
		if _, e = conn.Read(buffer); e != nil {
			return
		} // LDAP StartTLS ExtendedResponse(success), messageID1.
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
		<-closed
	}()
	defer close(closed)
	start := time.Now()
	_, e = dialLDAP(LDAPConfig{URL: "ldap://" + listener.Addr().String(), StartTLS: true})
	if e == nil || time.Since(start) > 2500*time.Millisecond {
		t.Fatalf("stalled TLS not bounded: %v %s", e, time.Since(start))
	}
}

type applicationZeroReader struct{}

func (applicationZeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
func TestApplicationStreams64MiBUploadAndDownload(t *testing.T) {
	const payloadSize = 64 << 20
	expected := sha256.New()
	if n, err := io.Copy(expected, io.LimitReader(applicationZeroReader{}, payloadSize)); err != nil || n != payloadSize {
		t.Fatalf("prepare payload digest: bytes=%d err=%v", n, err)
	}
	wantDigest := expected.Sum(nil)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received := sha256.New()
		n, err := io.Copy(io.MultiWriter(w, received), r.Body)
		if err != nil || n != payloadSize || !bytes.Equal(received.Sum(nil), wantDigest) {
			t.Errorf("backend streamed%d bytes SHA256%x: %v", n, received.Sum(nil), err)
		}
	}))
	defer backend.Close()
	s, a, c := applicationFixture(t, backend.URL)
	gateway := httptest.NewServer(s.routes())
	defer gateway.Close()
	r, err := http.NewRequestWithContext(t.Context(), "POST", gateway.URL+"/large", io.LimitReader(applicationZeroReader{}, payloadSize))
	if err != nil {
		t.Fatal(err)
	}
	r.ContentLength = payloadSize
	r.Host = a.PublicHostname
	r.Header.Set("Origin", "https://"+a.PublicHostname)
	r.AddCookie(&http.Cookie{Name: applicationCookie, Value: c})
	// Race detection and package-wide atomic coverage can slow a correct bulk
	// transfer on shared CI CPUs. Bound the integrity check at two minutes;
	// separate stalled-upload and revocation tests retain their short bounds.
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	received := sha256.New()
	n, err := io.Copy(received, resp.Body)
	if err != nil || n != payloadSize || resp.StatusCode != http.StatusOK || !bytes.Equal(received.Sum(nil), wantDigest) {
		t.Fatalf("streamed%d bytes HTTP%d SHA256%x: %v", n, resp.StatusCode, received.Sum(nil), err)
	}
}

func TestApplicationWebSocketRevocationClosesBothSockets(t *testing.T) {
	backendClosed := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer conn.Close()
		defer close(backendClosed)
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, conn)
	}))
	defer backend.Close()
	s, a, c := applicationFixture(t, backend.URL)
	gateway := httptest.NewServer(s.routes())
	defer gateway.Close()
	address := strings.TrimPrefix(gateway.URL, "http://")
	conn, e := net.DialTimeout("tcp", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	r, _ := http.NewRequest("GET", gateway.URL+"/socket", nil)
	r.Host = a.PublicHostname
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Origin", "https://"+a.PublicHostname)
	r.AddCookie(&http.Cookie{Name: applicationCookie, Value: c})
	if e = r.Write(conn); e != nil {
		t.Fatal(e)
	}
	reader := bufio.NewReader(conn)
	response, e := http.ReadResponse(reader, r)
	if e != nil || response.StatusCode != 101 {
		t.Fatalf("upgrade %#v %v", response, e)
	}
	frame := []byte{0x81, 0x01, 'x'}
	if _, e = conn.Write(frame); e != nil {
		t.Fatal(e)
	}
	read := make([]byte, 3)
	if _, e = io.ReadFull(reader, read); e != nil || !bytes.Equal(frame, read) {
		t.Fatal("websocket data", e)
	}
	ss, _ := s.store.GetApplicationSession(refreshDigest(c))
	if e = s.store.RevokeApplicationFamily(ss.UserID, ss.AnchorID, "revoked", s.now()); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	_, e = reader.ReadByte()
	if e == nil || time.Since(start) > 5*time.Second {
		t.Fatal("browser websocket not revoked", e)
	}
	select {
	case <-backendClosed:
	case <-time.After(time.Second):
		t.Fatal("backend websocket not closed")
	}
}
func TestApplicationCookieAndRedirectMappingUsesPrefixBoundary(t *testing.T) {
	a := &model.Application{PublicHostname: "demo.apps.example.test"}
	backend, _ := url.Parse("https://private.example.test/base")
	resp := &http.Response{Header: http.Header{"Set-Cookie": []string{"native=yes; Domain=private.example.test; Path=/base/path", "other=yes; Domain=evil.example.test; Path=/", "lookalike=yes; Path=/baseball", "__Host-veyport_app=forged; Secure; Path=/"}, "Location": []string{"https://private.example.test/base/native?x=1"}}}
	if e := rewriteApplicationResponse(resp, a, backend); e != nil {
		t.Fatal(e)
	}
	if resp.Header.Get("Location") != "https://demo.apps.example.test/native?x=1" {
		t.Fatal("redirect mapping")
	}
	cookies := resp.Cookies()
	if len(cookies) != 2 || cookies[0].Domain != "" || cookies[0].Path != "/path" || cookies[1].Path != "/baseball" {
		t.Fatalf("cookie boundary %+v", cookies)
	}
	resp.Header.Set("Location", "https://idp.example.test/login")
	if e := rewriteApplicationResponse(resp, a, backend); e != nil || resp.Header.Get("Location") != "https://idp.example.test/login" {
		t.Fatal("native external IdP redirect lost")
	}
	resp.Header.Set("Location", "https://private.example.test/baseball/secret")
	if e := rewriteApplicationResponse(resp, a, backend); e == nil {
		t.Fatal("redirect escaped prefix")
	}
}
func TestApplicationOnlySocketLoopbackCanProbeFixedHealth(t *testing.T) {
	s := testServer(t)
	s.applicationDomain = "apps.example.test"
	s.applicationPortalOrigin = "https://portal.example.test"
	for _, tc := range []struct {
		remote, path, method string
		want                 int
	}{{"127.0.0.1:1234", "/api/health", "GET", 200}, {"[::1]:1234", "/api/health", "HEAD", 200}, {"192.0.2.1:1234", "/api/health", "GET", 421}, {"127.0.0.1:1234", "/api/auth/status", "GET", 421}, {"127.0.0.1:1234", "/api/health", "POST", 421}} {
		r := httptest.NewRequest(tc.method, "http://unknown.example.test"+tc.path, nil)
		r.RemoteAddr = tc.remote
		r.Header.Set("X-Forwarded-For", "127.0.0.1")
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%+v got%d", tc, w.Code)
		}
	}
}
func TestApplicationDirectLinkAndLaunchExchangeRefuseInvalidAuthority(t *testing.T) {
	s, a, _ := applicationFixture(t, "http://127.0.0.1:9999")
	r := httptest.NewRequest("GET", "https://"+a.PublicHostname+"/native?x=1", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), s.applicationPortalOrigin+"/applications/"+a.ID+"/launch?") {
		t.Fatal("direct app link did not route to portal", w.Code)
	}
	for _, tc := range []struct {
		method, origin, body, path string
		want                       int
	}{{"GET", s.applicationPortalOrigin, "", "/_veyport/launch", 403}, {"POST", "null", "ticket=" + strings.Repeat("A", 43), "/_veyport/launch", 403}, {"POST", "https://sibling.apps.example.test", "ticket=" + strings.Repeat("A", 43), "/_veyport/launch", 403}, {"POST", s.applicationPortalOrigin, "ticket=short", "/_veyport/launch", 403}, {"POST", s.applicationPortalOrigin, "ticket=" + strings.Repeat("A", 43), "/_veyport/launch", 403}, {"GET", "", "", "/_veyport/unknown", 404}} {
		r = httptest.NewRequest(tc.method, "https://"+a.PublicHostname+tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", tc.origin)
		w = httptest.NewRecorder()
		s.routes().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("gateway denial %+v got%d", tc, w.Code)
		}
	}
	r = appRequest(a, "opaque-app-credential", "GET", "/")
	r.AddCookie(&http.Cookie{Name: applicationCookie, Value: "second"})
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("duplicate app cookie accepted")
	}
}
func TestApplicationRootRelativeBackendRedirectStripsConfiguredPrefix(t *testing.T) {
	a := &model.Application{PublicHostname: "demo.apps.example.test"}
	backend, _ := url.Parse("https://private.example.test/base")
	response := &http.Response{Header: http.Header{"Location": []string{"/base/login?native=1"}}}
	if e := rewriteApplicationResponse(response, a, backend); e != nil || response.Header.Get("Location") != "/login?native=1" {
		t.Fatal("root-relative redirect duplicated prefix", e, response.Header)
	}
}
func TestApplicationEndAndRequestAuditsOmitSecretsAndRecordLifecycle(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201); w.Write([]byte("payload")) }))
	defer backend.Close()
	s, a, c := applicationFixture(t, backend.URL)
	r := appRequest(a, c, "GET", "/native?secret-query=hidden")
	r.Header.Set("Authorization", "Bearer native-secret")
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	ss, _ := s.store.GetApplicationSession(refreshDigest(c))
	if e := s.store.EndApplicationSession(ss.ID, "expired_idle", s.now()); e != nil {
		t.Fatal(e)
	}
	s.auditApplicationSessionEnds()
	s.auditApplicationSessionEnds()
	entries, total, e := s.store.ListAuditLogs(model.AuditFilter{Action: stringPtr("application.session_ended"), Limit: 10})
	if e != nil || total != 1 || len(entries) != 1 {
		t.Fatal("end audit missing or duplicated", e, total)
	}
	if entries[0].UserID == nil || *entries[0].UserID != ss.UserID {
		t.Fatal("session audit actor missing")
	}
	requests, total, e := s.store.ListAuditLogs(model.AuditFilter{Action: stringPtr("application.request"), Limit: 10})
	if e != nil || total != 1 {
		t.Fatal("request audit missing", e, total)
	}
	detail := *requests[0].Detail
	for _, secret := range []string{c, "native-secret", "secret-query", "payload"} {
		if strings.Contains(detail, secret) {
			t.Fatal("audit leaked secret/content")
		}
	}
	for _, field := range []string{"\"method\":\"GET\"", "\"status\":201", "\"response_bytes\":7", "\"route\":\"hub\""} {
		if !strings.Contains(detail, field) {
			t.Fatal("audit metadata missing", field, detail)
		}
	}
	if requests[0].CorrelationID == nil || *requests[0].CorrelationID == "" || requests[0].UserID == nil {
		t.Fatal("request audit correlation/actor missing")
	}
}
func TestApplicationNativeCSRFHeaderSurvivesProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSRF-Token") != "native-app-csrf" {
			http.Error(w, "native CSRF denied", 403)
			return
		}
		w.WriteHeader(204)
	}))
	defer backend.Close()
	s, a, c := applicationFixture(t, backend.URL)
	r := appRequest(a, c, "POST", "/form")
	r.Header.Set("Origin", "https://"+a.PublicHostname)
	r.Header.Set("X-CSRF-Token", "native-app-csrf")
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal("native CSRF broken", w.Code)
	}
	if w.Header().Get("Referrer-Policy") != "strict-origin" {
		t.Fatal("native app document policy must preserve same-origin form Origin")
	}
}
func TestApplicationHousekeepingAuditsExpiryBeforeRetention(t *testing.T) {
	s, a, c := applicationFixture(t, "http://127.0.0.1:9999")
	now := s.now()
	s.SetClock(func() time.Time { return now.Add(46 * time.Minute) })
	if _, e := s.runSessionPrune(30 * 24 * time.Hour); e != nil {
		t.Fatal(e)
	}
	ss, e := s.store.GetApplicationSession(refreshDigest(c))
	if e != nil || ss.EndReason != "expired_idle" {
		t.Fatal("idle cleanup", e, ss.EndReason)
	}
	count, e := s.store.ApplicationAuditExists("application-session-end:" + ss.ID)
	if e != nil || !count {
		t.Fatal("idle end not audited")
	}
	if a.ID != ss.ApplicationID {
		t.Fatal("wrong app")
	}
}
func TestApplicationLaunchDocumentUsesOriginOnlyReferrerPolicy(t *testing.T) {
	s := testServer(t)
	s.applicationDomain = "apps.example.test"
	s.applicationPortalOrigin = "https://portal.example.test"
	for _, path := range []string{"/applications/abc/launch?path=%2Fnative%3Fsecret%3Dx", "/login?returnTo=launch"} {
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, httptest.NewRequest("GET", s.applicationPortalOrigin+path, nil))
		if w.Header().Get("Referrer-Policy") != "strict-origin" {
			t.Fatal("portal launch/login must preserve form Origin without exposing path/query")
		}
		if strings.HasPrefix(path, "/applications") && w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("launch document cached")
		}
	}
}
func TestApplicationLogoutPersistenceFailureDoesNotClearCredentials(t *testing.T) {
	s, _, cookie := applicationFixture(t, "http://127.0.0.1:9999")
	ss, _ := s.store.GetApplicationSession(refreshDigest(cookie))
	_, refresh, e := auth.GenerateSessionTokenPair(s.jwtSecret, ss.UserID, "viewer", 0, ss.AnchorID)
	if e != nil {
		t.Fatal(e)
	}
	_ = s.store.Close()
	r := httptest.NewRequest("POST", s.applicationPortalOrigin+"/api/auth/logout", nil)
	r.Header.Set("Origin", s.applicationPortalOrigin)
	r.Header.Set("X-CSRF-Token", "csrf")
	r.AddCookie(&http.Cookie{Name: cookieCSRF, Value: "csrf"})
	r.AddCookie(&http.Cookie{Name: cookieRefresh, Value: refresh})
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	if w.Code != 500 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("false logout result%d cookies%d", w.Code, len(w.Result().Cookies()))
	}
}

func TestApplicationRevocationInterruptsStalledHTTPResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "67108864")
		_, _ = io.Copy(w, io.LimitReader(applicationZeroReader{}, 64<<20))
	}))
	defer backend.Close()
	s, a, c := applicationFixture(t, backend.URL)
	done := make(chan struct{})
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(done); s.routes().ServeHTTP(w, r) }))
	defer gateway.Close()
	socket, e := net.Dial("tcp", gateway.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer socket.Close()
	_, e = io.WriteString(socket, "GET /large HTTP/1.1\r\nHost: "+a.PublicHostname+"\r\nCookie: "+applicationCookie+"="+c+"\r\n\r\n")
	if e != nil {
		t.Fatal(e)
	}
	reader := bufio.NewReader(socket)
	for {
		line, e := reader.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		if line == "\r\n" {
			break
		}
	}
	time.Sleep(300 * time.Millisecond)
	ss, _ := s.store.GetApplicationSession(refreshDigest(c))
	if e := s.store.EndApplicationSession(ss.ID, "revoked_self", s.now()); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		socket.Close()
		t.Fatal("revocation did not interrupt stalled frontend write within5s")
	}
}
func TestApplicationRevocationInterruptsStalledHTTPUpload(t *testing.T) {
	backendStarted := make(chan struct{})
	backendDone := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(backendDone)
		close(backendStarted)
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer backend.Close()
	s, a, c := applicationFixture(t, backend.URL)
	done := make(chan struct{})
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(done); s.routes().ServeHTTP(w, r) }))
	defer gateway.Close()
	socket, e := net.Dial("tcp", gateway.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer socket.Close()
	_, e = io.WriteString(socket, "POST /upload HTTP/1.1\r\nHost: "+a.PublicHostname+"\r\nOrigin: https://"+a.PublicHostname+"\r\nCookie: "+applicationCookie+"="+c+"\r\nContent-Length: 67108864\r\n\r\n"+strings.Repeat("x", 65536))
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-backendStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("backend upload not started")
	}
	ss, _ := s.store.GetApplicationSession(refreshDigest(c))
	if e = s.store.EndApplicationSession(ss.ID, "revoked_self", s.now()); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		socket.Close()
		t.Fatal("revocation left incoming upload stalled")
	}
	select {
	case <-backendDone:
	case <-time.After(time.Second):
		t.Fatal("backend upload worker not cleaned up")
	}
}
func TestApplicationRedirectsKeepUntrustedDataWithinFixedOrigins(t *testing.T) {
	origin := "https://portal.example.test"
	for _, path := range []string{"/native?next=https://evil.example/login", "/https://evil.example", "/?next=//evil.example", "/%252f%252fevil.example"} {
		target, e := applicationPortalRedirect(origin, "application-id", path)
		if e != nil {
			t.Fatal(e)
		}
		parsed, e := url.Parse(target)
		if e != nil || parsed.Scheme != "https" || parsed.Host != "portal.example.test" || parsed.Path != "/applications/application-id/launch" || parsed.Query().Get("path") != path {
			t.Fatalf("redirect origin escaped %q", target)
		}
	}
	for _, path := range []string{"//evil.example", "https://evil.example", "/%2f%2fevil.example", "/%5cevil", "/path\r\nLocation: https://evil.example"} {
		if _, e := applicationPortalRedirect(origin, "application-id", path); e == nil {
			t.Fatal("unsafe redirect accepted", path)
		}
	}
	for _, badOrigin := range []string{"https://portal.example.test/other", "https://user:pass@portal.example.test", "http://portal.example.test", "https://portal.example.test?next=evil"} {
		if _, e := applicationPortalRedirect(badOrigin, "application-id", "/"); e == nil {
			t.Fatal("invalid fixed portal origin accepted")
		}
	}
}
func TestApplicationExchangeRevalidatesStoredRedirectBeforeIssuingCookie(t *testing.T) {
	s, a, c := applicationFixture(t, "http://127.0.0.1:9999")
	ss, _ := s.store.GetApplicationSession(refreshDigest(c))
	secret, e := applicationSecret()
	if e != nil {
		t.Fatal(e)
	}
	ticket := model.ApplicationLaunchTicket{Digest: refreshDigest(secret), ApplicationID: a.ID, UserID: ss.UserID, AnchorID: ss.AnchorID, Hostname: a.PublicHostname, Path: "//evil.example", ConfigVersion: a.ConfigVersion, AccessRevision: ss.AccessRevision, ExpiresAt: s.now().Add(time.Minute)}
	if e = s.store.CreateApplicationTicket(ticket); e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", "https://"+a.PublicHostname+"/_veyport/launch", strings.NewReader("ticket="+secret))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", s.applicationPortalOrigin)
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	if w.Code != 400 || w.Header().Get("Location") != "" || len(w.Result().Cookies()) != 0 {
		t.Fatalf("unsafe stored redirect escaped%d %s", w.Code, w.Body.String())
	}
}

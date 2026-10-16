package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestApplicationGatewayRefusalsNeverReachBackendOrRefreshIdle(t *testing.T) {
	for _, scenario := range []struct {
		name string
		want int
	}{{"unsafe_path", 400}, {"no_transport", 503}, {"session_capacity", 429}, {"global_capacity", 429}, {"invalid_backend", 502}, {"invalid_CA", 502}, {"activity_storage", 503}} {
		t.Run(scenario.name, func(t *testing.T) {
			var reached atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
			defer backend.Close()
			s, app, cookie := applicationFixture(t, backend.URL)
			s.stopSessionPruner()
			session, err := s.store.GetApplicationSession(refreshDigest(cookie))
			if err != nil {
				t.Fatal(err)
			}
			r := appRequest(app, cookie, http.MethodGet, "/native")
			switch scenario.name {
			case "unsafe_path":
				r = appRequest(app, cookie, http.MethodGet, "/%2e%2e/private")
			case "no_transport":
				s.SetApplicationDialer(nil)
			case "session_capacity":
				for i := 0; i < 8; i++ {
					if !s.applicationStreams.register(uuid.NewString(), session.ID, app.ID, func() {}) {
						t.Fatal("fixture capacity")
					}
				}
			case "global_capacity":
				for i := 0; i < 128; i++ {
					if !s.applicationStreams.register(uuid.NewString(), uuid.NewString(), app.ID, func() {}) {
						t.Fatal("fixture capacity")
					}
				}
			case "invalid_backend":
				app.BackendURL = "http://127.0.0.1:invalid"
			case "invalid_CA":
				app.CAPEM = "not a certificate"
			case "activity_storage":
				if _, err = s.store.DB().Exec(`CREATE TRIGGER fail_app_activity BEFORE UPDATE OF last_seen_at ON application_sessions BEGIN SELECT RAISE(ABORT,'synthetic activity storage unavailable'); END`); err != nil {
					t.Fatal(err)
				}
			}
			response := httptest.NewRecorder()
			s.serveApplication(response, r, app)
			current, err := s.store.GetApplicationSession(refreshDigest(cookie))
			if response.Code != scenario.want || reached.Load() != 0 || err != nil || !current.LastSeenAt.Equal(session.LastSeenAt) {
				t.Fatalf("refused request reached backend/extended idle: status%d reached%d err%v", response.Code, reached.Load(), err)
			}
		})
	}
}

func TestApplicationLaunchExchangeRejectsBrokenOrLostAuthorityWithoutCookie(t *testing.T) {
	for _, scenario := range []struct {
		name string
		want int
	}{{"malformed_form", 400}, {"revoked_anchor", 403}, {"absolute_maximum", 401}, {"consume_storage", 403}, {"password_change_required", 403}} {
		t.Run(scenario.name, func(t *testing.T) {
			s, app, cookie := applicationFixture(t, "http://127.0.0.1:9999")
			s.stopSessionPruner()
			session, err := s.store.GetApplicationSession(refreshDigest(cookie))
			if err != nil {
				t.Fatal(err)
			}
			secret, err := applicationSecret()
			if err != nil {
				t.Fatal(err)
			}
			ticket := model.ApplicationLaunchTicket{Digest: refreshDigest(secret), ApplicationID: app.ID, UserID: session.UserID, AnchorID: session.AnchorID, Hostname: app.PublicHostname, Path: "/", ConfigVersion: app.ConfigVersion, AccessRevision: session.AccessRevision, ExpiresAt: s.now().Add(time.Minute)}
			if err = s.store.CreateApplicationTicket(ticket); err != nil {
				t.Fatal(err)
			}
			body := "ticket=" + secret
			switch scenario.name {
			case "malformed_form":
				body = "ticket=%zz"
			case "revoked_anchor":
				if err = s.store.RevokeApplicationFamily(session.UserID, session.AnchorID, "logout", s.now()); err != nil {
					t.Fatal(err)
				}
			case "absolute_maximum":
				if _, err = s.store.DB().Exec(`UPDATE application_login_anchors SET completed_mfa_at=? WHERE id=?`, s.now().Add(-13*time.Hour).UnixMilli(), session.AnchorID); err != nil {
					t.Fatal(err)
				}
			case "consume_storage":
				if _, err = s.store.DB().Exec(`CREATE TRIGGER fail_exchange BEFORE INSERT ON application_sessions BEGIN SELECT RAISE(ABORT,'synthetic session storage unavailable'); END`); err != nil {
					t.Fatal(err)
				}
			case "password_change_required":
				if _, err = s.store.DB().Exec(`UPDATE users SET must_change_password=1 WHERE id=?`, session.UserID); err != nil {
					t.Fatal(err)
				}
			}
			r := httptest.NewRequest(http.MethodPost, "https://"+app.PublicHostname+"/_veyport/launch", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", s.applicationPortalOrigin)
			response := httptest.NewRecorder()
			s.exchangeApplicationLaunch(response, r, app)
			if response.Code != scenario.want || len(response.Result().Cookies()) != 0 || response.Header().Get("Location") != "" {
				t.Fatal("failed exchange issued browser authority", response.Code)
			}
		})
	}
}

func TestApplicationDirectLinkAndResponseRejectMalformedDestinations(t *testing.T) {
	s, app, _ := applicationFixture(t, "http://127.0.0.1:9999")
	s.stopSessionPruner()
	response := httptest.NewRecorder()
	navigation := appRequest(app, "", http.MethodGet, "/%2fevil.example")
	navigation.Header.Set("Accept", "text/html")
	s.applicationUnauthenticated(response, navigation, app)
	if response.Code != 400 {
		t.Fatal("encoded external destination accepted", response.Code)
	}
	s.applicationPortalOrigin = "https://portal.example.test/unsafe"
	response = httptest.NewRecorder()
	navigation = appRequest(app, "", http.MethodGet, "/native")
	navigation.Header.Set("Sec-Fetch-Dest", "document")
	s.applicationUnauthenticated(response, navigation, app)
	if response.Code != 503 {
		t.Fatal("invalid operator portal origin accepted", response.Code)
	}
	backend, _ := url.Parse("https://backend.example.test/base")
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Location", "https://backend.example.test/%zz")
	if err := rewriteApplicationResponse(resp, app, backend); err == nil {
		t.Fatal("invalid backend Location accepted")
	}
	resp = &http.Response{Header: make(http.Header)}
	resp.Header.Add("Set-Cookie", (&http.Cookie{Name: "native", Value: "synthetic", Path: "/base", Secure: true, HttpOnly: true}).String())
	resp.Header.Set("Location", backend.String())
	if err := rewriteApplicationResponse(resp, app, backend); err != nil || resp.Cookies()[0].Path != "/" || resp.Header.Get("Location") != "https://"+app.PublicHostname+"/" {
		t.Fatal("backend root cookie/redirect prefix not mapped safely", err)
	}
}

type applicationDeadlineFailureWriter struct{ *httptest.ResponseRecorder }

func (*applicationDeadlineFailureWriter) SetWriteDeadline(time.Time) error {
	return errors.New("synthetic write deadline unavailable")
}
func (*applicationDeadlineFailureWriter) SetReadDeadline(time.Time) error {
	return errors.New("synthetic read deadline unavailable")
}
func TestApplicationFrontendDeadlineFailureAbortsBeforeBodyIO(t *testing.T) {
	underlying := &applicationDeadlineFailureWriter{httptest.NewRecorder()}
	writer := &applicationWriter{ResponseWriter: underlying, ctx: context.Background()}
	if n, err := writer.Write([]byte("native")); err == nil || n != 0 || underlying.Body.Len() != 0 {
		t.Fatal("failed write deadline allowed body output", n, err)
	}
	if err := writer.FlushError(); err == nil {
		t.Fatal("failed deadline allowed flush")
	}
	body := &applicationBody{ReadCloser: io.NopCloser(strings.NewReader("native")), writer: writer}
	if n, err := body.Read(make([]byte, 6)); err == nil || n != 0 {
		t.Fatal("failed read deadline allowed upload bytes", n, err)
	}
	if _, _, err := writer.Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatal("unsupported upgrade capability error lost", err)
	}
}

func TestApplicationWriteConnectionPreservesHalfCloseAndClosedSocketErrors(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peerReady := make(chan net.Conn, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		peerReady <- peer
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer := <-peerReady
	defer peer.Close()
	_ = peer.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))
	wrapped := applicationWriteConn{Conn: client}
	if err = wrapped.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err = peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("TCP write half remained open", err)
	}
	if _, err = peer.Write([]byte("r")); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Read(make([]byte, 1)); err != nil || n != 1 {
		t.Fatal("half-close destroyed read half", n, err)
	}
	left, right := net.Pipe()
	defer right.Close()
	if err = (applicationWriteConn{Conn: left}).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err = (applicationWriteConn{Conn: left}).Write([]byte("x")); err == nil {
		t.Fatal("closed socket deadline failure ignored")
	}
}

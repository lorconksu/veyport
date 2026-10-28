package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
)

func TestBrowserTerminalRetainsOriginalSignedAuthorityAcrossBody(t *testing.T) {
	for _, mutation := range []string{"generation", "expiry", "session"} {
		t.Run(mutation, func(t *testing.T) {
			s, token, node := testServerWithAgent(t)
			claims, err := auth.ValidateToken(s.jwtSecret, token)
			if err != nil {
				t.Fatal(err)
			}
			before, err := s.store.GetUserByID(claims.Subject)
			if err != nil {
				t.Fatal(err)
			}
			actorToken := ""
			if mutation == "generation" {
				_, actorToken, _, _ = quickSecurityUser(t, s, "terminal-admin", model.RoleAdmin)
			}
			req := httptest.NewRequest("POST", testServersPrefix+node+testTerminalSessionsSuffix, nil)
			req.Header.Set("Authorization", testBearerPrefix+token)
			req.Body = io.NopCloser(&managementDelayedBody{reader: strings.NewReader(`{"cols":80,"rows":24}`), before: func() {
				switch mutation {
				case "generation":
					// A real role mutation leaves an LDAP viewer eligible through its explicit
					// grant, while requiring the old signed caller to authenticate again.
					if _, err := s.store.DB().Exec("UPDATE users SET auth_provider='ldap',terminal_access=1,ldap_username='operator' WHERE id=?", before.ID); err != nil {
						t.Fatal(err)
					}
					if _, err := s.store.CreatePermission(before.ID, node, "/"); err != nil {
						t.Fatal(err)
					}
					response := lifecycleRequest(t, s, "PUT", "/api/users/"+before.ID+"/role", actorToken, model.UpdateRoleRequest{Role: model.RoleViewer})
					if response.Code != http.StatusOK {
						t.Fatalf("role mutation: %d %s", response.Code, response.Body.String())
					}
					refused := lifecycleRequest(t, s, "GET", "/api/auth/me", token, nil)
					if refused.Code != http.StatusUnauthorized {
						t.Fatal("old signed authority was not revoked")
					}
					owning, err := s.store.GetSession(claims.SessionID)
					if err != nil || owning.EndedAt != nil {
						t.Fatalf("role transition ended owning session: %v", err)
					}
				case "expiry":
					s.SetClock(func() time.Time { return claims.ExpiresAt.Time.Add(time.Second) })
				case "session":
					if _, err := s.store.EndSession(claims.SessionID, model.SessionEndLogout, nil, s.now()); err != nil {
						t.Fatal(err)
					}
				}
			}})
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)
			if rec.Code < 400 {
				t.Fatalf("revoked request admitted: %d %s", rec.Code, rec.Body.String())
			}
			if shells := s.terminalSessions.ListByUser(before.ID); len(shells) != 0 {
				t.Fatal("revoked request left a shell")
			}
			stream := s.connMgr.GetConn(node).Stream.(*mockGRPCStream)
			for _, msg := range stream.sent {
				if msg.GetTerminalOpenRequest() != nil {
					t.Fatal("revoked authority reached agent")
				}
			}
		})
	}
}

func TestBrowserTerminalSurvivesOpeningTokenExpiryAfterRefresh(t *testing.T) {
	s, token, node := testServerWithAgent(t)
	if err := s.store.SetConfig(lockout.KeySessionIdleMinutes, "45"); err != nil {
		t.Fatal(err)
	}
	claims, err := auth.ValidateToken(s.jwtSecret, token)
	if err != nil {
		t.Fatal(err)
	}
	id := createTerminalSessionForTest(t, s, token, node)

	// Model the browser's normal access-token refresh: the replacement carries
	// the same durable session and credential generation. Advancing the server
	// clock beyond the opening token must not revoke that still-live session.
	user, err := s.store.GetUserByID(claims.Subject)
	if err != nil {
		t.Fatal(err)
	}
	refreshed, _, err := auth.GenerateSessionTokenPair(s.jwtSecret, user.ID, string(user.Role), user.TokenGeneration, claims.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	s.SetClock(func() time.Time { return claims.ExpiresAt.Time.Add(time.Second) })

	input := lifecycleRequest(t, s, "POST", testServersPrefix+node+testTerminalSessionsSuffix+"/"+id+"/input", refreshed, map[string]string{"data": "echo still-live\n"})
	if input.Code != http.StatusAccepted {
		t.Fatalf("refreshed session lost its terminal at opening-token expiry: %d %s", input.Code, input.Body.String())
	}
	info, ok := s.terminalSessions.Get(node, id)
	if !ok || info.Closed {
		t.Fatal("opening-token expiry closed a terminal owned by a live refreshed session")
	}
}

func TestBrowserTerminalOpeningTokenMustSurviveOrderedOpenSend(t *testing.T) {
	s, token, node := testServerWithAgent(t)
	claims, err := auth.ValidateToken(s.jwtSecret, token)
	if err != nil {
		t.Fatal(err)
	}
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Second))
	shortToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.jwtSecret))
	if err != nil {
		t.Fatal(err)
	}
	conn := s.connMgr.GetConn(node)
	conn.SendMu.Lock()
	locked := true
	defer func() {
		if locked {
			conn.SendMu.Unlock()
		}
	}()
	req := httptest.NewRequest("POST", testServersPrefix+node+testTerminalSessionsSuffix, strings.NewReader(`{"cols":80,"rows":24}`))
	req.Header.Set("Authorization", testBearerPrefix+shortToken)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); s.routes().ServeHTTP(rec, req) }()
	deadline := time.After(1500 * time.Millisecond)
	for len(s.terminalSessions.ListByUser(claims.Subject)) == 0 {
		select {
		case <-done:
			conn.SendMu.Unlock()
			locked = false
			t.Fatalf("terminal request ended before ordered send: %d %s", rec.Code, rec.Body.String())
		case <-deadline:
			conn.SendMu.Unlock()
			locked = false
			t.Fatal("terminal request did not reach ordered send")
		case <-time.After(10 * time.Millisecond):
		}
	}
	time.Sleep(time.Until(claims.ExpiresAt.Time) + 100*time.Millisecond)
	conn.SendMu.Unlock()
	locked = false
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("expired opening request did not terminate")
	}
	if rec.Code < 400 {
		t.Fatalf("expired opening authority reached the agent: %d %s", rec.Code, rec.Body.String())
	}
	stream := conn.Stream.(*mockGRPCStream)
	for _, msg := range stream.sent {
		if msg.GetTerminalOpenRequest() != nil {
			t.Fatal("expired opening authority sent TerminalOpenRequest")
		}
	}
}

func TestBrowserSSEForcedExitDiscardsOutputDequeuedBeforeWrite(t *testing.T) {
	s, token, node := testServerWithAgent(t)
	id := createTerminalSessionForTest(t, s, token, node)
	s.terminalSessions.DeliverData(node, id, []byte("PRIVATE_QUEUED_OUTPUT"))
	// Force closure in the first header flush, after attachment but before the
	// transport starts draining its queue. Exercise the real HTTP handler.
	rec := &terminalRevokingRecorder{ResponseRecorder: httptest.NewRecorder(), onFlush: func() { s.terminalSessions.EndOne(node, id, 1, "revoked") }}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := httptest.NewRequest("GET", testServersPrefix+node+testTerminalSessionsSuffix+"/"+id+"/stream", nil).WithContext(ctx)
	req.Header.Set("Authorization", testBearerPrefix+token)
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "event: exit") || strings.Contains(rec.Body.String(), "UFJJVkFURV8") {
		t.Fatalf("private data preceded forced exit: %s", rec.Body.String())
	}
}

type terminalRevokingRecorder struct {
	*httptest.ResponseRecorder
	onFlush func()
}

func (w *terminalRevokingRecorder) Flush() {
	w.ResponseRecorder.Flush()
	if fn := w.onFlush; fn != nil {
		w.onFlush = nil
		fn()
	}
}

func TestBrowserSSEForcedClosureAbortsInflightPrivateWrite(t *testing.T) {
	s, token, node := testServerWithAgent(t)
	a := &daybreakTerminalAgent{mockGRPCStream: mockGRPCStream{pending: s.pending, serverID: node, terms: s.terminalSessions}, close: make(chan struct{})}
	s.connMgr.Register(node, a)
	id := createTerminalSessionForTest(t, s, token, node)
	rec := &blockedTerminalRecorder{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), abort: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := httptest.NewRequest("GET", testServersPrefix+node+testTerminalSessionsSuffix+"/"+id+"/stream", nil).WithContext(ctx)
	req.Header.Set("Authorization", testBearerPrefix+token)
	done := make(chan struct{})
	go func() { defer close(done); s.routes().ServeHTTP(rec, req) }()
	s.terminalSessions.DeliverData(node, id, []byte("PRIVATE_INFLIGHT_OUTPUT"))
	select {
	case <-rec.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not dequeue output")
	}
	closed := make(chan struct{})
	go func() { s.terminalSessions.EndOne(node, id, 1, "revoked"); close(closed) }()
	for _, ch := range []<-chan struct{}{closed, done, a.close} {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatal("revocation did not abort output and close captured agent")
		}
	}
	if strings.Contains(rec.Body.String(), "data:") {
		t.Fatalf("private output escaped revocation: %s", rec.Body.String())
	}
}

type blockedTerminalRecorder struct {
	*httptest.ResponseRecorder
	entered, abort chan struct{}
	once           sync.Once
}

func (w *blockedTerminalRecorder) Write(b []byte) (int, error) {
	if strings.HasPrefix(string(b), "data: ") {
		close(w.entered)
		<-w.abort
		return 0, context.Canceled
	}
	return w.ResponseRecorder.Write(b)
}
func (w *blockedTerminalRecorder) SetWriteDeadline(deadline time.Time) error {
	if !deadline.After(time.Now()) {
		w.once.Do(func() { close(w.abort) })
	}
	return nil
}

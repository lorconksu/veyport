package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"

	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
)

func TestCLISessionIdleDefaultAndActivityReset(t *testing.T) {
	s, clk := sessionServer(t)
	user := newLocalUser(t, s, "cli-idle", lockoutTestPassword)
	sess, err := s.newSession(sessionRequest(sessionTestCLIAgent), user)
	if err != nil {
		t.Fatal(err)
	}
	created := clk.now()
	if sess.ExpiresAt == nil || !sess.ExpiresAt.Equal(created.Add(12*time.Hour)) {
		t.Fatalf("absolute lifetime = %v, want 12h", sess.ExpiresAt)
	}
	clk.advance(20 * time.Minute)
	if err := s.sessionAccessError(claimsFor(sess.ID)); err != nil {
		t.Fatalf("CLI session idle for 20m refused: %v", err)
	}
	if got := reloadSession(t, s, sess.ID).LastSeenAt; !got.Equal(clk.now()) {
		t.Fatalf("successful activity did not reset idle clock: %s", got)
	}
	rows, err := s.sessionsFor(user.ID, sess.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	var serialized []model.Session
	if err = json.Unmarshal(raw, &serialized); err != nil || len(serialized) != 1 {
		t.Fatalf("session list decode: %v, %s", err, raw)
	}
	wantDeadline := clk.now().Add(45 * time.Minute)
	if serialized[0].IdleDeadlineAt == nil || !serialized[0].IdleDeadlineAt.Equal(wantDeadline) {
		t.Fatalf("serialized CLI idle deadline = %v, want %s", serialized[0].IdleDeadlineAt, wantDeadline)
	}
	clk.advance(45 * time.Minute)
	if err := s.checkSessionAccess(claimsFor(sess.ID), false); err != nil {
		t.Fatalf("CLI session refused at exact 45m boundary: %v", err)
	}
	clk.advance(time.Second)
	assertSessionError(t, s.sessionAccessError(claimsFor(sess.ID)), session.MsgExpired, "CLI past45m")
	if got := reloadSession(t, s, sess.ID).EndReason; got != model.SessionEndExpiredIdle {
		t.Fatalf("expiry reason = %q", got)
	}
}

func TestCLIRefreshUsesStoredKindDespiteBrowserUserAgent(t *testing.T) {
	s, clk := sessionServer(t)
	user := newLocalUser(t, s, "cli-refresh-idle", lockoutTestPassword)
	secret := enableTOTPForUser(t, s, user)
	_, refresh, sid := signInWith(t, s, user, secret, sessionTestCLIAgent)
	clk.advance(20 * time.Minute)
	response := postRefresh(t, s, refresh) // no CLI user agent on this request
	if response.Code != http.StatusOK {
		t.Fatalf("CLI refresh after20m: status=%d body=%s", response.Code, response.Body.String())
	}
	if got := reloadSession(t, s, sid).LastSeenAt; !got.Equal(clk.now()) {
		t.Fatalf("refresh did not reset CLI idle clock: %s", got)
	}
}

func TestWebSessionIdleRemains15MinutesWithCLIUserAgentStored(t *testing.T) {
	s, clk := sessionServer(t)
	user := newLocalUser(t, s, "web-idle", lockoutTestPassword)
	sess := newSessionRow(t, s, user.ID)
	if _, err := s.store.DB().Exec("UPDATE sessions SET user_agent=? WHERE id=?", sessionTestCLIAgent, sess.ID); err != nil {
		t.Fatal(err)
	}
	clk.advance(15 * time.Minute)
	if err := s.checkSessionAccess(claimsFor(sess.ID), false); err != nil {
		t.Fatalf("web session refused at exact15m boundary: %v", err)
	}
	clk.advance(time.Second)
	assertSessionError(t, s.sessionAccessError(claimsFor(sess.ID)), session.MsgExpired, "web past15m")
}

func TestCLITouchIntervalUsesIndependentConfiguredLimit(t *testing.T) {
	s, clk := sessionServer(t)
	if err := s.store.SetConfig(lockout.KeyCLISessionIdleMinutes, "1"); err != nil {
		t.Fatal(err)
	}
	user := newLocalUser(t, s, "cli-touch", lockoutTestPassword)
	sess, err := s.newSession(sessionRequest(sessionTestCLIAgent), user)
	if err != nil {
		t.Fatal(err)
	}
	created := clk.now()
	clk.advance(5 * time.Second)
	if err := s.sessionAccessError(claimsFor(sess.ID)); err != nil {
		t.Fatal(err)
	}
	if !reloadSession(t, s, sess.ID).LastSeenAt.Equal(created) {
		t.Fatal("CLI touch exceeded throttle")
	}
	clk.advance(2 * time.Second)
	if err := s.sessionAccessError(claimsFor(sess.ID)); err != nil {
		t.Fatal(err)
	}
	if !reloadSession(t, s, sess.ID).LastSeenAt.Equal(clk.now()) {
		t.Fatal("CLI activity did not use its6s throttle")
	}
	clk.advance(time.Minute + time.Second)
	assertSessionError(t, s.sessionAccessError(claimsFor(sess.ID)), session.MsgExpired, "configured CLI idle")
}

func TestOriginalAuthorityUsesStoredCLIIdle(t *testing.T) {
	h := newOriginalHTTP(t, nil)
	for _, tc := range []struct {
		name, kind string
		gap        time.Duration
		wantOK     bool
	}{
		{"cli20m", model.SessionKindCLI, 20 * time.Minute, true},
		{"cli46m", model.SessionKindCLI, 46 * time.Minute, false},
		{"web20m", model.SessionKindWeb, 20 * time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.s.store.DB().Exec("UPDATE sessions SET kind=?,user_agent='vey/spoof',last_seen_at=? WHERE id=?", tc.kind, h.clock.Now().Add(-tc.gap).Format("2006-01-02 15:04:05"), h.sid); err != nil {
				t.Fatal(err)
			}
			_, _, err := h.s.originalAuthority("original-reader", h.sid, nil)
			if (err == nil) != tc.wantOK {
				t.Fatalf("original authority=%v, wantOK=%v", err, tc.wantOK)
			}
		})
	}
}

// Invoke the handler after authentication to prove its registration-time
// authority check also selects the persisted kind before sending to the agent.
func TestCLITerminalRegistrationUsesStoredIdlePolicy(t *testing.T) {
	for _, tc := range []struct {
		kind string
		gap  time.Duration
		want int
	}{
		{model.SessionKindCLI, 20 * time.Minute, http.StatusCreated},
		{model.SessionKindCLI, 46 * time.Minute, http.StatusForbidden},
		{model.SessionKindWeb, 20 * time.Minute, http.StatusForbidden},
	} {
		t.Run(tc.kind+"/"+tc.gap.String(), func(t *testing.T) {
			s, token, serverID := testServerWithAgent(t)
			claims, err := auth.ValidateToken(s.jwtSecret, token)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			s.SetClock(func() time.Time { return now })
			if _, err = s.store.DB().Exec("UPDATE sessions SET kind=?,last_seen_at=? WHERE id=?", tc.kind, now.Add(-tc.gap).Format("2006-01-02 15:04:05"), claims.SessionID); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", testServersPrefix+serverID+testTerminalSessionsSuffix, mustJSON(t, map[string]uint32{"cols": 80, "rows": 24}))
			req.SetPathValue("id", serverID)
			ctx := context.WithValue(req.Context(), ctxUserID, claims.Subject)
			ctx = context.WithValue(ctx, ctxSessionID, claims.SessionID)
			rec := httptest.NewRecorder()
			s.handleCreateTerminalSession(rec, req.WithContext(ctx))
			if rec.Code != tc.want {
				t.Fatalf("registration=%d body=%s, want%d", rec.Code, rec.Body.String(), tc.want)
			}
		})
	}
}

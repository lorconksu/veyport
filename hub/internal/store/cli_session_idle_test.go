package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestSessionRefreshStoredKindIdlePolicy(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		gap        time.Duration
		ended      bool
		absolute   bool
		wantOK     bool
	}{
		{"cli_after20m", model.SessionKindCLI, 20 * time.Minute, false, false, true},
		{"cli_exact45m", model.SessionKindCLI, 45 * time.Minute, false, false, true},
		{"cli_after45m", model.SessionKindCLI, 45*time.Minute + time.Second, false, false, false},
		{"web_exact15m", model.SessionKindWeb, 15 * time.Minute, false, false, true},
		{"web_after15m", model.SessionKindWeb, 15*time.Minute + time.Second, false, false, false},
		{"unknown_uses_web", "future-client", 20 * time.Minute, false, false, false},
		{"missing_uses_web", "", 20 * time.Minute, false, false, false},
		{"cli_revoked", model.SessionKindCLI, 20 * time.Minute, true, false, false},
		{"cli_absolute", model.SessionKindCLI, 20 * time.Minute, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			allowCorruptSessionKindFixture(t, s, tc.kind)
			u := refreshStoreOwner(t, s)
			sid := refreshStoreSession(t, s, u)
			if _, err := s.DB().Exec("UPDATE sessions SET kind=?,user_agent='vey/spoof' WHERE id=?", tc.kind, sid); err != nil {
				t.Fatal(err)
			}
			policy := lockout.Defaults()
			old, next := strings.Repeat("a", 64), strings.Repeat("b", 64)
			if err := s.RotateSessionRefresh(context.Background(), u, sid, "", old, refreshTime, policy); err != nil {
				t.Fatal(err)
			}
			now := refreshTime.Add(tc.gap)
			if tc.ended {
				if _, err := s.EndSession(sid, model.SessionEndRevokedAdmin, &u.ID, now); err != nil {
					t.Fatal(err)
				}
			}
			if tc.absolute {
				if _, err := s.DB().Exec("UPDATE sessions SET expires_at=? WHERE id=?", now.Format("2006-01-02 15:04:05"), sid); err != nil {
					t.Fatal(err)
				}
			}
			err := s.RotateSessionRefresh(context.Background(), u, sid, old, next, now, policy)
			if tc.wantOK && err != nil || !tc.wantOK && !errors.Is(err, store.ErrSessionRefreshRejected) {
				t.Fatalf("rotation=%v, wantOK=%v", err, tc.wantOK)
			}
			var digest string
			if err := s.DB().QueryRow("SELECT refresh_token_sha256 FROM sessions WHERE id=?", sid).Scan(&digest); err != nil {
				t.Fatal(err)
			}
			wantDigest, wantSeen := old, refreshTime
			if tc.wantOK {
				wantDigest, wantSeen = next, now
			}
			if digest != wantDigest || !mustGetSession(t, s, sid).LastSeenAt.Equal(wantSeen) {
				t.Fatal("rotation changed authority or activity contrary to its result")
			}
		})
	}
}

func TestSessionRefreshIdleLimitsDisableIndependently(t *testing.T) {
	for _, disabledKind := range []string{model.SessionKindWeb, model.SessionKindCLI} {
		for _, kind := range []string{model.SessionKindWeb, model.SessionKindCLI} {
			t.Run(disabledKind+"_disabled/"+kind, func(t *testing.T) {
				s := testStore(t)
				u := refreshStoreOwner(t, s)
				sid := refreshStoreSession(t, s, u)
				if _, err := s.DB().Exec("UPDATE sessions SET kind=? WHERE id=?", kind, sid); err != nil {
					t.Fatal(err)
				}
				policy := lockout.Defaults()
				if disabledKind == model.SessionKindCLI {
					policy.CLISessionIdle = 0
				} else {
					policy.SessionIdle = 0
				}
				err := s.RotateSessionRefresh(context.Background(), u, sid, strings.Repeat("a", 64), strings.Repeat("b", 64), refreshTime.Add(46*time.Minute), policy)
				if kind == disabledKind && err != nil || kind != disabledKind && !errors.Is(err, store.ErrSessionRefreshRejected) {
					t.Fatalf("rotation=%v, disabledkind=%s sessionkind=%s", err, disabledKind, kind)
				}
			})
		}
	}
}

// Each operation checks the principal in its transaction: passing the HTTP
// precheck must not let a later stale session create, authorize or claim a permit.
func TestOriginalAccessStoredKindIdlePolicyAtEveryCommit(t *testing.T) {
	for _, phase := range []string{"create", "authorize", "consume"} {
		for _, tc := range []struct {
			name, kind string
			gap        time.Duration
			ended      bool
			absolute   bool
			wantOK     bool
		}{
			{"cli_after20m", model.SessionKindCLI, 20 * time.Minute, false, false, true},
			{"cli_exact45m", model.SessionKindCLI, 45 * time.Minute, false, false, true},
			{"cli_after45m", model.SessionKindCLI, 45*time.Minute + time.Second, false, false, false},
			{"web_exact15m", model.SessionKindWeb, 15 * time.Minute, false, false, true},
			{"web_after15m", model.SessionKindWeb, 15*time.Minute + time.Second, false, false, false},
			{"unknown_uses_web", "future-client", 20 * time.Minute, false, false, false},
			{"missing_uses_web", "", 20 * time.Minute, false, false, false},
			{"cli_revoked", model.SessionKindCLI, 20 * time.Minute, true, false, false},
			{"cli_absolute", model.SessionKindCLI, 20 * time.Minute, false, true, false},
		} {
			t.Run(phase+"/"+tc.name, func(t *testing.T) {
				s := testStore(t)
				allowCorruptSessionKindFixture(t, s, tc.kind)
				now := refreshTime
				a, proof := originalFixture(t, s, "cli-original", now)
				policy := lockout.Defaults()
				if phase != "create" {
					if err := s.CreateOriginalAccess(a, proof, now.Add(24*time.Hour), now, policy); err != nil {
						t.Fatal(err)
					}
				}
				if phase == "consume" {
					if err := s.AuthorizeOriginalAccess(a.ID, "verified-intent", a.ExpiresAt, a.Object, now, policy); err != nil {
						t.Fatal(err)
					}
				}
				originalExec(t, s, "UPDATE sessions SET kind=?,user_agent='vey/spoof',last_seen_at=? WHERE id=?", tc.kind, now.Add(-tc.gap).Format("2006-01-02 15:04:05"), a.SessionID)
				if tc.ended {
					originalExec(t, s, "UPDATE sessions SET ended_at=? WHERE id=?", now.Format("2006-01-02 15:04:05"), a.SessionID)
				}
				if tc.absolute {
					originalExec(t, s, "UPDATE sessions SET expires_at=? WHERE id=?", now.Format("2006-01-02 15:04:05"), a.SessionID)
				}
				operation := func() error {
					switch phase {
					case "create":
						return s.CreateOriginalAccess(a, proof, now.Add(24*time.Hour), now, policy)
					case "authorize":
						return s.AuthorizeOriginalAccess(a.ID, "verified-intent", a.ExpiresAt, a.Object, now, policy)
					default:
						_, err := s.ConsumeOriginalAccess(a.HandleSHA256, a.UserID, a.SessionID, now, policy)
						return err
					}
				}
				err := operation()
				if tc.wantOK && err != nil || !tc.wantOK && !errors.Is(err, store.ErrOriginalAccess) {
					t.Fatalf("%s=%v, wantOK=%v", phase, err, tc.wantOK)
				}
				if !tc.wantOK {
					// A refused transaction must preserve its one-use authority.
					originalExec(t, s, "UPDATE sessions SET last_seen_at=?,ended_at=NULL,expires_at=NULL WHERE id=?", now.Format("2006-01-02 15:04:05"), a.SessionID)
					if err := operation(); err != nil {
						t.Fatalf("refused transaction consumed authority: %v", err)
					}
				}
			})
		}
	}
}

// Production constrains kind to web/cli. These two defensive cases emulate a
// corrupted or future kind only inside this disposable in-memory database.
func allowCorruptSessionKindFixture(t *testing.T, s *store.Store, kind string) {
	t.Helper()
	if kind == model.SessionKindWeb || kind == model.SessionKindCLI {
		return
	}
	s.DB().SetMaxOpenConns(1)
	if _, err := s.DB().Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
		t.Fatal(err)
	}
}

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

var refreshTime = time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)

func refreshStoreOwner(t *testing.T, s *store.Store) *model.User {
	t.Helper()
	u := &model.User{ID: "refresh-owner", Username: "refresh_owner", Email: "refresh@test.invalid", PasswordHash: "test-hash", Role: model.RoleViewer, TOTPEnabled: true}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetUserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func refreshStoreSession(t *testing.T, s *store.Store, u *model.User) string {
	t.Helper()
	expires := refreshTime.Add(time.Hour)
	newSession(t, s, "refresh-session", u.ID, refreshTime, &expires)
	return "refresh-session"
}

func TestSessionRefreshPersistsSpendAcrossRestartWithoutDisclosingDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	u := refreshStoreOwner(t, s)
	sid := refreshStoreSession(t, s, u)
	old, next := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := s.RotateSessionRefresh(context.Background(), u, sid, "", old, refreshTime, lockout.Policy{SessionIdle: 15 * time.Minute, CLISessionIdle: 15 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateSessionRefresh(context.Background(), u, sid, old, next, refreshTime.Add(time.Minute), lockout.Policy{SessionIdle: 15 * time.Minute, CLISessionIdle: 15 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	var durability int
	if err := s.DB().QueryRow("PRAGMA synchronous").Scan(&durability); err != nil || durability != 2 {
		t.Fatalf("refresh durability=%d err=%v, want FULL", durability, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.RotateSessionRefresh(context.Background(), u, sid, old, strings.Repeat("c", 64), refreshTime.Add(2*time.Minute), lockout.Policy{SessionIdle: 15 * time.Minute, CLISessionIdle: 15 * time.Minute}); !errors.Is(err, store.ErrSessionRefreshRejected) {
		t.Fatalf("spent token after restart: %v", err)
	}
	if err := s.RotateSessionRefresh(context.Background(), u, sid, next, strings.Repeat("d", 64), refreshTime.Add(2*time.Minute), lockout.Policy{SessionIdle: 15 * time.Minute, CLISessionIdle: 15 * time.Minute}); err != nil {
		t.Fatalf("current token after restart: %v", err)
	}
	sessions, err := s.ListUserSessions(u.ID, false, refreshTime)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(sessions)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "refresh_token") || strings.Contains(string(encoded), next) {
		t.Fatal("session listing disclosed refresh authority")
	}
	after, err := s.GetUserByID(u.ID)
	if err != nil || after.TokenGeneration != u.TokenGeneration || after.SecurityRevision != u.SecurityRevision {
		t.Fatalf("routine rotation changed user authority: err=%v", err)
	}
}

func TestLegacySessionRefreshAdoptionHasOneDurableWinner(t *testing.T) {
	s := testStore(t)
	u := refreshStoreOwner(t, s)
	sid := refreshStoreSession(t, s, u)
	start := make(chan struct{})
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.RotateSessionRefresh(context.Background(), u, sid, strings.Repeat("a", 64), strings.Repeat("b", 64), refreshTime.Add(time.Minute), lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	winners := 0
	for err := range errs {
		if err == nil {
			winners++
		} else if !errors.Is(err, store.ErrSessionRefreshRejected) {
			t.Fatalf("adoption error: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("legacy adoption winners=%d", winners)
	}
}

func TestSessionRefreshRefusesRevokedAuthorityBeforeDurableSpend(t *testing.T) {
	for _, mutation := range []struct {
		name  string
		apply func(*testing.T, *store.Store, *model.User, string)
	}{
		{"explicit_generation", func(t *testing.T, s *store.Store, u *model.User, _ string) {
			if _, err := s.IncrementTokenGeneration(u.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{"role_revision", func(t *testing.T, s *store.Store, u *model.User, _ string) {
			if err := s.UpdateUserRole(u.ID, model.RoleAuditor); err != nil {
				t.Fatal(err)
			}
		}},
		{"disabled", func(t *testing.T, s *store.Store, u *model.User, _ string) {
			if _, err := s.DB().Exec("UPDATE users SET disabled_at=? WHERE id=?", refreshTime.Format(time.RFC3339), u.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{"mfa_reset", func(t *testing.T, s *store.Store, u *model.User, _ string) {
			if _, err := s.DB().Exec("UPDATE users SET totp_enabled=0,totp_secret=NULL WHERE id=?", u.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{"password_recovery", func(t *testing.T, s *store.Store, u *model.User, _ string) {
			if _, err := s.DB().Exec("UPDATE users SET must_change_password=1 WHERE id=?", u.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{"ended", func(t *testing.T, s *store.Store, u *model.User, sid string) {
			if _, err := s.EndSession(sid, model.SessionEndLogout, &u.ID, refreshTime); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			s := testStore(t)
			u := refreshStoreOwner(t, s)
			sid := refreshStoreSession(t, s, u)
			old := strings.Repeat("a", 64)
			if err := s.RotateSessionRefresh(context.Background(), u, sid, "", old, refreshTime, lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour}); err != nil {
				t.Fatal(err)
			}
			mutation.apply(t, s, u, sid)
			if err := s.RotateSessionRefresh(context.Background(), u, sid, old, strings.Repeat("b", 64), refreshTime.Add(time.Minute), lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour}); !errors.Is(err, store.ErrSessionRefreshRejected) {
				t.Fatalf("revoked snapshot rotation: %v", err)
			}
			var stored string
			if err := s.DB().QueryRow("SELECT refresh_token_sha256 FROM sessions WHERE id=?", sid).Scan(&stored); err != nil || stored != old {
				t.Fatalf("rejected operation spent refresh authority: err=%v", err)
			}
		})
	}
}

func TestRecoverySessionNeverPublishesNormalAuthority(t *testing.T) {
	t.Run("initial_issue_without_refresh_permission", func(t *testing.T) {
		s := testStore(t)
		u := refreshStoreOwner(t, s)
		if _, err := s.DB().Exec("UPDATE users SET must_change_password=1 WHERE id=?", u.ID); err != nil {
			t.Fatal(err)
		}
		u, err := s.GetUserByID(u.ID)
		if err != nil {
			t.Fatal(err)
		}
		sid := refreshStoreSession(t, s, u)
		issued := strings.Repeat("a", 64)
		if err := s.RotateSessionRefresh(context.Background(), u, sid, "", issued, refreshTime, lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour}); !errors.Is(err, store.ErrSessionRefreshRejected) {
			t.Fatalf("mandatory-change sign-in published normal authority: %v", err)
		}
		if err := s.RotateSessionRefresh(context.Background(), u, sid, issued, strings.Repeat("b", 64), refreshTime.Add(time.Minute), lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour}); !errors.Is(err, store.ErrSessionRefreshRejected) {
			t.Fatalf("unfinished recovery rotated refresh authority: %v", err)
		}
		var current string
		if err := s.DB().QueryRow("SELECT refresh_token_sha256 FROM sessions WHERE id=?", sid).Scan(&current); err != nil || current != "" {
			t.Fatal("rejected recovery request published normal authority")
		}
	})
	for _, initial := range []bool{false, true} {
		name := "recovery_started_after_authentication"
		if initial {
			name = "recovery_completed_after_authentication"
		}
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			u := refreshStoreOwner(t, s)
			if _, err := s.DB().Exec("UPDATE users SET must_change_password=? WHERE id=?", initial, u.ID); err != nil {
				t.Fatal(err)
			}
			u, err := s.GetUserByID(u.ID)
			if err != nil {
				t.Fatal(err)
			}
			sid := refreshStoreSession(t, s, u)
			if _, err := s.DB().Exec("UPDATE users SET must_change_password=? WHERE id=?", !initial, u.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.RotateSessionRefresh(context.Background(), u, sid, "", strings.Repeat("a", 64), refreshTime, lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour}); !errors.Is(err, store.ErrSessionRefreshRejected) {
				t.Fatalf("stale authenticated password state issued a session pair: %v", err)
			}
			var current string
			if err := s.DB().QueryRow("SELECT refresh_token_sha256 FROM sessions WHERE id=?", sid).Scan(&current); err != nil || current != "" {
				t.Fatal("refused issuance published a refresh digest")
			}
		})
	}
}

func TestSessionRefreshEnforcesOwnerAndExactSessionLimits(t *testing.T) {
	for _, tc := range []struct {
		name       string
		now        time.Time
		idle       time.Duration
		wrongOwner bool
		wantOK     bool
	}{
		{"idle_boundary", refreshTime.Add(15 * time.Minute), 15 * time.Minute, false, true},
		{"idle_expired", refreshTime.Add(15*time.Minute + time.Second), 15 * time.Minute, false, false},
		{"absolute_boundary", refreshTime.Add(time.Hour), 0, false, false},
		{"owner", refreshTime.Add(time.Minute), 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			u := refreshStoreOwner(t, s)
			sid := refreshStoreSession(t, s, u)
			if tc.wrongOwner {
				copy := *u
				copy.ID = "another-owner"
				u = &copy
			}
			err := s.RotateSessionRefresh(context.Background(), u, sid, strings.Repeat("a", 64), strings.Repeat("b", 64), tc.now, lockout.Policy{SessionIdle: tc.idle, CLISessionIdle: tc.idle})
			if tc.wantOK && err != nil {
				t.Fatal(err)
			}
			if !tc.wantOK && !errors.Is(err, store.ErrSessionRefreshRejected) {
				t.Fatalf("rotation: %v", err)
			}
		})
	}
}

func TestSessionRefreshIndependentStoreHandlesHaveOneSpend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	first, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	u := refreshStoreOwner(t, first)
	sid := refreshStoreSession(t, first, u)
	old := strings.Repeat("a", 64)
	if err := first.RotateSessionRefresh(context.Background(), u, sid, "", old, refreshTime, lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour}); err != nil {
		t.Fatal(err)
	}
	second, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, handle := range []*store.Store{first, second} {
		go func() {
			<-start
			errs <- handle.RotateSessionRefresh(context.Background(), u, sid, old, strings.Repeat("b", 64), refreshTime.Add(time.Minute), lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour})
		}()
	}
	close(start)
	winners := 0
	for range 2 {
		err := <-errs
		if err == nil {
			winners++
		} else if !errors.Is(err, store.ErrSessionRefreshRejected) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("independent database handles produced %d winners", winners)
	}
}

func TestSessionRefreshCancellationAndUnavailableStorePreserveAuthority(t *testing.T) {
	s := testStore(t)
	u := refreshStoreOwner(t, s)
	sid := refreshStoreSession(t, s, u)
	old := strings.Repeat("a", 64)
	if err := s.RotateSessionRefresh(context.Background(), u, sid, "", old, refreshTime, lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.RotateSessionRefresh(ctx, u, sid, old, strings.Repeat("b", 64), refreshTime.Add(time.Minute), lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled rotation: %v", err)
	}
	var digest string
	if err := s.DB().QueryRow("SELECT refresh_token_sha256 FROM sessions WHERE id=?", sid).Scan(&digest); err != nil || digest != old {
		t.Fatalf("cancelled rotation changed authority: err=%v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateSessionRefresh(context.Background(), u, sid, old, strings.Repeat("b", 64), refreshTime, lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour}); err == nil {
		t.Fatal("unavailable database granted refresh authority")
	}
}

func TestSessionRefreshCannotReplaceAuthorityWithTheSameDigest(t *testing.T) {
	s := testStore(t)
	u := refreshStoreOwner(t, s)
	sid := refreshStoreSession(t, s, u)
	digest := strings.Repeat("a", 64)
	if err := s.RotateSessionRefresh(context.Background(), u, sid, "", digest, refreshTime, lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateSessionRefresh(context.Background(), u, sid, digest, digest, refreshTime.Add(time.Minute), lockout.Policy{SessionIdle: time.Hour, CLISessionIdle: time.Hour}); !errors.Is(err, store.ErrSessionRefreshRejected) {
		t.Fatalf("unchanged refresh authority could be reused: %v", err)
	}
	if got := mustGetSession(t, s, sid); !got.LastSeenAt.Equal(refreshTime) {
		t.Fatal("rejected unchanged token extended activity")
	}
}

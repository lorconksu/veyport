package store_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

func TestPasswordHistoryLegacyActiveSeedDoesNotConsumeReducedDepth(t *testing.T) {
	s := testStore(t)
	u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
	prior := "PriorPermanent!1234"
	priorHash, err := auth.HashPassword(prior)
	if err != nil {
		t.Fatal(err)
	}
	activeHash, err := auth.HashPassword("ActivePermanent!1234")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUserPassword(u.ID, activeHash); err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{priorHash, activeHash} {
		if err := s.AddPasswordHistory(u.ID, hash); err != nil {
			t.Fatal(err)
		}
	}
	settings := s.GetAuditSettings()
	settings.PasswordHistoryCount = 1
	if err := s.UpdateAuditSettings(settings); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		candidate string
		want      bool
	}{{prior, true}, {"ActivePermanent!1234", false}} {
		match, err := s.PasswordMatchesRecent(u.ID, test.candidate, s.GetAuditSettings().PasswordHistoryCount)
		if err != nil || match != test.want {
			t.Fatalf("match=%t want=%t err=%v", match, test.want, err)
		}
	}
}

func TestPasswordHistoryCountsPriorPermanentPasswords(t *testing.T) {
	for _, limit := range []int{1, 2, 5, 24} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			s := testStore(t)
			u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
			now := time.Now().UTC().Truncate(time.Second)
			// Legacy accounts may have their active hash seeded in history.
			if err := s.AddPasswordHistory(u.ID, u.PasswordHash); err != nil {
				t.Fatal(err)
			}
			var want []string
			for i := range limit + 2 {
				want = append([]string{u.PasswordHash}, want...)
				if len(want) > limit {
					want = want[:limit]
				}
				// Same-second transitions must still retain the newest outgoing hash.
				if _, err := s.ChangeLocalPassword(u, fmt.Sprintf("permanent-%d", i), now, limit, false, managementAudit(u.ID, u.ID, model.AuditUserPasswordChanged)); err != nil {
					t.Fatal(err)
				}
				assertPasswordHistoryHashes(t, s, u.ID, want)
				u = mustGetUser(t, s, u.ID)
			}
		})
	}
}

func TestPasswordHistorySurvivesRepeatedTemporaryResetAndCompletion(t *testing.T) {
	for _, seeded := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy-seeded-%t", seeded), func(t *testing.T) {
			s := testStore(t)
			u := newLifecycleUser(t, s, "target", "target", model.RoleViewer)
			now := time.Now().UTC().Truncate(time.Second)
			if seeded {
				if err := s.AddPasswordHistory(u.ID, u.PasswordHash); err != nil {
					t.Fatal(err)
				}
			}
			want := []string{u.PasswordHash}
			for i := range 2 {
				var err error
				u, err = s.ResetLocalPassword(store.PasswordResetTarget{UserID: u.ID, ExpectedGeneration: u.TokenGeneration}, store.TemporaryPasswordCredential{Hash: fmt.Sprintf("temporary-%d", i), ExpiresAt: now.Add(time.Hour)}, now, 1, managementAudit(u.ID, u.ID, model.AuditUserPasswordReset))
				if err != nil {
					t.Fatal(err)
				}
				assertPasswordHistoryHashes(t, s, u.ID, want)
			}
			// Simulate a temporary credential seeded by an older version, without
			// losing the permanent entry. Completion must remove it, not retain it.
			if err := s.AddPasswordHistory(u.ID, u.PasswordHash); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ChangeLocalPassword(u, "replacement", now, 1, true, managementAudit(u.ID, u.ID, model.AuditUserPasswordChanged)); err != nil {
				t.Fatal(err)
			}
			assertPasswordHistoryHashes(t, s, u.ID, want)
		})
	}
}

func assertPasswordHistoryHashes(t *testing.T, s *store.Store, userID string, want []string) {
	t.Helper()
	rows, err := s.DB().Query("SELECT password_hash FROM password_history WHERE user_id=? ORDER BY created_at DESC,rowid DESC", userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			t.Fatal(err)
		}
		got = append(got, hash)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("history hashes = %v, want %v", got, want)
	}
}

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
)

// T010 — unit tests for the shared account-lifecycle enforcement helper.
//
// Everything the HTTP handlers, the middleware and the SSH paths do about
// disabled and dormant accounts routes through these four functions, so the
// mapping from account state to (status, message, audit detail, HTTP shape) is
// pinned here once. The wiring tests then only have to prove each path calls
// the helper at the right point.

// sqliteTimeLayout is how the store writes timestamps; the lifecycle tests
// back-date columns directly, so they have to speak the same dialect.
const sqliteTimeLayout = "2006-01-02 15:04:05"

// disabledByActor is the administrator id recorded on a test disable.
const disabledByActor = "admin-actor"

// markDisabled disables the account directly in the database.
//
// The store's DisableUser does more than this (generation bump, token
// revocation), and it belongs to another task; enforcement must hold on the
// columns alone, so these tests set the columns and nothing else.
func markDisabled(t *testing.T, s *Server, userID string, when time.Time) {
	t.Helper()
	if _, err := s.store.DB().Exec(
		`UPDATE users SET disabled_at = ?, disabled_by = ? WHERE id = ?`,
		when.UTC().Format(sqliteTimeLayout), disabledByActor, userID,
	); err != nil {
		t.Fatalf("mark user %s disabled: %v", userID, err)
	}
}

// clearDisabled re-enables the account, the way an administrator's enable would
// leave it as far as these tests are concerned.
func clearDisabled(t *testing.T, s *Server, userID string, when time.Time) {
	t.Helper()
	if _, err := s.store.DB().Exec(
		`UPDATE users SET disabled_at = NULL, disabled_by = NULL, reactivated_at = ? WHERE id = ?`,
		when.UTC().Format(sqliteTimeLayout), userID,
	); err != nil {
		t.Fatalf("clear disabled on user %s: %v", userID, err)
	}
}

// backdateActivity moves every point on the account's activity clock into the
// past. All three columns have to move together: the derived status takes the
// latest of them, so leaving one at "now" would keep the account active.
func backdateActivity(t *testing.T, s *Server, userID string, when time.Time) {
	t.Helper()
	stamp := when.UTC().Format(sqliteTimeLayout)
	if _, err := s.store.DB().Exec(
		`UPDATE users SET created_at = ?, last_activity_at = ?, reactivated_at = ? WHERE id = ?`,
		stamp, stamp, stamp, userID,
	); err != nil {
		t.Fatalf("back-date activity for user %s: %v", userID, err)
	}
}

// setLastActivity stamps only the activity column, leaving the rest alone.
func setLastActivity(t *testing.T, s *Server, userID string, when time.Time) {
	t.Helper()
	if _, err := s.store.DB().Exec(
		`UPDATE users SET last_activity_at = ? WHERE id = ?`,
		when.UTC().Format(sqliteTimeLayout), userID,
	); err != nil {
		t.Fatalf("stamp activity for user %s: %v", userID, err)
	}
}

// setDormantDays writes the dormancy window through the config store.
func setDormantDays(t *testing.T, s *Server, days int) {
	t.Helper()
	if err := s.store.SetConfig(lockout.KeyDormantDays, strconv.Itoa(days)); err != nil {
		t.Fatalf("set %s: %v", lockout.KeyDormantDays, err)
	}
}

// markDormancyExempt sets the exemption flag directly.
func markDormancyExempt(t *testing.T, s *Server, userID string) {
	t.Helper()
	if _, err := s.store.DB().Exec(
		`UPDATE users SET dormancy_exempt = 1 WHERE id = ?`, userID,
	); err != nil {
		t.Fatalf("mark user %s dormancy exempt: %v", userID, err)
	}
}

// errorBody decodes the {"error": …} envelope every refusal uses.
func errorBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	return body["error"]
}

// The four statuses the helper has to distinguish, each built from the columns
// that produce it, with the refusal shape each one implies.
func TestAccountHelpers_StatusDrivesRefusalAndMessage(t *testing.T) {
	cases := []struct {
		name       string
		arrange    func(t *testing.T, s *Server, clk *testClock, user *model.User)
		wantStatus account.Status
		wantRefuse bool
		wantMsg    string
		wantDetail string
	}{
		{
			name:       "active",
			arrange:    func(*testing.T, *Server, *testClock, *model.User) {},
			wantStatus: account.StatusActive,
		},
		{
			name: "locked",
			arrange: func(t *testing.T, s *Server, clk *testClock, user *model.User) {
				lockAccountNow(t, s, user.ID, clk.now(), 15*time.Minute)
			},
			wantStatus: account.StatusLocked,
		},
		{
			name: "disabled",
			arrange: func(t *testing.T, s *Server, clk *testClock, user *model.User) {
				markDisabled(t, s, user.ID, clk.now())
			},
			wantStatus: account.StatusDisabled,
			wantRefuse: true,
			wantMsg:    account.MsgDisabled,
			wantDetail: detailAccountDisabled,
		},
		{
			name: "dormant",
			arrange: func(t *testing.T, s *Server, clk *testClock, user *model.User) {
				setDormantDays(t, s, 1)
				backdateActivity(t, s, user.ID, clk.now().Add(-48*time.Hour))
			},
			wantStatus: account.StatusDormant,
			wantRefuse: true,
			wantMsg:    account.MsgDormant,
			wantDetail: detailAccountDormant,
		},
		{
			name: "disabled outranks locked",
			arrange: func(t *testing.T, s *Server, clk *testClock, user *model.User) {
				lockAccountNow(t, s, user.ID, clk.now(), 15*time.Minute)
				markDisabled(t, s, user.ID, clk.now())
			},
			wantStatus: account.StatusDisabled,
			wantRefuse: true,
			wantMsg:    account.MsgDisabled,
			wantDetail: detailAccountDisabled,
		},
		{
			name: "dormant outranks locked",
			arrange: func(t *testing.T, s *Server, clk *testClock, user *model.User) {
				setDormantDays(t, s, 1)
				backdateActivity(t, s, user.ID, clk.now().Add(-48*time.Hour))
				lockAccountNow(t, s, user.ID, clk.now(), 15*time.Minute)
			},
			wantStatus: account.StatusDormant,
			wantRefuse: true,
			wantMsg:    account.MsgDormant,
			wantDetail: detailAccountDormant,
		},
		{
			name: "exempt admin never goes dormant",
			arrange: func(t *testing.T, s *Server, clk *testClock, user *model.User) {
				setDormantDays(t, s, 1)
				markDormancyExempt(t, s, user.ID)
				backdateActivity(t, s, user.ID, clk.now().Add(-48*time.Hour))
			},
			wantStatus: account.StatusActive,
		},
		{
			name: "dormancy disabled by policy",
			arrange: func(t *testing.T, s *Server, clk *testClock, user *model.User) {
				setDormantDays(t, s, 0)
				backdateActivity(t, s, user.ID, clk.now().Add(-365*24*time.Hour))
			},
			wantStatus: account.StatusActive,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, clk := lockoutServer(t)
			user := newLocalUser(t, s, "helper", lockoutTestPassword)
			c.arrange(t, s, clk, user)
			user = reloadUser(t, s, user.ID)

			gotStatus := s.accountStatus(user)
			if gotStatus != c.wantStatus {
				t.Fatalf("accountStatus() = %q, want %q", gotStatus, c.wantStatus)
			}
			if got := accountRefuses(gotStatus); got != c.wantRefuse {
				t.Fatalf("accountRefuses(%q) = %v, want %v", gotStatus, got, c.wantRefuse)
			}
			if got := accountRefusalDetail(gotStatus); got != c.wantDetail {
				t.Fatalf("accountRefusalDetail(%q) = %q, want %q", gotStatus, got, c.wantDetail)
			}

			err := s.accountAccessError(user)
			if !c.wantRefuse {
				if err != nil {
					t.Fatalf("accountAccessError() = %v, want nil for a usable account", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accountAccessError() = nil, want a refusal for a %q account", gotStatus)
			}
			var accountErr *accountAccessError
			if !errors.As(err, &accountErr) {
				t.Fatalf("accountAccessError() = %T, want *accountAccessError", err)
			}
			if accountErr.Status != c.wantStatus {
				t.Fatalf("carried status = %q, want %q", accountErr.Status, c.wantStatus)
			}
			if err.Error() != c.wantMsg {
				t.Fatalf("Error() = %q, want %q", err.Error(), c.wantMsg)
			}
		})
	}
}

// refuseAccount answers with 403 and the canonical message, and records the
// attempt as a login failure carrying the account-state detail — so the audit
// trail distinguishes "refused because of the account" from a bad password.
func TestAccountHelpers_RefuseAccountRespondsAndAudits(t *testing.T) {
	cases := []struct {
		name       string
		arrange    func(t *testing.T, s *Server, clk *testClock, user *model.User)
		wantMsg    string
		wantDetail string
	}{
		{
			name: "disabled",
			arrange: func(t *testing.T, s *Server, clk *testClock, user *model.User) {
				markDisabled(t, s, user.ID, clk.now())
			},
			wantMsg:    account.MsgDisabled,
			wantDetail: detailAccountDisabled,
		},
		{
			name: "dormant",
			arrange: func(t *testing.T, s *Server, clk *testClock, user *model.User) {
				setDormantDays(t, s, 1)
				backdateActivity(t, s, user.ID, clk.now().Add(-48*time.Hour))
			},
			wantMsg:    account.MsgDormant,
			wantDetail: detailAccountDormant,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, clk := lockoutServer(t)
			user := newLocalUser(t, s, "refused", lockoutTestPassword)
			c.arrange(t, s, clk, user)
			user = reloadUser(t, s, user.ID)

			req := httptest.NewRequest("POST", testLoginPath, nil)
			rec := httptest.NewRecorder()
			s.refuseAccount(rec, req, user, s.accountStatus(user))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
			}
			if got := errorBody(t, rec); got != c.wantMsg {
				t.Fatalf("message = %q, want %q", got, c.wantMsg)
			}

			entries := auditEntriesFor(t, s, user.ID, model.AuditUserLoginFailed)
			if len(entries) != 1 {
				t.Fatalf("expected one %s entry, got %d", model.AuditUserLoginFailed, len(entries))
			}
			entry := entries[0]
			if entry.Detail == nil || *entry.Detail != c.wantDetail {
				t.Fatalf("audit detail = %v, want %q", entry.Detail, c.wantDetail)
			}
			if entry.Outcome != model.AuditOutcomeFailure {
				t.Fatalf("audit outcome = %q, want %q", entry.Outcome, model.AuditOutcomeFailure)
			}

			// The attempt never reached a credential check, so it must not
			// move the lockout counter — the same rule refuseLocked follows.
			if after := reloadUser(t, s, user.ID); after.FailedLoginCount != 0 {
				t.Fatalf("refusal moved the failure counter to %d, want 0", after.FailedLoginCount)
			}
		})
	}
}

// A status that does not refuse must never produce a response body: the guard
// inside refuseAccount exists so a future miswiring fails loudly in tests
// rather than silently answering 200 with nothing in it.
func TestAccountHelpers_RefuseAccountIgnoresUsableAccounts(t *testing.T) {
	s, _ := lockoutServer(t)
	user := newLocalUser(t, s, "usable", lockoutTestPassword)

	req := httptest.NewRequest("POST", testLoginPath, nil)
	rec := httptest.NewRecorder()
	s.refuseAccount(rec, req, user, account.StatusActive)

	if rec.Body.Len() != 0 {
		t.Fatalf("refuseAccount wrote %q for an active account, want nothing", rec.Body.String())
	}
	if got := len(auditEntriesFor(t, s, user.ID, model.AuditUserLoginFailed)); got != 0 {
		t.Fatalf("refuseAccount audited %d failures for an active account, want 0", got)
	}
}

// clearDormancyExempt removes the exemption, which the first administrator is
// created with. Tests that need that account to go dormant must clear it.
func clearDormancyExempt(t *testing.T, s *Server, userID string) {
	t.Helper()
	if _, err := s.store.DB().Exec(
		`UPDATE users SET dormancy_exempt = 0 WHERE id = ?`, userID,
	); err != nil {
		t.Fatalf("clear dormancy exemption on user %s: %v", userID, err)
	}
}

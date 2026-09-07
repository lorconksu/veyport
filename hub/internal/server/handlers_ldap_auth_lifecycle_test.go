package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/model"
)

// T012 (directory half) — a disabled or dormant directory account must be
// refused before the hub opens a single connection to the directory.
//
// This is the same property 007 established for locked accounts, and it
// matters for the same reason: if the hub bound to the directory on behalf of
// an account it has already refused, an attacker could use a refused account
// as a credential-stuffing proxy against the directory, and the directory's
// own lockout would punish the user for it. The dialer call counter is the
// sentinel — it must stay at zero.

// ldapLifecycleState pairs a way of making the shadow account unusable with
// the message the refusal must carry.
type ldapLifecycleState struct {
	name    string
	apply   func(t *testing.T, s *Server, clk *testClock, user *model.User)
	message string
	detail  string
}

func ldapLifecycleStates() []ldapLifecycleState {
	return []ldapLifecycleState{
		{
			name: "disabled",
			apply: func(t *testing.T, s *Server, clk *testClock, user *model.User) {
				markDisabled(t, s, user.ID, clk.now())
			},
			message: account.MsgDisabled,
			detail:  detailAccountDisabled,
		},
		{
			name: "dormant",
			apply: func(t *testing.T, s *Server, clk *testClock, user *model.User) {
				setDormantDays(t, s, 1)
				backdateActivity(t, s, user.ID, clk.now().Add(-48*time.Hour))
			},
			message: account.MsgDormant,
			detail:  detailAccountDormant,
		},
	}
}

// The sign-in entry point refuses the directory account without dialling.
func TestLDAPLifecycle_UnusableAccountRefusedBeforeAnyDirectoryContact(t *testing.T) {
	for _, state := range ldapLifecycleStates() {
		t.Run(state.name, func(t *testing.T) {
			s, clk := lockoutServer(t)
			setLockoutPolicy(t, s, 5, 15, 15)
			dialer := installLDAPLockoutDirectory(t, s, "")
			user := newLDAPUser(t, s)
			state.apply(t, s, clk, user)

			rec := attemptLogin(t, s, ldapLockoutUsername, ldapLockoutPassword)
			assertRefused(t, rec, http.StatusForbidden, state.message, "ldap "+state.name)

			if dialer.count() != 0 {
				t.Fatalf("expected zero directory connections, got %d", dialer.count())
			}

			entries := auditEntriesFor(t, s, user.ID, model.AuditUserLoginFailed)
			if len(entries) != 1 {
				t.Fatalf("expected one %s entry, got %d", model.AuditUserLoginFailed, len(entries))
			}
			if entries[0].Detail == nil || *entries[0].Detail != state.detail {
				t.Fatalf("audit detail = %v, want %q", entries[0].Detail, state.detail)
			}
			if after := reloadUser(t, s, user.ID); after.FailedLoginCount != 0 {
				t.Fatalf("failure counter moved to %d on a refused directory account", after.FailedLoginCount)
			}
		})
	}
}

// The guard inside the directory branch itself: even entered directly, the
// branch refuses before authenticateLDAPLogin can dial.
func TestLDAPLifecycle_DirectoryBranchGuardsStatusDirectly(t *testing.T) {
	for _, state := range ldapLifecycleStates() {
		t.Run(state.name, func(t *testing.T) {
			s, clk := lockoutServer(t)
			setLockoutPolicy(t, s, 5, 15, 15)
			dialer := installLDAPLockoutDirectory(t, s, "")
			user := newLDAPUser(t, s)
			state.apply(t, s, clk, user)
			user = reloadUser(t, s, user.ID)

			loginReq := model.LoginRequest{Username: ldapLockoutUsername, Password: ldapLockoutPassword}
			req := httptest.NewRequest("POST", testLoginPath, mustJSON(t, loginReq))
			rec := httptest.NewRecorder()
			s.handleLDAPUserLogin(rec, req, loginReq, user)

			assertRefused(t, rec, http.StatusForbidden, state.message, "ldap branch "+state.name)
			if dialer.count() != 0 {
				t.Fatalf("expected zero directory connections, got %d", dialer.count())
			}
		})
	}
}

// A directory account that is both locked and unusable is refused for the
// unusable state, matching the local-account precedence exactly.
func TestLDAPLifecycle_RefusalOutranksLock(t *testing.T) {
	for _, state := range ldapLifecycleStates() {
		t.Run(state.name, func(t *testing.T) {
			s, clk := lockoutServer(t)
			setLockoutPolicy(t, s, 5, 15, 15)
			dialer := installLDAPLockoutDirectory(t, s, "")
			user := newLDAPUser(t, s)
			lockAccountNow(t, s, user.ID, clk.now(), 15*time.Minute)
			state.apply(t, s, clk, user)

			rec := attemptLogin(t, s, ldapLockoutUsername, ldapLockoutPassword)
			assertRefused(t, rec, http.StatusForbidden, state.message, "locked ldap "+state.name)
			if dialer.count() != 0 {
				t.Fatalf("expected zero directory connections, got %d", dialer.count())
			}
		})
	}
}

// The username-miss route: the typed name matches no hub account, but the
// directory resolves to a shadow account that already exists and is unusable.
// The upsert matches on the directory's stable identifier, so this route can
// hand back a disabled account under a name the hub does not index it by; it
// must be refused like any other.
func TestLDAPLifecycle_UnknownUsernameCannotReviveUnusableAccount(t *testing.T) {
	for _, state := range ldapLifecycleStates() {
		t.Run(state.name, func(t *testing.T) {
			s, clk := lockoutServer(t)
			setLockoutPolicy(t, s, 5, 15, 15)
			installLDAPLockoutDirectory(t, s, "")
			user := newLDAPUser(t, s)
			state.apply(t, s, clk, user)

			// The hub knows this account only by its directory identifier, so
			// a sign-in under a name it does not index reaches the directory
			// route rather than the shadow-account route.
			if _, err := s.store.DB().Exec(
				`UPDATE users SET username = ? WHERE id = ?`, "renamed-in-hub", user.ID,
			); err != nil {
				t.Fatalf("rename shadow account: %v", err)
			}

			rec := attemptLogin(t, s, ldapLockoutUsername, ldapLockoutPassword)
			assertRefused(t, rec, http.StatusForbidden, state.message, "ldap upsert route "+state.name)

			if findCookie(rec.Result().Cookies(), cookieAccess) != nil {
				t.Fatal("a refused directory sign-in set an access cookie")
			}
		})
	}
}

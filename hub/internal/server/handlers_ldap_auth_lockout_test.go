package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
)

// Directory-backed accounts are subject to the same lock, and a locked account
// must be refused before the hub contacts the directory at all (FR-005): a
// lock-out attack against a directory account must not turn the hub into a
// credential-stuffing proxy. The dialer call counter is the sentinel.

const (
	ldapLockoutUsername = "dana"
	ldapLockoutDN       = "uid=dana,ou=people,dc=example,dc=com"
	ldapLockoutPassword = "directory-password"
	ldapLockoutEntryID  = "entry-dana"
)

// countingLDAPDialer records how many times the hub opened a directory
// connection and hands out a freshly primed fake connection each time.
type countingLDAPDialer struct {
	mu      sync.Mutex
	calls   int
	newConn func() LDAPConnection
}

func (d *countingLDAPDialer) dial(LDAPConfig) (LDAPConnection, error) {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	return d.newConn(), nil
}

func (d *countingLDAPDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// ldapLockoutDirectory returns the user and group search results the fake
// directory replies with, in the order the authenticator asks for them.
func ldapLockoutDirectory() []*ldap.SearchResult {
	return []*ldap.SearchResult{
		{Entries: []*ldap.Entry{ldap.NewEntry(ldapLockoutDN, map[string][]string{
			"uid":       {ldapLockoutUsername},
			"mail":      {ldapLockoutUsername + "@example.com"},
			"entryUUID": {ldapLockoutEntryID},
		})}},
		{Entries: []*ldap.Entry{ldap.NewEntry("cn=veyport-viewers,ou=groups,dc=example,dc=com",
			map[string][]string{"cn": {"veyport-viewers"}})}},
	}
}

// installLDAPLockoutDirectory enables LDAP sign-in against a fake directory.
// When wrongPassword is non-empty, a bind with it fails the way a real
// directory rejects bad credentials.
func installLDAPLockoutDirectory(t *testing.T, s *Server, wrongPassword string) *countingLDAPDialer {
	t.Helper()
	setLDAPConfigForTest(t, s, map[string]string{
		"ldap.enabled":       "true",
		"ldap.url":           "ldaps://dir.example.com:636",
		"ldap.user_base_dn":  "ou=people,dc=example,dc=com",
		"ldap.group_base_dn": "ou=groups,dc=example,dc=com",
	})
	dialer := &countingLDAPDialer{}
	dialer.newConn = func() LDAPConnection {
		conn := &fakeLDAPConn{results: ldapLockoutDirectory()}
		if wrongPassword != "" {
			conn.bindFailures = map[string]error{
				ldapLockoutDN + "\x00" + wrongPassword: fmt.Errorf("invalid credentials"),
			}
		}
		return conn
	}
	s.SetLDAPDialer(dialer.dial)
	return dialer
}

// newLDAPUser creates the hub-side shadow account for the directory user.
func newLDAPUser(t *testing.T, s *Server) *model.User {
	t.Helper()
	user, err := s.store.UpsertLDAPUser(&model.User{
		Username:   ldapLockoutUsername,
		Email:      ldapLockoutUsername + "@example.com",
		Role:       model.RoleViewer,
		ExternalID: ldapLockoutEntryID,
		LDAPDN:     ldapLockoutDN,
	})
	if err != nil {
		t.Fatalf("create ldap shadow user: %v", err)
	}
	return user
}

// lockAccountNow drives the account into a locked state through the store,
// using a one-strike policy so the test does not depend on handler behaviour.
func lockAccountNow(t *testing.T, s *Server, userID string, now time.Time, duration time.Duration) {
	t.Helper()
	res, err := s.store.RecordLoginFailure(userID, now, lockout.Policy{
		Threshold: 1,
		Window:    time.Minute,
		Duration:  duration,
	})
	if err != nil {
		t.Fatalf("lock account: %v", err)
	}
	if !res.NewlyLocked {
		t.Fatal("expected the seeding failure to lock the account")
	}
}

// A locked directory account is refused without a single directory connection.
func TestLDAPLockout_LockedAccountIsRefusedBeforeAnyDirectoryContact(t *testing.T) {
	s, clk := lockoutServer(t)
	setLockoutPolicy(t, s, 5, 15, 15)
	dialer := installLDAPLockoutDirectory(t, s, "")
	user := newLDAPUser(t, s)
	lockAccountNow(t, s, user.ID, clk.now(), 15*time.Minute)

	rec := attemptLogin(t, s, ldapLockoutUsername, ldapLockoutPassword)
	assertLockedResponse(t, rec, "locked ldap account")

	if dialer.count() != 0 {
		t.Fatalf("expected zero directory connections while locked, got %d", dialer.count())
	}
}

// The guard inside the directory branch itself: even reached directly, a locked
// account never gets as far as a bind.
func TestLDAPLockout_DirectoryBranchGuardsLockDirectly(t *testing.T) {
	s, clk := lockoutServer(t)
	setLockoutPolicy(t, s, 5, 15, 15)
	dialer := installLDAPLockoutDirectory(t, s, "")
	user := newLDAPUser(t, s)
	lockAccountNow(t, s, user.ID, clk.now(), 15*time.Minute)
	user = reloadUser(t, s, user.ID)

	loginReq := model.LoginRequest{Username: ldapLockoutUsername, Password: ldapLockoutPassword}
	req := httptest.NewRequest("POST", testLoginPath, mustJSON(t, loginReq))
	rec := httptest.NewRecorder()
	s.handleLDAPUserLogin(rec, req, loginReq, user)

	assertLockedResponse(t, rec, "locked ldap account via directory branch")
	if dialer.count() != 0 {
		t.Fatalf("expected zero directory connections while locked, got %d", dialer.count())
	}
}

// Failed directory binds count toward the same threshold as local password
// failures and lock the account.
func TestLDAPLockout_BindFailuresCountTowardThreshold(t *testing.T) {
	s, _ := lockoutServer(t)
	setLockoutPolicy(t, s, 2, 15, 15)
	dialer := installLDAPLockoutDirectory(t, s, lockoutWrongPassword)
	user := newLDAPUser(t, s)

	for i := 1; i <= 2; i++ {
		rec := attemptLogin(t, s, ldapLockoutUsername, lockoutWrongPassword)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("bind failure %d: expected 401, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	locked := reloadUser(t, s, user.ID)
	if locked.FailedLoginCount != 2 {
		t.Fatalf("expected 2 counted bind failures, got %d", locked.FailedLoginCount)
	}
	if locked.LockedUntil == nil {
		t.Fatal("expected directory bind failures to lock the account")
	}

	dialsBefore := dialer.count()
	assertLockedResponse(t, attemptLogin(t, s, ldapLockoutUsername, ldapLockoutPassword), "after ldap lock")
	if dialer.count() != dialsBefore {
		t.Fatalf("refused attempt still contacted the directory: %d → %d", dialsBefore, dialer.count())
	}
}

// After the lock expires, the directory is consulted again and a completed
// sign-in clears the streak.
func TestLDAPLockout_SuccessAfterExpiryResetsCounter(t *testing.T) {
	s, clk := lockoutServer(t)
	setLockoutPolicy(t, s, 2, 15, 15)
	dialer := installLDAPLockoutDirectory(t, s, lockoutWrongPassword)
	user := newLDAPUser(t, s)
	secret := enableTOTPForUser(t, s, user)

	for i := 0; i < 2; i++ {
		attemptLogin(t, s, ldapLockoutUsername, lockoutWrongPassword)
	}
	if reloadUser(t, s, user.ID).LockedUntil == nil {
		t.Fatal("expected the account to be locked")
	}

	clk.advance(16 * time.Minute)

	totpToken := primaryLoginTOTPToken(t, s, ldapLockoutUsername, ldapLockoutPassword)
	if dialer.count() == 0 {
		t.Fatal("expected the directory to be consulted once the lock expired")
	}

	code, err := auth.GenerateValidCode(secret)
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	if rec := attemptTOTP(t, s, totpToken, code); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 completing sign-in, got %d: %s", rec.Code, rec.Body.String())
	}

	after := reloadUser(t, s, user.ID)
	if after.FailedLoginCount != 0 {
		t.Fatalf("expected the counter to reset after sign-in, got %d", after.FailedLoginCount)
	}
	if after.LockedUntil != nil {
		t.Fatalf("expected the lock cleared after sign-in, got %s", after.LockedUntil)
	}
	if after.LastLoginAt == nil {
		t.Fatal("expected last_login_at to be stamped")
	}
}

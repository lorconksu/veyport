package store_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// sqliteTimeFormat is unexported in package store; mirror it here so the tests
// can assert the second-precision round trip the store promises.
const testSQLiteTimeFormat = "2006-01-02 15:04:05"

const testRecordFailureFmt = "record login failure: %v"

// testPolicy is the policy used by most cases: lock after 3 consecutive
// failures inside 15 minutes, for 15 minutes.
func testPolicy() lockout.Policy {
	return lockout.Policy{Threshold: 3, Window: 15 * time.Minute, Duration: 15 * time.Minute}
}

// newLockoutUser creates a local user for a lockout test and returns its ID.
func newLockoutUser(t *testing.T, s *store.Store, id, username string) string {
	t.Helper()
	if err := s.CreateUser(&model.User{
		ID:           id,
		Username:     username,
		Email:        username + "@test.com",
		PasswordHash: "h",
		Role:         model.RoleViewer,
	}); err != nil {
		t.Fatalf("create user %s: %v", id, err)
	}
	return id
}

// assertSecond compares a stored timestamp against the wall clock value it was
// written from, allowing for the store's second precision.
func assertSecond(t *testing.T, label string, got *time.Time, want time.Time) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: expected %s, got nil", label, want.Format(testSQLiteTimeFormat))
	}
	if !got.Equal(want.UTC().Truncate(time.Second)) {
		t.Fatalf("%s: expected %s, got %s",
			label, want.UTC().Truncate(time.Second).Format(testSQLiteTimeFormat),
			got.Format(testSQLiteTimeFormat))
	}
}

// TestRecordLoginFailure_FreshUser covers the first failure on an account that
// has never failed: the count starts at 1, nothing locks, and the timestamp is
// persisted truncated to whole seconds.
func TestRecordLoginFailure_FreshUser(t *testing.T) {
	s := testStore(t)
	id := newLockoutUser(t, s, "u-fresh", "fresh")

	now := time.Date(2026, 9, 5, 10, 30, 15, 123456789, time.UTC)
	res, err := s.RecordLoginFailure(id, now, testPolicy())
	if err != nil {
		t.Fatalf(testRecordFailureFmt, err)
	}
	if res.Count != 1 {
		t.Fatalf("expected count 1, got %d", res.Count)
	}
	if res.LockedUntil != nil {
		t.Fatalf("expected nil locked_until, got %v", res.LockedUntil)
	}
	if res.NewlyLocked {
		t.Fatal("expected NewlyLocked false on the first failure")
	}

	got, err := s.GetUserByID(id)
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if got.FailedLoginCount != 1 {
		t.Fatalf("expected persisted failed_login_count 1, got %d", got.FailedLoginCount)
	}
	assertSecond(t, "last_failed_login_at", got.LastFailedLoginAt, now)
	if got.LockedUntil != nil {
		t.Fatalf("expected persisted locked_until nil, got %v", got.LockedUntil)
	}
	if got.LastLoginAt != nil {
		t.Fatalf("expected last_login_at untouched, got %v", got.LastLoginAt)
	}
}

// TestRecordLoginFailure_LocksAtThreshold covers the locking transition and the
// rule that an attempt made while locked never extends the lock.
func TestRecordLoginFailure_LocksAtThreshold(t *testing.T) {
	s := testStore(t)
	id := newLockoutUser(t, s, "u-lock", "locky")

	p := testPolicy()
	now := time.Date(2026, 9, 5, 11, 0, 0, 0, time.UTC)

	for i := 1; i <= 2; i++ {
		res, err := s.RecordLoginFailure(id, now, p)
		if err != nil {
			t.Fatalf("failure %d: %v", i, err)
		}
		if res.Count != i {
			t.Fatalf("failure %d: expected count %d, got %d", i, i, res.Count)
		}
		if res.NewlyLocked || res.LockedUntil != nil {
			t.Fatalf("failure %d: expected no lock, got %+v", i, res)
		}
	}

	third, err := s.RecordLoginFailure(id, now, p)
	if err != nil {
		t.Fatalf("third failure: %v", err)
	}
	if third.Count != 3 {
		t.Fatalf("expected count 3, got %d", third.Count)
	}
	if !third.NewlyLocked {
		t.Fatal("expected NewlyLocked true on the threshold failure")
	}
	wantUntil := now.Add(15 * time.Minute)
	if third.LockedUntil == nil || !third.LockedUntil.Equal(wantUntil) {
		t.Fatalf("expected locked_until %v, got %v", wantUntil, third.LockedUntil)
	}

	fourth, err := s.RecordLoginFailure(id, now, p)
	if err != nil {
		t.Fatalf("fourth failure: %v", err)
	}
	if fourth.NewlyLocked {
		t.Fatal("expected NewlyLocked false while already locked")
	}
	if fourth.Count != 4 {
		t.Fatalf("expected count 4, got %d", fourth.Count)
	}
	if fourth.LockedUntil == nil || !fourth.LockedUntil.Equal(wantUntil) {
		t.Fatalf("expected the lock not to be extended (%v), got %v", wantUntil, fourth.LockedUntil)
	}

	got, err := s.GetUserByID(id)
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if got.FailedLoginCount != 4 {
		t.Fatalf("expected persisted failed_login_count 4, got %d", got.FailedLoginCount)
	}
	assertSecond(t, "locked_until", got.LockedUntil, wantUntil)
}

// TestRecordLoginFailure_WindowElapsedResetsCount covers a failure that arrives
// after the counting window has passed: it starts a fresh streak.
func TestRecordLoginFailure_WindowElapsedResetsCount(t *testing.T) {
	s := testStore(t)
	id := newLockoutUser(t, s, "u-window", "windy")

	p := testPolicy()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	for i := 1; i <= 2; i++ {
		res, err := s.RecordLoginFailure(id, now, p)
		if err != nil {
			t.Fatalf("failure %d: %v", i, err)
		}
		if res.Count != i {
			t.Fatalf("failure %d: expected count %d, got %d", i, i, res.Count)
		}
	}

	later := now.Add(16 * time.Minute)
	res, err := s.RecordLoginFailure(id, later, p)
	if err != nil {
		t.Fatalf("failure after window: %v", err)
	}
	if res.Count != 1 {
		t.Fatalf("expected count to restart at 1 after the window, got %d", res.Count)
	}
	if res.NewlyLocked {
		t.Fatal("expected NewlyLocked false after the window reset")
	}

	got, err := s.GetUserByID(id)
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if got.FailedLoginCount != 1 {
		t.Fatalf("expected persisted failed_login_count 1, got %d", got.FailedLoginCount)
	}
	assertSecond(t, "last_failed_login_at", got.LastFailedLoginAt, later)
}

// TestRecordLoginSuccess_ClearsCountAndLock covers the success path: the streak
// and the lock are cleared, the last login is stamped, and the failure history
// timestamp is deliberately retained.
func TestRecordLoginSuccess_ClearsCountAndLock(t *testing.T) {
	s := testStore(t)
	id := newLockoutUser(t, s, "u-success", "succy")

	p := testPolicy()
	failedAt := time.Date(2026, 9, 5, 13, 0, 0, 0, time.UTC)
	for i := 1; i <= 3; i++ {
		if _, err := s.RecordLoginFailure(id, failedAt, p); err != nil {
			t.Fatalf("failure %d: %v", i, err)
		}
	}

	loggedInAt := failedAt.Add(20 * time.Minute)
	if err := s.RecordLoginSuccess(id, loggedInAt); err != nil {
		t.Fatalf("record login success: %v", err)
	}

	got, err := s.GetUserByID(id)
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if got.FailedLoginCount != 0 {
		t.Fatalf("expected failed_login_count 0 after success, got %d", got.FailedLoginCount)
	}
	if got.LockedUntil != nil {
		t.Fatalf("expected locked_until cleared after success, got %v", got.LockedUntil)
	}
	assertSecond(t, "last_login_at", got.LastLoginAt, loggedInAt)
	assertSecond(t, "last_failed_login_at", got.LastFailedLoginAt, failedAt)
}

// TestRecordLogin_UnknownUser covers both entry points refusing an unknown user
// without touching any other row.
func TestRecordLogin_UnknownUser(t *testing.T) {
	s := testStore(t)
	id := newLockoutUser(t, s, "u-bystander", "bystander")

	before, err := s.GetUserByID(id)
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}

	now := time.Date(2026, 9, 5, 14, 0, 0, 0, time.UTC)
	if _, err := s.RecordLoginFailure("does-not-exist", now, testPolicy()); err == nil {
		t.Fatal("expected an error recording a failure for an unknown user")
	} else if !strings.Contains(err.Error(), "user not found") {
		t.Fatalf("expected a user-not-found error, got %v", err)
	}

	if err := s.RecordLoginSuccess("does-not-exist", now); err == nil {
		t.Fatal("expected an error recording a success for an unknown user")
	} else if !strings.Contains(err.Error(), "user not found") {
		t.Fatalf("expected a user-not-found error, got %v", err)
	}

	after, err := s.GetUserByID(id)
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if after.FailedLoginCount != before.FailedLoginCount ||
		after.LastFailedLoginAt != nil || after.LastLoginAt != nil || after.LockedUntil != nil {
		t.Fatalf("expected the existing user to be untouched, got %+v", after)
	}

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
}

// TestRecordLoginFailure_ZeroDurationNoAutoUnlock covers a policy with no
// automatic expiry: the year-9999 sentinel must survive the store's
// second-precision format and parse back exactly.
func TestRecordLoginFailure_ZeroDurationNoAutoUnlock(t *testing.T) {
	s := testStore(t)
	id := newLockoutUser(t, s, "u-forever", "forever")

	p := lockout.Policy{Threshold: 1, Window: 15 * time.Minute, Duration: 0}
	now := time.Date(2026, 9, 5, 15, 0, 0, 0, time.UTC)

	res, err := s.RecordLoginFailure(id, now, p)
	if err != nil {
		t.Fatalf(testRecordFailureFmt, err)
	}
	if !res.NewlyLocked {
		t.Fatal("expected NewlyLocked true with threshold 1")
	}
	if res.LockedUntil == nil || !res.LockedUntil.Equal(lockout.NoAutoUnlock) {
		t.Fatalf("expected locked_until %v, got %v", lockout.NoAutoUnlock, res.LockedUntil)
	}

	got, err := s.GetUserByID(id)
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if got.LockedUntil == nil {
		t.Fatal("expected a persisted locked_until, got nil")
	}
	if !got.LockedUntil.Equal(lockout.NoAutoUnlock) {
		t.Fatalf("expected the no-auto-unlock sentinel to survive the round trip, got %v (%s)",
			got.LockedUntil, got.LockedUntil.Format(testSQLiteTimeFormat))
	}
	if !lockout.IsLocked(got.LockedUntil, now.Add(100*365*24*time.Hour)) {
		t.Fatal("expected the account to still read as locked a century later")
	}
}

// TestRecordLoginFailure_Race drives many concurrent failures at the threshold
// boundary. BEGIN IMMEDIATE must serialize them so exactly one caller observes
// the locking transition, with no busy/locked errors and no lost updates.
func TestRecordLoginFailure_Race(t *testing.T) {
	s := testStore(t)
	id := newLockoutUser(t, s, "u-race", "racy")

	p := lockout.Policy{Threshold: 5, Window: 15 * time.Minute, Duration: 15 * time.Minute}
	now := time.Date(2026, 9, 5, 16, 0, 0, 0, time.UTC)

	for i := 1; i <= 4; i++ {
		res, err := s.RecordLoginFailure(id, now, p)
		if err != nil {
			t.Fatalf("seed failure %d: %v", i, err)
		}
		if res.NewlyLocked {
			t.Fatalf("seed failure %d locked the account early", i)
		}
	}

	const goroutines = 20
	var wg sync.WaitGroup
	results := make([]store.FailureResult, goroutines)
	errs := make([]error, goroutines)
	start := make(chan struct{})
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = s.RecordLoginFailure(id, now, p)
		}(i)
	}
	close(start)
	wg.Wait()

	newlyLocked := 0
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
		if results[i].NewlyLocked {
			newlyLocked++
		}
	}
	if newlyLocked != 1 {
		t.Fatalf("expected exactly one NewlyLocked, got %d", newlyLocked)
	}

	got, err := s.GetUserByID(id)
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	if got.FailedLoginCount != 4+goroutines {
		t.Fatalf("expected failed_login_count %d, got %d", 4+goroutines, got.FailedLoginCount)
	}
	assertSecond(t, "locked_until", got.LockedUntil, now.Add(15*time.Minute))
}

package store_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

const (
	testDisableUserFmt = "disable user: %v"
	testEnableUserFmt  = "enable user: %v"
	testUnlockUserFmt  = "unlock user: %v"
)

// newLifecycleUser creates a user with an explicit role for a lifecycle test.
func newLifecycleUser(t *testing.T, s *store.Store, id, username string, role model.Role) *model.User {
	t.Helper()
	u := &model.User{
		ID:           id,
		Username:     username,
		Email:        username + "@test.com",
		PasswordHash: "h",
		Role:         role,
	}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create user %s: %v", id, err)
	}
	got, err := s.GetUserByID(id)
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	return got
}

// newLifecycleToken mints an active API token for a user.
func newLifecycleToken(t *testing.T, s *store.Store, id, userID, hash string) {
	t.Helper()
	if err := s.CreateAPIToken(&model.APIToken{
		ID:          id,
		UserID:      userID,
		Name:        id,
		TokenHash:   hash,
		TokenPrefix: "adt_" + id,
	}); err != nil {
		t.Fatalf("create api token %s: %v", id, err)
	}
}

// assertTokenActive asserts whether a token hash still resolves to an active token.
func assertTokenActive(t *testing.T, s *store.Store, hash string, want bool) {
	t.Helper()
	_, err := s.GetActiveAPITokenByHash(hash)
	if want && err != nil {
		t.Fatalf("expected token %q to still be active, got %v", hash, err)
	}
	if !want && err == nil {
		t.Fatalf("expected token %q to be revoked, but it is still active", hash)
	}
}

// mustGetUser re-reads a user or fails the test.
func mustGetUser(t *testing.T, s *store.Store, id string) *model.User {
	t.Helper()
	u, err := s.GetUserByID(id)
	if err != nil {
		t.Fatalf(testGetUserFmt, err)
	}
	return u
}

// TestDisableUser_SetsFieldsAndRevokesTokens covers the whole disable
// transaction: the disabled marker and actor are stamped, the token
// generation moves exactly one step (killing web sessions and refresh), and
// every one of the target's active API tokens is revoked while another user's
// tokens are left alone (FR-002, FR-003).
func TestDisableUser_SetsFieldsAndRevokesTokens(t *testing.T) {
	s := testStore(t)
	target := newLifecycleUser(t, s, "dis-target", "distarget", model.RoleViewer)
	newLifecycleUser(t, s, "dis-actor", "disactor", model.RoleAdmin)
	newLifecycleUser(t, s, "dis-other", "disother", model.RoleViewer)

	newLifecycleToken(t, s, "tok-a", "dis-target", "hash-a")
	newLifecycleToken(t, s, "tok-b", "dis-target", "hash-b")
	newLifecycleToken(t, s, "tok-c", "dis-other", "hash-c")

	now := time.Date(2026, 9, 6, 9, 0, 0, 0, time.UTC)
	revoked, err := s.DisableUser("dis-target", "dis-actor", now)
	if err != nil {
		t.Fatalf(testDisableUserFmt, err)
	}
	if revoked != 2 {
		t.Fatalf("expected 2 revoked api tokens, got %d", revoked)
	}

	got := mustGetUser(t, s, "dis-target")
	assertSecond(t, "disabled_at", got.DisabledAt, now)
	if got.DisabledBy == nil || *got.DisabledBy != "dis-actor" {
		t.Fatalf("expected disabled_by 'dis-actor', got %v", got.DisabledBy)
	}
	if got.TokenGeneration != target.TokenGeneration+1 {
		t.Fatalf("expected token_generation %d, got %d", target.TokenGeneration+1, got.TokenGeneration)
	}

	assertTokenActive(t, s, "hash-a", false)
	assertTokenActive(t, s, "hash-b", false)
	assertTokenActive(t, s, "hash-c", true)
}

// TestDisableUser_AlreadyDisabled covers the idempotence signal: a second
// disable reports ErrAlreadyDisabled and changes nothing, so the handler can
// answer 200 without bumping the generation again.
func TestDisableUser_AlreadyDisabled(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "dis2-target", "dis2target", model.RoleViewer)
	newLifecycleUser(t, s, "dis2-actor", "dis2actor", model.RoleAdmin)

	now := time.Date(2026, 9, 6, 9, 0, 0, 0, time.UTC)
	if _, err := s.DisableUser("dis2-target", "dis2-actor", now); err != nil {
		t.Fatalf(testDisableUserFmt, err)
	}
	first := mustGetUser(t, s, "dis2-target")

	later := now.Add(time.Hour)
	revoked, err := s.DisableUser("dis2-target", "dis2-actor", later)
	if !errors.Is(err, store.ErrAlreadyDisabled) {
		t.Fatalf("expected ErrAlreadyDisabled, got %v", err)
	}
	if revoked != 0 {
		t.Fatalf("expected 0 revoked tokens on a repeat disable, got %d", revoked)
	}

	after := mustGetUser(t, s, "dis2-target")
	if after.TokenGeneration != first.TokenGeneration {
		t.Fatalf("expected token_generation to stay %d, got %d", first.TokenGeneration, after.TokenGeneration)
	}
	assertSecond(t, "disabled_at", after.DisabledAt, now)
}

// TestDisableUser_LastEnabledAdmin covers the zero-admin guard: the only
// enabled administrator cannot be disabled and nothing at all is written
// (FR-002, SC-003).
func TestDisableUser_LastEnabledAdmin(t *testing.T) {
	s := testStore(t)
	admin := newLifecycleUser(t, s, "last-admin", "lastadmin", model.RoleAdmin)
	newLifecycleUser(t, s, "plain-viewer", "plainviewer", model.RoleViewer)
	newLifecycleToken(t, s, "tok-admin", "last-admin", "hash-admin")

	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	if _, err := s.DisableUser("last-admin", "last-admin", now); !errors.Is(err, store.ErrLastAdmin) {
		t.Fatalf("expected ErrLastAdmin, got %v", err)
	}

	after := mustGetUser(t, s, "last-admin")
	if after.DisabledAt != nil || after.DisabledBy != nil {
		t.Fatalf("expected the last admin to be untouched, got %+v", after)
	}
	if after.TokenGeneration != admin.TokenGeneration {
		t.Fatalf("expected token_generation to stay %d, got %d", admin.TokenGeneration, after.TokenGeneration)
	}
	assertTokenActive(t, s, "hash-admin", true)
}

// TestDisableUser_SecondAdminAllowedThenLastRefused covers the boundary: with
// two enabled admins one may be disabled, after which the survivor is the last
// enabled admin and is refused. A disabled admin does not count as enabled.
func TestDisableUser_SecondAdminAllowedThenLastRefused(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "admin-a", "admina", model.RoleAdmin)
	newLifecycleUser(t, s, "admin-b", "adminb", model.RoleAdmin)

	now := time.Date(2026, 9, 6, 11, 0, 0, 0, time.UTC)
	if _, err := s.DisableUser("admin-a", "admin-b", now); err != nil {
		t.Fatalf("expected the first of two admins to be disabled, got %v", err)
	}

	count, err := s.CountEnabledAdmins()
	if err != nil {
		t.Fatalf("count enabled admins: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 enabled admin, got %d", count)
	}

	if _, err := s.DisableUser("admin-b", "admin-a", now); !errors.Is(err, store.ErrLastAdmin) {
		t.Fatalf("expected ErrLastAdmin for the survivor, got %v", err)
	}
}

// TestDisableUser_UnknownUser covers an unknown id writing nothing.
func TestDisableUser_UnknownUser(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "dis3-actor", "dis3actor", model.RoleAdmin)

	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	_, err := s.DisableUser("does-not-exist", "dis3-actor", now)
	if err == nil {
		t.Fatal("expected an error disabling an unknown user")
	}
	if !strings.Contains(err.Error(), "user not found") {
		t.Fatalf("expected a user-not-found error, got %v", err)
	}
}

// TestDisableUser_Race is the adversarial case behind SC-003: two enabled
// administrators, many goroutines racing to disable each other from a start
// barrier. BEGIN IMMEDIATE must serialize the guard with the write so at least
// one enabled administrator always survives, and no caller may see a
// busy/locked error — only the two expected refusals.
func TestDisableUser_Race(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "race-a", "racea", model.RoleAdmin)
	newLifecycleUser(t, s, "race-b", "raceb", model.RoleAdmin)

	now := time.Date(2026, 9, 6, 13, 0, 0, 0, time.UTC)

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	start := make(chan struct{})
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target, actor := "race-a", "race-b"
			if i%2 == 1 {
				target, actor = "race-b", "race-a"
			}
			<-start
			_, errs[i] = s.DisableUser(target, actor, now)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err == nil || errors.Is(err, store.ErrLastAdmin) || errors.Is(err, store.ErrAlreadyDisabled) {
			continue
		}
		t.Fatalf("goroutine %d: expected success, ErrLastAdmin or ErrAlreadyDisabled, got %v", i, err)
	}

	count, err := s.CountEnabledAdmins()
	if err != nil {
		t.Fatalf("count enabled admins: %v", err)
	}
	if count < 1 {
		t.Fatalf("expected at least one enabled admin to survive the race, got %d", count)
	}
}

// TestEnableUser_ClearsDisabledLockAndCount covers FR-004: enabling clears the
// disabled marker and actor, any lock and the failure streak, and stamps the
// reactivation time that restarts the dormancy clock.
func TestEnableUser_ClearsDisabledLockAndCount(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "en-target", "entarget", model.RoleViewer)
	newLifecycleUser(t, s, "en-actor", "enactor", model.RoleAdmin)

	failedAt := time.Date(2026, 9, 6, 14, 0, 0, 0, time.UTC)
	for i := 1; i <= 3; i++ {
		if _, err := s.RecordLoginFailure("en-target", failedAt, testPolicy()); err != nil {
			t.Fatalf("seed failure %d: %v", i, err)
		}
	}
	if _, err := s.DisableUser("en-target", "en-actor", failedAt); err != nil {
		t.Fatalf(testDisableUserFmt, err)
	}

	now := failedAt.Add(time.Hour)
	wasDisabled, err := s.EnableUser("en-target", now)
	if err != nil {
		t.Fatalf(testEnableUserFmt, err)
	}
	if !wasDisabled {
		t.Fatal("expected wasDisabled true for a disabled account")
	}

	got := mustGetUser(t, s, "en-target")
	if got.DisabledAt != nil || got.DisabledBy != nil {
		t.Fatalf("expected the disabled marker cleared, got %+v", got)
	}
	if got.LockedUntil != nil {
		t.Fatalf("expected locked_until cleared, got %v", got.LockedUntil)
	}
	if got.FailedLoginCount != 0 {
		t.Fatalf("expected failed_login_count 0, got %d", got.FailedLoginCount)
	}
	assertSecond(t, "reactivated_at", got.ReactivatedAt, now)
}

// TestEnableUser_IdempotentOnEnabledAccount covers the spec's decision that
// enabling an already-enabled account succeeds without touching the activity
// clock.
func TestEnableUser_IdempotentOnEnabledAccount(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "en2-target", "en2target", model.RoleViewer)
	newLifecycleUser(t, s, "en2-actor", "en2actor", model.RoleAdmin)

	disabledAt := time.Date(2026, 9, 6, 15, 0, 0, 0, time.UTC)
	if _, err := s.DisableUser("en2-target", "en2-actor", disabledAt); err != nil {
		t.Fatalf(testDisableUserFmt, err)
	}
	firstEnable := disabledAt.Add(time.Hour)
	if _, err := s.EnableUser("en2-target", firstEnable); err != nil {
		t.Fatalf(testEnableUserFmt, err)
	}

	wasDisabled, err := s.EnableUser("en2-target", firstEnable.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("second enable: %v", err)
	}
	if wasDisabled {
		t.Fatal("expected wasDisabled false for an already-enabled account")
	}

	got := mustGetUser(t, s, "en2-target")
	assertSecond(t, "reactivated_at", got.ReactivatedAt, firstEnable)
}

// TestEnableUser_UnknownUser covers an unknown id.
func TestEnableUser_UnknownUser(t *testing.T) {
	s := testStore(t)
	_, err := s.EnableUser("does-not-exist", time.Date(2026, 9, 6, 16, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("expected an error enabling an unknown user")
	}
	if !strings.Contains(err.Error(), "user not found") {
		t.Fatalf("expected a user-not-found error, got %v", err)
	}
}

// TestUnlockUser_ClearsActiveLock covers FR-005: clearing a live lock resets
// the streak and stamps the reactivation time.
func TestUnlockUser_ClearsActiveLock(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "un-target", "untarget", model.RoleViewer)

	failedAt := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	for i := 1; i <= 3; i++ {
		if _, err := s.RecordLoginFailure("un-target", failedAt, testPolicy()); err != nil {
			t.Fatalf("seed failure %d: %v", i, err)
		}
	}

	now := failedAt.Add(time.Minute)
	wasLocked, err := s.UnlockUser("un-target", now)
	if err != nil {
		t.Fatalf(testUnlockUserFmt, err)
	}
	if !wasLocked {
		t.Fatal("expected wasLocked true for a locked account")
	}

	got := mustGetUser(t, s, "un-target")
	if got.LockedUntil != nil {
		t.Fatalf("expected locked_until cleared, got %v", got.LockedUntil)
	}
	if got.FailedLoginCount != 0 {
		t.Fatalf("expected failed_login_count 0, got %d", got.FailedLoginCount)
	}
	assertSecond(t, "reactivated_at", got.ReactivatedAt, now)
}

// TestUnlockUser_IdempotentOnUnlockedAccount covers the spec's decision that
// unlocking an unlocked account leaves reactivated_at alone — including the
// case of a lock that has already expired on its own.
func TestUnlockUser_IdempotentOnUnlockedAccount(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "un2-target", "un2target", model.RoleViewer)

	now := time.Date(2026, 9, 6, 18, 0, 0, 0, time.UTC)
	wasLocked, err := s.UnlockUser("un2-target", now)
	if err != nil {
		t.Fatalf(testUnlockUserFmt, err)
	}
	if wasLocked {
		t.Fatal("expected wasLocked false for a never-locked account")
	}
	if got := mustGetUser(t, s, "un2-target"); got.ReactivatedAt != nil {
		t.Fatalf("expected reactivated_at untouched, got %v", got.ReactivatedAt)
	}

	// An expired lock does not count as locked, but is still cleared.
	failedAt := now.Add(time.Hour)
	p := lockout.Policy{Threshold: 1, Window: 15 * time.Minute, Duration: 15 * time.Minute}
	if _, err := s.RecordLoginFailure("un2-target", failedAt, p); err != nil {
		t.Fatalf(testRecordFailureFmt, err)
	}

	afterExpiry := failedAt.Add(time.Hour)
	wasLocked, err = s.UnlockUser("un2-target", afterExpiry)
	if err != nil {
		t.Fatalf(testUnlockUserFmt, err)
	}
	if wasLocked {
		t.Fatal("expected wasLocked false for an expired lock")
	}
	got := mustGetUser(t, s, "un2-target")
	if got.LockedUntil != nil {
		t.Fatalf("expected the expired lock cleared, got %v", got.LockedUntil)
	}
	if got.ReactivatedAt != nil {
		t.Fatalf("expected reactivated_at untouched for an expired lock, got %v", got.ReactivatedAt)
	}
	if got.FailedLoginCount != 0 {
		t.Fatalf("expected failed_login_count 0, got %d", got.FailedLoginCount)
	}
}

// TestUnlockUser_NoAutoUnlockSentinel covers a lock with no automatic expiry
// (duration 0 → the year-9999 sentinel) reading as locked.
func TestUnlockUser_NoAutoUnlockSentinel(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "un3-target", "un3target", model.RoleViewer)

	failedAt := time.Date(2026, 9, 6, 19, 0, 0, 0, time.UTC)
	p := lockout.Policy{Threshold: 1, Window: 15 * time.Minute, Duration: 0}
	if _, err := s.RecordLoginFailure("un3-target", failedAt, p); err != nil {
		t.Fatalf(testRecordFailureFmt, err)
	}

	now := failedAt.Add(24 * time.Hour)
	wasLocked, err := s.UnlockUser("un3-target", now)
	if err != nil {
		t.Fatalf(testUnlockUserFmt, err)
	}
	if !wasLocked {
		t.Fatal("expected wasLocked true for the no-auto-unlock sentinel")
	}
	assertSecond(t, "reactivated_at", mustGetUser(t, s, "un3-target").ReactivatedAt, now)
}

// TestUnlockUser_UnknownUser covers an unknown id.
func TestUnlockUser_UnknownUser(t *testing.T) {
	s := testStore(t)
	_, err := s.UnlockUser("does-not-exist", time.Date(2026, 9, 6, 20, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("expected an error unlocking an unknown user")
	}
	if !strings.Contains(err.Error(), "user not found") {
		t.Fatalf("expected a user-not-found error, got %v", err)
	}
}

// TestSetDormancyExempt_AdminOnly covers the exemption being settable on an
// administrator, refused on any other role, and clearable again.
func TestSetDormancyExempt_AdminOnly(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "exempt-admin", "exemptadmin", model.RoleAdmin)
	newLifecycleUser(t, s, "exempt-viewer", "exemptviewer", model.RoleViewer)

	if err := s.SetDormancyExempt("exempt-admin", true); err != nil {
		t.Fatalf("set dormancy exempt on admin: %v", err)
	}
	if !mustGetUser(t, s, "exempt-admin").DormancyExempt {
		t.Fatal("expected dormancy_exempt true on the admin")
	}

	if err := s.SetDormancyExempt("exempt-admin", false); err != nil {
		t.Fatalf("clear dormancy exempt on admin: %v", err)
	}
	if mustGetUser(t, s, "exempt-admin").DormancyExempt {
		t.Fatal("expected dormancy_exempt false after clearing")
	}

	if err := s.SetDormancyExempt("exempt-viewer", true); !errors.Is(err, store.ErrNotAdmin) {
		t.Fatalf("expected ErrNotAdmin for a viewer, got %v", err)
	}
	if mustGetUser(t, s, "exempt-viewer").DormancyExempt {
		t.Fatal("expected the viewer to remain unexempt")
	}
}

// TestSetDormancyExempt_UnknownUser covers an unknown id.
func TestSetDormancyExempt_UnknownUser(t *testing.T) {
	s := testStore(t)
	err := s.SetDormancyExempt("does-not-exist", true)
	if err == nil {
		t.Fatal("expected an error setting the exemption on an unknown user")
	}
	if !strings.Contains(err.Error(), "user not found") {
		t.Fatalf("expected a user-not-found error, got %v", err)
	}
}

// TestTouchUserActivity_ThrottlesWithinOneMinute covers R3: the activity clock
// is written at most once a minute per user, so a hot API-token path costs one
// cheap guarded UPDATE rather than a write per request.
func TestTouchUserActivity_ThrottlesWithinOneMinute(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "touch-1", "touch1", model.RoleViewer)

	t0 := time.Date(2026, 9, 6, 21, 0, 0, 0, time.UTC)
	if err := s.TouchUserActivity("touch-1", t0); err != nil {
		t.Fatalf("touch at t0: %v", err)
	}
	assertSecond(t, "last_activity_at", mustGetUser(t, s, "touch-1").LastActivityAt, t0)

	if err := s.TouchUserActivity("touch-1", t0.Add(30*time.Second)); err != nil {
		t.Fatalf("touch at t0+30s: %v", err)
	}
	assertSecond(t, "last_activity_at", mustGetUser(t, s, "touch-1").LastActivityAt, t0)

	later := t0.Add(61 * time.Second)
	if err := s.TouchUserActivity("touch-1", later); err != nil {
		t.Fatalf("touch at t0+61s: %v", err)
	}
	assertSecond(t, "last_activity_at", mustGetUser(t, s, "touch-1").LastActivityAt, later)
}

// TestTouchUserActivity_DoesNotTouchUpdatedAt covers the hot path leaving the
// row's updated_at alone, so activity is not mistaken for an administrative
// change.
func TestTouchUserActivity_DoesNotTouchUpdatedAt(t *testing.T) {
	s := testStore(t)
	newLifecycleUser(t, s, "touch-2", "touch2", model.RoleViewer)

	before := mustGetUser(t, s, "touch-2").UpdatedAt
	if err := s.TouchUserActivity("touch-2", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if after := mustGetUser(t, s, "touch-2").UpdatedAt; !after.Equal(before) {
		t.Fatalf("expected updated_at %v to be untouched, got %v", before, after)
	}
}

// TestTouchUserActivity_UnknownUserIsNotAnError covers the fire-and-forget
// contract: the hot path never fails a request over a vanished row.
func TestTouchUserActivity_UnknownUserIsNotAnError(t *testing.T) {
	s := testStore(t)
	if err := s.TouchUserActivity("does-not-exist", time.Date(2026, 9, 6, 22, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("expected no error touching an unknown user, got %v", err)
	}
}

// TestCountEnabledAdmins_ExcludesDisabledAndNonAdmins covers the definition of
// "enabled administrator" the last-admin guard depends on.
func TestCountEnabledAdmins_ExcludesDisabledAndNonAdmins(t *testing.T) {
	s := testStore(t)

	count, err := s.CountEnabledAdmins()
	if err != nil {
		t.Fatalf("count enabled admins: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 enabled admins on an empty hub, got %d", count)
	}

	newLifecycleUser(t, s, "cnt-admin-1", "cntadmin1", model.RoleAdmin)
	newLifecycleUser(t, s, "cnt-admin-2", "cntadmin2", model.RoleAdmin)
	newLifecycleUser(t, s, "cnt-viewer", "cntviewer", model.RoleViewer)

	count, err = s.CountEnabledAdmins()
	if err != nil {
		t.Fatalf("count enabled admins: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 enabled admins, got %d", count)
	}

	now := time.Date(2026, 9, 6, 23, 0, 0, 0, time.UTC)
	if _, err := s.DisableUser("cnt-admin-1", "cnt-admin-2", now); err != nil {
		t.Fatalf(testDisableUserFmt, err)
	}

	count, err = s.CountEnabledAdmins()
	if err != nil {
		t.Fatalf("count enabled admins: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 enabled admin after disabling one, got %d", count)
	}
}
